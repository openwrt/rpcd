/*
 * luci-rpcd - LuCI UBUS RPC server
 *
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *   Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <libubox/avl-cmp.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <fnmatch.h>

#include "session.h"

static struct avl_tree sessions;
static struct blob_buf buf;

static const struct blobmsg_policy new_policy = {
	.name = "timeout", .type = BLOBMSG_TYPE_INT32
};

static const struct blobmsg_policy sid_policy = {
	.name = "sid", .type = BLOBMSG_TYPE_STRING
};

enum {
	RPC_SS_SID,
	RPC_SS_VALUES,
	__RPC_SS_MAX,
};
static const struct blobmsg_policy set_policy[__RPC_SS_MAX] = {
	[RPC_SS_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[RPC_SS_VALUES] = { .name = "values", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	RPC_SG_SID,
	RPC_SG_KEYS,
	__RPC_SG_MAX,
};
static const struct blobmsg_policy get_policy[__RPC_SG_MAX] = {
	[RPC_SG_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[RPC_SG_KEYS] = { .name = "keys", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	RPC_SA_SID,
	RPC_SA_SCOPE,
	RPC_SA_OBJECTS,
	__RPC_SA_MAX,
};
static const struct blobmsg_policy acl_policy[__RPC_SA_MAX] = {
	[RPC_SA_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[RPC_SA_SCOPE] = { .name = "scope", .type = BLOBMSG_TYPE_STRING },
	[RPC_SA_OBJECTS] = { .name = "objects", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	RPC_SP_SID,
	RPC_SP_SCOPE,
	RPC_SP_OBJECT,
	RPC_SP_FUNCTION,
	__RPC_SP_MAX,
};
static const struct blobmsg_policy perm_policy[__RPC_SP_MAX] = {
	[RPC_SP_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_SCOPE] = { .name = "scope", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_OBJECT] = { .name = "object", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_FUNCTION] = { .name = "function", .type = BLOBMSG_TYPE_STRING },
};

/*
 * Keys in the AVL tree contain all pattern characters up to the first wildcard.
 * To look up entries, start with the last entry that has a key less than or
 * equal to the method name, then work backwards as long as the AVL key still
 * matches its counterpart in the object name
 */
#define uh_foreach_matching_acl_prefix(_acl, _avl, _obj, _func)		\
	for (_acl = avl_find_le_element(_avl, _obj, _acl, avl);			\
	     _acl;														\
	     _acl = avl_is_first(_avl, &(_acl)->avl) ? NULL :			\
		    avl_prev_element((_acl), avl))

#define uh_foreach_matching_acl(_acl, _avl, _obj, _func)			\
	uh_foreach_matching_acl_prefix(_acl, _avl, _obj, _func)			\
		if (!strncmp((_acl)->object, _obj, (_acl)->sort_len) &&		\
		    !fnmatch((_acl)->object, (_obj), FNM_NOESCAPE) &&		\
		    !fnmatch((_acl)->function, (_func), FNM_NOESCAPE))

static void
rpc_random(char *dest)
{
	unsigned char buf[16] = { 0 };
	FILE *f;
	int i;

	f = fopen("/dev/urandom", "r");
	if (!f)
		return;

	fread(buf, 1, sizeof(buf), f);
	fclose(f);

	for (i = 0; i < sizeof(buf); i++)
		sprintf(dest + (i<<1), "%02x", buf[i]);
}

static void
rpc_session_dump_data(struct rpc_session *ses, struct blob_buf *b)
{
	struct rpc_session_data *d;

	avl_for_each_element(&ses->data, d, avl) {
		blobmsg_add_field(b, blobmsg_type(d->attr), blobmsg_name(d->attr),
				  blobmsg_data(d->attr), blobmsg_data_len(d->attr));
	}
}

static void
rpc_session_dump_acls(struct rpc_session *ses, struct blob_buf *b)
{
	struct rpc_session_acl *acl;
	struct rpc_session_acl_scope *acl_scope;
	const char *lastobj = NULL;
	const char *lastscope = NULL;
	void *c = NULL, *d = NULL;

	avl_for_each_element(&ses->acls, acl_scope, avl) {
		if (!lastscope || strcmp(acl_scope->avl.key, lastscope))
		{
			if (c) blobmsg_close_table(b, c);
			c = blobmsg_open_table(b, acl_scope->avl.key);
		}

		d = NULL;

		avl_for_each_element(&acl_scope->acls, acl, avl) {
			if (!lastobj || strcmp(acl->object, lastobj))
			{
				if (d) blobmsg_close_array(b, d);
				d = blobmsg_open_array(b, acl->object);
			}

			blobmsg_add_string(b, NULL, acl->function);
			lastobj = acl->object;
		}

		if (d) blobmsg_close_array(b, d);
	}

	if (c) blobmsg_close_table(b, c);
}

static void
rpc_session_dump(struct rpc_session *ses,
					 struct ubus_context *ctx,
					 struct ubus_request_data *req)
{
	void *c;

	blob_buf_init(&buf, 0);

	blobmsg_add_string(&buf, "sid", ses->id);
	blobmsg_add_u32(&buf, "timeout", ses->timeout);
	blobmsg_add_u32(&buf, "expires", uloop_timeout_remaining(&ses->t) / 1000);

	c = blobmsg_open_table(&buf, "acls");
	rpc_session_dump_acls(ses, &buf);
	blobmsg_close_table(&buf, c);

	c = blobmsg_open_table(&buf, "data");
	rpc_session_dump_data(ses, &buf);
	blobmsg_close_table(&buf, c);

	ubus_send_reply(ctx, req, buf.head);
}

static void
rpc_touch_session(struct rpc_session *ses)
{
	uloop_timeout_set(&ses->t, ses->timeout * 1000);
}

static void
rpc_session_destroy(struct rpc_session *ses)
{
	struct rpc_session_acl *acl, *nacl;
	struct rpc_session_acl_scope *acl_scope, *nacl_scope;
	struct rpc_session_data *data, *ndata;

	uloop_timeout_cancel(&ses->t);

	avl_for_each_element_safe(&ses->acls, acl_scope, avl, nacl_scope) {
		avl_remove_all_elements(&acl_scope->acls, acl, avl, nacl)
			free(acl);

		avl_delete(&ses->acls, &acl_scope->avl);
		free(acl_scope);
	}

	avl_remove_all_elements(&ses->data, data, avl, ndata)
		free(data);

	avl_delete(&sessions, &ses->avl);
	free(ses);
}

static void rpc_session_timeout(struct uloop_timeout *t)
{
	struct rpc_session *ses;

	ses = container_of(t, struct rpc_session, t);
	rpc_session_destroy(ses);
}

static struct rpc_session *
rpc_session_create(int timeout)
{
	struct rpc_session *ses;

	ses = calloc(1, sizeof(*ses));
	if (!ses)
		return NULL;

	ses->timeout  = timeout;
	ses->avl.key  = ses->id;
	rpc_random(ses->id);

	avl_insert(&sessions, &ses->avl);
	avl_init(&ses->acls, avl_strcmp, true, NULL);
	avl_init(&ses->data, avl_strcmp, false, NULL);

	ses->t.cb = rpc_session_timeout;
	rpc_touch_session(ses);

	return ses;
}

static struct rpc_session *
rpc_session_get(const char *id)
{
	struct rpc_session *ses;

	ses = avl_find_element(&sessions, id, ses, avl);
	if (!ses)
		return NULL;

	rpc_touch_session(ses);
	return ses;
}

static int
rpc_handle_create(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method,
                  struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb;
	int timeout = RPC_DEFAULT_SESSION_TIMEOUT;

	blobmsg_parse(&new_policy, 1, &tb, blob_data(msg), blob_len(msg));
	if (tb)
		timeout = blobmsg_get_u32(tb);

	ses = rpc_session_create(timeout);
	if (ses)
		rpc_session_dump(ses, ctx, req);

	return 0;
}

static int
rpc_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb;

	blobmsg_parse(&sid_policy, 1, &tb, blob_data(msg), blob_len(msg));

	if (!tb) {
		avl_for_each_element(&sessions, ses, avl)
			rpc_session_dump(ses, ctx, req);
		return 0;
	}

	ses = rpc_session_get(blobmsg_data(tb));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	rpc_session_dump(ses, ctx, req);

	return 0;
}

static int
uh_id_len(const char *str)
{
	return strcspn(str, "*?[");
}

static int
rpc_session_grant(struct rpc_session *ses, struct ubus_context *ctx,
                  const char *scope, const char *object, const char *function)
{
	struct rpc_session_acl *acl;
	struct rpc_session_acl_scope *acl_scope;
	char *new_scope, *new_obj, *new_func, *new_id;
	int id_len;

	if (!object || !function)
		return UBUS_STATUS_INVALID_ARGUMENT;

	acl_scope = avl_find_element(&ses->acls, scope, acl_scope, avl);

	if (acl_scope) {
		uh_foreach_matching_acl_prefix(acl, &acl_scope->acls, object, function) {
			if (!strcmp(acl->object, object) &&
				!strcmp(acl->function, function))
				return 0;
		}
	}

	if (!acl_scope) {
		acl_scope = calloc_a(sizeof(*acl_scope),
		                     &new_scope, strlen(scope) + 1);

		if (!acl_scope)
			return UBUS_STATUS_UNKNOWN_ERROR;

		acl_scope->avl.key = strcpy(new_scope, scope);
		avl_init(&acl_scope->acls, avl_strcmp, true, NULL);
		avl_insert(&ses->acls, &acl_scope->avl);
	}

	id_len = uh_id_len(object);
	acl = calloc_a(sizeof(*acl),
		&new_obj, strlen(object) + 1,
		&new_func, strlen(function) + 1,
		&new_id, id_len + 1);

	if (!acl)
		return UBUS_STATUS_UNKNOWN_ERROR;

	acl->object = strcpy(new_obj, object);
	acl->function = strcpy(new_func, function);
	acl->avl.key = strncpy(new_id, object, id_len);
	avl_insert(&acl_scope->acls, &acl->avl);

	return 0;
}

static int
rpc_session_revoke(struct rpc_session *ses, struct ubus_context *ctx,
                   const char *scope, const char *object, const char *function)
{
	struct rpc_session_acl *acl, *next;
	struct rpc_session_acl_scope *acl_scope;
	int id_len;
	char *id;

	acl_scope = avl_find_element(&ses->acls, scope, acl_scope, avl);

	if (!acl_scope)
		return 0;

	if (!object && !function) {
		avl_remove_all_elements(&acl_scope->acls, acl, avl, next)
			free(acl);
		avl_delete(&ses->acls, &acl_scope->avl);
		free(acl_scope);
		return 0;
	}

	id_len = uh_id_len(object);
	id = alloca(id_len + 1);
	strncpy(id, object, id_len);
	id[id_len] = 0;

	acl = avl_find_element(&acl_scope->acls, id, acl, avl);
	while (acl) {
		if (!avl_is_last(&acl_scope->acls, &acl->avl))
			next = avl_next_element(acl, avl);
		else
			next = NULL;

		if (strcmp(id, acl->avl.key) != 0)
			break;

		if (!strcmp(acl->object, object) &&
		    !strcmp(acl->function, function)) {
			avl_delete(&acl_scope->acls, &acl->avl);
			free(acl);
		}
		acl = next;
	}

	if (avl_is_empty(&acl_scope->acls)) {
		avl_delete(&ses->acls, &acl_scope->avl);
		free(acl_scope);
	}

	return 0;
}


static int
rpc_handle_acl(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb[__RPC_SA_MAX];
	struct blob_attr *attr, *sattr;
	const char *object, *function;
	const char *scope = "ubus";
	int rem1, rem2;

	int (*cb)(struct rpc_session *ses, struct ubus_context *ctx,
		  const char *scope, const char *object, const char *function);

	blobmsg_parse(acl_policy, __RPC_SA_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_SA_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SA_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	if (tb[RPC_SA_SCOPE])
		scope = blobmsg_data(tb[RPC_SA_SCOPE]);

	if (!strcmp(method, "grant"))
		cb = rpc_session_grant;
	else
		cb = rpc_session_revoke;

	if (!tb[RPC_SA_OBJECTS])
		return cb(ses, ctx, scope, NULL, NULL);

	blobmsg_for_each_attr(attr, tb[RPC_SA_OBJECTS], rem1) {
		if (blob_id(attr) != BLOBMSG_TYPE_ARRAY)
			continue;

		object = NULL;
		function = NULL;

		blobmsg_for_each_attr(sattr, attr, rem2) {
			if (blob_id(sattr) != BLOBMSG_TYPE_STRING)
				continue;

			if (!object)
				object = blobmsg_data(sattr);
			else if (!function)
				function = blobmsg_data(sattr);
			else
				break;
		}

		if (object && function)
			cb(ses, ctx, scope, object, function);
	}

	return 0;
}

static bool
rpc_session_acl_allowed(struct rpc_session *ses, const char *scope,
                        const char *obj, const char *fun)
{
	struct rpc_session_acl *acl;
	struct rpc_session_acl_scope *acl_scope;

	acl_scope = avl_find_element(&ses->acls, scope, acl_scope, avl);

	if (acl_scope) {
		uh_foreach_matching_acl(acl, &acl_scope->acls, obj, fun)
			return true;
	}

	return false;
}

static int
rpc_handle_access(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method,
                  struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb[__RPC_SP_MAX];
	const char *scope = "ubus";
	bool allow;

	blobmsg_parse(perm_policy, __RPC_SP_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_SP_SID] || !tb[RPC_SP_OBJECT] || !tb[RPC_SP_FUNCTION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SP_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	if (tb[RPC_SP_SCOPE])
		scope = blobmsg_data(tb[RPC_SP_SCOPE]);

	allow = rpc_session_acl_allowed(ses, scope,
									blobmsg_data(tb[RPC_SP_OBJECT]),
									blobmsg_data(tb[RPC_SP_FUNCTION]));

	blob_buf_init(&buf, 0);
	blobmsg_add_u8(&buf, "access", allow);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct rpc_session_data *data;
	struct blob_attr *tb[__RPC_SA_MAX];
	struct blob_attr *attr;
	int rem;

	blobmsg_parse(set_policy, __RPC_SS_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_SS_SID] || !tb[RPC_SS_VALUES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SS_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	blobmsg_for_each_attr(attr, tb[RPC_SS_VALUES], rem) {
		if (!blobmsg_name(attr)[0])
			continue;

		data = avl_find_element(&ses->data, blobmsg_name(attr), data, avl);
		if (data) {
			avl_delete(&ses->data, &data->avl);
			free(data);
		}

		data = calloc(1, sizeof(*data) + blob_pad_len(attr));
		if (!data)
			break;

		memcpy(data->attr, attr, blob_pad_len(attr));
		data->avl.key = blobmsg_name(data->attr);
		avl_insert(&ses->data, &data->avl);
	}

	return 0;
}

static int
rpc_handle_get(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct rpc_session_data *data;
	struct blob_attr *tb[__RPC_SA_MAX];
	struct blob_attr *attr;
	void *c;
	int rem;

	blobmsg_parse(get_policy, __RPC_SG_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_SG_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SG_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&buf, 0);
	c = blobmsg_open_table(&buf, "values");

	if (tb[RPC_SG_KEYS])
		blobmsg_for_each_attr(attr, tb[RPC_SG_KEYS], rem) {
			if (blob_id(attr) != BLOBMSG_TYPE_STRING)
				continue;

			data = avl_find_element(&ses->data, blobmsg_data(attr), data, avl);
			if (!data)
				continue;

			blobmsg_add_field(&buf, blobmsg_type(data->attr),
					  blobmsg_name(data->attr),
					  blobmsg_data(data->attr),
					  blobmsg_data_len(data->attr));
		}
	else
		rpc_session_dump_data(ses, &buf);

	blobmsg_close_table(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_handle_unset(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct rpc_session_data *data, *ndata;
	struct blob_attr *tb[__RPC_SA_MAX];
	struct blob_attr *attr;
	int rem;

	blobmsg_parse(get_policy, __RPC_SG_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_SG_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SG_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	if (!tb[RPC_SG_KEYS]) {
		avl_remove_all_elements(&ses->data, data, avl, ndata)
			free(data);
		return 0;
	}

	blobmsg_for_each_attr(attr, tb[RPC_SG_KEYS], rem) {
		if (blob_id(attr) != BLOBMSG_TYPE_STRING)
			continue;

		data = avl_find_element(&ses->data, blobmsg_data(attr), data, avl);
		if (!data)
			continue;

		avl_delete(&ses->data, &data->avl);
		free(data);
	}

	return 0;
}

static int
rpc_handle_destroy(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb;

	blobmsg_parse(&sid_policy, 1, &tb, blob_data(msg), blob_len(msg));

	if (!tb)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	rpc_session_destroy(ses);

	return 0;
}

int rpc_session_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method session_methods[] = {
		UBUS_METHOD("create",  rpc_handle_create,  &new_policy),
		UBUS_METHOD("list",    rpc_handle_list,    &sid_policy),
		UBUS_METHOD("grant",   rpc_handle_acl,     acl_policy),
		UBUS_METHOD("revoke",  rpc_handle_acl,     acl_policy),
		UBUS_METHOD("access",  rpc_handle_access,  perm_policy),
		UBUS_METHOD("set",     rpc_handle_set,     set_policy),
		UBUS_METHOD("get",     rpc_handle_get,     get_policy),
		UBUS_METHOD("unset",   rpc_handle_unset,   get_policy),
		UBUS_METHOD("destroy", rpc_handle_destroy, &sid_policy),
	};

	static struct ubus_object_type session_type =
		UBUS_OBJECT_TYPE("luci-rpc-session", session_methods);

	static struct ubus_object obj = {
		.name = "session",
		.type = &session_type,
		.methods = session_methods,
		.n_methods = ARRAY_SIZE(session_methods),
	};

	avl_init(&sessions, avl_strcmp, false, NULL);

	return ubus_add_object(ctx, &obj);
}
