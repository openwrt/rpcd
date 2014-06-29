/*
 * rpcd - UBUS RPC server
 *
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *   Copyright (C) 2013-2014 Jo-Philipp Wich <jow@openwrt.org>
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

#define _GNU_SOURCE	/* crypt() */

#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <fnmatch.h>
#include <glob.h>
#include <uci.h>
#include <limits.h>

#ifdef HAVE_SHADOW
#include <shadow.h>
#endif

#include <rpcd/session.h>

static struct avl_tree sessions;
static struct blob_buf buf;

static LIST_HEAD(create_callbacks);
static LIST_HEAD(destroy_callbacks);

static const struct blobmsg_policy new_policy = {
	.name = "timeout", .type = BLOBMSG_TYPE_INT32
};

static const struct blobmsg_policy sid_policy = {
	.name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING
};

enum {
	RPC_SS_SID,
	RPC_SS_VALUES,
	__RPC_SS_MAX,
};
static const struct blobmsg_policy set_policy[__RPC_SS_MAX] = {
	[RPC_SS_SID] = { .name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING },
	[RPC_SS_VALUES] = { .name = "values", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	RPC_SG_SID,
	RPC_SG_KEYS,
	__RPC_SG_MAX,
};
static const struct blobmsg_policy get_policy[__RPC_SG_MAX] = {
	[RPC_SG_SID] = { .name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING },
	[RPC_SG_KEYS] = { .name = "keys", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	RPC_SA_SID,
	RPC_SA_SCOPE,
	RPC_SA_OBJECTS,
	__RPC_SA_MAX,
};
static const struct blobmsg_policy acl_policy[__RPC_SA_MAX] = {
	[RPC_SA_SID] = { .name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING },
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
	[RPC_SP_SID] = { .name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_SCOPE] = { .name = "scope", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_OBJECT] = { .name = "object", .type = BLOBMSG_TYPE_STRING },
	[RPC_SP_FUNCTION] = { .name = "function", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_DUMP_SID,
	RPC_DUMP_TIMEOUT,
	RPC_DUMP_EXPIRES,
	RPC_DUMP_DATA,
	__RPC_DUMP_MAX,
};
static const struct blobmsg_policy dump_policy[__RPC_DUMP_MAX] = {
	[RPC_DUMP_SID] = { .name = "ubus_rpc_session", .type = BLOBMSG_TYPE_STRING },
	[RPC_DUMP_TIMEOUT] = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
	[RPC_DUMP_EXPIRES] = { .name = "expires", .type = BLOBMSG_TYPE_INT32 },
	[RPC_DUMP_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	RPC_L_USERNAME,
	RPC_L_PASSWORD,
	RPC_L_TIMEOUT,
	__RPC_L_MAX,
};
static const struct blobmsg_policy login_policy[__RPC_L_MAX] = {
	[RPC_L_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[RPC_L_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[RPC_L_TIMEOUT]  = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
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
			lastobj = NULL;
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
rpc_session_to_blob(struct rpc_session *ses, bool acls)
{
	void *c;

	blob_buf_init(&buf, 0);

	blobmsg_add_string(&buf, "ubus_rpc_session", ses->id);
	blobmsg_add_u32(&buf, "timeout", ses->timeout);
	blobmsg_add_u32(&buf, "expires", uloop_timeout_remaining(&ses->t) / 1000);

	if (acls) {
		c = blobmsg_open_table(&buf, "acls");
		rpc_session_dump_acls(ses, &buf);
		blobmsg_close_table(&buf, c);
	}

	c = blobmsg_open_table(&buf, "data");
	rpc_session_dump_data(ses, &buf);
	blobmsg_close_table(&buf, c);
}

static void
rpc_session_dump(struct rpc_session *ses, struct ubus_context *ctx,
                 struct ubus_request_data *req)
{
	rpc_session_to_blob(ses, true);

	ubus_send_reply(ctx, req, buf.head);
}

static void
rpc_touch_session(struct rpc_session *ses)
{
	if (ses->timeout > 0)
		uloop_timeout_set(&ses->t, ses->timeout * 1000);
}

static void
rpc_session_destroy(struct rpc_session *ses)
{
	struct rpc_session_acl *acl, *nacl;
	struct rpc_session_acl_scope *acl_scope, *nacl_scope;
	struct rpc_session_data *data, *ndata;
	struct rpc_session_cb *cb;

	list_for_each_entry(cb, &destroy_callbacks, list)
		cb->cb(ses, cb->priv);

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
rpc_session_new(void)
{
	struct rpc_session *ses;

	ses = calloc(1, sizeof(*ses));

	if (!ses)
		return NULL;

	ses->avl.key = ses->id;

	avl_init(&ses->acls, avl_strcmp, true, NULL);
	avl_init(&ses->data, avl_strcmp, false, NULL);

	ses->t.cb = rpc_session_timeout;

	return ses;
}

static struct rpc_session *
rpc_session_create(int timeout)
{
	struct rpc_session *ses;
	struct rpc_session_cb *cb;

	ses = rpc_session_new();

	if (!ses)
		return NULL;

	rpc_random(ses->id);

	ses->timeout = timeout;

	avl_insert(&sessions, &ses->avl);

	rpc_touch_session(ses);

	list_for_each_entry(cb, &create_callbacks, list)
		cb->cb(ses, cb->priv);

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
rpc_session_grant(struct rpc_session *ses,
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
rpc_session_revoke(struct rpc_session *ses,
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

	int (*cb)(struct rpc_session *ses,
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
		return cb(ses, scope, NULL, NULL);

	blobmsg_for_each_attr(attr, tb[RPC_SA_OBJECTS], rem1) {
		if (blobmsg_type(attr) != BLOBMSG_TYPE_ARRAY)
			continue;

		object = NULL;
		function = NULL;

		blobmsg_for_each_attr(sattr, attr, rem2) {
			if (blobmsg_type(sattr) != BLOBMSG_TYPE_STRING)
				continue;

			if (!object)
				object = blobmsg_data(sattr);
			else if (!function)
				function = blobmsg_data(sattr);
			else
				break;
		}

		if (object && function)
			cb(ses, scope, object, function);
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

	if (!tb[RPC_SP_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = rpc_session_get(blobmsg_data(tb[RPC_SP_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&buf, 0);

	if (tb[RPC_SP_OBJECT] && tb[RPC_SP_FUNCTION])
	{
		if (tb[RPC_SP_SCOPE])
			scope = blobmsg_data(tb[RPC_SP_SCOPE]);

		allow = rpc_session_acl_allowed(ses, scope,
		                                blobmsg_data(tb[RPC_SP_OBJECT]),
		                                blobmsg_data(tb[RPC_SP_FUNCTION]));

		blobmsg_add_u8(&buf, "access", allow);
	}
	else
	{
		rpc_session_dump_acls(ses, &buf);
	}

	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static void
rpc_session_set(struct rpc_session *ses, const char *key, struct blob_attr *val)
{
	struct rpc_session_data *data;

	data = avl_find_element(&ses->data, key, data, avl);
	if (data) {
		avl_delete(&ses->data, &data->avl);
		free(data);
	}

	data = calloc(1, sizeof(*data) + blob_pad_len(val));
	if (!data)
		return;

	memcpy(data->attr, val, blob_pad_len(val));
	data->avl.key = blobmsg_name(data->attr);
	avl_insert(&ses->data, &data->avl);
}

static int
rpc_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct rpc_session *ses;
	struct blob_attr *tb[__RPC_SS_MAX];
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

		rpc_session_set(ses, blobmsg_name(attr), attr);
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
	struct blob_attr *tb[__RPC_SG_MAX];
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
			if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
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
		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
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

	if (!strcmp(blobmsg_get_string(tb), RPC_DEFAULT_SESSION_ID))
		return UBUS_STATUS_PERMISSION_DENIED;

	ses = rpc_session_get(blobmsg_data(tb));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	rpc_session_destroy(ses);

	return 0;
}


static bool
rpc_login_test_password(const char *hash, const char *password)
{
	char *crypt_hash;

	/* password is not set */
	if (!hash || !*hash || !strcmp(hash, "!") || !strcmp(hash, "x"))
	{
		return true;
	}

	/* password hash refers to shadow/passwd */
	else if (!strncmp(hash, "$p$", 3))
	{
#ifdef HAVE_SHADOW
		struct spwd *sp = getspnam(hash + 3);

		if (!sp)
			return false;

		return rpc_login_test_password(sp->sp_pwdp, password);
#else
		struct passwd *pw = getpwnam(hash + 3);

		if (!pw)
			return false;

		return rpc_login_test_password(pw->pw_passwd, password);
#endif
	}

	crypt_hash = crypt(password, hash);

	return !strcmp(crypt_hash, hash);
}

static struct uci_section *
rpc_login_test_login(struct uci_context *uci,
                     const char *username, const char *password)
{
	struct uci_package *p = NULL;
	struct uci_section *s;
	struct uci_element *e;
	struct uci_ptr ptr = { .package = "rpcd" };

	uci_load(uci, ptr.package, &p);

	if (!p)
		return false;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "login"))
			continue;

		ptr.section = s->e.name;
		ptr.s = NULL;

		/* test for matching username */
		ptr.option = "username";
		ptr.o = NULL;

		if (uci_lookup_ptr(uci, &ptr, NULL, true))
			continue;

		if (ptr.o->type != UCI_TYPE_STRING)
			continue;

		if (strcmp(ptr.o->v.string, username))
			continue;

		/* If password is NULL, we're restoring ACLs for an existing session,
		 * in this case do not check the password again. */
		if (!password)
			return ptr.s;

		/* test for matching password */
		ptr.option = "password";
		ptr.o = NULL;

		if (uci_lookup_ptr(uci, &ptr, NULL, true))
			continue;

		if (ptr.o->type != UCI_TYPE_STRING)
			continue;

		if (rpc_login_test_password(ptr.o->v.string, password))
			return ptr.s;
	}

	return NULL;
}

static bool
rpc_login_test_permission(struct uci_section *s,
                          const char *perm, const char *group)
{
	const char *p;
	struct uci_option *o;
	struct uci_element *e, *l;

	/* If the login section is not provided, we're setting up acls for the
	 * default session, in this case uncondionally allow access to the
	 * "unauthenticated" access group */
	if (!s) {
		return !strcmp(group, "unauthenticated");
	}

	uci_foreach_element(&s->options, e)
	{
		o = uci_to_option(e);

		if (o->type != UCI_TYPE_LIST)
			continue;

		if (strcmp(o->e.name, perm))
			continue;

		/* Match negative expressions first. If a negative expression matches
		 * the current group name then deny access. */
		uci_foreach_element(&o->v.list, l) {
			p = l->name;

			if (!p || *p != '!')
				continue;

			while (isspace(*++p));

			if (!*p)
				continue;

			if (!fnmatch(p, group, 0))
				return false;
		}

		uci_foreach_element(&o->v.list, l) {
			if (!l->name || !*l->name || *l->name == '!')
				continue;

			if (!fnmatch(l->name, group, 0))
				return true;
		}
	}

	/* make sure that write permission implies read permission */
	if (!strcmp(perm, "read"))
		return rpc_login_test_permission(s, "write", group);

	return false;
}

static void
rpc_login_setup_acl_scope(struct rpc_session *ses,
                          struct blob_attr *acl_perm,
                          struct blob_attr *acl_scope)
{
	struct blob_attr *acl_obj, *acl_func;
	int rem, rem2;

	/*
	 * Parse ACL scopes in table notation.
	 *
	 *	"<scope>": {
	 *		"<object>": [
	 *			"<function>",
	 *			"<function>",
	 *			...
	 *		]
	 *	}
	 */
	if (blobmsg_type(acl_scope) == BLOBMSG_TYPE_TABLE) {
		blobmsg_for_each_attr(acl_obj, acl_scope, rem) {
			if (blobmsg_type(acl_obj) != BLOBMSG_TYPE_ARRAY)
				continue;

			blobmsg_for_each_attr(acl_func, acl_obj, rem2) {
				if (blobmsg_type(acl_func) != BLOBMSG_TYPE_STRING)
					continue;

				rpc_session_grant(ses, blobmsg_name(acl_scope),
				                       blobmsg_name(acl_obj),
				                       blobmsg_data(acl_func));
			}
		}
	}

	/*
	 * Parse ACL scopes in array notation. The permission ("read" or "write")
	 * will be used as function name for each object.
	 *
	 *	"<scope>": [
	 *		"<object>",
	 *		"<object>",
	 *		...
	 *	]
	 */
	else if (blobmsg_type(acl_scope) == BLOBMSG_TYPE_ARRAY) {
		blobmsg_for_each_attr(acl_obj, acl_scope, rem) {
			if (blobmsg_type(acl_obj) != BLOBMSG_TYPE_STRING)
				continue;

			rpc_session_grant(ses, blobmsg_name(acl_scope),
			                       blobmsg_data(acl_obj),
			                       blobmsg_name(acl_perm));
		}
	}
}

static void
rpc_login_setup_acl_file(struct rpc_session *ses, struct uci_section *login,
                         const char *path)
{
	struct blob_buf acl = { 0 };
	struct blob_attr *acl_group, *acl_perm, *acl_scope;
	int rem, rem2, rem3;

	blob_buf_init(&acl, 0);

	if (!blobmsg_add_json_from_file(&acl, path)) {
		fprintf(stderr, "Failed to parse %s\n", path);
		goto out;
	}

	/* Iterate access groups in toplevel object */
	blob_for_each_attr(acl_group, acl.head, rem) {
		/* Iterate permission objects in each access group object */
		blobmsg_for_each_attr(acl_perm, acl_group, rem2) {
			if (blobmsg_type(acl_perm) != BLOBMSG_TYPE_TABLE)
				continue;

			/* Only "read" and "write" permissions are defined */
			if (strcmp(blobmsg_name(acl_perm), "read") &&
				strcmp(blobmsg_name(acl_perm), "write"))
				continue;

			/*
			 * Check if the current user context specifies the current
			 * "read" or "write" permission in the given access group.
			 */
			if (!rpc_login_test_permission(login, blobmsg_name(acl_perm),
			                                      blobmsg_name(acl_group)))
				continue;

			/* Iterate scope objects within the permission object */
			blobmsg_for_each_attr(acl_scope, acl_perm, rem3) {
				/* Setup the scopes of the access group */
				rpc_login_setup_acl_scope(ses, acl_perm, acl_scope);

				/*
				 * Add the access group itself as object to the "access-group"
				 * meta scope and the the permission level ("read" or "write")
				 * as function, so
				 *	"<group>": {
				 *		"<permission>": {
				 *			"<scope>": ...
				 *		}
				 *	}
				 * becomes
				 *	"access-group": {
				 *		"<group>": [
				 *			"<permission>"
				 *		]
				 *	}
				 *
				 * This allows session clients to easily query the allowed
				 * access groups without having to test access of each single
				 * <scope>/<object>/<function> tuple defined in a group.
				 */
				rpc_session_grant(ses, "access-group",
				                       blobmsg_name(acl_group),
				                       blobmsg_name(acl_perm));
			}
		}
	}

out:
	blob_buf_free(&acl);
}

static void
rpc_login_setup_acls(struct rpc_session *ses, struct uci_section *login)
{
	int i;
	glob_t gl;

	if (glob(RPC_SESSION_ACL_DIR "/*.json", 0, NULL, &gl))
		return;

	for (i = 0; i < gl.gl_pathc; i++)
		rpc_login_setup_acl_file(ses, login, gl.gl_pathv[i]);

	globfree(&gl);
}

static int
rpc_handle_login(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	struct uci_context *uci = NULL;
	struct uci_section *login;
	struct rpc_session *ses;
	struct blob_attr *tb[__RPC_L_MAX];
	int timeout = RPC_DEFAULT_SESSION_TIMEOUT;
	int rv = 0;

	blobmsg_parse(login_policy, __RPC_L_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_L_USERNAME] || !tb[RPC_L_PASSWORD]) {
		rv = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	uci = uci_alloc_context();

	if (!uci) {
		rv = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	login = rpc_login_test_login(uci, blobmsg_get_string(tb[RPC_L_USERNAME]),
	                                  blobmsg_get_string(tb[RPC_L_PASSWORD]));

	if (!login) {
		rv = UBUS_STATUS_PERMISSION_DENIED;
		goto out;
	}

	if (tb[RPC_L_TIMEOUT])
		timeout = blobmsg_get_u32(tb[RPC_L_TIMEOUT]);

	ses = rpc_session_create(timeout);

	if (!ses) {
		rv = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	rpc_login_setup_acls(ses, login);

	rpc_session_set(ses, "user", tb[RPC_L_USERNAME]);
	rpc_session_dump(ses, ctx, req);

out:
	if (uci)
		uci_free_context(uci);

	return rv;
}


static bool
rpc_validate_sid(const char *id)
{
	if (!id)
		return false;

	if (strlen(id) != RPC_SID_LEN)
		return false;

	while (*id)
		if (!isxdigit(*id++))
			return false;

	return true;
}

static int
rpc_blob_to_file(const char *path, struct blob_attr *attr)
{
	int fd, len;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

	if (fd < 0)
		return fd;

	len = write(fd, attr, blob_pad_len(attr));

	close(fd);

	if (len != blob_pad_len(attr))
	{
		unlink(path);
		return -1;
	}

	return len;
}

static struct blob_attr *
rpc_blob_from_file(const char *path)
{
	int fd = -1, len;
	struct stat s;
	struct blob_attr head, *attr = NULL;

	if (stat(path, &s) || !S_ISREG(s.st_mode))
		return NULL;

	fd = open(path, O_RDONLY);

	if (fd < 0)
		goto fail;

	len = read(fd, &head, sizeof(head));

	if (len != sizeof(head) || blob_pad_len(&head) != s.st_size)
		goto fail;

	attr = calloc(1, s.st_size);

	if (!attr)
		goto fail;

	memcpy(attr, &head, sizeof(head));

	len += read(fd, (char *)attr + sizeof(head), s.st_size - sizeof(head));

	if (len != blob_pad_len(&head))
		goto fail;

	close(fd);

	return attr;

fail:
	if (fd >= 0)
		close(fd);

	if (attr)
		free(attr);

	return NULL;
}

static bool
rpc_session_from_blob(struct uci_context *uci, struct blob_attr *attr)
{
	int i, rem;
	const char *user = NULL;
	struct rpc_session *ses;
	struct uci_section *login;
	struct blob_attr *tb[__RPC_DUMP_MAX], *data;

	blobmsg_parse(dump_policy, __RPC_DUMP_MAX, tb,
	              blob_data(attr), blob_len(attr));

	for (i = 0; i < __RPC_DUMP_MAX; i++)
		if (!tb[i])
			return false;

	ses = rpc_session_new();

	if (!ses)
		return false;

	memcpy(ses->id, blobmsg_data(tb[RPC_DUMP_SID]), RPC_SID_LEN);

	ses->timeout = blobmsg_get_u32(tb[RPC_DUMP_TIMEOUT]);

	blobmsg_for_each_attr(data, tb[RPC_DUMP_DATA], rem) {
		rpc_session_set(ses, blobmsg_name(data), data);

		if (!strcmp(blobmsg_name(data), "username"))
			user = blobmsg_get_string(data);
	}

	if (uci && user) {
		login = rpc_login_test_login(uci, user, NULL);
		if (login)
			rpc_login_setup_acls(ses, login);
	}

	avl_insert(&sessions, &ses->avl);

	uloop_timeout_set(&ses->t, blobmsg_get_u32(tb[RPC_DUMP_EXPIRES]) * 1000);

	return true;
}

int rpc_session_api_init(struct ubus_context *ctx)
{
	struct rpc_session *ses;

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
		UBUS_METHOD("login",   rpc_handle_login,   login_policy),
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

	/* setup the default session */
	ses = rpc_session_new();

	if (ses) {
		strcpy(ses->id, RPC_DEFAULT_SESSION_ID);
		rpc_login_setup_acls(ses, NULL);
		avl_insert(&sessions, &ses->avl);
	}

	return ubus_add_object(ctx, &obj);
}

bool rpc_session_access(const char *sid, const char *scope,
                        const char *object, const char *function)
{
	struct rpc_session *ses = rpc_session_get(sid);

	if (!ses)
		return false;

	return rpc_session_acl_allowed(ses, scope, object, function);
}

void rpc_session_create_cb(struct rpc_session_cb *cb)
{
	if (cb && cb->cb)
		list_add(&cb->list, &create_callbacks);
}

void rpc_session_destroy_cb(struct rpc_session_cb *cb)
{
	if (cb && cb->cb)
		list_add(&cb->list, &destroy_callbacks);
}

void rpc_session_freeze(void)
{
	struct stat s;
	struct rpc_session *ses;
	char path[PATH_MAX];

	if (stat(RPC_SESSION_DIRECTORY, &s))
		mkdir(RPC_SESSION_DIRECTORY, 0700);

	avl_for_each_element(&sessions, ses, avl) {
		/* skip default session */
		if (!strcmp(ses->id, RPC_DEFAULT_SESSION_ID))
			continue;

		snprintf(path, sizeof(path) - 1, RPC_SESSION_DIRECTORY "/%s", ses->id);
		rpc_session_to_blob(ses, false);
		rpc_blob_to_file(path, buf.head);
	}
}

void rpc_session_thaw(void)
{
	DIR *d;
	char path[PATH_MAX];
	struct dirent *e;
	struct blob_attr *attr;
	struct uci_context *uci;

	d = opendir(RPC_SESSION_DIRECTORY);

	if (!d)
		return;

	uci = uci_alloc_context();

	if (!uci)
		return;

	while ((e = readdir(d)) != NULL) {
		if (!rpc_validate_sid(e->d_name))
			continue;

		snprintf(path, sizeof(path) - 1,
		         RPC_SESSION_DIRECTORY "/%s", e->d_name);

		attr = rpc_blob_from_file(path);

		if (attr) {
			rpc_session_from_blob(uci, attr);
			free(attr);
		}

		unlink(path);
	}

	closedir(d);

	uci_free_context(uci);
}
