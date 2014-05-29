/*
 * rpcd - UBUS RPC server
 *
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

#include <libgen.h>
#include <glob.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include <rpcd/uci.h>
#include <rpcd/session.h>

static struct blob_buf buf;
static struct uci_context *cursor;
static struct uloop_timeout apply_timer;
static struct ubus_context *apply_ctx;
static char apply_sid[RPC_SID_LEN + 1];

enum {
	RPC_G_CONFIG,
	RPC_G_SECTION,
	RPC_G_OPTION,
	RPC_G_TYPE,
	RPC_G_MATCH,
	RPC_G_SESSION,
	__RPC_G_MAX,
};

static const struct blobmsg_policy rpc_uci_get_policy[__RPC_G_MAX] = {
	[RPC_G_CONFIG]  = { .name = "config",  .type = BLOBMSG_TYPE_STRING },
	[RPC_G_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
	[RPC_G_OPTION]  = { .name = "option",  .type = BLOBMSG_TYPE_STRING },
	[RPC_G_TYPE]    = { .name = "type",    .type = BLOBMSG_TYPE_STRING },
	[RPC_G_MATCH]   = { .name = "match",   .type = BLOBMSG_TYPE_TABLE  },
	[RPC_G_SESSION] = { .name = "ubus_rpc_session",
	                                       .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_A_CONFIG,
	RPC_A_TYPE,
	RPC_A_NAME,
	RPC_A_VALUES,
	RPC_A_SESSION,
	__RPC_A_MAX,
};

static const struct blobmsg_policy rpc_uci_add_policy[__RPC_A_MAX] = {
	[RPC_A_CONFIG]  = { .name = "config",  .type = BLOBMSG_TYPE_STRING },
	[RPC_A_TYPE]    = { .name = "type",    .type = BLOBMSG_TYPE_STRING },
	[RPC_A_NAME]    = { .name = "name",    .type = BLOBMSG_TYPE_STRING },
	[RPC_A_VALUES]  = { .name = "values",  .type = BLOBMSG_TYPE_TABLE  },
	[RPC_A_SESSION] = { .name = "ubus_rpc_session",
	                                       .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_S_CONFIG,
	RPC_S_SECTION,
	RPC_S_TYPE,
	RPC_S_MATCH,
	RPC_S_VALUES,
	RPC_S_SESSION,
	__RPC_S_MAX,
};

static const struct blobmsg_policy rpc_uci_set_policy[__RPC_S_MAX] = {
	[RPC_S_CONFIG]  = { .name = "config",   .type = BLOBMSG_TYPE_STRING },
	[RPC_S_SECTION] = { .name = "section",  .type = BLOBMSG_TYPE_STRING },
	[RPC_S_TYPE]    = { .name = "type",     .type = BLOBMSG_TYPE_STRING },
	[RPC_S_MATCH]   = { .name = "match",    .type = BLOBMSG_TYPE_TABLE  },
	[RPC_S_VALUES]  = { .name = "values",   .type = BLOBMSG_TYPE_TABLE  },
	[RPC_S_SESSION] = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_D_CONFIG,
	RPC_D_SECTION,
	RPC_D_TYPE,
	RPC_D_MATCH,
	RPC_D_OPTION,
	RPC_D_OPTIONS,
	RPC_D_SESSION,
	__RPC_D_MAX,
};

static const struct blobmsg_policy rpc_uci_delete_policy[__RPC_D_MAX] = {
	[RPC_D_CONFIG]  = { .name = "config",   .type = BLOBMSG_TYPE_STRING },
	[RPC_D_SECTION] = { .name = "section",  .type = BLOBMSG_TYPE_STRING },
	[RPC_D_TYPE]    = { .name = "type",     .type = BLOBMSG_TYPE_STRING },
	[RPC_D_MATCH]   = { .name = "match",    .type = BLOBMSG_TYPE_TABLE  },
	[RPC_D_OPTION]  = { .name = "option",   .type = BLOBMSG_TYPE_STRING },
	[RPC_D_OPTIONS] = { .name = "options",  .type = BLOBMSG_TYPE_ARRAY  },
	[RPC_D_SESSION] = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_R_CONFIG,
	RPC_R_SECTION,
	RPC_R_OPTION,
	RPC_R_NAME,
	RPC_R_SESSION,
	__RPC_R_MAX,
};

static const struct blobmsg_policy rpc_uci_rename_policy[__RPC_R_MAX] = {
	[RPC_R_CONFIG]  = { .name = "config",   .type = BLOBMSG_TYPE_STRING },
	[RPC_R_SECTION] = { .name = "section",  .type = BLOBMSG_TYPE_STRING },
	[RPC_R_OPTION]  = { .name = "option",   .type = BLOBMSG_TYPE_STRING },
	[RPC_R_NAME]    = { .name = "name",     .type = BLOBMSG_TYPE_STRING },
	[RPC_R_SESSION] = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_O_CONFIG,
	RPC_O_SECTIONS,
	RPC_O_SESSION,
	__RPC_O_MAX,
};

static const struct blobmsg_policy rpc_uci_order_policy[__RPC_O_MAX] = {
	[RPC_O_CONFIG]   = { .name = "config",   .type = BLOBMSG_TYPE_STRING },
	[RPC_O_SECTIONS] = { .name = "sections", .type = BLOBMSG_TYPE_ARRAY  },
	[RPC_O_SESSION]  = { .name = "ubus_rpc_session",
	                                         .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_C_CONFIG,
	RPC_C_SESSION,
	__RPC_C_MAX,
};

static const struct blobmsg_policy rpc_uci_config_policy[__RPC_C_MAX] = {
	[RPC_C_CONFIG]   = { .name = "config",  .type = BLOBMSG_TYPE_STRING },
	[RPC_C_SESSION]  = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_T_ROLLBACK,
	RPC_T_TIMEOUT,
	RPC_T_SESSION,
	__RPC_T_MAX,
};

static const struct blobmsg_policy rpc_uci_apply_policy[__RPC_T_MAX] = {
	[RPC_T_ROLLBACK] = { .name = "rollback", .type = BLOBMSG_TYPE_BOOL },
	[RPC_T_TIMEOUT]  = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
	[RPC_T_SESSION]  = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_B_SESSION,
	__RPC_B_MAX,
};

static const struct blobmsg_policy rpc_uci_rollback_policy[__RPC_B_MAX] = {
	[RPC_B_SESSION]  = { .name = "ubus_rpc_session",
	                                        .type = BLOBMSG_TYPE_STRING },
};

/*
 * Turn uci error state into ubus return code
 */
static int
rpc_uci_status(void)
{
	switch (cursor->err)
	{
	case UCI_OK:
		return UBUS_STATUS_OK;

	case UCI_ERR_INVAL:
		return UBUS_STATUS_INVALID_ARGUMENT;

	case UCI_ERR_NOTFOUND:
		return UBUS_STATUS_NOT_FOUND;

	default:
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
}

/*
 * Setup per-session delta save directory. If the passed "sid" blob attribute
 * pointer is NULL then the precedure was not invoked through the ubus-rpc so
 * we do not perform session isolation and use the default save directory.
 */
static void
rpc_uci_set_savedir(struct blob_attr *sid)
{
	char path[PATH_MAX];

	if (!sid)
	{
		uci_set_savedir(cursor, "/tmp/.uci");
		return;
	}

	snprintf(path, sizeof(path) - 1,
	         RPC_UCI_SAVEDIR_PREFIX "%s", blobmsg_get_string(sid));

	uci_set_savedir(cursor, path);
}

/*
 * Test read access to given config. If the passed "sid" blob attribute pointer
 * is NULL then the precedure was not invoked through the ubus-rpc so we do not
 * perform access control and always assume true.
 */
static bool
rpc_uci_read_access(struct blob_attr *sid, struct blob_attr *config)
{
	rpc_uci_set_savedir(sid);

	if (!sid)
		return true;

	return rpc_session_access(blobmsg_data(sid), "uci",
	                          blobmsg_data(config), "read");
}

/*
 * Test write access to given config. If the passed "sid" blob attribute pointer
 * is NULL then the precedure was not invoked through the ubus-rpc so we do not
 * perform access control and always assume true.
 */
static bool
rpc_uci_write_access(struct blob_attr *sid, struct blob_attr *config)
{
	rpc_uci_set_savedir(sid);

	if (!sid)
		return true;

	return rpc_session_access(blobmsg_data(sid), "uci",
	                          blobmsg_data(config), "write");
}

/*
 * Format applicable blob value as string and place a pointer to the string
 * buffer in "p". Uses a static string buffer.
 */
static bool
rpc_uci_format_blob(struct blob_attr *v, const char **p)
{
	static char buf[21];

	*p = NULL;

	switch (blobmsg_type(v))
	{
	case BLOBMSG_TYPE_STRING:
		if (blobmsg_data_len(v) > 1)
			*p = blobmsg_data(v);
		break;

	case BLOBMSG_TYPE_INT64:
		snprintf(buf, sizeof(buf), "%"PRIu64, blobmsg_get_u64(v));
		*p = buf;
		break;

	case BLOBMSG_TYPE_INT32:
		snprintf(buf, sizeof(buf), "%u", blobmsg_get_u32(v));
		*p = buf;
		break;

	case BLOBMSG_TYPE_INT16:
		snprintf(buf, sizeof(buf), "%u", blobmsg_get_u16(v));
		*p = buf;
		break;

	case BLOBMSG_TYPE_INT8:
		snprintf(buf, sizeof(buf), "%u", !!blobmsg_get_u8(v));
		*p = buf;
		break;

	default:
		break;
	}

	return !!*p;
}

/*
 * Lookup the given uci_ptr and enable extended lookup format if the .section
 * value of the uci_ptr looks like extended syntax. Uses an internal copy
 * of the given uci_ptr to perform the lookup as failing extended section
 * lookup operations in libuci will zero our the uci_ptr struct.
 * Copies the internal uci_ptr back to given the uci_ptr on success.
 */
static int
rpc_uci_lookup(struct uci_ptr *ptr)
{
	int rv;
	struct uci_ptr lookup = *ptr;

	if (!lookup.s && lookup.section && *lookup.section == '@')
		lookup.flags |= UCI_LOOKUP_EXTENDED;

	rv = uci_lookup_ptr(cursor, &lookup, NULL, true);

	if (!rv)
		*ptr = lookup;

	return rv;
}

/*
 * Checks whether the given uci_option object matches the given string value.
 *  1) If the uci_option is of type list, check whether any of the list elements
 *     equals to the given string
 *  2) If the uci_option is of type string, parse it into space separated tokens
 *     and check if any of the tokens equals to the given string.
 *  Returns true if a list element or token matched the given string.
 */
static bool
rpc_uci_match_option(struct uci_option *o, const char *cmp)
{
	struct uci_element *e;
	char *s, *p;

	if (o->type == UCI_TYPE_LIST)
	{
		uci_foreach_element(&o->v.list, e)
			if (e->name && !strcmp(e->name, cmp))
				return true;

		return false;
	}

	if (!o->v.string)
		return false;

	s = strdup(o->v.string);

	if (!s)
		return false;

	for (p = strtok(s, " \t"); p; p = strtok(NULL, " \t"))
	{
		if (!strcmp(p, cmp))
		{
			free(s);
			return true;
		}
	}

	free(s);
	return false;
}

/*
 * Checks whether the given uci_section matches the type and value blob attrs.
 *  1) Returns false if "type" is given and the section type does not match
 *     the value specified in the "type" string blob attribute, else continue.
 *  2) Tests whether any key in the "matches" table blob attribute exists in
 *     the given uci_section and whether each value is contained in the
 *     corresponding uci option value (see rpc_uci_match_option()).
 *  3) A missing or empty "matches" table blob attribute is always considered
 *     to be a match.
 * Returns true if "type" matches or is NULL and "matches" matches or is NULL.
 */
static bool
rpc_uci_match_section(struct uci_section *s,
                      struct blob_attr *type, struct blob_attr *matches)
{
	struct uci_element *e;
	struct blob_attr *cur;
	const char *cmp;
	bool match = false;
	bool empty = true;
	int rem;

	if (type && strcmp(s->type, blobmsg_data(type)))
		return false;

	if (!matches)
		return true;

	blobmsg_for_each_attr(cur, matches, rem)
	{
		if (!rpc_uci_format_blob(cur, &cmp))
			continue;

		uci_foreach_element(&s->options, e)
		{
			if (strcmp(e->name, blobmsg_name(cur)))
				continue;

			if (!rpc_uci_match_option(uci_to_option(e), cmp))
				return false;

			match = true;
		}

		empty = false;
	}

	return (empty || match);
}

/*
 * Dump the given uci_option value into the global blobmsg buffer and use
 * given "name" as key.
 *  1) If the uci_option is of type list, put a table into the blob buffer and
 *     add each list item as string to it.
 *  2) If the uci_option is of type string, put its value directly into the blob
 *     buffer.
 */
static void
rpc_uci_dump_option(struct uci_option *o, const char *name)
{
	void *c;
	struct uci_element *e;

	switch (o->type)
	{
	case UCI_TYPE_STRING:
		blobmsg_add_string(&buf, name, o->v.string);
		break;

	case UCI_TYPE_LIST:
		c = blobmsg_open_array(&buf, name);

		uci_foreach_element(&o->v.list, e)
			blobmsg_add_string(&buf, NULL, e->name);

		blobmsg_close_array(&buf, c);
		break;

	default:
		break;
	}
}

/*
 * Dump the given uci_section object into the global blobmsg buffer and use
 * given "name" as key.
 * Puts a table into the blob buffer and puts each section option member value
 * as value into the table using the option name as key.
 * Adds three special keys ".anonymous", ".type" and ".name" which specify the
 * corresponding section properties.
 */
static void
rpc_uci_dump_section(struct uci_section *s, const char *name, int index)
{
	void *c;
	struct uci_option *o;
	struct uci_element *e;

	c = blobmsg_open_table(&buf, name);

	blobmsg_add_u8(&buf, ".anonymous", s->anonymous);
	blobmsg_add_string(&buf, ".type", s->type);
	blobmsg_add_string(&buf, ".name", s->e.name);

	if (index >= 0)
		blobmsg_add_u32(&buf, ".index", index);

	uci_foreach_element(&s->options, e)
	{
		o = uci_to_option(e);
		rpc_uci_dump_option(o, o->e.name);
	}

	blobmsg_close_table(&buf, c);
}

/*
 * Dump the given uci_package object into the global blobmsg buffer and use
 * given "name" as key.
 * Puts a table into the blob buffer and puts each package section member as
 * value into the table using the section name as key.
 * Only dumps sections matching the given "type" and "matches", see explaination
 * of rpc_uci_match_section() for details.
 */
static void
rpc_uci_dump_package(struct uci_package *p, const char *name,
                     struct blob_attr *type, struct blob_attr *matches)
{
	void *c;
	struct uci_element *e;
	int i = -1;

	c = blobmsg_open_table(&buf, name);

	uci_foreach_element(&p->sections, e)
	{
		i++;

		if (!rpc_uci_match_section(uci_to_section(e), type, matches))
			continue;

		rpc_uci_dump_section(uci_to_section(e), e->name, i);
	}

	blobmsg_close_table(&buf, c);
}


static int
rpc_uci_getcommon(struct ubus_context *ctx, struct ubus_request_data *req,
                  struct blob_attr *msg, bool use_state)
{
	struct blob_attr *tb[__RPC_G_MAX];
	struct uci_package *p = NULL;
	struct uci_ptr ptr = { 0 };

	blobmsg_parse(rpc_uci_get_policy, __RPC_G_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_G_CONFIG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_read_access(tb[RPC_G_SESSION], tb[RPC_G_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_G_CONFIG]);

	if (use_state)
		uci_set_savedir(cursor, "/var/state");

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	if (tb[RPC_G_SECTION])
	{
		ptr.section = blobmsg_data(tb[RPC_G_SECTION]);

		if (tb[RPC_G_OPTION])
			ptr.option = blobmsg_data(tb[RPC_G_OPTION]);
	}

	if (rpc_uci_lookup(&ptr) || !(ptr.flags & UCI_LOOKUP_COMPLETE))
		goto out;

	blob_buf_init(&buf, 0);

	switch (ptr.last->type)
	{
	case UCI_TYPE_PACKAGE:
		rpc_uci_dump_package(ptr.p, "values", tb[RPC_G_TYPE], tb[RPC_G_MATCH]);
		break;

	case UCI_TYPE_SECTION:
		rpc_uci_dump_section(ptr.s, "values", -1);
		break;

	case UCI_TYPE_OPTION:
		rpc_uci_dump_option(ptr.o, "value");
		break;

	default:
		break;
	}

	ubus_send_reply(ctx, req, buf.head);

out:
	uci_unload(cursor, p);

	return rpc_uci_status();
}

static int
rpc_uci_get(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
	return rpc_uci_getcommon(ctx, req, msg, false);
}

static int
rpc_uci_state(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	return rpc_uci_getcommon(ctx, req, msg, true);
}

static int
rpc_uci_add(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_A_MAX];
	struct blob_attr *cur, *elem;
	struct uci_package *p = NULL;
	struct uci_section *s;
	struct uci_ptr ptr = { 0 };
	int rem, rem2;

	blobmsg_parse(rpc_uci_add_policy, __RPC_A_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_A_CONFIG] || !tb[RPC_A_TYPE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_A_SESSION], tb[RPC_A_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_A_CONFIG]);

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	/* add named section */
	if (tb[RPC_A_NAME])
	{
		ptr.section = blobmsg_data(tb[RPC_A_NAME]);
		ptr.value   = blobmsg_data(tb[RPC_A_TYPE]);
		ptr.option  = NULL;

		if (rpc_uci_lookup(&ptr) || uci_set(cursor, &ptr))
			goto out;
	}

	/* add anon section */
	else
	{
		if (uci_add_section(cursor, p, blobmsg_data(tb[RPC_A_TYPE]), &s) || !s)
			goto out;

		ptr.section = s->e.name;
	}

	if (tb[RPC_A_VALUES])
	{
		blobmsg_for_each_attr(cur, tb[RPC_A_VALUES], rem)
		{
			ptr.o = NULL;
			ptr.option = blobmsg_name(cur);

			if (rpc_uci_lookup(&ptr) || !ptr.s)
				continue;

			switch (blobmsg_type(cur))
			{
			case BLOBMSG_TYPE_ARRAY:
				blobmsg_for_each_attr(elem, cur, rem2)
					if (rpc_uci_format_blob(elem, &ptr.value))
						uci_add_list(cursor, &ptr);
				break;

			default:
				if (rpc_uci_format_blob(cur, &ptr.value))
					uci_set(cursor, &ptr);
				break;
			}
		}
	}

	uci_save(cursor, p);

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "section", ptr.section);
	ubus_send_reply(ctx, req, buf.head);

out:
	uci_unload(cursor, p);

	return rpc_uci_status();
}

/*
 * Turn value from a blob attribute into uci set operation
 *  1) if the blob is of type array, delete existing option (if any) and
 *     emit uci add_list operations for each element
 *  2) if the blob is not an array but an option of type list exists,
 *     delete existing list and emit uci set operation for the blob value
 *  3) in all other cases only emit a set operation if there is no existing
 *     option of if the existing options value differs from the blob value
 */
static void
rpc_uci_merge_set(struct blob_attr *opt, struct uci_ptr *ptr)
{
	struct blob_attr *cur;
	int rem;

	ptr->o = NULL;
	ptr->option = blobmsg_name(opt);
	ptr->value = NULL;

	if (rpc_uci_lookup(ptr) || !ptr->s)
		return;

	if (blobmsg_type(opt) == BLOBMSG_TYPE_ARRAY)
	{
		if (ptr->o)
			uci_delete(cursor, ptr);

		blobmsg_for_each_attr(cur, opt, rem)
			if (rpc_uci_format_blob(cur, &ptr->value))
				uci_add_list(cursor, ptr);
	}
	else if (ptr->o && ptr->o->type == UCI_TYPE_LIST)
	{
		uci_delete(cursor, ptr);

		if (rpc_uci_format_blob(opt, &ptr->value))
			uci_set(cursor, ptr);
	}
	else if (rpc_uci_format_blob(opt, &ptr->value))
	{
		if (!ptr->o || !ptr->o->v.string || strcmp(ptr->o->v.string, ptr->value))
			uci_set(cursor, ptr);
	}
}

static int
rpc_uci_set(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_S_MAX];
	struct blob_attr *cur;
	struct uci_package *p = NULL;
	struct uci_element *e;
	struct uci_ptr ptr = { 0 };
	int rem;

	blobmsg_parse(rpc_uci_set_policy, __RPC_S_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_S_CONFIG] || !tb[RPC_S_VALUES] ||
		(!tb[RPC_S_SECTION] && !tb[RPC_S_TYPE] && !tb[RPC_S_MATCH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_S_SESSION], tb[RPC_S_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_S_CONFIG]);

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	if (tb[RPC_S_SECTION])
	{
		ptr.section = blobmsg_data(tb[RPC_S_SECTION]);
		blobmsg_for_each_attr(cur, tb[RPC_S_VALUES], rem)
			rpc_uci_merge_set(cur, &ptr);
	}
	else
	{
		uci_foreach_element(&p->sections, e)
		{
			if (!rpc_uci_match_section(uci_to_section(e),
			                           tb[RPC_S_TYPE], tb[RPC_S_MATCH]))
				continue;

			ptr.s = NULL;
			ptr.section = e->name;

			blobmsg_for_each_attr(cur, tb[RPC_S_VALUES], rem)
				rpc_uci_merge_set(cur, &ptr);
		}
	}

	uci_save(cursor, p);
	uci_unload(cursor, p);

	return rpc_uci_status();
}

/*
 * Delete option or section from uci specified by given blob attribute pointer
 *  1) if the blob is of type array, delete any option named after each element
 *  2) if the blob is of type string, delete the option named after its value
 *  3) if the blob is NULL, delete entire section
 */
static void
rpc_uci_merge_delete(struct blob_attr *opt, struct uci_ptr *ptr)
{
	struct blob_attr *cur;
	int rem;

	if (rpc_uci_lookup(ptr) || !ptr->s)
		return;

	if (!opt)
	{
		ptr->o = NULL;
		ptr->option = NULL;

		uci_delete(cursor, ptr);
	}
	else if (blobmsg_type(opt) == BLOBMSG_TYPE_ARRAY)
	{
		blobmsg_for_each_attr(cur, opt, rem)
		{
			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
				continue;

			ptr->o = NULL;
			ptr->option = blobmsg_data(cur);

			if (rpc_uci_lookup(ptr) || !ptr->o)
				continue;

			uci_delete(cursor, ptr);
		}
	}
	else if (blobmsg_type(opt) == BLOBMSG_TYPE_STRING)
	{
		ptr->o = NULL;
		ptr->option = blobmsg_data(opt);

		if (rpc_uci_lookup(ptr) || !ptr->o)
			return;

		uci_delete(cursor, ptr);
	}
}

static int
rpc_uci_delete(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_D_MAX];
	struct uci_package *p = NULL;
	struct uci_element *e, *tmp;
	struct uci_ptr ptr = { 0 };

	blobmsg_parse(rpc_uci_delete_policy, __RPC_D_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_D_CONFIG] ||
		(!tb[RPC_D_SECTION] && !tb[RPC_D_TYPE] && !tb[RPC_D_MATCH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_D_SESSION], tb[RPC_D_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_D_CONFIG]);

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	if (tb[RPC_D_SECTION])
	{
		ptr.section = blobmsg_data(tb[RPC_D_SECTION]);

		if (tb[RPC_D_OPTIONS])
			rpc_uci_merge_delete(tb[RPC_D_OPTIONS], &ptr);
		else
			rpc_uci_merge_delete(tb[RPC_D_OPTION], &ptr);
	}
	else
	{
		uci_foreach_element_safe(&p->sections, tmp, e)
		{
			if (!rpc_uci_match_section(uci_to_section(e),
			                           tb[RPC_D_TYPE], tb[RPC_D_MATCH]))
				continue;

			ptr.s = NULL;
			ptr.section = e->name;

			if (tb[RPC_D_OPTIONS])
				rpc_uci_merge_delete(tb[RPC_D_OPTIONS], &ptr);
			else
				rpc_uci_merge_delete(tb[RPC_D_OPTION], &ptr);
		}
	}

	uci_save(cursor, p);
	uci_unload(cursor, p);

	return rpc_uci_status();
}

static int
rpc_uci_rename(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_R_MAX];
	struct uci_package *p = NULL;
	struct uci_ptr ptr = { 0 };

	blobmsg_parse(rpc_uci_rename_policy, __RPC_R_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_R_CONFIG] || !tb[RPC_R_SECTION] || !tb[RPC_R_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_R_SESSION], tb[RPC_R_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_R_CONFIG]);
	ptr.section = blobmsg_data(tb[RPC_R_SECTION]);
	ptr.value   = blobmsg_data(tb[RPC_R_NAME]);

	if (tb[RPC_R_OPTION])
		ptr.option = blobmsg_data(tb[RPC_R_OPTION]);

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	if (uci_lookup_ptr(cursor, &ptr, NULL, true))
		goto out;

	if ((ptr.option && !ptr.o) || !ptr.s)
	{
		cursor->err = UCI_ERR_NOTFOUND;
		goto out;
	}

	if (uci_rename(cursor, &ptr))
		goto out;

	uci_save(cursor, p);

out:
	uci_unload(cursor, p);

	return rpc_uci_status();
}

static int
rpc_uci_order(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_O_MAX];
	struct blob_attr *cur;
	struct uci_package *p = NULL;
	struct uci_ptr ptr = { 0 };
	int rem, i = 1;

	blobmsg_parse(rpc_uci_order_policy, __RPC_O_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_O_CONFIG] || !tb[RPC_O_SECTIONS])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_O_SESSION], tb[RPC_O_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_O_CONFIG]);

	if (uci_load(cursor, ptr.package, &p))
		return rpc_uci_status();

	blobmsg_for_each_attr(cur, tb[RPC_O_SECTIONS], rem)
	{
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		ptr.s = NULL;
		ptr.section = blobmsg_data(cur);

		if (uci_lookup_ptr(cursor, &ptr, NULL, true) || !ptr.s)
			continue;

		uci_reorder_section(cursor, ptr.s, i++);
	}

	uci_save(cursor, p);
	uci_unload(cursor, p);

	return rpc_uci_status();
}

static void
rpc_uci_dump_change(struct uci_delta *d)
{
	void *c;
	const char *types[] = {
		[UCI_CMD_REORDER]  = "order",
		[UCI_CMD_REMOVE]   = "remove",
		[UCI_CMD_RENAME]   = "rename",
		[UCI_CMD_ADD]      = "add",
		[UCI_CMD_LIST_ADD] = "list-add",
		[UCI_CMD_LIST_DEL] = "list-del",
		[UCI_CMD_CHANGE]   = "set",
	};

	if (!d->section)
		return;

	c = blobmsg_open_array(&buf, NULL);

	blobmsg_add_string(&buf, NULL, types[d->cmd]);
	blobmsg_add_string(&buf, NULL, d->section);

	if (d->e.name)
		blobmsg_add_string(&buf, NULL, d->e.name);

	if (d->value)
	{
		if (d->cmd == UCI_CMD_REORDER)
			blobmsg_add_u32(&buf, NULL, strtoul(d->value, NULL, 10));
		else
			blobmsg_add_string(&buf, NULL, d->value);
	}

	blobmsg_close_array(&buf, c);
}

static int
rpc_uci_changes(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_C_MAX];
	struct uci_package *p = NULL;
	struct uci_element *e;
	char **configs;
	void *c, *d;
	int i;

	blobmsg_parse(rpc_uci_config_policy, __RPC_C_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (tb[RPC_C_CONFIG])
	{
		if (!rpc_uci_read_access(tb[RPC_C_SESSION], tb[RPC_C_CONFIG]))
			return UBUS_STATUS_PERMISSION_DENIED;

		if (uci_load(cursor, blobmsg_data(tb[RPC_C_CONFIG]), &p))
			return rpc_uci_status();

		blob_buf_init(&buf, 0);
		c = blobmsg_open_array(&buf, "changes");

		uci_foreach_element(&p->saved_delta, e)
			rpc_uci_dump_change(uci_to_delta(e));

		blobmsg_close_array(&buf, c);

		uci_unload(cursor, p);

		ubus_send_reply(ctx, req, buf.head);

		return rpc_uci_status();
	}

	rpc_uci_set_savedir(tb[RPC_C_SESSION]);

	if (uci_list_configs(cursor, &configs))
		return rpc_uci_status();

	blob_buf_init(&buf, 0);

	c = blobmsg_open_table(&buf, "changes");

	for (i = 0; configs[i]; i++)
	{
		if (tb[RPC_C_SESSION] &&
		    !rpc_session_access(blobmsg_data(tb[RPC_C_SESSION]), "uci",
		                        configs[i], "read"))
			continue;

		if (uci_load(cursor, configs[i], &p))
			continue;

		if (!uci_list_empty(&p->saved_delta))
		{
			d = blobmsg_open_array(&buf, configs[i]);

			uci_foreach_element(&p->saved_delta, e)
				rpc_uci_dump_change(uci_to_delta(e));

			blobmsg_close_array(&buf, d);
		}

		uci_unload(cursor, p);
	}

	blobmsg_close_table(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static void
rpc_uci_trigger_event(struct ubus_context *ctx, const char *config)
{
	char *pkg = strdup(config);
	static struct blob_buf b;
	uint32_t id;

	if (!ubus_lookup_id(ctx, "service", &id)) {
		void *c;

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "type", "config.change");
		c = blobmsg_open_table(&b, "data");
		blobmsg_add_string(&b, "package", pkg);
		blobmsg_close_table(&b, c);
		ubus_invoke(ctx, id, "event", b.head, NULL, 0, 1000);
	}
	free(pkg);
}

static int
rpc_uci_revert_commit(struct ubus_context *ctx, struct blob_attr *msg, bool commit)
{
	struct blob_attr *tb[__RPC_C_MAX];
	struct uci_package *p = NULL;
	struct uci_ptr ptr = { 0 };

	if (apply_sid[0])
		return UBUS_STATUS_PERMISSION_DENIED;

	blobmsg_parse(rpc_uci_config_policy, __RPC_C_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_C_CONFIG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_C_SESSION], tb[RPC_C_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_C_CONFIG]);

	if (commit)
	{
		if (!uci_load(cursor, ptr.package, &p))
		{
			uci_commit(cursor, &p, false);
			uci_unload(cursor, p);
			rpc_uci_trigger_event(ctx, blobmsg_get_string(tb[RPC_C_CONFIG]));
		}
	}
	else
	{
		if (!uci_lookup_ptr(cursor, &ptr, NULL, true) && ptr.p)
			uci_revert(cursor, &ptr);
	}

	return rpc_uci_status();
}

static int
rpc_uci_revert(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	return rpc_uci_revert_commit(ctx, msg, false);
}

static int
rpc_uci_commit(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	return rpc_uci_revert_commit(ctx, msg, true);
}

static int
rpc_uci_configs(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	char **configs;
	void *c;
	int i;

	if (uci_list_configs(cursor, &configs))
		goto out;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "configs");

	for (i = 0; configs[i]; i++)
		blobmsg_add_string(&buf, NULL, configs[i]);

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

out:
	return rpc_uci_status();
}


/*
 * Remove given delta save directory (if any).
 */
static void
rpc_uci_purge_dir(const char *path)
{
	DIR *d;
	struct stat s;
	struct dirent *e;
	char file[PATH_MAX];

	if (stat(path, &s) || !S_ISDIR(s.st_mode))
		return;

	if ((d = opendir(path)) != NULL)
	{
		while ((e = readdir(d)) != NULL)
		{
			snprintf(file, sizeof(file) - 1, "%s/%s", path, e->d_name);

			if (stat(file, &s) || !S_ISREG(s.st_mode))
				continue;

			unlink(file);
		}

		closedir(d);

		rmdir(path);
	}
}

static int
rpc_uci_apply_config(struct ubus_context *ctx, char *config)
{
	struct uci_package *p = NULL;

	if (!uci_load(cursor, config, &p)) {
		uci_commit(cursor, &p, false);
		uci_unload(cursor, p);
	}
	rpc_uci_trigger_event(ctx, config);

	return 0;
}

static void
rpc_uci_copy_file(const char *src, const char *target, const char *file)
{
	char tmp[256];
	FILE *in, *out;

	snprintf(tmp, sizeof(tmp), "%s%s", src, file);
	in = fopen(tmp, "rb");
	snprintf(tmp, sizeof(tmp), "%s%s", target, file);
	out = fopen(tmp, "wb+");
	if (in && out)
		while (!feof(in)) {
			int len = fread(tmp, 1, sizeof(tmp), in);

			if(len > 0)
				fwrite(tmp, 1, len, out);
		}
	if(in)
		fclose(in);
	if(out)
		fclose(out);
}

static void
rpc_uci_do_rollback(struct ubus_context *ctx, const char *sid, glob_t *gl)
{
	int i;
	char tmp[PATH_MAX];

	if (sid) {
		snprintf(tmp, sizeof(tmp), RPC_UCI_SAVEDIR_PREFIX "%s/", sid);
		mkdir(tmp, 0700);
	}

	for (i = 0; i < gl->gl_pathc; i++) {
		char *config = basename(gl->gl_pathv[i]);

		if (*config == '.')
			continue;

		rpc_uci_copy_file(RPC_SNAPSHOT_FILES, RPC_UCI_DIR, config);
		rpc_uci_apply_config(ctx, config);
		if (sid)
			rpc_uci_copy_file(RPC_SNAPSHOT_DELTA, tmp, config);
	}

	rpc_uci_purge_dir(RPC_SNAPSHOT_FILES);
	rpc_uci_purge_dir(RPC_SNAPSHOT_DELTA);

	uloop_timeout_cancel(&apply_timer);
	memset(apply_sid, 0, sizeof(apply_sid));
	apply_ctx = NULL;
}

static void
rpc_uci_apply_timeout(struct uloop_timeout *t)
{
	glob_t gl;
	char tmp[PATH_MAX];

	snprintf(tmp, sizeof(tmp), "%s/*", RPC_SNAPSHOT_FILES);
	if (glob(tmp, GLOB_PERIOD, NULL, &gl) < 0)
		return;

	rpc_uci_do_rollback(apply_ctx, NULL, &gl);
}

static int
rpc_uci_apply_access(const char *sid, glob_t *gl)
{
	struct stat s;
	int i, c = 0;

	if (gl->gl_pathc < 3)
		return UBUS_STATUS_NO_DATA;

	for (i = 0; i < gl->gl_pathc; i++) {
		char *config = basename(gl->gl_pathv[i]);

		if (*config == '.')
			continue;
		if (stat(gl->gl_pathv[i], &s) || !s.st_size)
			continue;
		if (!rpc_session_access(sid, "uci", config, "write"))
			return UBUS_STATUS_PERMISSION_DENIED;
		c++;
	}

	if (!c)
		return UBUS_STATUS_NO_DATA;

	return 0;
}

static int
rpc_uci_apply(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_T_MAX];
	int timeout = RPC_APPLY_TIMEOUT;
	char tmp[PATH_MAX];
	bool rollback = false;
	int ret, i;
	char *sid;
	glob_t gl;

	blobmsg_parse(rpc_uci_apply_policy, __RPC_T_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (tb[RPC_T_ROLLBACK])
		rollback = blobmsg_get_bool(tb[RPC_T_ROLLBACK]);

	if (apply_sid[0] && rollback)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (!tb[RPC_T_SESSION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	sid = blobmsg_data(tb[RPC_T_SESSION]);

	if (tb[RPC_T_TIMEOUT])
		timeout = blobmsg_get_u32(tb[RPC_T_TIMEOUT]);

	rpc_uci_purge_dir(RPC_SNAPSHOT_FILES);
	rpc_uci_purge_dir(RPC_SNAPSHOT_DELTA);

	if (!apply_sid[0]) {
		mkdir(RPC_SNAPSHOT_FILES, 0700);
		mkdir(RPC_SNAPSHOT_DELTA, 0700);

		snprintf(tmp, sizeof(tmp), RPC_UCI_SAVEDIR_PREFIX "%s/*", sid);
		if (glob(tmp, GLOB_PERIOD, NULL, &gl) < 0)
			return UBUS_STATUS_NOT_FOUND;

		snprintf(tmp, sizeof(tmp), RPC_UCI_SAVEDIR_PREFIX "%s/", sid);

		ret = rpc_uci_apply_access(sid, &gl);
		if (ret) {
			globfree(&gl);
			return ret;
		}

		/* copy SID early because rpc_uci_apply_config() will clobber buf */
		if (rollback)
			strncpy(apply_sid, sid, RPC_SID_LEN);

		for (i = 0; i < gl.gl_pathc; i++) {
			char *config = basename(gl.gl_pathv[i]);
			struct stat s;

			if (*config == '.')
				continue;

			if (stat(gl.gl_pathv[i], &s) || !s.st_size)
				continue;

			rpc_uci_copy_file(RPC_UCI_DIR, RPC_SNAPSHOT_FILES, config);
			rpc_uci_copy_file(tmp, RPC_SNAPSHOT_DELTA, config);
			rpc_uci_apply_config(ctx, config);
		}

		globfree(&gl);

		if (rollback) {
			apply_timer.cb = rpc_uci_apply_timeout;
			uloop_timeout_set(&apply_timer, timeout * 1000);
			apply_ctx = ctx;
		}
	}

	return 0;
}

static int
rpc_uci_confirm(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_B_MAX];
	char *sid;

	blobmsg_parse(rpc_uci_rollback_policy, __RPC_B_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_B_SESSION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	sid = blobmsg_data(tb[RPC_B_SESSION]);

	if (!apply_sid[0])
		return UBUS_STATUS_NO_DATA;

	if (strcmp(apply_sid, sid))
		return UBUS_STATUS_PERMISSION_DENIED;

	rpc_uci_purge_dir(RPC_SNAPSHOT_FILES);
	rpc_uci_purge_dir(RPC_SNAPSHOT_DELTA);

	uloop_timeout_cancel(&apply_timer);
	memset(apply_sid, 0, sizeof(apply_sid));
	apply_ctx = NULL;

	return 0;
}

static int
rpc_uci_rollback(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_B_MAX];
	char tmp[PATH_MAX];
	glob_t gl;
	char *sid;

	blobmsg_parse(rpc_uci_rollback_policy, __RPC_B_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!apply_sid[0])
		return UBUS_STATUS_NO_DATA;

	if (!tb[RPC_B_SESSION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	sid = blobmsg_data(tb[RPC_B_SESSION]);

	if (strcmp(apply_sid, sid))
		return UBUS_STATUS_PERMISSION_DENIED;

	snprintf(tmp, sizeof(tmp), "%s/*", RPC_SNAPSHOT_FILES);
	if (glob(tmp, GLOB_PERIOD, NULL, &gl) < 0)
		return UBUS_STATUS_NOT_FOUND;

	rpc_uci_do_rollback(ctx, sid, &gl);

	globfree(&gl);

	return 0;
}


/*
 * Session destroy callback to purge associated delta directory.
 */
static void
rpc_uci_purge_savedir_cb(struct rpc_session *ses, void *priv)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path) - 1, RPC_UCI_SAVEDIR_PREFIX "%s", ses->id);
	rpc_uci_purge_dir(path);
}

/*
 * Removes all delta directories which match the RPC_UCI_SAVEDIR_PREFIX.
 * This is used to clean up garbage when starting rpcd.
 */
void rpc_uci_purge_savedirs(void)
{
	int i;
	glob_t gl;

	if (!glob(RPC_UCI_SAVEDIR_PREFIX "*", 0, NULL, &gl))
	{
		for (i = 0; i < gl.gl_pathc; i++)
			rpc_uci_purge_dir(gl.gl_pathv[i]);

		globfree(&gl);
	}
}

int rpc_uci_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method uci_methods[] = {
		{ .name = "configs", .handler = rpc_uci_configs },
		UBUS_METHOD("get",      rpc_uci_get,      rpc_uci_get_policy),
		UBUS_METHOD("state",    rpc_uci_state,    rpc_uci_get_policy),
		UBUS_METHOD("add",      rpc_uci_add,      rpc_uci_add_policy),
		UBUS_METHOD("set",      rpc_uci_set,      rpc_uci_set_policy),
		UBUS_METHOD("delete",   rpc_uci_delete,   rpc_uci_delete_policy),
		UBUS_METHOD("rename",   rpc_uci_rename,   rpc_uci_rename_policy),
		UBUS_METHOD("order",    rpc_uci_order,    rpc_uci_order_policy),
		UBUS_METHOD("changes",  rpc_uci_changes,  rpc_uci_config_policy),
		UBUS_METHOD("revert",   rpc_uci_revert,   rpc_uci_config_policy),
		UBUS_METHOD("commit",   rpc_uci_commit,   rpc_uci_config_policy),
		UBUS_METHOD("apply",    rpc_uci_apply,    rpc_uci_apply_policy),
		UBUS_METHOD("confirm",  rpc_uci_confirm,  rpc_uci_rollback_policy),
		UBUS_METHOD("rollback", rpc_uci_rollback, rpc_uci_rollback_policy),
	};

	static struct ubus_object_type uci_type =
		UBUS_OBJECT_TYPE("luci-rpc-uci", uci_methods);

	static struct ubus_object obj = {
		.name = "uci",
		.type = &uci_type,
		.methods = uci_methods,
		.n_methods = ARRAY_SIZE(uci_methods),
	};

	static struct rpc_session_cb cb = {
		.cb = rpc_uci_purge_savedir_cb
	};

	cursor = uci_alloc_context();

	if (!cursor)
		return UBUS_STATUS_UNKNOWN_ERROR;

	rpc_session_destroy_cb(&cb);

	return ubus_add_object(ctx, &obj);
}
