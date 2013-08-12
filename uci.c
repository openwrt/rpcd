/*
 * luci-rpcd - LuCI UBUS RPC server
 *
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

#include "uci.h"
#include "session.h"

static struct blob_buf buf;
static struct uci_context *cursor;

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
 * Test read access to given config. If the passed "sid" blob attribute pointer
 * is NULL then the precedure was not invoked through the ubus-rpc so we do not
 * perform access control and always assume true.
 */
static bool
rpc_uci_read_access(struct blob_attr *sid, struct blob_attr *config)
{
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
rpc_uci_get(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
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
	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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
	if (p)
		uci_unload(cursor, p);

	return rpc_uci_status();
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

	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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
	if (p)
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
	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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

out:
	if (p)
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
	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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

out:
	if (p)
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

	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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
	if (p)
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

	uci_load(cursor, ptr.package, &p);

	if (!p)
		goto out;

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

out:
	if (p)
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
	void *c;

	blobmsg_parse(rpc_uci_config_policy, __RPC_C_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_C_CONFIG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_read_access(tb[RPC_C_SESSION], tb[RPC_C_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	uci_load(cursor, blobmsg_data(tb[RPC_C_CONFIG]), &p);

	if (!p)
		goto out;

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "changes");

	uci_foreach_element(&p->saved_delta, e)
		rpc_uci_dump_change(uci_to_delta(e));

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

out:
	if (p)
		uci_unload(cursor, p);

	return rpc_uci_status();
}

static int
rpc_uci_revert_commit(struct blob_attr *msg, bool commit)
{
	struct blob_attr *tb[__RPC_C_MAX];
	struct uci_package *p = NULL;
	struct uci_ptr ptr = { 0 };

	blobmsg_parse(rpc_uci_config_policy, __RPC_C_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_C_CONFIG])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!rpc_uci_write_access(tb[RPC_C_SESSION], tb[RPC_C_CONFIG]))
		return UBUS_STATUS_PERMISSION_DENIED;

	ptr.package = blobmsg_data(tb[RPC_C_CONFIG]);
	uci_load(cursor, ptr.package, &p);

	if (!p || uci_lookup_ptr(cursor, &ptr, NULL, true) || !ptr.p)
		goto out;

	if (commit)
		uci_commit(cursor, &p, false);
	else
		uci_revert(cursor, &ptr);

out:
	if (p)
		uci_unload(cursor, p);

	return rpc_uci_status();
}

static int
rpc_uci_revert(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	return rpc_uci_revert_commit(msg, false);
}

static int
rpc_uci_commit(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	return rpc_uci_revert_commit(msg, true);
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


int rpc_uci_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method uci_methods[] = {
		{ .name = "configs", .handler = rpc_uci_configs },
		UBUS_METHOD("get",     rpc_uci_get,     rpc_uci_get_policy),
		UBUS_METHOD("add",     rpc_uci_add,     rpc_uci_add_policy),
		UBUS_METHOD("set",     rpc_uci_set,     rpc_uci_set_policy),
		UBUS_METHOD("delete",  rpc_uci_delete,  rpc_uci_delete_policy),
		UBUS_METHOD("rename",  rpc_uci_rename,  rpc_uci_rename_policy),
		UBUS_METHOD("order",   rpc_uci_order,   rpc_uci_order_policy),
		UBUS_METHOD("changes", rpc_uci_changes, rpc_uci_config_policy),
		UBUS_METHOD("revert",  rpc_uci_revert,  rpc_uci_config_policy),
		UBUS_METHOD("commit",  rpc_uci_commit,  rpc_uci_config_policy),
	};

	static struct ubus_object_type uci_type =
		UBUS_OBJECT_TYPE("luci-rpc-uci", uci_methods);

	static struct ubus_object obj = {
		.name = "uci",
		.type = &uci_type,
		.methods = uci_methods,
		.n_methods = ARRAY_SIZE(uci_methods),
	};

	cursor = uci_alloc_context();

	if (!cursor)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return ubus_add_object(ctx, &obj);
}
