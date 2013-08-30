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

#include "plugin.h"

static struct blob_buf buf;

struct rpc_plugin_lookup_context {
	uint32_t id;
	char *name;
	bool found;
};

static void
rpc_plugin_lookup_plugin_cb(struct ubus_context *ctx,
                            struct ubus_object_data *obj, void *priv)
{
	struct rpc_plugin_lookup_context *c = priv;

	if (c->id == obj->id)
	{
		c->found = true;
		sprintf(c->name, "%s", obj->path);
	}
}

static bool
rpc_plugin_lookup_plugin(struct ubus_context *ctx, struct ubus_object *obj,
                         char *strptr)
{
	struct rpc_plugin_lookup_context c = { .id = obj->id, .name = strptr };

	if (ubus_lookup(ctx, NULL, rpc_plugin_lookup_plugin_cb, &c))
		return false;

	return c.found;
}

static int
rpc_plugin_call(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	pid_t pid;
	struct stat s;
	int rv, fd, in_fds[2], out_fds[2];
	char *input, *plugin, *meth, output[4096] = { 0 }, path[PATH_MAX] = { 0 };

	meth = strdup(method);
	input = blobmsg_format_json(msg, true);
	plugin = path + sprintf(path, "%s/", RPC_PLUGIN_DIRECTORY);

	if (!rpc_plugin_lookup_plugin(ctx, obj, plugin))
		return UBUS_STATUS_NOT_FOUND;

	if (stat(path, &s) || !(s.st_mode & S_IXUSR))
		return UBUS_STATUS_NOT_FOUND;

	if (pipe(in_fds) || pipe(out_fds))
		return UBUS_STATUS_UNKNOWN_ERROR;

	switch ((pid = fork()))
	{
	case -1:
		return UBUS_STATUS_UNKNOWN_ERROR;

	case 0:
		uloop_done();

		fd = open("/dev/null", O_RDWR);

		if (fd > -1)
		{
			dup2(fd, 2);

			if (fd > 2)
				close(fd);
		}

		dup2(in_fds[0], 0);
		dup2(out_fds[1], 1);

		close(in_fds[0]);
		close(in_fds[1]);
		close(out_fds[0]);
		close(out_fds[1]);

		if (execl(path, plugin, "call", meth, NULL))
			return UBUS_STATUS_UNKNOWN_ERROR;

	default:
		rv = UBUS_STATUS_NO_DATA;

		if (input)
		{
			write(in_fds[1], input, strlen(input));
			free(input);
		}

		close(in_fds[0]);
		close(in_fds[1]);

		if (read(out_fds[0], output, sizeof(output) - 1) > 0)
		{
			blob_buf_init(&buf, 0);

			if (!blobmsg_add_json_from_string(&buf, output))
				rv = UBUS_STATUS_INVALID_ARGUMENT;

			rv = UBUS_STATUS_OK;
		}

		close(out_fds[0]);
		close(out_fds[1]);

		waitpid(pid, NULL, 0);

		if (!rv)
			ubus_send_reply(ctx, req, buf.head);

		free(meth);

		return rv;
	}
}

static bool
rpc_plugin_parse_signature(struct blob_attr *sig, struct ubus_method *method)
{
	int rem, n_attr;
	enum blobmsg_type type;
	struct blob_attr *attr;
	struct blobmsg_policy *policy = NULL;

	if (!sig || blob_id(sig) != BLOBMSG_TYPE_TABLE)
		return false;

	n_attr = 0;

	blobmsg_for_each_attr(attr, sig, rem)
		n_attr++;

	if (n_attr)
	{
		policy = calloc(n_attr, sizeof(*policy));

		if (!policy)
			return false;

		n_attr = 0;

		blobmsg_for_each_attr(attr, sig, rem)
		{
			type = blob_id(attr);

			if (type == BLOBMSG_TYPE_INT32)
			{
				switch (blobmsg_get_u32(attr))
				{
				case 8:
					type = BLOBMSG_TYPE_INT8;
					break;

				case 16:
					type = BLOBMSG_TYPE_INT16;
					break;

				case 64:
					type = BLOBMSG_TYPE_INT64;
					break;

				default:
					type = BLOBMSG_TYPE_INT32;
					break;
				}
			}

			policy[n_attr].name = strdup(blobmsg_name(attr));
			policy[n_attr].type = type;

			n_attr++;
		}
	}

	method->name = strdup(blobmsg_name(sig));
	method->handler = rpc_plugin_call;
	method->policy = policy;
	method->n_policy = n_attr;

	return true;
}

static struct ubus_object *
rpc_plugin_parse_plugin(const char *name, const char *listbuf)
{
	int rem, n_method;
	struct blob_attr *cur;
	struct ubus_method *methods;
	struct ubus_object_type *obj_type;
	struct ubus_object *obj;

	blob_buf_init(&buf, 0);

	if (!blobmsg_add_json_from_string(&buf, listbuf))
		return NULL;

	n_method = 0;

	blob_for_each_attr(cur, buf.head, rem)
		n_method++;

	if (!n_method)
		return NULL;

	methods = calloc(n_method, sizeof(*methods));

	if (!methods)
		return NULL;

	n_method = 0;

	blob_for_each_attr(cur, buf.head, rem)
	{
		if (!rpc_plugin_parse_signature(cur, &methods[n_method]))
			continue;

		n_method++;
	}

	obj = calloc(1, sizeof(*obj));

	if (!obj)
		return NULL;

	obj_type = calloc(1, sizeof(*obj_type));

	if (!obj_type)
		return NULL;

	asprintf((char **)&obj_type->name, "luci-rpc-plugin-%s", name);
	obj_type->methods = methods;
	obj_type->n_methods = n_method;

	obj->name = strdup(name);
	obj->type = obj_type;
	obj->methods = methods;
	obj->n_methods = n_method;

	return obj;
}

static int
rpc_plugin_register(struct ubus_context *ctx, const char *path)
{
	pid_t pid;
	int rv, fd, fds[2];
	const char *name;
	char listbuf[4096] = { 0 };
	struct ubus_object *plugin;

	name = strrchr(path, '/');

	if (!name)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (pipe(fds))
		return UBUS_STATUS_UNKNOWN_ERROR;

	switch ((pid = fork()))
	{
	case -1:
		return UBUS_STATUS_UNKNOWN_ERROR;

	case 0:
		fd = open("/dev/null", O_RDWR);

		if (fd > -1)
		{
			dup2(fd, 0);
			dup2(fd, 2);

			if (fd > 2)
				close(fd);
		}

		dup2(fds[1], 1);

		close(fds[0]);
		close(fds[1]);

		if (execl(path, path, "list", NULL))
			return UBUS_STATUS_UNKNOWN_ERROR;

	default:
		rv = 0;

		if (read(fds[0], listbuf, sizeof(listbuf) - 1) <= 0)
			goto out;

		plugin = rpc_plugin_parse_plugin(name + 1, listbuf);

		if (!plugin)
			goto out;

		rv = ubus_add_object(ctx, plugin);

out:
		close(fds[0]);
		close(fds[1]);
		waitpid(pid, NULL, 0);

		return rv;
	}
}

int rpc_plugin_api_init(struct ubus_context *ctx)
{
	DIR *d;
	int rv = 0;
	struct stat s;
	struct dirent *e;
	char path[PATH_MAX];

	d = opendir(RPC_PLUGIN_DIRECTORY);

	if (!d)
		return UBUS_STATUS_NOT_FOUND;

	while ((e = readdir(d)) != NULL)
	{
		snprintf(path, sizeof(path) - 1, RPC_PLUGIN_DIRECTORY "/%s", e->d_name);

		if (stat(path, &s) || !S_ISREG(s.st_mode) || !(s.st_mode & S_IXUSR))
			continue;

		rv |= rpc_plugin_register(ctx, path);
	}

	closedir(d);

	return rv;
}
