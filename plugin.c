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

#include <rpcd/plugin.h>

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

struct call_context {
	char path[PATH_MAX];
	const char *argv[4];
	char *method;
	char *input;
	json_tokener *tok;
	json_object *obj;
	bool input_done;
	bool output_done;
};

static int
rpc_plugin_call_stdin_cb(struct ustream *s, void *priv)
{
	struct call_context *c = priv;

	if (!c->input_done)
	{
		ustream_write(s, c->input, strlen(c->input), false);
		c->input_done = true;
	}

	return 0;
}

static int
rpc_plugin_call_stdout_cb(struct blob_buf *blob, char *buf, int len, void *priv)
{
	struct call_context *c = priv;

	if (!c->output_done)
	{
		c->obj = json_tokener_parse_ex(c->tok, buf, len);

		if (json_tokener_get_error(c->tok) != json_tokener_continue)
			c->output_done = true;
	}

	return len;
}

static int
rpc_plugin_call_stderr_cb(struct blob_buf *blob, char *buf, int len, void *priv)
{
	return len;
}

static int
rpc_plugin_call_finish_cb(struct blob_buf *blob, int stat, void *priv)
{
	struct call_context *c = priv;
	int rv = UBUS_STATUS_INVALID_ARGUMENT;

	if (json_tokener_get_error(c->tok) == json_tokener_success)
	{
		if (c->obj)
		{
			if (json_object_get_type(c->obj) == json_type_object &&
			    blobmsg_add_object(blob, c->obj))
				rv = UBUS_STATUS_OK;

			json_object_put(c->obj);
		}
		else
		{
			rv = UBUS_STATUS_NO_DATA;
		}
	}

	json_tokener_free(c->tok);

	free(c->input);
	free(c->method);

	return rv;
}

static int
rpc_plugin_call(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	int rv = UBUS_STATUS_UNKNOWN_ERROR;
	struct call_context *c;
	char *plugin;

	c = calloc(1, sizeof(*c));

	if (!c)
		goto fail;

	c->method = strdup(method);
	c->input = blobmsg_format_json(msg, true);
	c->tok = json_tokener_new();

	if (!c->method || !c->input || !c->tok)
		goto fail;

	plugin = c->path + sprintf(c->path, "%s/", RPC_PLUGIN_DIRECTORY);

	if (!rpc_plugin_lookup_plugin(ctx, obj, plugin))
	{
		rv = UBUS_STATUS_NOT_FOUND;
		goto fail;
	}

	c->argv[0] = c->path;
	c->argv[1] = "call";
	c->argv[2] = c->method;

	return rpc_exec(c->argv, rpc_plugin_call_stdin_cb,
	                rpc_plugin_call_stdout_cb, rpc_plugin_call_stderr_cb,
	                rpc_plugin_call_finish_cb, c, ctx, req);

fail:
	if (c)
	{
		if (c->method)
			free(c->method);

		if (c->input)
			free(c->input);

		if (c->tok)
			json_tokener_free(c->tok);

		free(c);
	}

	return rv;
}

static bool
rpc_plugin_parse_signature(struct blob_attr *sig, struct ubus_method *method)
{
	int rem, n_attr;
	enum blobmsg_type type;
	struct blob_attr *attr;
	struct blobmsg_policy *policy = NULL;

	if (!sig || blobmsg_type(sig) != BLOBMSG_TYPE_TABLE)
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
			type = blobmsg_type(attr);

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
rpc_plugin_parse_exec(const char *name, int fd)
{
	int len, rem, n_method;
	struct blob_attr *cur;
	struct ubus_method *methods;
	struct ubus_object_type *obj_type;
	struct ubus_object *obj;
	char outbuf[1024];

	json_tokener *tok;
	json_object *jsobj;

	blob_buf_init(&buf, 0);

	tok = json_tokener_new();

	if (!tok)
		return NULL;

	while ((len = read(fd, outbuf, sizeof(outbuf))) > 0)
	{
		jsobj = json_tokener_parse_ex(tok, outbuf, len);

		if (json_tokener_get_error(tok) == json_tokener_continue)
			continue;

		if (json_tokener_get_error(tok) != json_tokener_success)
			break;

		if (jsobj)
		{
			if (json_object_get_type(jsobj) == json_type_object)
				blobmsg_add_object(&buf, jsobj);

			json_object_put(jsobj);
			break;
		}
	}

	json_tokener_free(tok);

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
rpc_plugin_register_exec(struct ubus_context *ctx, const char *path)
{
	pid_t pid;
	int rv = UBUS_STATUS_NO_DATA, fd, fds[2];
	const char *name;
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
		plugin = rpc_plugin_parse_exec(name + 1, fds[0]);

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


static LIST_HEAD(plugins);

static const struct rpc_daemon_ops ops = {
	.session_access     = rpc_session_access,
	.session_create_cb  = rpc_session_create_cb,
	.session_destroy_cb = rpc_session_destroy_cb,
	.exec               = rpc_exec,
};

static int
rpc_plugin_register_library(struct ubus_context *ctx, const char *path)
{
	struct rpc_plugin *p;
	void *dlh;

	dlh = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);

	if (!dlh)
		return UBUS_STATUS_UNKNOWN_ERROR;

	p = dlsym(dlh, "rpc_plugin");

	if (!p)
		return UBUS_STATUS_NOT_FOUND;

	list_add(&p->list, &plugins);

	return p->init(&ops, ctx);
}

int rpc_plugin_api_init(struct ubus_context *ctx)
{
	DIR *d;
	int rv = 0;
	struct stat s;
	struct dirent *e;
	char path[PATH_MAX];

	if ((d = opendir(RPC_PLUGIN_DIRECTORY)) != NULL)
	{
		while ((e = readdir(d)) != NULL)
		{
			snprintf(path, sizeof(path) - 1,
			         RPC_PLUGIN_DIRECTORY "/%s", e->d_name);

			if (stat(path, &s) || !S_ISREG(s.st_mode) || !(s.st_mode & S_IXUSR))
				continue;

			rv |= rpc_plugin_register_exec(ctx, path);
		}

		closedir(d);
	}

	if ((d = opendir(RPC_LIBRARY_DIRECTORY)) != NULL)
	{
		while ((e = readdir(d)) != NULL)
		{
			snprintf(path, sizeof(path) - 1,
			         RPC_LIBRARY_DIRECTORY "/%s", e->d_name);

			if (stat(path, &s) || !S_ISREG(s.st_mode))
				continue;

			rv |= rpc_plugin_register_library(ctx, path);
		}

		closedir(d);
	}

	return rv;
}
