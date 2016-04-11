/*
 * rpcd - UBUS RPC server
 *
 *   Copyright (C) 2013-2014 Jo-Philipp Wich <jow@openwrt.org>
 *   Copyright (C) 2016 Luka Perkov <luka@openwrt.org>
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

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/md5.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>

#include <rpcd/plugin.h>

/* limit of sys & proc files */
#define RPC_FILE_MIN_SIZE		(128)

/* limit of regular files and command output data */
#define RPC_FILE_MAX_SIZE		(4096 * 64)
#define RPC_FILE_MAX_RUNTIME	(3 * 1000)

#define ustream_for_each_read_buffer(stream, ptr, len) \
	for (ptr = ustream_get_read_buf(stream, &len);     \
	     ptr != NULL && len > 0;                       \
	     ustream_consume(stream, len), ptr = ustream_get_read_buf(stream, &len))

#define ustream_declare(us, fd, name)                     \
	us.stream.string_data   = true;                       \
	us.stream.r.buffer_len  = 4096;                       \
	us.stream.r.max_buffers = RPC_FILE_MAX_SIZE / 4096;   \
	us.stream.notify_read   = rpc_file_##name##_read_cb;  \
	us.stream.notify_state  = rpc_file_##name##_state_cb; \
	ustream_fd_init(&us, fd);

struct rpc_file_exec_context {
	struct ubus_context *context;
	struct ubus_request_data request;
	struct uloop_timeout timeout;
	struct uloop_process process;
	struct ustream_fd opipe;
	struct ustream_fd epipe;
	int outlen;
	char *out;
	int errlen;
	char *err;
	int stat;
};


static struct blob_buf buf;

enum {
	RPC_F_R_PATH,
	__RPC_F_R_MAX,
};

static const struct blobmsg_policy rpc_file_r_policy[__RPC_F_R_MAX] = {
	[RPC_F_R_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_F_RB_PATH,
	RPC_F_RB_BASE64,
	__RPC_F_RB_MAX,
};

static const struct blobmsg_policy rpc_file_rb_policy[__RPC_F_RB_MAX] = {
	[RPC_F_RB_PATH]   = { .name = "path",   .type = BLOBMSG_TYPE_STRING },
	[RPC_F_RB_BASE64] = { .name = "base64", .type = BLOBMSG_TYPE_BOOL   },
};

enum {
	RPC_F_RW_PATH,
	RPC_F_RW_DATA,
	RPC_F_RW_APPEND,
	RPC_F_RW_MODE,
	RPC_F_RW_BASE64,
	__RPC_F_RW_MAX,
};

static const struct blobmsg_policy rpc_file_rw_policy[__RPC_F_RW_MAX] = {
	[RPC_F_RW_PATH]   = { .name = "path",   .type = BLOBMSG_TYPE_STRING },
	[RPC_F_RW_DATA]   = { .name = "data",   .type = BLOBMSG_TYPE_STRING },
	[RPC_F_RW_APPEND] = { .name = "append", .type = BLOBMSG_TYPE_BOOL  },
	[RPC_F_RW_MODE]   = { .name = "mode",   .type = BLOBMSG_TYPE_INT32  },
	[RPC_F_RW_BASE64] = { .name = "base64", .type = BLOBMSG_TYPE_BOOL   },
};

enum {
	RPC_E_CMD,
	RPC_E_PARM,
	RPC_E_ENV,
	__RPC_E_MAX,
};

static const struct blobmsg_policy rpc_exec_policy[__RPC_E_MAX] = {
	[RPC_E_CMD]  = { .name = "command", .type = BLOBMSG_TYPE_STRING },
	[RPC_E_PARM] = { .name = "params",  .type = BLOBMSG_TYPE_ARRAY  },
	[RPC_E_ENV]  = { .name = "env",     .type = BLOBMSG_TYPE_TABLE  },
};

static const char *d_types[] = {
	[DT_BLK]     = "block",
	[DT_CHR]     = "char",
	[DT_DIR]     = "directory",
	[DT_FIFO]    = "fifo",
	[DT_LNK]     = "symlink",
	[DT_REG]     = "file",
	[DT_SOCK]    = "socket",
	[DT_UNKNOWN] = "unknown",
};


static int
rpc_errno_status(void)
{
	switch (errno)
	{
	case EACCES:
		return UBUS_STATUS_PERMISSION_DENIED;

	case ENOTDIR:
		return UBUS_STATUS_INVALID_ARGUMENT;

	case ENOENT:
		return UBUS_STATUS_NOT_FOUND;

	case EINVAL:
		return UBUS_STATUS_INVALID_ARGUMENT;

	default:
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
}

static struct blob_attr **
rpc_check_path(struct blob_attr *msg, char **path, struct stat *s)
{
	static struct blob_attr *tb[__RPC_F_R_MAX];

	blobmsg_parse(rpc_file_r_policy, __RPC_F_R_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_F_R_PATH])
	{
		errno = EINVAL;
		return NULL;
	}

	*path = blobmsg_data(tb[RPC_F_R_PATH]);

	if (stat(*path, s))
		return NULL;

	return tb;
}

static int
rpc_file_read(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	static struct blob_attr *tb[__RPC_F_RB_MAX];
	bool base64 = false;
	int fd, rv;
	ssize_t len;
	char *path;
	struct stat s;
	char *wbuf;

	blobmsg_parse(rpc_file_rb_policy, __RPC_F_RB_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_F_RB_PATH])
		return rpc_errno_status();

	path = blobmsg_data(tb[RPC_F_RB_PATH]);

	if (stat(path, &s))
		return rpc_errno_status();

	if (s.st_size >= RPC_FILE_MAX_SIZE)
		return UBUS_STATUS_NOT_SUPPORTED;

	if ((fd = open(path, O_RDONLY)) < 0)
		return rpc_errno_status();

	/* some sysfs files do not report a length */
	if (s.st_size == 0)
		s.st_size = RPC_FILE_MIN_SIZE;

	blob_buf_init(&buf, 0);

	if (tb[RPC_F_RB_BASE64])
		base64 = blobmsg_get_bool(tb[RPC_F_RB_BASE64]);

	len = s.st_size + 1;
	if (base64)
		len = B64_ENCODE_LEN(s.st_size);
	wbuf = blobmsg_alloc_string_buffer(&buf, "data", len);

	if (!wbuf)
	{
		rv = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	if ((len = read(fd, wbuf, s.st_size)) <= 0)
	{
		rv = UBUS_STATUS_NO_DATA;
		goto out;
	}

	if (base64)
	{
		uint8_t *data = calloc(len, sizeof(uint8_t));
		if (!data)
		{
			rv = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}
		memcpy(data, wbuf, len);

		len = b64_encode(data, len, wbuf, B64_ENCODE_LEN(len));
		free(data);
		if (len < 0)
		{
			rv = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}
	}

	*(wbuf + len) = '\0';
	blobmsg_add_string_buffer(&buf);

	ubus_send_reply(ctx, req, buf.head);
	rv = UBUS_STATUS_OK;

out:
	blob_buf_free(&buf);
	close(fd);
	return rv;
}

static int
rpc_file_write(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_F_RW_MAX];
	int append = O_TRUNC;
	mode_t prev_mode, mode = 0666;
	int fd, rv = 0;
	void *data = NULL;
	ssize_t data_len = 0;

	blobmsg_parse(rpc_file_rw_policy, __RPC_F_RW_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_F_RW_PATH] || !tb[RPC_F_RW_DATA])
		return UBUS_STATUS_INVALID_ARGUMENT;

	data = blobmsg_data(tb[RPC_F_RW_DATA]);
	data_len = blobmsg_data_len(tb[RPC_F_RW_DATA]) - 1;

	if (tb[RPC_F_RW_APPEND] && blobmsg_get_bool(tb[RPC_F_RW_APPEND]))
		append = O_APPEND;

	if (tb[RPC_F_RW_MODE])
		mode = blobmsg_get_u32(tb[RPC_F_RW_MODE]);

	prev_mode = umask(0);
	fd = open(blobmsg_data(tb[RPC_F_RW_PATH]), O_CREAT | O_WRONLY | append, mode);
	umask(prev_mode);
	if (fd < 0)
		return rpc_errno_status();

	if (tb[RPC_F_RW_BASE64] && blobmsg_get_bool(tb[RPC_F_RW_BASE64]))
	{
		data_len = b64_decode(data, data, data_len);
		if (data_len < 0)
		{
			rv = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}
	}

	if (write(fd, data, data_len) < 0)
		rv = -1;

out:
	if (fsync(fd) < 0)
		rv = -1;

	close(fd);
	sync();

	if (rv)
		return rpc_errno_status();

	return 0;
}

static int
rpc_file_md5(struct ubus_context *ctx, struct ubus_object *obj,
             struct ubus_request_data *req, const char *method,
             struct blob_attr *msg)
{ 
	int rv, i;
	char *path;
	struct stat s;
	uint8_t md5[16];
	char *wbuf;

	if (!rpc_check_path(msg, &path, &s))
		return rpc_errno_status();

	if (!S_ISREG(s.st_mode))
		return UBUS_STATUS_NOT_SUPPORTED;

	if ((rv = md5sum(path, md5)) <= 0)
		return rpc_errno_status();

	blob_buf_init(&buf, 0);
	wbuf = blobmsg_alloc_string_buffer(&buf, "md5", 33);

	for (i = 0; i < 16; i++)
		sprintf(wbuf + (i * 2), "%02x", (uint8_t) md5[i]);

	blobmsg_add_string_buffer(&buf);
	ubus_send_reply(ctx, req, buf.head);
	blob_buf_free(&buf);

	return UBUS_STATUS_OK;
}

static int
rpc_file_list(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	DIR *fd;
	void *c, *d;
	char *path;
	struct stat s;
	struct dirent *e;

	if (!rpc_check_path(msg, &path, &s))
		return rpc_errno_status();

	if ((fd = opendir(path)) == NULL)
		return rpc_errno_status();

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "entries");

	while ((e = readdir(fd)) != NULL)
	{
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		d = blobmsg_open_table(&buf, NULL);
		blobmsg_add_string(&buf, "name", e->d_name);
		blobmsg_add_string(&buf, "type", d_types[e->d_type]);
		blobmsg_close_table(&buf, d);
	}

	closedir(fd);

	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);
	blob_buf_free(&buf);

	return 0;
}

static int
rpc_file_stat(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	int type;
	char *path;
	struct stat s;

	if (!rpc_check_path(msg, &path, &s))
		return rpc_errno_status();

	blob_buf_init(&buf, 0);

	type = S_ISREG(s.st_mode) ? DT_REG :
	        S_ISDIR(s.st_mode) ? DT_DIR :
	         S_ISCHR(s.st_mode) ? DT_CHR :
	          S_ISBLK(s.st_mode) ? DT_BLK :
	           S_ISFIFO(s.st_mode) ? DT_FIFO :
	            S_ISLNK(s.st_mode) ? DT_LNK :
	             S_ISSOCK(s.st_mode) ? DT_SOCK :
	              DT_UNKNOWN;

	blobmsg_add_string(&buf, "path", path);
	blobmsg_add_string(&buf, "type", d_types[type]);
	blobmsg_add_u32(&buf, "size",  s.st_size);
	blobmsg_add_u32(&buf, "mode",  s.st_mode);
	blobmsg_add_u32(&buf, "atime", s.st_atime);
	blobmsg_add_u32(&buf, "mtime", s.st_mtime);
	blobmsg_add_u32(&buf, "ctime", s.st_ctime);
	blobmsg_add_u32(&buf, "inode", s.st_ino);
	blobmsg_add_u32(&buf, "uid",   s.st_uid);
	blobmsg_add_u32(&buf, "gid",   s.st_gid);

	ubus_send_reply(ctx, req, buf.head);
	blob_buf_free(&buf);

	return 0;
}

static const char *
rpc_file_exec_lookup(const char *cmd)
{
	struct stat s;
	int plen = 0, clen = strlen(cmd) + 1;
	char *search, *p;
	static char path[PATH_MAX];

	if (!stat(cmd, &s) && S_ISREG(s.st_mode))
		return cmd;

	search = getenv("PATH");

	if (!search)
		search = "/bin:/usr/bin:/sbin:/usr/sbin";

	p = search;

	do
	{
		if (*p != ':' && *p != '\0')
			continue;

		plen = p - search;

		if ((plen + clen) >= sizeof(path))
			continue;

		strncpy(path, search, plen);
		sprintf(path + plen, "/%s", cmd);

		if (!stat(path, &s) && S_ISREG(s.st_mode))
			return path;

		search = p + 1;
	}
	while (*p++);

	return NULL;
}


static void
rpc_ustream_to_blobmsg(struct ustream *s, const char *name)
{
	int len;
	char *rbuf, *wbuf;

	if ((len = ustream_pending_data(s, false)) > 0)
	{
		wbuf = blobmsg_alloc_string_buffer(&buf, name, len + 1);

		if (!wbuf)
			return;

		ustream_for_each_read_buffer(s, rbuf, len)
		{
			memcpy(wbuf, rbuf, len);
			wbuf += len;
		}

		*wbuf = 0;
		blobmsg_add_string_buffer(&buf);
	}
}

static void
rpc_file_exec_reply(struct rpc_file_exec_context *c, int rv)
{
	uloop_timeout_cancel(&c->timeout);
	uloop_process_delete(&c->process);

	if (rv == UBUS_STATUS_OK)
	{
		blob_buf_init(&buf, 0);

		blobmsg_add_u32(&buf, "code", WEXITSTATUS(c->stat));

		rpc_ustream_to_blobmsg(&c->opipe.stream, "stdout");
		rpc_ustream_to_blobmsg(&c->epipe.stream, "stderr");

		ubus_send_reply(c->context, &c->request, buf.head);
		blob_buf_free(&buf);
	}

	ubus_complete_deferred_request(c->context, &c->request, rv);

	ustream_free(&c->opipe.stream);
	ustream_free(&c->epipe.stream);

	close(c->opipe.fd.fd);
	close(c->epipe.fd.fd);

	free(c);
}

static void
rpc_file_exec_timeout_cb(struct uloop_timeout *t)
{
	struct rpc_file_exec_context *c =
		container_of(t, struct rpc_file_exec_context, timeout);

	kill(c->process.pid, SIGKILL);
	rpc_file_exec_reply(c, UBUS_STATUS_TIMEOUT);
}

static void
rpc_file_exec_process_cb(struct uloop_process *p, int stat)
{
	struct rpc_file_exec_context *c =
		container_of(p, struct rpc_file_exec_context, process);

	c->stat = stat;

	ustream_poll(&c->opipe.stream);
	ustream_poll(&c->epipe.stream);
}

static void
rpc_file_exec_opipe_read_cb(struct ustream *s, int bytes)
{
	struct rpc_file_exec_context *c =
		container_of(s, struct rpc_file_exec_context, opipe.stream);

	if (ustream_read_buf_full(s))
		rpc_file_exec_reply(c, UBUS_STATUS_NOT_SUPPORTED);
}

static void
rpc_file_exec_epipe_read_cb(struct ustream *s, int bytes)
{
	struct rpc_file_exec_context *c =
		container_of(s, struct rpc_file_exec_context, epipe.stream);

	if (ustream_read_buf_full(s))
		rpc_file_exec_reply(c, UBUS_STATUS_NOT_SUPPORTED);
}

static void
rpc_file_exec_opipe_state_cb(struct ustream *s)
{
	struct rpc_file_exec_context *c =
		container_of(s, struct rpc_file_exec_context, opipe.stream);

	if (c->opipe.stream.eof && c->epipe.stream.eof)
		rpc_file_exec_reply(c, UBUS_STATUS_OK);
}

static void
rpc_file_exec_epipe_state_cb(struct ustream *s)
{
	struct rpc_file_exec_context *c =
		container_of(s, struct rpc_file_exec_context, epipe.stream);

	if (c->opipe.stream.eof && c->epipe.stream.eof)
		rpc_file_exec_reply(c, UBUS_STATUS_OK);
}

static int
rpc_file_exec_run(const char *cmd,
                  const struct blob_attr *arg, const struct blob_attr *env,
                  struct ubus_context *ctx, struct ubus_request_data *req)
{
	pid_t pid;

	int opipe[2];
	int epipe[2];

	int rem;
	struct blob_attr *cur;

	char arglen;
	char **args;

	struct rpc_file_exec_context *c;

	cmd = rpc_file_exec_lookup(cmd);

	if (!cmd)
		return UBUS_STATUS_NOT_FOUND;

	c = malloc(sizeof(*c));

	if (!c)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (pipe(opipe) || pipe(epipe))
		return rpc_errno_status();

	switch ((pid = fork()))
	{
	case -1:
		return rpc_errno_status();

	case 0:
		uloop_done();

		dup2(opipe[1], 1);
		dup2(epipe[1], 2);

		close(0);
		close(opipe[0]);
		close(opipe[1]);
		close(epipe[0]);
		close(epipe[1]);

		arglen = 2;
		args = malloc(sizeof(char *) * arglen);

		if (!args)
			return UBUS_STATUS_UNKNOWN_ERROR;

		args[0] = (char *)cmd;
		args[1] = NULL;

		if (arg)
		{
			blobmsg_for_each_attr(cur, arg, rem)
			{
				if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
					continue;

				arglen++;

				if (!(args = realloc(args, sizeof(char *) * arglen)))
					return UBUS_STATUS_UNKNOWN_ERROR;

				args[arglen-2] = blobmsg_data(cur);
				args[arglen-1] = NULL;
			}
		}

		if (env)
		{
			blobmsg_for_each_attr(cur, env, rem)
			{
				if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
					continue;

				setenv(blobmsg_name(cur), blobmsg_data(cur), 1);
			}
		}

		if (execv(cmd, args))
			return rpc_errno_status();

	default:
		memset(c, 0, sizeof(*c));

		ustream_declare(c->opipe, opipe[0], exec_opipe);
		ustream_declare(c->epipe, epipe[0], exec_epipe);

		c->process.pid = pid;
		c->process.cb = rpc_file_exec_process_cb;
		uloop_process_add(&c->process);

		c->timeout.cb = rpc_file_exec_timeout_cb;
		uloop_timeout_set(&c->timeout, RPC_FILE_MAX_RUNTIME);

		close(opipe[1]);
		close(epipe[1]);

		c->context = ctx;
		ubus_defer_request(ctx, req, &c->request);
	}

	return UBUS_STATUS_OK;
}

static int
rpc_file_exec(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_E_MAX];

	blobmsg_parse(rpc_exec_policy, __RPC_E_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_E_CMD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	return rpc_file_exec_run(blobmsg_data(tb[RPC_E_CMD]),
					      tb[RPC_E_PARM], tb[RPC_E_ENV], ctx, req);
}


static int
rpc_file_api_init(const struct rpc_daemon_ops *o, struct ubus_context *ctx)
{
	static const struct ubus_method file_methods[] = {
		UBUS_METHOD("read",    rpc_file_read,  rpc_file_rb_policy),
		UBUS_METHOD("write",   rpc_file_write, rpc_file_rw_policy),
		UBUS_METHOD("list",    rpc_file_list,  rpc_file_r_policy),
		UBUS_METHOD("stat",    rpc_file_stat,  rpc_file_r_policy),
		UBUS_METHOD("md5",     rpc_file_md5,   rpc_file_r_policy),
		UBUS_METHOD("exec",    rpc_file_exec,  rpc_exec_policy),
	};

	static struct ubus_object_type file_type =
		UBUS_OBJECT_TYPE("luci-rpc-file", file_methods);

	static struct ubus_object obj = {
		.name = "file",
		.type = &file_type,
		.methods = file_methods,
		.n_methods = ARRAY_SIZE(file_methods),
	};

	return ubus_add_object(ctx, &obj);
}

struct rpc_plugin rpc_plugin = {
	.init = rpc_file_api_init
};
