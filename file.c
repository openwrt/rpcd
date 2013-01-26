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

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "file.h"

static struct blob_buf buf;

enum {
	RPC_F_PATH,
	RPC_F_DATA,
	__RPC_F_MAX,
};

static const struct blobmsg_policy file_policy[__RPC_F_MAX] = {
	[RPC_F_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[RPC_F_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
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
	static struct blob_attr *tb[__RPC_F_MAX];

	blobmsg_parse(file_policy, __RPC_F_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[RPC_F_PATH])
	{
		errno = EINVAL;
		return NULL;
	}

	*path = blobmsg_data(tb[RPC_F_PATH]);

	if (stat(*path, s))
		return NULL;

	return tb;
}

static int
rpc_handle_read(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	int fd, rlen;
	char *path;
	char buffer[RPC_FILE_MAX_SIZE];
	struct stat s;

	if (!rpc_check_path(msg, &path, &s))
		return rpc_errno_status();

	if (s.st_size >= RPC_FILE_MAX_SIZE)
		return UBUS_STATUS_NOT_SUPPORTED;

	if ((fd = open(path, O_RDONLY)) < 0)
		return rpc_errno_status();

	if ((rlen = read(fd, buffer, RPC_FILE_MAX_SIZE-1)) > 0)
		buffer[rlen] = 0;

	close(fd);

	if (rlen <= 0)
		return UBUS_STATUS_NO_DATA;

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "data", buffer);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_handle_write(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	int fd, rv;
	char *path;
	struct stat s;
	struct blob_attr **tb;

	if (!(tb = rpc_check_path(msg, &path, &s)))
		return rpc_errno_status();

	if (!tb[RPC_F_DATA])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((fd = open(path, O_WRONLY)) < 0)
		return rpc_errno_status();

	rv = write(fd, blobmsg_data(tb[RPC_F_DATA]), blobmsg_data_len(tb[RPC_F_DATA]));

	close(fd);

	if (rv <= 0)
		return UBUS_STATUS_NO_DATA;

	return 0;
}

static int
rpc_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
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

	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_handle_stat(struct ubus_context *ctx, struct ubus_object *obj,
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

	return 0;
}


int rpc_file_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method file_methods[] = {
		UBUS_METHOD("read",    rpc_handle_read,  file_policy),
		UBUS_METHOD("write",   rpc_handle_write, file_policy),
		UBUS_METHOD("list",    rpc_handle_list,  file_policy),
		UBUS_METHOD("stat",    rpc_handle_stat,  file_policy),
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
