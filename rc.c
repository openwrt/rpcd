// SPDX-License-Identifier: ISC OR MIT
/*
 * rpcd - UBUS RPC server
 *
 * Copyright (C) 2020 Rafał Miłecki <rafal@milecki.pl>
 */

#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <libubox/blobmsg.h>
#include <libubox/ulog.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include <rpcd/rc.h>

#define RC_LIST_EXEC_TIMEOUT_MS			3000

enum {
	RC_LIST_NAME,
	RC_LIST_SKIP_RUNNING_CHECK,
	__RC_LIST_MAX
};

static const struct blobmsg_policy rc_list_policy[] = {
	[RC_LIST_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[RC_LIST_SKIP_RUNNING_CHECK] = { "skip_running_check", BLOBMSG_TYPE_BOOL },
};

enum {
	RC_INIT_NAME,
	RC_INIT_ACTION,
	__RC_INIT_MAX
};

static const struct blobmsg_policy rc_init_policy[] = {
	[RC_INIT_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[RC_INIT_ACTION] = { "action", BLOBMSG_TYPE_STRING },
};

struct rc_list_context {
	struct uloop_process process;
	struct uloop_timeout timeout;
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct blob_buf *buf;
	DIR *dir;
	bool skip_running_check;
	const char *req_name;

	/* Info about currently processed init.d entry */
	struct {
		char path[PATH_MAX];
		const char *d_name;
		int start;
		int stop;
		bool enabled;
		bool running;
		bool use_procd;
	} entry;
};

static void rc_list_readdir(struct rc_list_context *c);

/**
 * rc_check_script - check if script is safe to execute as root
 *
 * Check if it's owned by root and if only root can modify it.
 */
static int rc_check_script(const char *path)
{
	struct stat s;

	if (stat(path, &s))
		return UBUS_STATUS_NOT_FOUND;

	if (s.st_uid != 0 || s.st_gid != 0 || !(s.st_mode & S_IXUSR) || (s.st_mode & S_IWOTH))
		return UBUS_STATUS_PERMISSION_DENIED;

	return UBUS_STATUS_OK;
}

static void rc_list_add_table(struct rc_list_context *c)
{
	void *e;

	e = blobmsg_open_table(c->buf, c->entry.d_name);

	if (c->entry.start >= 0)
		blobmsg_add_u16(c->buf, "start", c->entry.start);
	if (c->entry.stop >= 0)
		blobmsg_add_u16(c->buf, "stop", c->entry.stop);
	blobmsg_add_u8(c->buf, "enabled", c->entry.enabled);
	if (!c->skip_running_check && c->entry.use_procd)
		blobmsg_add_u8(c->buf, "running", c->entry.running);

	blobmsg_close_table(c->buf, e);
}

static void rpc_list_exec_timeout_cb(struct uloop_timeout *t)
{
	struct rc_list_context *c = container_of(t, struct rc_list_context, timeout);

	ULOG_WARN("Timeout waiting for %s\n", c->entry.path);

	uloop_process_delete(&c->process);
	kill(c->process.pid, SIGKILL);

	rc_list_readdir(c);
}

/**
 * rc_exec - execute a file and call callback on complete
 */
static int rc_list_exec(struct rc_list_context *c, const char *action, uloop_process_handler cb)
{
	pid_t pid;
	int err;
	int fd;

	pid = fork();
	switch (pid) {
	case -1:
		return -errno;
	case 0:
		if (c->skip_running_check)
			exit(-EFAULT);

		if (!c->entry.use_procd)
			exit(-EOPNOTSUPP);

		/* Set stdin, stdout & stderr to /dev/null */
		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}

		uloop_end();

		execl(c->entry.path, c->entry.path, action, NULL);
		exit(errno);
	default:
		c->process.pid = pid;
		c->process.cb = cb;

		err = uloop_process_add(&c->process);
		if (err)
			return err;

		c->timeout.cb = rpc_list_exec_timeout_cb;
		err = uloop_timeout_set(&c->timeout, RC_LIST_EXEC_TIMEOUT_MS);
		if (err) {
			uloop_process_delete(&c->process);
			return err;
		}

		return 0;
	}
}

static void rc_list_exec_running_cb(struct uloop_process *p, int stat)
{
	struct rc_list_context *c = container_of(p, struct rc_list_context, process);

	uloop_timeout_cancel(&c->timeout);

	c->entry.running = !stat;
	rc_list_add_table(c);

	rc_list_readdir(c);
}

static void rc_list_readdir(struct rc_list_context *c)
{
	struct dirent *e;
	FILE *fp;

	e = readdir(c->dir);
	/* 
	 * If scanning for a specific script and entry.d_name is set
	 * we can assume we found a matching one in the previous
	 * iteration since entry.d_name is set only if a match is found.
	 */
	if (!e || (c->req_name && c->entry.d_name)) {
		closedir(c->dir);
		ubus_send_reply(c->ctx, &c->req, c->buf->head);
		ubus_complete_deferred_request(c->ctx, &c->req, UBUS_STATUS_OK);
		return;
	}

	if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
		goto next;

	if (c->req_name && strcmp(e->d_name, c->req_name))
		goto next;

	memset(&c->entry, 0, sizeof(c->entry));
	c->entry.start = -1;
	c->entry.stop = -1;

	snprintf(c->entry.path, sizeof(c->entry.path), "/etc/init.d/%s", e->d_name);
	if (rc_check_script(c->entry.path))
		goto next;

	c->entry.d_name = e->d_name;

	fp = fopen(c->entry.path, "r");
	if (fp) {
		struct stat s;
		char path[PATH_MAX];
		char line[255];
		bool beginning;
		int count = 0;

		beginning = true;
		while ((c->entry.start < 0 || c->entry.stop < 0 ||
		       (!c->skip_running_check && !c->entry.use_procd)) &&
		       count <= 10 && fgets(line, sizeof(line), fp)) {
			if (beginning) {
				if (!strncmp(line, "START=", 6)) {
					c->entry.start = strtoul(line + 6, NULL, 0);
				} else if (!strncmp(line, "STOP=", 5)) {
					c->entry.stop = strtoul(line + 5, NULL, 0);
				} else if (!c->skip_running_check && !strncmp(line, "USE_PROCD=", 10)) {
					c->entry.use_procd = !!strtoul(line + 10, NULL, 0);
				}
				count++;
			}

			beginning = !!strchr(line, '\n');
		}
		fclose(fp);

		if (c->entry.start >= 0) {
			snprintf(path, sizeof(path), "/etc/rc.d/S%02d%s", c->entry.start, c->entry.d_name);
			if (!stat(path, &s) && (s.st_mode & S_IXUSR))
				c->entry.enabled = true;
		}
	}

	if (rc_list_exec(c, "running", rc_list_exec_running_cb))
		goto next;

	return;
next:
	rc_list_readdir(c);
}

/**
 * rc_list - allocate listing context and start reading directory
 */
static int rc_list(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__RC_LIST_MAX];
	static struct blob_buf buf;
	struct rc_list_context *c;

	blobmsg_parse(rc_list_policy, __RC_LIST_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	blob_buf_init(&buf, 0);

	c = calloc(1, sizeof(*c));
	if (!c)
		return UBUS_STATUS_UNKNOWN_ERROR;

	c->ctx = ctx;
	c->buf = &buf;
	c->dir = opendir("/etc/init.d");
	if (!c->dir) {
		free(c);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	if (tb[RC_LIST_SKIP_RUNNING_CHECK])
		c->skip_running_check = blobmsg_get_bool(tb[RC_LIST_SKIP_RUNNING_CHECK]);
	if (tb[RC_LIST_NAME])
		c->req_name = blobmsg_get_string(tb[RC_LIST_NAME]);

	ubus_defer_request(ctx, req, &c->req);

	rc_list_readdir(c);

	return 0; /* Deferred */
}

struct rc_init_context {
	struct uloop_process process;
	struct ubus_context *ctx;
	struct ubus_request_data req;
};

static void rc_init_cb(struct uloop_process *p, int stat)
{
	struct rc_init_context *c = container_of(p, struct rc_init_context, process);

	ubus_complete_deferred_request(c->ctx, &c->req, UBUS_STATUS_OK);

	free(c);
}

static int rc_init(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__RC_INIT_MAX];
	struct rc_init_context *c;
	char path[PATH_MAX];
	const char *action;
	const char *name;
	const char *chr;
	pid_t pid;
	int err;
	int fd;

	blobmsg_parse(rc_init_policy, __RC_INIT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[RC_INIT_NAME] || !tb[RC_INIT_ACTION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[RC_INIT_NAME]);

	/* Validate script name */
	for (chr = name; (chr = strchr(chr, '.')); chr++) {
		if (*(chr + 1) == '.')
			return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (strchr(name, '/'))
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, sizeof(path), "/etc/init.d/%s", name);

	/* Validate script privileges */
	err = rc_check_script(path);
	if (err)
		return err;

	action = blobmsg_get_string(tb[RC_INIT_ACTION]);
	if (strcmp(action, "disable") &&
	    strcmp(action, "enable") &&
	    strcmp(action, "stop") &&
	    strcmp(action, "start") &&
	    strcmp(action, "restart") &&
	    strcmp(action, "reload"))
		return UBUS_STATUS_INVALID_ARGUMENT;

	c = calloc(1, sizeof(*c));
	if (!c)
		return UBUS_STATUS_UNKNOWN_ERROR;

	pid = fork();
	switch (pid) {
	case -1:
		free(c);
		return UBUS_STATUS_UNKNOWN_ERROR;
	case 0:
		/* Set stdin, stdout & stderr to /dev/null */
		fd = open("/dev/null", O_RDWR);
		if (fd >= 0) {
			dup2(fd, 0);
			dup2(fd, 1);
			dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}

		uloop_end();

		execl(path, path, action, NULL);
		exit(errno);
	default:
		c->ctx = ctx;
		c->process.pid = pid;
		c->process.cb = rc_init_cb;
		uloop_process_add(&c->process);

		ubus_defer_request(ctx, req, &c->req);

		return 0; /* Deferred */
	}
}

int rpc_rc_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method rc_methods[] = {
		UBUS_METHOD("list", rc_list, rc_list_policy),
		UBUS_METHOD("init", rc_init, rc_init_policy),
	};

	static struct ubus_object_type rc_type =
		UBUS_OBJECT_TYPE("rc", rc_methods);

	static struct ubus_object obj = {
		.name = "rc",
		.type = &rc_type,
		.methods = rc_methods,
		.n_methods = ARRAY_SIZE(rc_methods),
	};

	return ubus_add_object(ctx, &obj);
}
