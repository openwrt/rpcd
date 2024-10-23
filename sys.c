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

#include <stdbool.h>
#include <libubus.h>

#include <rpcd/exec.h>
#include <rpcd/plugin.h>
#include <rpcd/session.h>
#include <sys/reboot.h>

static const struct rpc_daemon_ops *ops;

enum {
	RPC_P_USER,
	RPC_P_PASSWORD,
	__RPC_P_MAX
};

static const struct blobmsg_policy rpc_password_policy[__RPC_P_MAX] = {
	[RPC_P_USER]     = { .name = "user",     .type = BLOBMSG_TYPE_STRING },
	[RPC_P_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_UPGRADE_KEEP,
	__RPC_UPGRADE_MAX
};

static const struct blobmsg_policy rpc_upgrade_policy[__RPC_UPGRADE_MAX] = {
	[RPC_UPGRADE_KEEP] = { .name = "keep",    .type = BLOBMSG_TYPE_BOOL },
};

enum {
	RPC_PACKAGELIST_ALL,
	__RPC_PACKAGELIST_MAX
};

static const struct blobmsg_policy rpc_packagelist_policy[__RPC_PACKAGELIST_MAX] = {
	[RPC_PACKAGELIST_ALL] = { .name = "all",    .type = BLOBMSG_TYPE_BOOL },
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

static int
rpc_cgi_password_set(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	pid_t pid;
	int fd, fds[2];
	struct stat s;
	struct blob_attr *tb[__RPC_P_MAX];
	ssize_t n;
	int ret;
	const char *const passwd = "/bin/passwd";
	const struct timespec ts = {0, 100 * 1000 * 1000};

	blobmsg_parse(rpc_password_policy, __RPC_P_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_P_USER] || !tb[RPC_P_PASSWORD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (stat(passwd, &s))
		return UBUS_STATUS_NOT_FOUND;

	if (!(s.st_mode & S_IXUSR))
		return UBUS_STATUS_PERMISSION_DENIED;

	if (pipe(fds))
		return rpc_errno_status();

	switch ((pid = fork()))
	{
	case -1:
		close(fds[0]);
		close(fds[1]);
		return rpc_errno_status();

	case 0:
		uloop_done();

		dup2(fds[0], 0);
		close(fds[0]);
		close(fds[1]);

		if ((fd = open("/dev/null", O_RDWR)) > -1)
		{
			dup2(fd, 1);
			dup2(fd, 2);
			close(fd);
		}

		ret = chdir("/");
		if (ret < 0)
			return rpc_errno_status();

		if (execl(passwd, passwd,
		          blobmsg_data(tb[RPC_P_USER]), NULL))
			return rpc_errno_status();

	default:
		close(fds[0]);

		n = write(fds[1], blobmsg_data(tb[RPC_P_PASSWORD]),
		              blobmsg_data_len(tb[RPC_P_PASSWORD]) - 1);
		if (n < 0)
			return rpc_errno_status();

		n = write(fds[1], "\n", 1);
		if (n < 0)
			return rpc_errno_status();

		nanosleep(&ts, NULL);

		n = write(fds[1], blobmsg_data(tb[RPC_P_PASSWORD]),
		              blobmsg_data_len(tb[RPC_P_PASSWORD]) - 1);
		if (n < 0)
			return rpc_errno_status();
		n = write(fds[1], "\n", 1);
		if (n < 0)
			return rpc_errno_status();

		close(fds[1]);

		waitpid(pid, NULL, 0);

		return 0;
	}
}

static bool
is_field(const char *type, const char *line)
{
	return strncmp(line, type, strlen(type)) == 0;
}

static bool
is_blank(const char *line)
{
	for (; *line; line++)
		if (!isspace(*line))
			return false;
	return true;
}

static int
rpc_sys_packagelist(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_PACKAGELIST_MAX];
	bool all = false, installed = false, auto_installed = false;
	struct blob_buf buf = { 0 };
	char line[256], tmp[128], pkg[128], ver[128];
	char *pkg_abi;
	void *tbl;

	blobmsg_parse(rpc_packagelist_policy, __RPC_PACKAGELIST_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (tb[RPC_PACKAGELIST_ALL] && blobmsg_get_bool(tb[RPC_PACKAGELIST_ALL]))
		all = true;

	FILE *f = fopen("/usr/lib/opkg/status", "r");
	if (!f)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&buf, 0);
	tbl = blobmsg_open_table(&buf, "packages");
	pkg[0] = ver[0] = '\0';

	while (fgets(line, sizeof(line), f)) {
		switch (line[0]) {
		case 'A':
			if (is_field("ABIVersion", line)) {
				/* if there is ABIVersion, remove that suffix */
				if (sscanf(line, "ABIVersion: %127s", tmp) == 1
					&& strlen(tmp) < strlen(pkg)) {
					pkg_abi = pkg + (strlen(pkg) - strlen(tmp));
					if (strncmp(pkg_abi, tmp, strlen(tmp)) == 0)
						pkg_abi[0] = '\0';
				}
			} else if (is_field("Auto-Installed", line))
				if (sscanf(line, "Auto-Installed: %63s", tmp) == 1)
					auto_installed = (strcmp(tmp, "yes") == 0);
			break;
		case 'P':
			if (is_field("Package", line))
				if (sscanf(line, "Package: %127s", pkg) != 1)
					pkg[0] = '\0';
			break;
		case 'V':
			if (is_field("Version", line))
				if (sscanf(line, "Version: %127s", ver) != 1)
					ver[0] = '\0';
			break;
		case 'S':
			if (is_field("Status", line))
				installed = !!strstr(line, " installed");
			break;
		default:
			if (is_blank(line)) {
				if (installed && (all || !auto_installed) && pkg[0] && ver[0])
					blobmsg_add_string(&buf, pkg, ver);
				pkg[0] = ver[0] = '\0';
				installed = auto_installed = false;
			}
			break;
		}
	}

	blobmsg_close_table(&buf, tbl);
	ubus_send_reply(ctx, req, buf.head);
	blob_buf_free(&buf);
	fclose(f);

	return 0;
}

static int
rpc_sys_upgrade_test(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	const char *cmd[4] = { "sysupgrade", "--test", "/tmp/firmware.bin", NULL };
	return ops->exec(cmd, NULL, NULL, NULL, NULL, NULL, ctx, req);
}

static int
rpc_sys_upgrade_start(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
	struct blob_attr *tb[__RPC_UPGRADE_MAX];
	char * const cmd[4] = { "/sbin/sysupgrade", "-n", "/tmp/firmware.bin", NULL };
	char * const cmd_keep[3] = { "/sbin/sysupgrade", "/tmp/firmware.bin", NULL };
	char * const * c = cmd;

	blobmsg_parse(rpc_upgrade_policy, __RPC_UPGRADE_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (tb[RPC_UPGRADE_KEEP] && blobmsg_get_bool(tb[RPC_UPGRADE_KEEP]))
		c = cmd_keep;

	if (!fork()) {
		/* wait for the RPC call to complete */
		sleep(2);
		return execv(c[0], c);
	}

	return 0;
}

static int
rpc_sys_upgrade_clean(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
	if (unlink("/tmp/firmware.bin"))
		return rpc_errno_status();

	return 0;
}

static int
rpc_sys_factory(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	char * const cmd[4] = { "/sbin/jffs2reset", "-y", "-r", NULL };

	if (!fork()) {
		/* wait for the RPC call to complete */
		sleep(2);
		return execv(cmd[0], cmd);
	}

	return 0;
}

static int
rpc_sys_reboot(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	if (!fork()) {
		sync();
		sleep(2);
		reboot(RB_AUTOBOOT);
		while (1)
			;
	}

	return 0;
}

static int
rpc_sys_api_init(const struct rpc_daemon_ops *o, struct ubus_context *ctx)
{
	static const struct ubus_method sys_methods[] = {
		UBUS_METHOD("packagelist", rpc_sys_packagelist, rpc_packagelist_policy),
		UBUS_METHOD("password_set", rpc_cgi_password_set, rpc_password_policy),
		UBUS_METHOD_NOARG("upgrade_test", rpc_sys_upgrade_test),
		UBUS_METHOD("upgrade_start",      rpc_sys_upgrade_start,
		                                  rpc_upgrade_policy),
		UBUS_METHOD_NOARG("upgrade_clean", rpc_sys_upgrade_clean),
		UBUS_METHOD_NOARG("factory", rpc_sys_factory),
		UBUS_METHOD_NOARG("reboot", rpc_sys_reboot),
	};

	static struct ubus_object_type sys_type =
		UBUS_OBJECT_TYPE("rpcd-plugin-sys", sys_methods);

	static struct ubus_object obj = {
		.name = "rpc-sys",
		.type = &sys_type,
		.methods = sys_methods,
		.n_methods = ARRAY_SIZE(sys_methods),
	};

	ops = o;

	return ubus_add_object(ctx, &obj);
}

struct rpc_plugin rpc_plugin = {
	.init = rpc_sys_api_init
};
