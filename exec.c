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

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <rpcd/exec.h>

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

const char *
rpc_exec_lookup(const char *cmd)
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
rpc_ustream_to_blobmsg(struct blob_buf *blob, struct ustream *s,
                       const char *name)
{
	int len;
	char *rbuf, *wbuf;

	if ((len = ustream_pending_data(s, false)) > 0)
	{
		wbuf = blobmsg_alloc_string_buffer(blob, name, len + 1);

		if (!wbuf)
			return;

		ustream_for_each_read_buffer(s, rbuf, len)
		{
			memcpy(wbuf, rbuf, len);
			wbuf += len;
		}

		*wbuf = 0;
		blobmsg_add_string_buffer(blob);
	}
}

static void
rpc_exec_reply(struct rpc_exec_context *c, int rv)
{
	uloop_timeout_cancel(&c->timeout);
	uloop_process_delete(&c->process);

	if (rv == UBUS_STATUS_OK)
	{
		if (!c->stdout_cb && !c->stderr_cb && !c->finish_cb)
		{
			blobmsg_add_u32(&c->blob, "code", WEXITSTATUS(c->stat));
			rpc_ustream_to_blobmsg(&c->blob, &c->opipe.stream, "stdout");
			rpc_ustream_to_blobmsg(&c->blob, &c->epipe.stream, "stderr");
		}

		if (c->finish_cb)
			rv = c->finish_cb(&c->blob, c->stat, c->priv);

		if (rv == UBUS_STATUS_OK)
			ubus_send_reply(c->context, &c->request, c->blob.head);
	}

	ubus_complete_deferred_request(c->context, &c->request, rv);

	blob_buf_free(&c->blob);

	ustream_free(&c->opipe.stream);
	ustream_free(&c->epipe.stream);

	close(c->opipe.fd.fd);
	close(c->epipe.fd.fd);

	if (c->priv)
		free(c->priv);

	free(c);
}

static void
rpc_exec_timeout_cb(struct uloop_timeout *t)
{
	struct rpc_exec_context *c =
		container_of(t, struct rpc_exec_context, timeout);

	kill(c->process.pid, SIGKILL);
	rpc_exec_reply(c, UBUS_STATUS_TIMEOUT);
}

static void
rpc_exec_process_cb(struct uloop_process *p, int stat)
{
	struct rpc_exec_context *c =
		container_of(p, struct rpc_exec_context, process);

	c->stat = stat;

	ustream_poll(&c->opipe.stream);
	ustream_poll(&c->epipe.stream);
}

static void
rpc_exec_ipipe_write_cb(struct ustream *s, int bytes)
{
	struct rpc_exec_context *c =
		container_of(s, struct rpc_exec_context, ipipe.stream);

	if (c->stdin_cb(s, c->priv) <= 0)
	{
		ustream_free(&c->ipipe.stream);
		close(c->ipipe.fd.fd);
	}
}

static void
rpc_exec_opipe_read_cb(struct ustream *s, int bytes)
{
	int len, rv;
	char *buf;
	struct rpc_exec_context *c =
		container_of(s, struct rpc_exec_context, opipe.stream);

	if (c->stdout_cb)
	{
		do {
			buf = ustream_get_read_buf(s, &len);

			if (!buf || !len)
				break;

			rv = c->stdout_cb(&c->blob, buf, len, c->priv);

			if (rv <= 0)
				break;

			ustream_consume(s, rv);
		} while(1);
	}
	else if (ustream_read_buf_full(s))
	{
		rpc_exec_reply(c, UBUS_STATUS_NOT_SUPPORTED);
	}
}

static void
rpc_exec_epipe_read_cb(struct ustream *s, int bytes)
{
	int len, rv;
	char *buf;
	struct rpc_exec_context *c =
		container_of(s, struct rpc_exec_context, epipe.stream);

	if (c->stderr_cb)
	{
		do {
			buf = ustream_get_read_buf(s, &len);

			if (!buf || !len)
				break;

			rv = c->stderr_cb(&c->blob, buf, len, c->priv);

			if (rv <= 0)
				break;

			ustream_consume(s, rv);
		} while(1);
	}
	else if (ustream_read_buf_full(s))
	{
		rpc_exec_reply(c, UBUS_STATUS_NOT_SUPPORTED);
	}
}

static void
rpc_exec_opipe_state_cb(struct ustream *s)
{
	struct rpc_exec_context *c =
		container_of(s, struct rpc_exec_context, opipe.stream);

	if (c->opipe.stream.eof && c->epipe.stream.eof)
		rpc_exec_reply(c, UBUS_STATUS_OK);
}

static void
rpc_exec_epipe_state_cb(struct ustream *s)
{
	struct rpc_exec_context *c =
		container_of(s, struct rpc_exec_context, epipe.stream);

	if (c->opipe.stream.eof && c->epipe.stream.eof)
		rpc_exec_reply(c, UBUS_STATUS_OK);
}

int
rpc_exec(const char **args, rpc_exec_write_cb_t in,
         rpc_exec_read_cb_t out, rpc_exec_read_cb_t err,
         rpc_exec_done_cb_t end, void *priv, struct ubus_context *ctx,
         struct ubus_request_data *req)
{
	pid_t pid;

	int ipipe[2];
	int opipe[2];
	int epipe[2];

	const char *cmd;
	struct rpc_exec_context *c;

	cmd = rpc_exec_lookup(args[0]);

	if (!cmd)
		return UBUS_STATUS_NOT_FOUND;

	c = malloc(sizeof(*c));

	if (!c)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (pipe(ipipe))
		goto fail_ipipe;

	if (pipe(opipe))
		goto fail_opipe;

	if (pipe(epipe))
		goto fail_epipe;

	switch ((pid = fork()))
	{
	case -1:
		return rpc_errno_status();

	case 0:
		uloop_done();

		dup2(ipipe[0], 0);
		dup2(opipe[1], 1);
		dup2(epipe[1], 2);

		close(ipipe[0]);
		close(ipipe[1]);
		close(opipe[0]);
		close(opipe[1]);
		close(epipe[0]);
		close(epipe[1]);

		if (execv(cmd, (char * const *)args))
			return rpc_errno_status();

	default:
		memset(c, 0, sizeof(*c));
		blob_buf_init(&c->blob, 0);

		c->stdin_cb  = in;
		c->stdout_cb = out;
		c->stderr_cb = err;
		c->finish_cb = end;
		c->priv      = priv;

		ustream_declare_read(c->opipe, opipe[0], opipe);
		ustream_declare_read(c->epipe, epipe[0], epipe);

		c->process.pid = pid;
		c->process.cb = rpc_exec_process_cb;
		uloop_process_add(&c->process);

		c->timeout.cb = rpc_exec_timeout_cb;
		uloop_timeout_set(&c->timeout, RPC_EXEC_MAX_RUNTIME);

		if (c->stdin_cb)
		{
			ustream_declare_write(c->ipipe, ipipe[1], ipipe);
			rpc_exec_ipipe_write_cb(&c->ipipe.stream, 0);
		}
		else
		{
			close(ipipe[1]);
		}

		close(ipipe[0]);
		close(opipe[1]);
		close(epipe[1]);

		c->context = ctx;
		ubus_defer_request(ctx, req, &c->request);
	}

	return UBUS_STATUS_OK;

fail_epipe:
	close(opipe[0]);
	close(opipe[1]);

fail_opipe:
	close(ipipe[0]);
	close(ipipe[1]);

fail_ipipe:
	return rpc_errno_status();
}
