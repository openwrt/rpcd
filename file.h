/*
 * rpcd - UBUS RPC server
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

#ifndef __RPC_FILE_H
#define __RPC_FILE_H

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
#include <libubox/ustream.h>

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

#endif
