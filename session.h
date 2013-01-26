/*
 * luci-rpcd - LuCI UBUS RPC server
 *
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
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

#ifndef __RPC_SESSION_H
#define __RPC_SESSION_H

#include <libubox/avl.h>
#include <libubox/blobmsg_json.h>

#define RPC_SID_LEN	32
#define RPC_DEFAULT_SESSION_TIMEOUT	300

struct rpc_session {
	struct avl_node avl;
	char id[RPC_SID_LEN + 1];

	struct uloop_timeout t;
	struct avl_tree data;
	struct avl_tree acls;

	int timeout;
};

struct rpc_session_data {
	struct avl_node avl;
	struct blob_attr attr[];
};

struct rpc_session_acl {
	struct avl_node avl;
	const char *object;
	const char *function;
	int sort_len;
};

int rpc_session_api_init(struct ubus_context *ctx);

#endif
