/*
 * rpcd - UBUS RPC server
 *
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
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

#include <unistd.h>

#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <signal.h>
#include <sys/stat.h>

#include <rpcd/session.h>
#include <rpcd/uci.h>
#include <rpcd/plugin.h>
#include <rpcd/exec.h>

static struct ubus_context *ctx;
static bool respawn = false;

static void
handle_signal(int sig)
{
	rpc_session_freeze();
	uloop_cancelled = true;
	respawn = (sig == SIGHUP);
}

static void
exec_self(int argc, char **argv)
{
	int i;
	const char *cmd = rpc_exec_lookup(argv[0]);
	char **args = calloc(argc + 1, sizeof(char *));

	if (!cmd || !args)
		return;

	for (i = 0; i < argc; i++)
		args[i] = argv[i];

	setenv("RPC_HANGUP", "1", 1);
	execv(cmd, (char * const *)args);
}

int main(int argc, char **argv)
{
	struct stat s;
	const char *hangup;
	const char *ubus_socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		default:
			break;
		}
	}

	if (stat("/var/run/rpcd", &s))
		mkdir("/var/run/rpcd", 0700);

	umask(0077);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP,  handle_signal);
	signal(SIGUSR1, handle_signal);

	uloop_init();

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ctx);

	rpc_session_api_init(ctx);
	rpc_uci_api_init(ctx);
	rpc_plugin_api_init(ctx);

	hangup = getenv("RPC_HANGUP");

	if (!hangup || strcmp(hangup, "1"))
		rpc_uci_purge_savedirs();
	else
		rpc_session_thaw();

	uloop_run();
	ubus_free(ctx);
	uloop_done();

	if (respawn)
		exec_self(argc, argv);

	return 0;
}
