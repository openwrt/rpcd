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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include "system.h"

static struct blob_buf buf;

static int
rpc_system_board(struct ubus_context *ctx, struct ubus_object *obj,
                 struct ubus_request_data *req, const char *method,
                 struct blob_attr *msg)
{
	void *c;
	char line[256];
	char *key, *val;
	struct utsname utsname;
	FILE *f;

	blob_buf_init(&buf, 0);

	if (uname(&utsname) >= 0)
	{
		blobmsg_add_string(&buf, "kernel", utsname.release);
		blobmsg_add_string(&buf, "hostname", utsname.nodename);
	}

	if ((f = fopen("/proc/cpuinfo", "r")) != NULL)
	{
		while(fgets(line, sizeof(line), f))
		{
			key = strtok(line, "\t:");
			val = strtok(NULL, "\t\n");

			if (!key || !val)
				continue;

			if (!strcasecmp(key, "system type") ||
			    !strcasecmp(key, "processor") ||
			    !strcasecmp(key, "model name"))
			{
				blobmsg_add_string(&buf, "system", val + 2);
				break;
			}
		}

		fclose(f);
	}

	if ((f = fopen("/tmp/sysinfo/model", "r")) != NULL)
	{
		if (fgets(line, sizeof(line), f))
		{
			val = strtok(line, "\t\n");

			if (val)
				blobmsg_add_string(&buf, "model", val);
		}

		fclose(f);
	}
	else if ((f = fopen("/proc/cpuinfo", "r")) != NULL)
	{
		while(fgets(line, sizeof(line), f))
		{
			key = strtok(line, "\t:");
			val = strtok(NULL, "\t\n");

			if (!key || !val)
				continue;

			if (!strcasecmp(key, "machine") ||
			    !strcasecmp(key, "hardware"))
			{
				blobmsg_add_string(&buf, "model", val + 2);
				break;
			}
		}

		fclose(f);
	}

	if ((f = fopen("/etc/openwrt_release", "r")) != NULL)
	{
		c = blobmsg_open_table(&buf, "release");

		while (fgets(line, sizeof(line), f))
		{
			key = strtok(line, "=\"");
			val = strtok(NULL, "\"\n");

			if (!key || !val)
				continue;

			if (!strcasecmp(key, "DISTRIB_ID"))
				blobmsg_add_string(&buf, "distribution", val);
			else if (!strcasecmp(key, "DISTRIB_RELEASE"))
				blobmsg_add_string(&buf, "version", val);
			else if (!strcasecmp(key, "DISTRIB_REVISION"))
				blobmsg_add_string(&buf, "revision", val);
			else if (!strcasecmp(key, "DISTRIB_CODENAME"))
				blobmsg_add_string(&buf, "codename", val);
			else if (!strcasecmp(key, "DISTRIB_TARGET"))
				blobmsg_add_string(&buf, "target", val);
			else if (!strcasecmp(key, "DISTRIB_DESCRIPTION"))
				blobmsg_add_string(&buf, "description", val);
		}

		blobmsg_close_array(&buf, c);

		fclose(f);
	}

	ubus_send_reply(ctx, req, buf.head);

	return UBUS_STATUS_OK;
}

static int
rpc_system_info(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	void *c;
	time_t now;
	struct tm *tm;
	struct sysinfo info;

	now = time(NULL);

	if (!(tm = localtime(&now)))
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (sysinfo(&info))
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&buf, 0);

	blobmsg_add_u32(&buf, "uptime",    info.uptime);
	blobmsg_add_u32(&buf, "localtime", mktime(tm));

	c = blobmsg_open_array(&buf, "load");
	blobmsg_add_u32(&buf, NULL, info.loads[0]);
	blobmsg_add_u32(&buf, NULL, info.loads[1]);
	blobmsg_add_u32(&buf, NULL, info.loads[2]);
	blobmsg_close_array(&buf, c);

	c = blobmsg_open_table(&buf, "memory");
	blobmsg_add_u32(&buf, "total",    info.mem_unit * info.totalram);
	blobmsg_add_u32(&buf, "free",     info.mem_unit * info.freeram);
	blobmsg_add_u32(&buf, "shared",   info.mem_unit * info.sharedram);
	blobmsg_add_u32(&buf, "buffered", info.mem_unit * info.bufferram);
	blobmsg_close_table(&buf, c);

	c = blobmsg_open_table(&buf, "swap");
	blobmsg_add_u32(&buf, "total",    info.mem_unit * info.totalswap);
	blobmsg_add_u32(&buf, "free",     info.mem_unit * info.freeswap);
	blobmsg_close_table(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	return UBUS_STATUS_OK;
}

int rpc_system_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method system_methods[] = {
		UBUS_METHOD_NOARG("board", rpc_system_board),
		UBUS_METHOD_NOARG("info",  rpc_system_info),
	};

	static struct ubus_object_type system_type =
		UBUS_OBJECT_TYPE("luci-rpc-system", system_methods);

	static struct ubus_object obj = {
		.name = "system",
		.type = &system_type,
		.methods = system_methods,
		.n_methods = ARRAY_SIZE(system_methods),
	};

	return ubus_add_object(ctx, &obj);
}
