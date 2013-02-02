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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "iwinfo.h"

static struct blob_buf buf;
static const struct iwinfo_ops *iw;
static const char *ifname;

enum {
	RPC_D_DEVICE,
	__RPC_D_MAX,
};

static const struct blobmsg_policy rpc_device_policy[__RPC_D_MAX] = {
	[RPC_D_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
};


static int
rpc_iwinfo_open(struct blob_attr *msg)
{
	static struct blob_attr *tb[__RPC_D_MAX];

	blobmsg_parse(rpc_device_policy, __RPC_D_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_D_DEVICE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ifname = blobmsg_data(tb[RPC_D_DEVICE]);
	iw = iwinfo_backend(ifname);

	return iw ? UBUS_STATUS_OK : UBUS_STATUS_NOT_FOUND;
}

static void
rpc_iwinfo_call_int(const char *name, int (*func)(const char *, int *),
                    const char **map)
{
	int rv;

	if (!func(ifname, &rv))
	{
		if (!map)
			blobmsg_add_u32(&buf, name, rv);
		else
			blobmsg_add_string(&buf, name, map[rv]);
	}
}

static void
rpc_iwinfo_call_hardware_id(const char *name)
{
	struct iwinfo_hardware_id ids;
	void *c;

	if (!iw->hardware_id(ifname, (char *)&ids))
	{
		c = blobmsg_open_array(&buf, name);

		blobmsg_add_u32(&buf, NULL, ids.vendor_id);
		blobmsg_add_u32(&buf, NULL, ids.device_id);
		blobmsg_add_u32(&buf, NULL, ids.subsystem_vendor_id);
		blobmsg_add_u32(&buf, NULL, ids.subsystem_device_id);

		blobmsg_close_array(&buf, c);
	}
}

static void
rpc_iwinfo_call_encryption(const char *name)
{
	struct iwinfo_crypto_entry crypto = { 0 };
	void *c, *d;
	int ciph;

	if (!iw->encryption(ifname, (char *)&crypto))
	{
		c = blobmsg_open_table(&buf, name);

		blobmsg_add_u8(&buf, "enabled", crypto.enabled);

		if (crypto.enabled)
		{
			if (!crypto.wpa_version)
			{
				d = blobmsg_open_array(&buf, "wep");

				if (crypto.auth_algs & IWINFO_AUTH_OPEN)
					blobmsg_add_string(&buf, NULL, "open");

				if (crypto.auth_algs & IWINFO_AUTH_SHARED)
					blobmsg_add_string(&buf, NULL, "shared");

				blobmsg_close_array(&buf, d);
			}
			else
			{
				d = blobmsg_open_array(&buf, "wpa");

				if (crypto.wpa_version > 2)
				{
					blobmsg_add_u32(&buf, NULL, 1);
					blobmsg_add_u32(&buf, NULL, 2);
				}
				else
				{
					blobmsg_add_u32(&buf, NULL, crypto.wpa_version);
				}

				blobmsg_close_array(&buf, d);


				d = blobmsg_open_array(&buf, "authentication");

				if (crypto.auth_suites & IWINFO_KMGMT_PSK)
					blobmsg_add_string(&buf, NULL, "psk");

				if (crypto.auth_suites & IWINFO_KMGMT_8021x)
					blobmsg_add_string(&buf, NULL, "802.1x");

				if (!crypto.auth_suites ||
				    (crypto.auth_suites & IWINFO_KMGMT_NONE))
					blobmsg_add_string(&buf, NULL, "none");

				blobmsg_close_array(&buf, d);
			}

			d = blobmsg_open_array(&buf, "ciphers");
			ciph = crypto.pair_ciphers | crypto.group_ciphers;

			if (ciph & IWINFO_CIPHER_WEP40)
				blobmsg_add_string(&buf, NULL, "wep-40");

			if (ciph & IWINFO_CIPHER_WEP104)
				blobmsg_add_string(&buf, NULL, "wep-104");

			if (ciph & IWINFO_CIPHER_TKIP)
				blobmsg_add_string(&buf, NULL, "tkip");

			if (ciph & IWINFO_CIPHER_CCMP)
				blobmsg_add_string(&buf, NULL, "ccmp");

			if (ciph & IWINFO_CIPHER_WRAP)
				blobmsg_add_string(&buf, NULL, "wrap");

			if (ciph & IWINFO_CIPHER_AESOCB)
				blobmsg_add_string(&buf, NULL, "aes-ocb");

			if (ciph & IWINFO_CIPHER_CKIP)
				blobmsg_add_string(&buf, NULL, "ckip");

			if (!ciph || (ciph & IWINFO_CIPHER_NONE))
				blobmsg_add_string(&buf, NULL, "none");

			blobmsg_close_array(&buf, d);
		}

		blobmsg_close_table(&buf, c);
	}
}

static void
rpc_iwinfo_call_hwmodes(const char *name)
{
	int modes;
	void *c;

	if (!iw->hwmodelist(ifname, &modes))
	{
		c = blobmsg_open_array(&buf, name);

		if (modes & IWINFO_80211_A);
			blobmsg_add_string(&buf, NULL, "a");

		if (modes & IWINFO_80211_B);
			blobmsg_add_string(&buf, NULL, "b");

		if (modes & IWINFO_80211_G);
			blobmsg_add_string(&buf, NULL, "g");

		if (modes & IWINFO_80211_N);
			blobmsg_add_string(&buf, NULL, "n");

		blobmsg_close_array(&buf, c);
	}
}

static void
rpc_iwinfo_call_str(const char *name, int (*func)(const char *, char *))
{
	char rv[IWINFO_BUFSIZE] = { 0 };

	if (!func(ifname, rv))
		blobmsg_add_string(&buf, name, rv);
}

static int
rpc_iwinfo_info(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	int rv;
	void *c;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	rpc_iwinfo_call_str("ssid", iw->ssid);
	rpc_iwinfo_call_str("bssid", iw->bssid);
	rpc_iwinfo_call_str("country", iw->country);

	rpc_iwinfo_call_int("mode", iw->mode, IWINFO_OPMODE_NAMES);
	rpc_iwinfo_call_int("channel", iw->channel, NULL);

	rpc_iwinfo_call_int("frequency", iw->frequency, NULL);
	rpc_iwinfo_call_int("frequency_offset", iw->frequency_offset, NULL);

	rpc_iwinfo_call_int("txpower", iw->txpower, NULL);
	rpc_iwinfo_call_int("txpower_offset", iw->txpower_offset, NULL);

	rpc_iwinfo_call_int("quality", iw->quality, NULL);
	rpc_iwinfo_call_int("quality_max", iw->quality_max, NULL);

	rpc_iwinfo_call_int("signal", iw->signal, NULL);
	rpc_iwinfo_call_int("noise", iw->noise, NULL);

	rpc_iwinfo_call_int("bitrate", iw->bitrate, NULL);

	rpc_iwinfo_call_encryption("encryption");
	rpc_iwinfo_call_hwmodes("hwmodes");

	c = blobmsg_open_table(&buf, "hardware");
	rpc_iwinfo_call_hardware_id("id");
	rpc_iwinfo_call_str("name", iw->hardware_name);
	blobmsg_close_table(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	iw->close();

	return UBUS_STATUS_OK;
}


int rpc_iwinfo_api_init(struct ubus_context *ctx)
{
	static const struct ubus_method iwinfo_methods[] = {
		UBUS_METHOD("info",    rpc_iwinfo_info,  rpc_device_policy),
	};

	static struct ubus_object_type iwinfo_type =
		UBUS_OBJECT_TYPE("luci-rpc-iwinfo", iwinfo_methods);

	static struct ubus_object obj = {
		.name = "iwinfo",
		.type = &iwinfo_type,
		.methods = iwinfo_methods,
		.n_methods = ARRAY_SIZE(iwinfo_methods),
	};

	return ubus_add_object(ctx, &obj);
}
