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

#include <sys/types.h>
#include <dirent.h>
#include <libubus.h>
#include <iwinfo.h>
#include <iwinfo/utils.h>

#include <rpcd/plugin.h>


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
rpc_iwinfo_close(void)
{
	iw = NULL;
	ifname = NULL;
	iwinfo_finish();
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
rpc_iwinfo_add_encryption(const char *name, struct iwinfo_crypto_entry *e)
{
	int ciph;
	void *c, *d;

	c = blobmsg_open_table(&buf, name);

	blobmsg_add_u8(&buf, "enabled", e->enabled);

	if (e->enabled)
	{
		if (!e->wpa_version)
		{
			d = blobmsg_open_array(&buf, "wep");

			if (e->auth_algs & IWINFO_AUTH_OPEN)
				blobmsg_add_string(&buf, NULL, "open");

			if (e->auth_algs & IWINFO_AUTH_SHARED)
				blobmsg_add_string(&buf, NULL, "shared");

			blobmsg_close_array(&buf, d);
		}
		else
		{
			d = blobmsg_open_array(&buf, "wpa");

			if (e->wpa_version > 2)
			{
				blobmsg_add_u32(&buf, NULL, 1);
				blobmsg_add_u32(&buf, NULL, 2);
			}
			else
			{
				blobmsg_add_u32(&buf, NULL, e->wpa_version);
			}

			blobmsg_close_array(&buf, d);


			d = blobmsg_open_array(&buf, "authentication");

			if (e->auth_suites & IWINFO_KMGMT_PSK)
				blobmsg_add_string(&buf, NULL, "psk");

			if (e->auth_suites & IWINFO_KMGMT_8021x)
				blobmsg_add_string(&buf, NULL, "802.1x");

			if (!e->auth_suites ||
				(e->auth_suites & IWINFO_KMGMT_NONE))
				blobmsg_add_string(&buf, NULL, "none");

			blobmsg_close_array(&buf, d);
		}

		d = blobmsg_open_array(&buf, "ciphers");
		ciph = e->pair_ciphers | e->group_ciphers;

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

static void
rpc_iwinfo_call_encryption(const char *name)
{
	struct iwinfo_crypto_entry crypto = { 0 };

	if (!iw->encryption(ifname, (char *)&crypto))
		rpc_iwinfo_add_encryption(name, &crypto);
}

static void
rpc_iwinfo_call_hwmodes(const char *name)
{
	int modes;
	void *c;

	if (!iw->hwmodelist(ifname, &modes))
	{
		c = blobmsg_open_array(&buf, name);

		if (modes & IWINFO_80211_A)
			blobmsg_add_string(&buf, NULL, "a");

		if (modes & IWINFO_80211_B)
			blobmsg_add_string(&buf, NULL, "b");

		if (modes & IWINFO_80211_G)
			blobmsg_add_string(&buf, NULL, "g");

		if (modes & IWINFO_80211_N)
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

	rpc_iwinfo_call_str("phy", iw->phyname);

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

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_scan(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	int i, rv, len;
	void *c, *d;
	char mac[18];
	char res[IWINFO_BUFSIZE];
	struct iwinfo_scanlist_entry *e;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "results");

	if (!iw->scanlist(ifname, res, &len) && (len > 0))
	{
		for (i = 0; i < len; i += sizeof(struct iwinfo_scanlist_entry))
		{
			e = (struct iwinfo_scanlist_entry *)&res[i];
			d = blobmsg_open_table(&buf, NULL);

			if (e->ssid[0])
				blobmsg_add_string(&buf, "ssid", (const char *)e->ssid);

			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					 e->mac[0], e->mac[1], e->mac[2],
					 e->mac[3], e->mac[4], e->mac[5]);

			blobmsg_add_string(&buf, "bssid", mac);

			blobmsg_add_string(&buf, "mode", IWINFO_OPMODE_NAMES[e->mode]);

			blobmsg_add_u32(&buf, "channel", e->channel);
			blobmsg_add_u32(&buf, "signal", (uint32_t)(e->signal - 0x100));

			blobmsg_add_u32(&buf, "quality", e->quality);
			blobmsg_add_u32(&buf, "quality_max", e->quality_max);

			rpc_iwinfo_add_encryption("encryption", &e->crypto);

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_assoclist(struct ubus_context *ctx, struct ubus_object *obj,
                     struct ubus_request_data *req, const char *method,
                     struct blob_attr *msg)
{
	int i, rv, len;
	char mac[18];
	char res[IWINFO_BUFSIZE];
	struct iwinfo_assoclist_entry *a;
	void *c, *d, *e;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "results");

	if (!iw->assoclist(ifname, res, &len) && (len > 0))
	{
		for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry))
		{
			a = (struct iwinfo_assoclist_entry *)&res[i];
			d = blobmsg_open_table(&buf, NULL);

			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					 a->mac[0], a->mac[1], a->mac[2],
					 a->mac[3], a->mac[4], a->mac[5]);

			blobmsg_add_string(&buf, "mac", mac);
			blobmsg_add_u32(&buf, "signal", a->signal);
			blobmsg_add_u32(&buf, "noise", a->noise);
			blobmsg_add_u32(&buf, "inactive", a->inactive);

			e = blobmsg_open_table(&buf, "rx");
			blobmsg_add_u32(&buf, "rate", a->rx_rate.rate);
			blobmsg_add_u32(&buf, "mcs", a->rx_rate.mcs);
			blobmsg_add_u8(&buf, "40mhz", a->rx_rate.is_40mhz);
			blobmsg_add_u8(&buf, "short_gi", a->rx_rate.is_short_gi);
			blobmsg_close_table(&buf, e);

			e = blobmsg_open_table(&buf, "tx");
			blobmsg_add_u32(&buf, "rate", a->tx_rate.rate);
			blobmsg_add_u32(&buf, "mcs", a->tx_rate.mcs);
			blobmsg_add_u8(&buf, "40mhz", a->tx_rate.is_40mhz);
			blobmsg_add_u8(&buf, "short_gi", a->tx_rate.is_short_gi);
			blobmsg_close_table(&buf, e);

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_freqlist(struct ubus_context *ctx, struct ubus_object *obj,
                    struct ubus_request_data *req, const char *method,
                    struct blob_attr *msg)
{
	int i, rv, len, ch;
	char res[IWINFO_BUFSIZE];
	struct iwinfo_freqlist_entry *f;
	void *c, *d;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "results");

	if (!iw->freqlist(ifname, res, &len) && (len > 0))
	{
		if (iw->channel(ifname, &ch))
			ch = -1;

		for (i = 0; i < len; i += sizeof(struct iwinfo_freqlist_entry))
		{
			f = (struct iwinfo_freqlist_entry *)&res[i];
			d = blobmsg_open_table(&buf, NULL);

			blobmsg_add_u32(&buf, "channel", f->channel);
			blobmsg_add_u32(&buf, "mhz", f->mhz);
			blobmsg_add_u8(&buf, "restricted", f->restricted);

			if (ch > -1)
				blobmsg_add_u8(&buf, "active", f->channel == ch);

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_txpowerlist(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	int i, rv, len, pwr, off;
	char res[IWINFO_BUFSIZE];
	struct iwinfo_txpwrlist_entry *t;
	void *c, *d;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "results");

	if (!iw->txpwrlist(ifname, res, &len) && (len > 0))
	{
		if (iw->txpower(ifname, &pwr))
			pwr = -1;

		if (iw->txpower_offset(ifname, &off))
			off = 0;

		for (i = 0; i < len; i += sizeof(struct iwinfo_txpwrlist_entry))
		{
			t = (struct iwinfo_txpwrlist_entry *)&res[i];
			d = blobmsg_open_table(&buf, NULL);

			blobmsg_add_u32(&buf, "dbm", t->dbm + off);
			blobmsg_add_u32(&buf, "mw", iwinfo_dbm2mw(t->dbm + off));

			if (pwr > -1)
				blobmsg_add_u8(&buf, "active", t->dbm == pwr);

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static const char *
rpc_iwinfo_lookup_country(char *buf, int len, int iso3166)
{
	int i;
	static char ccode[5];
	struct iwinfo_country_entry *c;

	for (i = 0; i < len; i += sizeof(struct iwinfo_country_entry))
	{
		c = (struct iwinfo_country_entry *)&buf[i];

		if (c->iso3166 == iso3166)
		{
			snprintf(ccode, sizeof(ccode), "%s", c->ccode);
			return ccode;
		}
	}

	return NULL;
}

static int
rpc_iwinfo_countrylist(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	int rv, len;
	char cur[3];
	char iso3166[3];
	char res[IWINFO_BUFSIZE];
	const char *ccode;
	const struct iwinfo_iso3166_label *l;
	void *c, *d;

	rv = rpc_iwinfo_open(msg);

	if (rv)
		return rv;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "results");

	if (!iw->countrylist(ifname, res, &len) && (len > 0))
	{
		if (iw->country(ifname, cur))
			memset(cur, 0, sizeof(cur));

		for (l = IWINFO_ISO3166_NAMES; l->iso3166; l++)
		{
			ccode = rpc_iwinfo_lookup_country(res, len, l->iso3166);

			if (!ccode)
				continue;

			d = blobmsg_open_table(&buf, NULL);

			blobmsg_add_string(&buf, "code", ccode);
			blobmsg_add_string(&buf, "country", (const char *)l->name);

			snprintf(iso3166, sizeof(iso3166), "%c%c",
			         (l->iso3166 / 256), (l->iso3166 % 256));

			blobmsg_add_string(&buf, "iso3166", iso3166);

			if (cur[0])
				blobmsg_add_u8(&buf, "active", !strncmp(ccode, cur, 2));

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_devices(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg)
{
	void *c;
	struct dirent *e;
	DIR *d;

	d = opendir("/sys/class/net");

	if (!d)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&buf, 0);

	c = blobmsg_open_array(&buf, "devices");

	while ((e = readdir(d)) != NULL)
	{
		if (e->d_type != DT_LNK)
			continue;

		if (iwinfo_type(e->d_name))
			blobmsg_add_string(&buf, NULL, e->d_name);
	}

	blobmsg_close_array(&buf, c);

	closedir(d);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}


static int
rpc_iwinfo_api_init(const struct rpc_daemon_ops *o, struct ubus_context *ctx)
{
	static const struct ubus_method iwinfo_methods[] = {
		{ .name = "devices", .handler = rpc_iwinfo_devices },
		UBUS_METHOD("info",        rpc_iwinfo_info,        rpc_device_policy),
		UBUS_METHOD("scan",        rpc_iwinfo_scan,        rpc_device_policy),
		UBUS_METHOD("assoclist",   rpc_iwinfo_assoclist,   rpc_device_policy),
		UBUS_METHOD("freqlist",    rpc_iwinfo_freqlist,    rpc_device_policy),
		UBUS_METHOD("txpowerlist", rpc_iwinfo_txpowerlist, rpc_device_policy),
		UBUS_METHOD("countrylist", rpc_iwinfo_countrylist, rpc_device_policy),
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

struct rpc_plugin rpc_plugin = {
	.init = rpc_iwinfo_api_init
};
