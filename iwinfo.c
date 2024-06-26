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
#include <ctype.h>
#include <dirent.h>
#include <libubus.h>
#include <iwinfo.h>
#include <iwinfo/utils.h>
#include <net/ethernet.h>

#ifdef linux
#include <netinet/ether.h>
#endif

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

enum {
	RPC_A_DEVICE,
	RPC_A_MACADDR,
	__RPC_A_MAX,
};

static const struct blobmsg_policy rpc_assoclist_policy[__RPC_A_MAX] = {
	[RPC_A_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
	[RPC_A_MACADDR] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_U_SECTION,
	__RPC_U_MAX
};

static const struct blobmsg_policy rpc_uci_policy[__RPC_U_MAX] = {
	[RPC_U_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
};

static int
__rpc_iwinfo_open(struct blob_attr *device)
{
	if (!device)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ifname = blobmsg_data(device);
	iw = iwinfo_backend(ifname);

	return iw ? UBUS_STATUS_OK : UBUS_STATUS_NOT_FOUND;
}

static int
rpc_iwinfo_open(struct blob_attr *msg)
{
	static struct blob_attr *tb[__RPC_D_MAX];

	blobmsg_parse(rpc_device_policy, __RPC_D_MAX, tb,
	              blob_data(msg), blob_len(msg));

	return __rpc_iwinfo_open(tb[RPC_D_DEVICE]);
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
                    const char * const *map)
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
rpc_iwinfo_lower(const char *src, char *dst, size_t len)
{
	size_t i;

	for (i = 0; *src && i < len; i++)
		*dst++ = tolower(*src++);

	*dst = 0;
}

static void
rpc_iwinfo_add_bit_array(const char *name, uint32_t bits,
                         const char * const values[], size_t len,
                         bool lower, uint32_t zero)
{
	void *c;
	size_t i;
	char l[128];
	const char *v;

	if (!bits)
		bits = zero;

	c = blobmsg_open_array(&buf, name);

	for (i = 0; i < len; i++)
		if (bits & 1 << i)
		{
			v = values[i];

			if (lower)
			{
				rpc_iwinfo_lower(v, l, strlen(values[i]));
				v = l;
			}

			blobmsg_add_string(&buf, NULL, v);
		}

	blobmsg_close_array(&buf, c);
}

static void
rpc_iwinfo_add_encryption(const char *name, struct iwinfo_crypto_entry *e)
{
	int wpa_version;
	void *c, *d;

	c = blobmsg_open_table(&buf, name);

	blobmsg_add_u8(&buf, "enabled", e->enabled);

	if (e->enabled)
	{
		if (!e->wpa_version)
		{
			rpc_iwinfo_add_bit_array("wep", e->auth_algs,
						IWINFO_AUTH_NAMES,
						IWINFO_AUTH_COUNT,
						true, 0);
		}
		else
		{
			d = blobmsg_open_array(&buf, "wpa");

			for (wpa_version = 1; wpa_version <= 3; wpa_version++)
				if (e->wpa_version & (1 << (wpa_version - 1)))
					blobmsg_add_u32(&buf, NULL, wpa_version);

			blobmsg_close_array(&buf, d);

			rpc_iwinfo_add_bit_array("authentication",
						e->auth_suites,
						IWINFO_KMGMT_NAMES,
						IWINFO_KMGMT_COUNT,
						true, IWINFO_KMGMT_NONE);
		}


		rpc_iwinfo_add_bit_array("ciphers",
					e->pair_ciphers | e->group_ciphers,
					IWINFO_CIPHER_NAMES,
					IWINFO_CIPHER_COUNT,
					true, IWINFO_CIPHER_NONE);
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
rpc_iwinfo_call_htmodes(const char *name)
{
	int modes;

	if (iw->htmodelist(ifname, &modes))
		return;

	rpc_iwinfo_add_bit_array(name, modes & ~IWINFO_HTMODE_NOHT,
				IWINFO_HTMODE_NAMES, IWINFO_HTMODE_COUNT,
				false, 0);
}

static int
rpc_iwinfo_call_hwmodes(const char *name)
{
	int modes;

	if (iw->hwmodelist(ifname, &modes))
		return -1;

	rpc_iwinfo_add_bit_array(name, modes,
				IWINFO_80211_NAMES, IWINFO_80211_COUNT,
				false, 0);

	return modes;
}

static void rpc_iwinfo_call_hw_ht_mode(int hwmodelist)
{
	char text[32];
	const char *hwmode_str;
	const char *htmode_str;
	int htmode;

	if (iwinfo_format_hwmodes(hwmodelist, text, sizeof(text)) > 0)
		blobmsg_add_string(&buf, "hwmodes_text", text);

	if (hwmodelist == IWINFO_80211_AD)
	{
		blobmsg_add_string(&buf, "hwmode", "ad");
		return;
	}

	if (iw->htmode(ifname, &htmode))
		return;

	htmode_str = iwinfo_htmode_name(htmode);
	if (htmode_str)
	{
		if (iwinfo_htmode_is_ht(htmode))
			hwmode_str = "n";
		else if (iwinfo_htmode_is_vht(htmode))
			hwmode_str = "ac";
		else if (iwinfo_htmode_is_he(htmode))
			hwmode_str = "ax";
		else if (iwinfo_htmode_is_eht(htmode))
			hwmode_str = "be";
		else {
			if (hwmodelist & IWINFO_80211_N)
				hwmode_str = "n";
			else if (hwmodelist & IWINFO_80211_G)
				hwmode_str = "g";
			else if (hwmodelist & IWINFO_80211_B)
				hwmode_str = "b";
			else if (hwmodelist & IWINFO_80211_A)
				hwmode_str = "a";
			else
				hwmode_str = "unknown";
		}
	} else
		htmode_str = hwmode_str = "unknown";

	blobmsg_add_string(&buf, "hwmode", hwmode_str);
	blobmsg_add_string(&buf, "htmode", htmode_str);
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
	int rv, hwmodes;
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
	rpc_iwinfo_call_int("center_chan1", iw->center_chan1, NULL);
	rpc_iwinfo_call_int("center_chan2", iw->center_chan2, NULL);

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
	rpc_iwinfo_call_htmodes("htmodes");
	hwmodes = rpc_iwinfo_call_hwmodes("hwmodes");

	if (hwmodes > 0)
		rpc_iwinfo_call_hw_ht_mode(hwmodes);

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
	int i, rv, len, band;
	void *c, *d, *t;
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

			band = iwinfo_band2ghz(e->band);
			if (band > 0)
				blobmsg_add_u32(&buf, "band", band);
			blobmsg_add_u32(&buf, "channel", e->channel);
			blobmsg_add_u32(&buf, "mhz", e->mhz);
			blobmsg_add_u32(&buf, "signal", (uint32_t)(e->signal - 0x100));

			blobmsg_add_u32(&buf, "quality", e->quality);
			blobmsg_add_u32(&buf, "quality_max", e->quality_max);

			if (e->ht_chan_info.primary_chan) {
				t = blobmsg_open_table(&buf, "ht_operation");
				blobmsg_add_u32(&buf, "primary_channel", e->ht_chan_info.primary_chan);
				blobmsg_add_string(&buf, "secondary_channel_offset", ht_secondary_offset[e->ht_chan_info.secondary_chan_off]);
				blobmsg_add_u32(&buf, "channel_width", ht_chan_width[e->ht_chan_info.chan_width]);
				blobmsg_close_table(&buf, t);
			}

			if (e->vht_chan_info.center_chan_1) {
				t = blobmsg_open_table(&buf, "vht_operation");
				blobmsg_add_u32(&buf, "channel_width", vht_chan_width[e->vht_chan_info.chan_width]);
				blobmsg_add_u32(&buf, "center_freq_1", e->vht_chan_info.center_chan_1);
				blobmsg_add_u32(&buf, "center_freq_2", e->vht_chan_info.center_chan_2);
				blobmsg_close_table(&buf, t);
			}

			rpc_iwinfo_add_encryption("encryption", &e->crypto);

			blobmsg_close_table(&buf, d);
		}
	}

	blobmsg_close_array(&buf, c);

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static void
rpc_iwinfo_add_rateinfo(struct iwinfo_rate_entry *r)
{
	blobmsg_add_u8(&buf, "ht", r->is_ht);
	blobmsg_add_u8(&buf, "vht", r->is_vht);
	blobmsg_add_u8(&buf, "he", r->is_he);
	blobmsg_add_u8(&buf, "eht", r->is_eht);
	blobmsg_add_u32(&buf, "mhz", r->mhz_hi * 256 + r->mhz);
	blobmsg_add_u32(&buf, "rate", r->rate);

	if (r->is_ht) {
		blobmsg_add_u32(&buf, "mcs", r->mcs);
		blobmsg_add_u8(&buf, "40mhz", r->is_40mhz);
		blobmsg_add_u8(&buf, "short_gi", r->is_short_gi);
	}
	else if (r->is_vht) {
		blobmsg_add_u32(&buf, "mcs", r->mcs);
		blobmsg_add_u32(&buf, "nss", r->nss);
		blobmsg_add_u8(&buf, "short_gi", r->is_short_gi);
	}
	else if (r->is_he) {
		blobmsg_add_u32(&buf, "mcs", r->mcs);
		blobmsg_add_u32(&buf, "nss", r->nss);
		blobmsg_add_u32(&buf, "he_gi", r->he_gi);
		blobmsg_add_u32(&buf, "he_dcm", r->he_dcm);
	}
	else if (r->is_eht) {
		blobmsg_add_u32(&buf, "mcs", r->mcs);
		blobmsg_add_u32(&buf, "nss", r->nss);
		blobmsg_add_u32(&buf, "eht_gi", r->eht_gi);
	}
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
	struct ether_addr *macaddr = NULL;
	void *c = NULL, *d, *e;
	struct blob_attr *tb[__RPC_A_MAX];
	bool found = false;

	blobmsg_parse(rpc_assoclist_policy, __RPC_A_MAX, tb,
	              blob_data(msg), blob_len(msg));

	rv = __rpc_iwinfo_open(tb[RPC_A_DEVICE]);
	if (rv)
		return rv;

	if (tb[RPC_A_MACADDR])
		macaddr = ether_aton(blobmsg_data(tb[RPC_A_MACADDR]));

	blob_buf_init(&buf, 0);

	if (!macaddr)
		c = blobmsg_open_array(&buf, "results");

	if (!iw->assoclist(ifname, res, &len) && (len > 0))
	{
		for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry))
		{
			a = (struct iwinfo_assoclist_entry *)&res[i];

			if (!macaddr)
				d = blobmsg_open_table(&buf, NULL);
			else if (memcmp(macaddr, a->mac, ETH_ALEN) != 0)
				continue;

			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					 a->mac[0], a->mac[1], a->mac[2],
					 a->mac[3], a->mac[4], a->mac[5]);

			blobmsg_add_string(&buf, "mac", mac);
			blobmsg_add_u32(&buf, "signal", a->signal);
			blobmsg_add_u32(&buf, "signal_avg", a->signal_avg);
			blobmsg_add_u32(&buf, "noise", a->noise);
			blobmsg_add_u32(&buf, "inactive", a->inactive);
			blobmsg_add_u32(&buf, "connected_time", a->connected_time);
			blobmsg_add_u32(&buf, "thr", a->thr);
			blobmsg_add_u8(&buf, "authorized", a->is_authorized);
			blobmsg_add_u8(&buf, "authenticated", a->is_authenticated);
			blobmsg_add_string(&buf, "preamble", a->is_preamble_short ? "short" : "long");
			blobmsg_add_u8(&buf, "wme", a->is_wme);
			blobmsg_add_u8(&buf, "mfp", a->is_mfp);
			blobmsg_add_u8(&buf, "tdls", a->is_tdls);

			blobmsg_add_u16(&buf, "mesh llid", a->llid);
			blobmsg_add_u16(&buf, "mesh plid", a->plid);
			blobmsg_add_string(&buf, "mesh plink", a->plink_state);
			blobmsg_add_string(&buf, "mesh local PS", a->local_ps);
			blobmsg_add_string(&buf, "mesh peer PS", a->peer_ps);
			blobmsg_add_string(&buf, "mesh non-peer PS", a->nonpeer_ps);

			e = blobmsg_open_table(&buf, "rx");
			blobmsg_add_u64(&buf, "drop_misc", a->rx_drop_misc);
			blobmsg_add_u32(&buf, "packets", a->rx_packets);
			blobmsg_add_u64(&buf, "bytes", a->rx_bytes);
			rpc_iwinfo_add_rateinfo(&a->rx_rate);
			blobmsg_close_table(&buf, e);

			e = blobmsg_open_table(&buf, "tx");
			blobmsg_add_u32(&buf, "failed", a->tx_failed);
			blobmsg_add_u32(&buf, "retries", a->tx_retries);
			blobmsg_add_u32(&buf, "packets", a->tx_packets);
			blobmsg_add_u64(&buf, "bytes", a->tx_bytes);
			rpc_iwinfo_add_rateinfo(&a->tx_rate);
			blobmsg_close_table(&buf, e);

			found = true;
			if (!macaddr)
				blobmsg_close_table(&buf, d);
			else
				break;
		}
	}

	if (!macaddr)
		blobmsg_close_array(&buf, c);
	else if (!found)
		return UBUS_STATUS_NOT_FOUND;

	ubus_send_reply(ctx, req, buf.head);

	rpc_iwinfo_close();

	return UBUS_STATUS_OK;
}

static int
rpc_iwinfo_survey(struct ubus_context *ctx, struct ubus_object *obj,
                    struct ubus_request_data *req, const char *method,
                    struct blob_attr *msg)
{
	char res[IWINFO_BUFSIZE];
	struct iwinfo_survey_entry *e;
	void *c, *d;
	int i, rv, len;

	blob_buf_init(&buf, 0);

	rv = rpc_iwinfo_open(msg);

	c = blobmsg_open_array(&buf, "results");

	if (rv || iw->survey(ifname, res, &len) || len < 0)
		return UBUS_STATUS_OK;

	for (i = 0; i < len; i += sizeof(struct iwinfo_survey_entry)) {
		e = (struct iwinfo_survey_entry *)&res[i];

		d = blobmsg_open_table(&buf, NULL);
		blobmsg_add_u32(&buf, "mhz", e->mhz);
		blobmsg_add_u32(&buf, "noise", e->noise);
		blobmsg_add_u64(&buf, "active_time", e->active_time);
		blobmsg_add_u64(&buf, "busy_time", e->busy_time);
		blobmsg_add_u64(&buf, "busy_time_ext", e->busy_time_ext);
		blobmsg_add_u64(&buf, "rx_time", e->rxtime);
		blobmsg_add_u64(&buf, "tx_time", e->txtime);
		blobmsg_close_table(&buf, d);
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
	int i, rv, len, ch, band;
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

			band = iwinfo_band2ghz(f->band);
			if (band > 0)
				blobmsg_add_u32(&buf, "band", band);
			blobmsg_add_u32(&buf, "channel", f->channel);
			blobmsg_add_u32(&buf, "mhz", f->mhz);
			blobmsg_add_u8(&buf, "restricted", f->restricted);

			rpc_iwinfo_add_bit_array("flags", f->flags,
						IWINFO_FREQ_FLAG_NAMES,
						IWINFO_FREQ_FLAG_COUNT,
						true, 0);

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
	char res[IWINFO_BUFSIZE] = {0};
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
rpc_iwinfo_phyname(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg)
{
	int i;
	bool found = false;
	char res[IWINFO_BUFSIZE];
	const struct iwinfo_ops *ops;
	struct blob_attr *tb[__RPC_U_MAX];
	const char *backends[] = {
		"nl80211",
		"madwifi",
		"wl"
	};

	blobmsg_parse(rpc_uci_policy, __RPC_U_MAX, tb,
	              blob_data(msg), blob_len(msg));

	if (!tb[RPC_U_SECTION])
		return UBUS_STATUS_INVALID_ARGUMENT;

	for (i = 0; i < ARRAY_SIZE(backends); i++)
	{
		ops = iwinfo_backend_by_name(backends[i]);

		if (!ops || !ops->lookup_phy)
			continue;

		if (!ops->lookup_phy(blobmsg_get_string(tb[RPC_U_SECTION]), res))
		{
			found = true;
			break;
		}
	}

	if (found)
	{
		blob_buf_init(&buf, 0);
		blobmsg_add_string(&buf, "phyname", res);

		ubus_send_reply(ctx, req, buf.head);
	}

	rpc_iwinfo_close();

	return found ? UBUS_STATUS_OK : UBUS_STATUS_NOT_FOUND;
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
		UBUS_METHOD_NOARG("devices", rpc_iwinfo_devices),
		UBUS_METHOD("info",        rpc_iwinfo_info,        rpc_device_policy),
		UBUS_METHOD("scan",        rpc_iwinfo_scan,        rpc_device_policy),
		UBUS_METHOD("assoclist",   rpc_iwinfo_assoclist,   rpc_assoclist_policy),
		UBUS_METHOD("freqlist",    rpc_iwinfo_freqlist,    rpc_device_policy),
		UBUS_METHOD("txpowerlist", rpc_iwinfo_txpowerlist, rpc_device_policy),
		UBUS_METHOD("countrylist", rpc_iwinfo_countrylist, rpc_device_policy),
		UBUS_METHOD("survey",      rpc_iwinfo_survey,      rpc_device_policy),
		UBUS_METHOD("phyname",     rpc_iwinfo_phyname,     rpc_uci_policy),
	};

	static struct ubus_object_type iwinfo_type =
		UBUS_OBJECT_TYPE("rpcd-plugin-iwinfo", iwinfo_methods);

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
