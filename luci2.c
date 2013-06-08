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
#include <sys/stat.h>
#include <arpa/inet.h>

#include "luci2.h"

static struct blob_buf buf;
static struct uci_context *cursor;


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

static void
log_read(FILE *log, int logsize)
{
	int len;
	char *logbuf;

	if (logsize == 0)
		logsize = RPC_LUCI2_DEF_LOGSIZE;

	len = (logsize > RPC_LUCI2_MAX_LOGSIZE) ? RPC_LUCI2_MAX_LOGSIZE : logsize;
	logbuf = blobmsg_alloc_string_buffer(&buf, "log", len + 1);

	if (!logbuf)
		return;

	while (logsize > RPC_LUCI2_MAX_LOGSIZE)
	{
		len = logsize % RPC_LUCI2_MAX_LOGSIZE;

		if (len == 0)
			len = RPC_LUCI2_MAX_LOGSIZE;

		fread(logbuf, 1, len, log);
		logsize -= len;
	}

	len = fread(logbuf, 1, logsize, log);
	*(logbuf + len) = 0;

	blobmsg_add_string_buffer(&buf);
}

static int
rpc_luci2_system_log(struct ubus_context *ctx, struct ubus_object *obj,
                     struct ubus_request_data *req, const char *method,
                     struct blob_attr *msg)
{
	FILE *log;
	int logsize = 0;
	const char *logfile = NULL;
	struct stat st;
	struct uci_package *p;
	struct uci_element *e;
	struct uci_section *s;
	struct uci_ptr ptr = { .package = "system" };

	uci_load(cursor, ptr.package, &p);

	if (!p)
		return UBUS_STATUS_NOT_FOUND;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "system"))
			continue;

		ptr.o = NULL;
		ptr.option = "log_type";
		ptr.section = e->name;
		uci_lookup_ptr(cursor, &ptr, NULL, true);
		break;
	}

	if (ptr.o && ptr.o->type == UCI_TYPE_STRING &&
	    !strcmp(ptr.o->v.string, "file"))
	{
		ptr.o = NULL;
		ptr.option = "log_file";
		uci_lookup_ptr(cursor, &ptr, NULL, true);

		if (ptr.o && ptr.o->type == UCI_TYPE_STRING)
			logfile = ptr.o->v.string;
		else
			logfile = "/var/log/messages";

		if (stat(logfile, &st) || !(log = fopen(logfile, "r")))
			goto fail;

		logsize = st.st_size;
	}
	else
	{
		ptr.o = NULL;
		ptr.option = "log_size";
		uci_lookup_ptr(cursor, &ptr, NULL, true);

		if (ptr.o && ptr.o->type == UCI_TYPE_STRING)
			logsize = atoi(ptr.o->v.string) * 1024;

		if (!(log = popen("logread", "r")))
			goto fail;
	}

	blob_buf_init(&buf, 0);

	log_read(log, logsize);
	fclose(log);

	uci_unload(cursor, p);
	ubus_send_reply(ctx, req, buf.head);
	return 0;

fail:
	uci_unload(cursor, p);
	return rpc_errno_status();
}

static int
rpc_luci2_system_dmesg(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	FILE *log;

	if (!(log = popen("dmesg", "r")))
		return rpc_errno_status();

	blob_buf_init(&buf, 0);

	log_read(log, RPC_LUCI2_MAX_LOGSIZE);
	fclose(log);

	ubus_send_reply(ctx, req, buf.head);
	return 0;
}


static FILE *
dnsmasq_leasefile(void)
{
	FILE *leases = NULL;
	struct uci_package *p;
	struct uci_element *e;
	struct uci_section *s;
	struct uci_ptr ptr = {
		.package = "dhcp",
		.section = NULL,
		.option  = "leasefile"
	};

	uci_load(cursor, ptr.package, &p);

	if (!p)
		return NULL;

	uci_foreach_element(&p->sections, e)
	{
		s = uci_to_section(e);

		if (strcmp(s->type, "dnsmasq"))
			continue;

		ptr.section = e->name;
		uci_lookup_ptr(cursor, &ptr, NULL, true);
		break;
	}

	if (ptr.o && ptr.o->type == UCI_TYPE_STRING)
		leases = fopen(ptr.o->v.string, "r");

	uci_unload(cursor, p);

	return leases;
}

static int
rpc_luci2_network_leases(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
	FILE *leases;
	void *c, *d;
	char line[128];
	char *ts, *mac, *addr, *name;
	time_t now = time(NULL);

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "leases");

	leases = dnsmasq_leasefile();

	if (!leases)
		goto out;

	while (fgets(line, sizeof(line) - 1, leases))
	{
		ts   = strtok(line, " \t");
		mac  = strtok(NULL, " \t");
		addr = strtok(NULL, " \t");
		name = strtok(NULL, " \t");

		if (!ts || !mac || !addr || !name)
			continue;

		if (strchr(addr, ':'))
			continue;

		d = blobmsg_open_table(&buf, NULL);

		blobmsg_add_u32(&buf, "expires", atoi(ts) - now);
		blobmsg_add_string(&buf, "macaddr", mac);
		blobmsg_add_string(&buf, "ipaddr", addr);

		if (strcmp(name, "*"))
			blobmsg_add_string(&buf, "hostname", name);

		blobmsg_close_table(&buf, d);
	}

	fclose(leases);

out:
	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_luci2_network_leases6(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
	FILE *leases;
	void *c, *d;
	char line[128];
	char *ts, *mac, *addr, *name, *duid;
	time_t now = time(NULL);

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "leases");

	leases = fopen("/tmp/hosts/6relayd", "r");

	if (leases)
	{
		while (fgets(line, sizeof(line) - 1, leases))
		{
			if (strncmp(line, "# ", 2))
				continue;

			strtok(line + 2, " \t"); /* iface */

			duid = strtok(NULL, " \t");

			strtok(NULL, " \t"); /* iaid */

			name = strtok(NULL, " \t");
			ts   = strtok(NULL, " \t");

			strtok(NULL, " \t"); /* id */
			strtok(NULL, " \t"); /* length */

			addr = strtok(NULL, " \t\n");

			if (!addr)
				continue;

			d = blobmsg_open_table(&buf, NULL);

			blobmsg_add_u32(&buf, "expires", atoi(ts) - now);
			blobmsg_add_string(&buf, "duid", duid);
			blobmsg_add_string(&buf, "ip6addr", addr);

			if (strcmp(name, "-"))
				blobmsg_add_string(&buf, "hostname", name);

			blobmsg_close_array(&buf, d);
		}

		fclose(leases);
	}
	else
	{
		leases = dnsmasq_leasefile();

		if (!leases)
			goto out;

		while (fgets(line, sizeof(line) - 1, leases))
		{
			ts   = strtok(line, " \t");
			mac  = strtok(NULL, " \t");
			addr = strtok(NULL, " \t");
			name = strtok(NULL, " \t");
			duid = strtok(NULL, " \t\n");

			if (!ts || !mac || !addr || !duid)
				continue;

			if (!strchr(addr, ':'))
				continue;

			d = blobmsg_open_table(&buf, NULL);

			blobmsg_add_u32(&buf, "expires", atoi(ts) - now);
			blobmsg_add_string(&buf, "macaddr", mac);
			blobmsg_add_string(&buf, "ip6addr", addr);

			if (strcmp(name, "*"))
				blobmsg_add_string(&buf, "hostname", name);

			if (strcmp(duid, "*"))
				blobmsg_add_string(&buf, "duid", name);

			blobmsg_close_table(&buf, d);
		}

		fclose(leases);
	}

out:
	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_luci2_network_ct_count(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg)
{
	FILE *f;
	char line[128];

	blob_buf_init(&buf, 0);

	if ((f = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r")) != NULL)
	{
		if (fgets(line, sizeof(line) - 1, f))
			blobmsg_add_u32(&buf, "count", atoi(line));

		fclose(f);
	}

	if ((f = fopen("/proc/sys/net/netfilter/nf_conntrack_max", "r")) != NULL)
	{
		if (fgets(line, sizeof(line) - 1, f))
			blobmsg_add_u32(&buf, "limit", atoi(line));

		fclose(f);
	}

	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_luci2_network_ct_table(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg)
{
	FILE *f;
	int i;
	void *c, *d;
	char *p, line[512];
	bool seen[6];

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "entries");

	if ((f = fopen("/proc/net/nf_conntrack", "r")) != NULL)
	{
		while (fgets(line, sizeof(line) - 1, f))
		{
			d = blobmsg_open_table(&buf, NULL);
			memset(seen, 0, sizeof(seen));

			for (i = 0, p = strtok(line, " "); p; i++, p = strtok(NULL, " "))
			{
				if (i == 0)
					blobmsg_add_u8(&buf, "ipv6", !strcmp(p, "ipv6"));
				else if (i == 3)
					blobmsg_add_u32(&buf, "protocol", atoi(p));
				else if (i == 4)
					blobmsg_add_u32(&buf, "expires", atoi(p));
				else if (i >= 5)
				{
					if (*p == '[')
						continue;

					if (!seen[0] && !strncmp(p, "src=", 4))
					{
						blobmsg_add_string(&buf, "src", p + 4);
						seen[0] = true;
					}
					else if (!seen[1] && !strncmp(p, "dst=", 4))
					{
						blobmsg_add_string(&buf, "dest", p + 4);
						seen[1] = true;
					}
					else if (!seen[2] && !strncmp(p, "sport=", 6))
					{
						blobmsg_add_u32(&buf, "sport", atoi(p + 6));
						seen[2] = true;
					}
					else if (!seen[3] && !strncmp(p, "dport=", 6))
					{
						blobmsg_add_u32(&buf, "dport", atoi(p + 6));
						seen[3] = true;
					}
					else if (!strncmp(p, "packets=", 8))
					{
						blobmsg_add_u32(&buf,
						                seen[4] ? "tx_packets" : "rx_packets",
						                atoi(p + 8));
						seen[4] = true;
					}
					else if (!strncmp(p, "bytes=", 6))
					{
						blobmsg_add_u32(&buf,
										seen[5] ? "tx_bytes" : "rx_bytes",
						                atoi(p + 6));
						seen[5] = true;
					}
				}
			}

			blobmsg_close_table(&buf, d);
		}

		fclose(f);
	}

	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static int
rpc_luci2_network_arp_table(struct ubus_context *ctx, struct ubus_object *obj,
                            struct ubus_request_data *req, const char *method,
                            struct blob_attr *msg)
{
	FILE *f;
	void *c, *d;
	char *addr, *mac, *dev, line[128];

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "entries");

	if ((f = fopen("/proc/net/arp", "r")) != NULL)
	{
		/* skip header line */
		fgets(line, sizeof(line) - 1, f);

		while (fgets(line, sizeof(line) - 1, f))
		{
			addr = strtok(line, " \t");

			strtok(NULL, " \t"); /* HW type */
			strtok(NULL, " \t"); /* Flags */

			mac = strtok(NULL, " \t");

			strtok(NULL, " \t"); /* Mask */

			dev = strtok(NULL, " \t\n");

			if (!dev)
				continue;

			d = blobmsg_open_table(&buf, NULL);
			blobmsg_add_string(&buf, "ipaddr", addr);
			blobmsg_add_string(&buf, "macaddr", mac);
			blobmsg_add_string(&buf, "device", dev);
			blobmsg_close_table(&buf, d);
		}

		fclose(f);
	}

	blobmsg_close_array(&buf, c);
	ubus_send_reply(ctx, req, buf.head);

	return 0;
}

static void
put_hexaddr(const char *name, const char *s, const char *m)
{
	int bits;
	struct in_addr a;
	char as[sizeof("255.255.255.255/32\0")];

	a.s_addr = strtoul(s, NULL, 16);
	inet_ntop(AF_INET, &a, as, sizeof(as));

	if (m)
	{
		for (a.s_addr = ntohl(strtoul(m, NULL, 16)), bits = 0;
		     a.s_addr & 0x80000000;
		     a.s_addr <<= 1)
			bits++;

		sprintf(as + strlen(as), "/%u", bits);
	}

	blobmsg_add_string(&buf, name, as);
}

static int
rpc_luci2_network_routes(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
	FILE *routes;
	void *c, *d;
	char *dst, *dmask, *next, *metric, *device;
	char line[256];
	unsigned int n;

	if (!(routes = fopen("/proc/net/route", "r")))
		return rpc_errno_status();

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "routes");

	/* skip header line */
	fgets(line, sizeof(line) - 1, routes);

	while (fgets(line, sizeof(line) - 1, routes))
	{
		device = strtok(line, "\t ");
		dst    = strtok(NULL, "\t ");
		next   = strtok(NULL, "\t ");

		strtok(NULL, "\t "); /* flags */
		strtok(NULL, "\t "); /* refcount */
		strtok(NULL, "\t "); /* usecount */

		metric = strtok(NULL, "\t ");
		dmask  = strtok(NULL, "\t ");

		if (!dmask)
			continue;

		d = blobmsg_open_table(&buf, NULL);

		put_hexaddr("target", dst, dmask);
		put_hexaddr("nexthop", next, NULL);

		n = strtoul(metric, NULL, 10);
		blobmsg_add_u32(&buf, "metric", n);

		blobmsg_add_string(&buf, "device", device);

		blobmsg_close_table(&buf, d);
	}

	blobmsg_close_array(&buf, c);
	fclose(routes);

	ubus_send_reply(ctx, req, buf.head);
	return 0;
}

static void
put_hex6addr(const char *name, const char *s, const char *m)
{
	int i;
	struct in6_addr a;
	char as[INET6_ADDRSTRLEN + sizeof("/128")];

#define hex(x) \
	(((x) <= '9') ? ((x) - '0') : \
		(((x) <= 'F') ? ((x) - 'A' + 10) : \
			((x) - 'a' + 10)))

	for (i = 0; i < 16; i++, s += 2)
		a.s6_addr[i] = (16 * hex(*s)) + hex(*(s+1));

	inet_ntop(AF_INET6, &a, as, sizeof(as));

	if (m)
		sprintf(as + strlen(as), "/%lu", strtoul(m, NULL, 16));

	blobmsg_add_string(&buf, name, as);
}

static int
rpc_luci2_network_routes6(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
	FILE *routes;
	void *c, *d;
	char *src, *smask, *dst, *dmask, *next, *metric, *flags, *device;
	char line[256];
	unsigned int n;

	if (!(routes = fopen("/proc/net/ipv6_route", "r")))
		return rpc_errno_status();

	blob_buf_init(&buf, 0);
	c = blobmsg_open_array(&buf, "routes");

	while (fgets(line, sizeof(line) - 1, routes))
	{
		dst    = strtok(line, " ");
		dmask  = strtok(NULL, " ");
		src    = strtok(NULL, " ");
		smask  = strtok(NULL, " ");
		next   = strtok(NULL, " ");
		metric = strtok(NULL, " ");

		strtok(NULL, " "); /* refcount */
		strtok(NULL, " "); /* usecount */

		flags  = strtok(NULL, " ");
		device = strtok(NULL, " \n");

		if (!device)
			continue;

		n = strtoul(flags, NULL, 16);

		if (!(n & 1))
			continue;

		d = blobmsg_open_table(&buf, NULL);

		put_hex6addr("target", dst, dmask);
		put_hex6addr("source", src, smask);
		put_hex6addr("nexthop", next, NULL);

		n = strtoul(metric, NULL, 16);
		blobmsg_add_u32(&buf, "metric", n);

		blobmsg_add_string(&buf, "device", device);

		blobmsg_close_table(&buf, d);
	}

	blobmsg_close_array(&buf, c);
	fclose(routes);

	ubus_send_reply(ctx, req, buf.head);
	return 0;
}


int rpc_luci2_api_init(struct ubus_context *ctx)
{
	int rv = 0;

	static const struct ubus_method luci2_system_methods[] = {
		UBUS_METHOD_NOARG("syslog", rpc_luci2_system_log),
		UBUS_METHOD_NOARG("dmesg",  rpc_luci2_system_dmesg),
	};

	static struct ubus_object_type luci2_system_type =
		UBUS_OBJECT_TYPE("luci-rpc-luci2-system", luci2_system_methods);

	static struct ubus_object system_obj = {
		.name = "luci2.system",
		.type = &luci2_system_type,
		.methods = luci2_system_methods,
		.n_methods = ARRAY_SIZE(luci2_system_methods),
	};


	static const struct ubus_method luci2_network_methods[] = {
		UBUS_METHOD_NOARG("conntrack_count", rpc_luci2_network_ct_count),
		UBUS_METHOD_NOARG("conntrack_table", rpc_luci2_network_ct_table),
		UBUS_METHOD_NOARG("arp_table",       rpc_luci2_network_arp_table),
		UBUS_METHOD_NOARG("dhcp_leases",     rpc_luci2_network_leases),
		UBUS_METHOD_NOARG("dhcp6_leases",    rpc_luci2_network_leases6),
		UBUS_METHOD_NOARG("routes",          rpc_luci2_network_routes),
		UBUS_METHOD_NOARG("routes6",         rpc_luci2_network_routes6),
	};

	static struct ubus_object_type luci2_network_type =
		UBUS_OBJECT_TYPE("luci-rpc-luci2-network", luci2_network_methods);

	static struct ubus_object network_obj = {
		.name = "luci2.network",
		.type = &luci2_network_type,
		.methods = luci2_network_methods,
		.n_methods = ARRAY_SIZE(luci2_network_methods),
	};

	cursor = uci_alloc_context();

	if (!cursor)
		return UBUS_STATUS_UNKNOWN_ERROR;

	rv |= ubus_add_object(ctx, &system_obj);
	rv |= ubus_add_object(ctx, &network_obj);

	return rv;
}
