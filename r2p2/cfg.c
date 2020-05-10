/*
 * MIT License
 *
 * Copyright (c) 2019-2021 Ecole Polytechnique Federale Lausanne (EPFL)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <libconfig.h>

#include <r2p2/cfg.h>
#ifdef WITH_RAFT
#include <r2p2/hovercraft.h>
#endif

#ifndef LINUX
#include <net/net.h>
#endif

struct cfg_parameters CFG;
config_t cfg;

#define CFG_PATH "/etc/r2p2.conf"

static int parse_addr(const char *name, uint32_t *dst)
{
	struct sockaddr_in router_addr;
	const char *parsed = NULL;

	config_lookup_string(&cfg, name, (const char **)&parsed);
	if (!parsed)
		return -1;
	inet_pton(AF_INET, parsed, &(router_addr.sin_addr));
	*dst = be32toh(router_addr.sin_addr.s_addr);

	return 0;
}

static int parse_port(const char *name, uint16_t *dst)
{
	int port = -1;

	config_lookup_int(&cfg, name, &port);
	if (port == -1)
		return -1;
	*dst = port;

	return 0;
}

#ifdef WITH_TIMESTAMPING
static int parse_ifname(void)
{
	const char *parsed = NULL;
	config_lookup_string(&cfg, "if_name", (const char **)&parsed);
	if (!parsed)
		return -1;

	strcpy(CFG.if_name, parsed);

	return 0;
}
#endif

#ifndef LINUX
static int parse_arp(void)
{
	const config_setting_t *arp = NULL, *entry = NULL;
	int i;
	const char *ip = NULL, *mac = NULL;

	arp = config_lookup(&cfg, "arp");
	if (!arp) {
		fprintf(stderr, "no static arp entries defined in config\n");
		return -1;
	}

	for (i = 0; i < config_setting_length(arp); ++i) {
		entry = config_setting_get_elem(arp, i);
		config_setting_lookup_string(entry, "ip", &ip);
		config_setting_lookup_string(entry, "mac", &mac);
		if (!ip || !mac)
			return -1;
		add_arp_entry(ip, mac);
	}
	return 0;
}

static int parse_multicast(void)
{
	const config_setting_t *multicast = NULL;
	int i, j;
	const char *ip_str;
	struct in_addr mcast_ip;
	char mac[64], *ptr;
	char tmp[64];
	uint8_t mac_parts[3];


	multicast = config_lookup(&cfg, "multicast");
	if (!multicast) {
		fprintf(stderr, "no multicast entries defined in config\n");
		return -1;
	}

	for (i = 0; i < config_setting_length(multicast); ++i) {
		ip_str = config_setting_get_string_elem (multicast,i);
		printf("Multicast IP: %s\n", ip_str);
		inet_pton(AF_INET, ip_str, &mcast_ip);
		CFG.multicast_ips[CFG.multicast_cnt++] = be32toh(mcast_ip.s_addr);
		strcpy(tmp, ip_str);
		ptr = strtok(tmp, ".");
		ptr = strtok(NULL, "."); // discard the first
		for (j=0;j<3;j++) {
			if (j==0)
				mac_parts[j] = 0x7F & atoi(ptr);
			else
				mac_parts[j] = atoi(ptr);
		}
		sprintf(mac, "01:00:5E:%02x:%02x:%02x", mac_parts[0], mac_parts[1],
				mac_parts[2]);
		add_arp_entry(ip_str, mac);
		assert(CFG.multicast_cnt <= MAX_MULTICAST_IPS);
	}
	return 0;

}
#endif

#ifdef WITH_RAFT
static int parse_raft_peers(void)
{
	const config_setting_t *raft = NULL, *entry = NULL;
	int i;
	const char *ip = NULL;
	uint32_t ip_int;

	raft = config_lookup(&cfg, "raft");
	if (!raft)
		return -1;

	CFG.raft_peers_cnt = config_setting_length(raft);
	CFG.raft_peers =  malloc(sizeof(struct r2p2_raft_peer)*CFG.raft_peers_cnt);
	for (i = 0; i < CFG.raft_peers_cnt; ++i) {
		int port = -1;
		printf("Found one peer: %d\n", i);
		entry = config_setting_get_elem(raft, i);
		config_setting_lookup_string(entry, "ip", &ip);
		config_setting_lookup_int(entry, "port", &port);
		if (!ip || (port < 0)) {
			fprintf(stderr, "Error parsing raft peer\n");
			return -1;
		}
		CFG.raft_peers[i].id = i;
		inet_pton(AF_INET, ip, &ip_int);
		CFG.raft_peers[i].host.ip = be32toh(ip_int);
		CFG.raft_peers[i].host.port = port;
	}
	return 0;
}
#endif

int parse_config(void)
{
	int ret;
	config_init(&cfg);

	if (!config_read_file(&cfg, CFG_PATH)) {
		fprintf(stderr, "Error parsing config %s:%d - %s\n",
				config_error_file(&cfg), config_error_line(&cfg),
				config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	ret = parse_addr("router_addr", &CFG.router_addr);
	if (ret) {
		fprintf(stderr, "no router addr found\n");
		CFG.router_addr = 0;
	}

	ret = parse_port("router_port", &CFG.router_port);
	if (ret) {
		fprintf(stderr, "no router port found\n");
		CFG.router_port = 0;
	}

#ifdef WITH_TIMESTAMPING
	ret = parse_ifname();
	if (ret) {
		fprintf(stderr, "no iface name found\n");
		return ret;
	}
#endif

#ifdef WITH_RAFT
	// Parse raft peers if any
	ret = parse_raft_peers();
	if (ret) {
		fprintf(stderr, "no Raft peers found\n");
		CFG.raft_peers_cnt = 0;
		CFG.raft_peers = NULL;
	}
#endif

#ifdef LINUX
	return 0;
#else
	ret = parse_addr("host_addr", &CFG.host_addr);
	if (ret) {
		fprintf(stderr, "error parsing ip\n");
		config_destroy(&cfg);
		return ret;
	}

	ret = parse_port("host_port", &CFG.host_port);
	if (ret) {
		fprintf(stderr, "error parsing port\n");
		config_destroy(&cfg);
		return ret;
	}

	ret = parse_arp();
	if (ret) {
		fprintf(stderr, "error parsing port\n");
		config_destroy(&cfg);
		return ret;
	}

	parse_multicast();
#endif

	return 0;
}
