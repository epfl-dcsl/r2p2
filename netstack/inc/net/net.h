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

#pragma once

#include <stdint.h>

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include <net/utils.h>
#include <net/igmp.h>

#include <r2p2/cfg.h>

#define ETH_MTU 1500
#define UDP_MAX_LEN (ETH_MTU - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr))
#define L2_HDR_LEN sizeof(struct ether_hdr)
#define L3_HDR_LEN (L2_HDR_LEN + sizeof(struct ipv4_hdr))
#define UDP_HDRS_LEN (L3_HDR_LEN + sizeof(struct udp_hdr))

struct ip_tuple {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
} __packed;

/* Initialization */
int net_init(void);
int net_init_per_core(void);
int igmp_init(void);

int add_arp_entry(const char *ip, const char *mac);

/* packet processing */
void eth_in(struct rte_mbuf *pkt_buf);
int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
			struct ether_addr *dst_haddr, uint16_t iplen);
void arp_in(struct rte_mbuf *pkt_buf, struct arp_hdr *arph);
struct ether_addr *arp_lookup_mac(uint32_t addr);
void ip_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph);
void ip_out(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph, uint32_t src_ip,
			uint32_t dst_ip, uint8_t ttl, uint8_t tos, uint8_t proto,
			uint16_t l4len, struct ether_addr *dst_haddr);
void icmp_in(void *pkt_buf, struct ipv4_hdr *iph, struct icmp_hdr *icmph);
void igmp_in(void *pkt_buf, struct ipv4_hdr *iph, struct igmpv2_hdr *igmph);
void udp_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			struct udp_hdr *udph);
int udp_out(struct rte_mbuf *pkt_buf, struct ip_tuple *id, int len);
#ifdef ROUTER
void router_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			   struct udp_hdr *udph);
#endif

static inline uint16_t get_local_port(void)
{
	return CFG.host_port;
}

static inline uint32_t get_local_ip(void)
{
	return CFG.host_addr;
}

static inline void get_local_mac(struct ether_addr *mac)
{
	rte_eth_macaddr_get(0, mac); // Assume only one NIC
}
