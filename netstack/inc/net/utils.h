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

#include <stdio.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

static inline uint32_t ip_str_to_int(const char *ip)
{
	uint32_t addr;
	unsigned char a, b, c, d;
	if (sscanf(ip, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}
	addr = IPv4(a, b, c, d);
	return addr;
}

static inline int str_to_eth_addr(const char *src, unsigned char *dst)
{
	struct ether_addr tmp;

	if (sscanf(src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &tmp.addr_bytes[0],
			   &tmp.addr_bytes[1], &tmp.addr_bytes[2], &tmp.addr_bytes[3],
			   &tmp.addr_bytes[4], &tmp.addr_bytes[5]) != 6)
		return -EINVAL;
	memcpy(dst, &tmp, sizeof(tmp));
	return 0;
}

static inline void ip_addr_to_str(uint32_t addr, char *str)
{
	snprintf(str, 15, "%d.%d.%d.%d", ((addr >> 24) & 0xff),
			 ((addr >> 16) & 0xff), ((addr >> 8) & 0xff), (addr & 0xff));
}

static inline void pkt_dump(struct rte_mbuf *pkt)
{
	struct ether_hdr *ethh = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv4_hdr *iph = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,
												   sizeof(struct ether_hdr));
	printf("DST MAC: ");
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		printf("%hhx ", (char)ethh->d_addr.addr_bytes[i]);
	printf("\nSRC MAC: ");
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		printf("%hhx ", (char)ethh->s_addr.addr_bytes[i]);
	char ipaddr[64];
	ip_addr_to_str(iph->src_addr, ipaddr);
	printf("\nSRC IP: %s\n", ipaddr);
	ip_addr_to_str(iph->dst_addr, ipaddr);
	printf("DST IP: %s\n", ipaddr);
}
