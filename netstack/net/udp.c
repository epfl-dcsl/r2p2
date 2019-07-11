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

#include <stdio.h>

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include <dp/api.h>
#include <dp/api_internal.h>
#include <net/net.h>
#include <net/utils.h>

void udp_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			struct udp_hdr *udph)
{
	struct ip_tuple *id;
	struct net_sge *e;

	id = rte_pktmbuf_mtod(pkt_buf, struct ip_tuple *);
	id->src_ip = rte_be_to_cpu_32(iph->src_addr);
	id->dst_ip = rte_be_to_cpu_32(iph->dst_addr);
	id->src_port = rte_be_to_cpu_16(udph->src_port);
	id->dst_port = rte_be_to_cpu_16(udph->dst_port);

	e = rte_pktmbuf_mtod_offset(pkt_buf, struct net_sge *,
								sizeof(struct ip_tuple));
	e->len = rte_be_to_cpu_16(udph->dgram_len) - sizeof(struct udp_hdr);
	e->payload = (void *)((unsigned char *)udph + sizeof(struct udp_hdr));
	e->handle = pkt_buf;

	global_ops->udp_recv(e, id);
}

int udp_out(struct rte_mbuf *pkt_buf, struct ip_tuple *id, int len)
{
	struct ipv4_hdr *iph = rte_pktmbuf_mtod_offset(pkt_buf, struct ipv4_hdr *,
												   sizeof(struct ether_hdr));
	struct udp_hdr *udph = rte_pktmbuf_mtod_offset(pkt_buf, struct udp_hdr *,
												   sizeof(struct ether_hdr) +
													   sizeof(struct ipv4_hdr));

	udph->dgram_cksum = 0;
	udph->dgram_len = rte_cpu_to_be_16(len + sizeof(struct udp_hdr));
	udph->src_port = rte_cpu_to_be_16(id->src_port);
	udph->dst_port = rte_cpu_to_be_16(id->dst_port);

	ip_out(pkt_buf, iph, id->src_ip, id->dst_ip, 64, 0, IPPROTO_UDP,
		   len + sizeof(struct udp_hdr), NULL);
	return 0;
}
