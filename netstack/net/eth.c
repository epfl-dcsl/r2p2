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

#include <inttypes.h>
#include <stdio.h>

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include <net/net.h>
#include <net/utils.h>

#include <dp/dpdk_api.h>

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct ether_hdr *hdr = (struct ether_hdr *)payload;
	struct arp_hdr *arph;
	struct ipv4_hdr *iph;

	if (hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		arph = (struct arp_hdr *)(payload + (sizeof(struct ether_hdr)));
		arp_in(pkt_buf, arph);
	} else if (hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
		iph = (struct ipv4_hdr *)(payload + (sizeof(struct ether_hdr)));
		ip_in(pkt_buf, iph);
	} else {
		//printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}

int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
			struct ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct ether_hdr *hdr = rte_pktmbuf_mtod(pkt_buf, struct ether_hdr *);

	hdr->d_addr = *dst_haddr;
	get_local_mac(&hdr->s_addr);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
	return dpdk_eth_send(pkt_buf, iplen + sizeof(struct ether_hdr));
}
