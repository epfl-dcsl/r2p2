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
#include <inttypes.h>
#include <stdio.h>

#include <rte_config.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <net/net.h>
#include <net/utils.h>

static inline int ip_is_multicast(uint32_t ip)
{
	uint32_t first_oct;

	first_oct = ip & 0xFF;
	return  (first_oct >= 224) && (first_oct <= 239);
}

void ip_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph)
{
	struct icmp_hdr *icmph;
	struct udp_hdr *udph;
	struct igmpv2_hdr *igmph;
	int hdrlen;

	if ((iph->dst_addr != rte_cpu_to_be_32(get_local_ip()))
			&& !ip_is_multicast(iph->dst_addr))
		goto out;

	/* perform necessary checks */
	hdrlen = (iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;

	switch (iph->next_proto_id) {
	case IPPROTO_TCP:
		printf("TCP not supported\n");
		break;
	case IPPROTO_UDP:
		udph = (struct udp_hdr *)((unsigned char *)iph + hdrlen);
#ifdef ROUTER
		router_in(pkt_buf, iph, udph);
#else
		udp_in(pkt_buf, iph, udph);
#endif
		break;
	case IPPROTO_ICMP:
		icmph = (struct icmp_hdr *)((unsigned char *)iph + hdrlen);
		icmp_in(pkt_buf, iph, icmph);
		break;
	case IPPROTO_IGMP:
		igmph = (struct igmpv2_hdr *)((unsigned char *)iph + hdrlen);
		igmp_in(pkt_buf, iph, igmph);
		break;
	default:
		goto out;
	}

	return;

out:
	printf("UNKNOWN L3 PROTOCOL OR WRONG DST IP\n");
	rte_pktmbuf_free(pkt_buf);
}

void ip_out(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph, uint32_t src_ip,
			uint32_t dst_ip, uint8_t ttl, uint8_t tos, uint8_t proto,
			uint16_t l4len, struct ether_addr *dst_haddr)
{
	int sent, hdrlen;
	char *options;

	hdrlen = sizeof(struct ipv4_hdr);
	if (proto == IPPROTO_IGMP)
		hdrlen += 4; // 4 bytes for options

	/* setup ip hdr */
	iph->version_ihl =
		(4 << 4) | (hdrlen / IPV4_IHL_MULTIPLIER);
	iph->type_of_service = tos;
	iph->total_length = rte_cpu_to_be_16(hdrlen + l4len);
	iph->packet_id = 0;
	iph->fragment_offset = rte_cpu_to_be_16(0x4000); // Don't fragment
	iph->time_to_live = ttl;
	iph->next_proto_id = proto;
	iph->hdr_checksum = 0;
	iph->src_addr = rte_cpu_to_be_32(src_ip);
	iph->dst_addr = rte_cpu_to_be_32(dst_ip);

	if (!dst_haddr)
		dst_haddr = arp_lookup_mac(dst_ip);
	char tmp[64];
	if (!dst_haddr) {
		ip_addr_to_str(dst_ip, tmp);
		printf("Unknown mac for %s\n", tmp);
	}
	assert(dst_haddr != NULL);

	/* Add options if IGMP */
	if (proto == IPPROTO_IGMP) {
		options = (char *)(iph+1);
		*options = 0x94;
		options++;
		*options = 0x4;
		options++;
		*options = 0x0;
		options++;
		*options = 0x0;
	}

	///* compute checksum */
	iph->hdr_checksum = rte_raw_cksum(iph, hdrlen);
	iph->hdr_checksum = (iph->hdr_checksum == 0xffff) ? iph->hdr_checksum : (uint16_t)~(iph->hdr_checksum);

	if (proto == IPPROTO_TCP) {
		assert(0);
	}

	sent = eth_out(pkt_buf, ETHER_TYPE_IPv4, dst_haddr,
				   rte_be_to_cpu_16(iph->total_length));
	assert(sent == 1);
}
