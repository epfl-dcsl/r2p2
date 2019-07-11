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

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_byteorder.h>
#include <rte_hexdump.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <net/net.h>
#include <net/utils.h>

static void icmp_echo(void *pkt_buf, struct ipv4_hdr *iph,
					  struct icmp_hdr *icmph)
{
	int iphlen;
	int icmplen;

	/* compute icmp length */
	iphlen = (iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
	icmph->icmp_type = IP_ICMP_ECHO_REPLY;

	icmplen = rte_be_to_cpu_16(iph->total_length) - iphlen;

	icmph->icmp_cksum = 0;
	icmph->icmp_cksum = rte_raw_cksum((void *)icmph, icmplen);

	ip_out(pkt_buf, iph, rte_be_to_cpu_32(iph->dst_addr),
		   rte_be_to_cpu_32(iph->src_addr), iph->time_to_live,
		   iph->type_of_service, IPPROTO_ICMP, icmplen, NULL);
}

void icmp_in(void *pkt_buf, struct ipv4_hdr *iph, struct icmp_hdr *icmph)
{
	if (icmph->icmp_type == IP_ICMP_ECHO_REQUEST)
		icmp_echo(pkt_buf, iph, icmph);
	else {
		printf("Wrong ICMP type: %d\n", icmph->icmp_type);
		pkt_dump(pkt_buf);
		rte_pktmbuf_free(pkt_buf);
	}
}
