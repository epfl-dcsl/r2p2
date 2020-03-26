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

#include <unistd.h>
#include <assert.h>
#include <stdio.h>

// Must be before all DPDK includes
#include <rte_config.h>
#include <rte_ip.h>

#include <net/igmp.h>
#include <net/net.h>
#include <r2p2/cfg.h>
#include <dp/api.h>

static void igmp_handle_membership_query(void)
{
	int i;
	struct net_sge *entry;
	struct rte_mbuf *pkt_buf;
	struct ipv4_hdr *iph;
	struct igmpv2_hdr *igmph;

	for (i=0;i<CFG.multicast_cnt;i++) {
		entry = alloc_net_sge();
		pkt_buf = entry->handle;
		iph = rte_pktmbuf_mtod_offset(pkt_buf, struct ipv4_hdr *, L2_HDR_LEN);
		igmph = rte_pktmbuf_mtod_offset(pkt_buf, struct igmpv2_hdr *,
				L3_HDR_LEN+4); // extra space for options
		igmph->gaddr = rte_cpu_to_be_32(CFG.multicast_ips[i]);
		igmph->type = IGMPV2_MEMBERSHIP_REPORT;
		igmph->max_resp_time = 0;
		igmph->cksum = 0;
		igmph->cksum = rte_raw_cksum(igmph, sizeof(struct igmpv2_hdr));
		igmph->cksum = (igmph->cksum == 0xffff) ? igmph->cksum : (uint16_t)~(igmph->cksum);
		ip_out(pkt_buf, iph, get_local_ip(), CFG.multicast_ips[i], 64, 0xC0,
				IPPROTO_IGMP, sizeof(struct igmpv2_hdr), NULL);
	}
}

int igmp_init(void)
{
	for (int i=0;i<10;i++) {
		igmp_handle_membership_query();
		sleep(1);
	}

	return 0;
}

void igmp_in(void *pkt_buf, __attribute__((unused))struct ipv4_hdr *iph,
		struct igmpv2_hdr *igmph)
{
	switch(igmph->type) {
		case IGMP_MEMBERSHIP_QUERY:
			igmp_handle_membership_query();
			break;
		case IGMPV1_MEMEBERSHIP_REPORT:
			printf("Membership report v1\n");
			assert(0);
			break;
		case IGMPV2_MEMBERSHIP_REPORT:
			printf("Membership report v2\n");
			break;
		case IGMPV3_MEMBERSHIP_REPORT:
			printf("Membership report v3\n");
			assert(0);
			break;
		case IGMP_LEAVE_GROUP:
			printf("Leave group\n");
			assert(0);
			break;
		default:
			fprintf(stderr, "UNKNOWN IGMP TYPE\n");
	}
	rte_pktmbuf_free(pkt_buf);
}
