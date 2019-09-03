#include <assert.h>
#include <stdio.h>

// Must be before all DPDK includes
#include <rte_config.h>
#include <rte_ip.h>

#include <net/igmp.h>
#include <net/net.h>
#include <r2p2/cfg.h>
#include <dp/api.h>

//void ip_out(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph, uint32_t src_ip,
//			uint32_t dst_ip, uint8_t ttl, uint8_t tos, uint8_t proto,
//			uint16_t l4len, struct ether_addr *dst_haddr);
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
			assert(0);
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
