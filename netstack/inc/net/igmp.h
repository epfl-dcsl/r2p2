#pragma once

/*
 * We implement IGMPv2
 */

#include <stdint.h>

#define IGMP_MEMBERSHIP_QUERY 0x11
#define IGMPV1_MEMEBERSHIP_REPORT 0x12
#define IGMPV2_MEMBERSHIP_REPORT 0x16
#define IGMPV3_MEMBERSHIP_REPORT 0x22
#define IGMP_LEAVE_GROUP 0x17

struct __attribute__((packed)) igmpv2_hdr {
	uint8_t type;
	uint8_t max_resp_time;
	uint16_t cksum;
	uint32_t gaddr;
};

void igmp_in(void *pkt_buf, struct ipv4_hdr *iph, struct igmpv2_hdr *igmph);
