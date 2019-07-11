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

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <net/net.h>
#include <net/utils.h>

#define ARP_ENTRIES_COUNT 64

struct arp_entry {
	uint32_t addr;
	struct ether_addr mac;
};

static struct arp_entry known_haddrs[ARP_ENTRIES_COUNT];
static uint16_t arp_count = 0;

int add_arp_entry(const char *ip, const char *mac)
{
	int ret;
	printf("Adding IP: %s MAC: %s\n", ip, mac);
	if (arp_count >= ARP_ENTRIES_COUNT) {
		fprintf(stderr, "Not enough space for new arp entry\n");
		return -1;
	}
	known_haddrs[arp_count].addr = ip_str_to_int(ip);
	ret = str_to_eth_addr(mac, (unsigned char *)&known_haddrs[arp_count++].mac);
	if (ret) {
		fprintf(stderr, "Error parsing marc\n");
		return -1;
	}

	return 0;
}

static void arp_out(struct rte_mbuf *pkt_buf, struct arp_hdr *arph, int opcode,
					uint32_t dst_ip, struct ether_addr *dst_haddr)
{
	int sent;

	/* fill arp header */
	/* previous fields remain the same */
	arph->arp_op = rte_cpu_to_be_16(opcode);

	/* fill arp body */
	arph->arp_data.arp_sip = rte_cpu_to_be_32(get_local_ip());
	arph->arp_data.arp_tip = dst_ip;

	arph->arp_data.arp_tha = *dst_haddr;
	get_local_mac(&arph->arp_data.arp_sha); // Assume only one NIC

	sent = eth_out(pkt_buf, ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
				   sizeof(struct arp_hdr));
	assert(sent == 1);
}

struct ether_addr *arp_lookup_mac(uint32_t addr)
{
#ifdef ROUTER
	return &known_haddrs[addr - known_haddrs[0].addr].mac;
#else
	int i;
	for (i = 0; i < ARP_ENTRIES_COUNT; i++) {
		if (addr == known_haddrs[i].addr)
			return &known_haddrs[i].mac;
	}
#endif
	return NULL;
}

void arp_in(struct rte_mbuf *pkt_buf, struct arp_hdr *arph)
{
	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != get_local_ip()) {
		rte_pktmbuf_free(pkt_buf);
		return;
	}

	switch (rte_be_to_cpu_16(arph->arp_op)) {
	case ARP_OP_REQUEST:
		arp_out(pkt_buf, arph, ARP_OP_REPLY, arph->arp_data.arp_sip,
				&arph->arp_data.arp_sha);
		break;
	case ARP_OP_REPLY:
		break;
	default:
		printf("apr: Received unknown ARP op");
		rte_pktmbuf_free(pkt_buf);
		break;
	}
}
