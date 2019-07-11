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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_lcore.h>

#include <dp/api.h>
#include <dp/core.h>
#include <dp/dpdk_api.h>
#include <net/utils.h>

#include <r2p2/api-internal.h>

// Assume even for app and odd for control
#define BASE_PORT 8000
#define BUFFER_CNT_THRES 2

struct __attribute__((__packed__)) target {
	uint32_t target_ip;
	uint16_t target_port;
	int idx;
} __attribute__((aligned(64)));

uint64_t *tokens;
uint64_t *sent;

int starting_port;
enum {
	RAND = 0,
	RR,
	JSQ,
	FC,
} policy;
static struct target targets[64];
int worker_count;
int per_queue_slots;
static uint16_t curr_idx;
static struct rte_mbuf *pending_routed_head;
static struct rte_mbuf *pending_routed_tail;
static int pending_routed_count;
static struct rte_mbuf *pending_direct_head;
static struct rte_mbuf *pending_direct_tail;
static int pending_direct_count;
static int jsq_idle[64];
static int jsq_idle_count;

static int configure_fdir(void)
{
	int ret;
	struct rte_flow *f;

	struct rte_flow_attr attr = {0};
	struct rte_flow_item pattern[4] = {0};
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv4 ipv4_mask = {0};
	struct rte_flow_item_udp udp;
	struct rte_flow_item_udp udp_mask = {0};
	struct rte_flow_action actions[2] = {0};
	struct rte_flow_action_queue queue;
	struct rte_flow_error err = {0};

	printf("Configuring port: %d\n", RTE_PER_LCORE(queue_id));
	attr.ingress = 1;
	// Allow all eth packets
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	// Handle control - one queue per server
	// if (RTE_PER_LCORE(queue_id) % 2) {
	//	if (RTE_PER_LCORE(queue_id)/2 > server_count)
	//		return 0;
	//	ipv4.hdr.src_addr = rte_cpu_to_be_32(ips[RTE_PER_LCORE(queue_id)/2]);
	//	ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
	//}
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4;
	pattern[1].mask = &ipv4_mask;

	/*// Filter UDP based on port*/
	// dst_port 8000 for app 9000 for control
	if (RTE_PER_LCORE(queue_id) % 2)
		udp.hdr.dst_port = rte_cpu_to_be_16(9000);
	else
		udp.hdr.dst_port = rte_cpu_to_be_16(8000 + RTE_PER_LCORE(queue_id) / 2);

	udp_mask.hdr.dst_port = rte_cpu_to_be_16(0xFFFF);

	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp;
	pattern[2].mask = &udp_mask;

	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

	queue.index = RTE_PER_LCORE(queue_id);
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue;
	actions[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(0, &attr, pattern, actions, &err);
	if (ret) {
		printf("Error: %s\n", err.message);
		return ret;
	}
	f = rte_flow_create(0, &attr, pattern, actions, &err);
	if (!f) {
		printf("Error creating flow in queue %d: %d %d %s\n",
			   RTE_PER_LCORE(queue_id), rte_errno, err.type, err.message);
		return -1;
	}
	return 0;
}

static int is_control(struct udp_hdr *udph)
{
	return rte_be_to_cpu_16(udph->dst_port) == 9000;
}

static void update_tokens(struct ipv4_hdr *iph, struct udp_hdr *udph)
{
	int i;
	uint16_t port;
	uint32_t ip_addr;

	ip_addr = rte_be_to_cpu_32(iph->src_addr);
	port = rte_be_to_cpu_16(udph->src_port);
	for (i = 0; i < worker_count; i++)
		if ((targets[i].target_ip == ip_addr) &&
			(targets[i].target_port == port))
			break;
	tokens[i]++;
}

static struct target *get_jsq_target(void)
{
	// initialize with zero tokens
	int backlog, i;
	int min = 0xFFFFFF;
	int min_idx = -1;

	// There are idle workers -> no need to read
	if (jsq_idle_count > 0) {
		sent[jsq_idle[--jsq_idle_count]]++;
		return &targets[jsq_idle[jsq_idle_count]];
	}

	// Find min and idle workers
	assert(jsq_idle_count == 0);
	for (i = 0; i < worker_count; i++) {
		backlog = sent[i] - tokens[i];
		if (backlog < min) {
			min = backlog;
			min_idx = i;
		}
		if (backlog == 0) {
			jsq_idle[jsq_idle_count++] = i;
		}
	}

	if (jsq_idle_count > 0) {
		sent[jsq_idle[--jsq_idle_count]]++;
		return &targets[jsq_idle[jsq_idle_count]];
	} else {
		sent[min_idx]++;
		return &targets[min_idx];
	}
}

static struct target *select_target(void)
{

	if (policy == RAND)
		return &targets[rand() % worker_count];
	else if (policy == RR)
		return &targets[curr_idx++ % worker_count];
	else if (policy == JSQ)
		return get_jsq_target();
	else
		assert(0);
	return NULL;
}

static void send_to_worker(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
						   struct udp_hdr *udph, struct target *t)
{
	udph->dst_port = rte_cpu_to_be_16(t->target_port);
	ip_out(pkt_buf, iph, rte_be_to_cpu_32(iph->src_addr), t->target_ip,
		   iph->time_to_live, iph->type_of_service, IPPROTO_UDP,
		   rte_be_to_cpu_16(udph->dgram_len), NULL);
}

static void ctrl_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
					struct udp_hdr *udph)
{
	if ((policy == FC) || (policy == JSQ))
		update_tokens(iph, udph);

	rte_pktmbuf_free(pkt_buf);
}

static void fw_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
				  struct udp_hdr *udph)
{
	struct target *t;
	struct r2p2_header *r2p2h;
	uint8_t policy;

	udph->dgram_cksum = 0;
	r2p2h = (struct r2p2_header *)(udph + 1);
	policy = r2p2h->type_policy & 0xF;

	if (policy == LB_ROUTE) {
		t = select_target();
		send_to_worker(pkt_buf, iph, udph, t);
	} else if (policy == FIXED_ROUTE)
		send_to_worker(pkt_buf, iph, udph, &targets[0]);
	else
		assert(0);
}

static void fc_fw_in(struct rte_mbuf *pkt_buf,
					 __attribute__((unused)) struct ipv4_hdr *iph,
					 struct udp_hdr *udph)
{
	struct r2p2_header *r2p2h;
	uint8_t policy;

	udph->dgram_cksum = 0;
	r2p2h = (struct r2p2_header *)(udph + 1);
	policy = r2p2h->type_policy & 0xF;

	if (policy == LB_ROUTE) {
		pending_routed_count++;
		if (pending_routed_tail)
			pending_routed_tail->userdata = pkt_buf;
		pending_routed_tail = pkt_buf;
		pkt_buf->userdata = NULL;
		if (pending_routed_count == 1)
			pending_routed_head = pkt_buf;
	} else if (policy == FIXED_ROUTE) {
		pending_direct_count++;
		if (pending_direct_tail)
			pending_direct_tail->userdata = pkt_buf;
		pending_direct_tail = pkt_buf;
		pkt_buf->userdata = NULL;
		if (pending_direct_count == 1)
			pending_direct_head = pkt_buf;
	} else
		assert(0);
}

void router_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			   struct udp_hdr *udph)
{
	if (is_control(udph))
		ctrl_in(pkt_buf, iph, udph);
	else {
		if (policy == FC)
			fc_fw_in(pkt_buf, iph, udph);
		else
			fw_in(pkt_buf, iph, udph);
	}
}

int app_init(int argc, char **argv)
{
	int i, port, workers;
	uint32_t tmp_ip;
	char *token1, *token2;

	printf("Hello router\n");
	if (argc != 4) {
		printf("Usage: ./router -l 0,2 -- <target_ip:base_port:count,...> "
			   "<per_queue_slots> <rand|rr|fc>\n");
		return -1;
	}

	per_queue_slots = atoi(argv[2]);

	if (!strcmp(argv[3], "rand"))
		policy = RAND;
	else if (!strcmp(argv[3], "rr"))
		policy = RR;
	else if (!strcmp(argv[3], "jsq"))
		policy = JSQ;
	else if (!strcmp(argv[3], "fc"))
		policy = FC;
	else {
		printf("Unknown policy\n");
		return -1;
	}

	// Parse targets
	token1 = strtok_r(argv[1], ",", &argv[1]);
	worker_count = 0;
	while (token1) {
		token2 = strtok_r(token1, ":", &token1);
		tmp_ip = ip_str_to_int(token2);
		token2 = strtok_r(token1, ":", &token1);
		port = atoi(token2);
		token2 = strtok_r(token1, ":", &token1);
		workers = atoi(token2);
		for (i = 0; i < workers; i++) {
			targets[worker_count].idx = worker_count;
			targets[worker_count].target_ip = tmp_ip;
			targets[worker_count++].target_port = port + i;
		}
		token1 = strtok_r(argv[1], ",", &argv[1]);
	}

	tokens = aligned_alloc(64, worker_count * sizeof(uint64_t));
	sent = aligned_alloc(64, worker_count * sizeof(uint64_t));

	volatile uint64_t *tmp1 = tokens;
	volatile uint64_t *tmp2 = sent;
	for (i = 0; i < worker_count; i++) {
		tmp1[i] = per_queue_slots;
		tmp2[i] = 0;
	}

	sleep(1);
	return 0;
}

static void send_from_pending_routed(struct target *t)
{
	int iphdrlen;
	struct rte_mbuf *to_send;
	struct ipv4_hdr *to_send_iph;
	struct udp_hdr *to_send_udph;

	to_send = pending_routed_head;
	pending_routed_head = to_send->userdata;
	pending_routed_count--;
	if (!pending_routed_count)
		pending_routed_tail = NULL;

	to_send_iph = rte_pktmbuf_mtod_offset(to_send, struct ipv4_hdr *,
										  sizeof(struct ether_hdr));
	iphdrlen =
		(to_send_iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
	to_send_udph = rte_pktmbuf_mtod_offset(to_send, struct udp_hdr *,
										   sizeof(struct ether_hdr) + iphdrlen);

	send_to_worker(to_send, to_send_iph, to_send_udph, t);
}

static void send_from_pending_direct(struct target *t)
{
	int iphdrlen;
	struct rte_mbuf *to_send;
	struct ipv4_hdr *to_send_iph;
	struct udp_hdr *to_send_udph;

	to_send = pending_direct_head;
	pending_direct_head = to_send->userdata;
	pending_direct_count--;
	if (!pending_direct_count)
		pending_direct_tail = NULL;

	to_send_iph = rte_pktmbuf_mtod_offset(to_send, struct ipv4_hdr *,
										  sizeof(struct ether_hdr));
	iphdrlen =
		(to_send_iph->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
	to_send_udph = rte_pktmbuf_mtod_offset(to_send, struct udp_hdr *,
										   sizeof(struct ether_hdr) + iphdrlen);

	send_to_worker(to_send, to_send_iph, to_send_udph, t);
}

static void fc_fw_main(void)
{
	int i, avail, avail_slots = 0, idle_slots = 0;
	int idx; //, tries;
	int *target_group, *target_group_count, *group_idx;

	/* Start polling loop */
	target_group =
		aligned_alloc(64, per_queue_slots * worker_count * sizeof(int));
	target_group_count = aligned_alloc(64, per_queue_slots * sizeof(int));
	group_idx = aligned_alloc(64, per_queue_slots * sizeof(int));
	do {
		// Get all incoming packets and queue them;
		net_poll();
		// Check for new slots only if it's necessary
		if ((!avail_slots) ||
			(!idle_slots && (pending_routed_count < BUFFER_CNT_THRES))) {
			avail_slots = 0;
			idle_slots = 0;
			bzero(target_group_count, per_queue_slots * sizeof(int));
			bzero(group_idx, per_queue_slots * sizeof(int));
			for (i = 0; i < worker_count; i++) {
				avail = tokens[i] - sent[i];
				if (avail < 1)
					continue;
				target_group[(avail - 1) * worker_count +
							 target_group_count[avail - 1]++] = i;
				avail_slots += avail;
				if (avail == per_queue_slots)
					idle_slots++;
			}
		}
		// send direct no matter what
		while (pending_direct_count) {
			send_from_pending_direct(&targets[0]);
			sent[0]++;
		}
		if (idle_slots) {
			while (pending_routed_count &&
				   (group_idx[per_queue_slots - 1] <
					target_group_count[per_queue_slots - 1])) {
				idx = (per_queue_slots - 1) * worker_count +
					  group_idx[(per_queue_slots - 1)]++;
				send_from_pending_routed(&targets[target_group[idx]]);
				sent[target_group[idx]]++;
				avail_slots--;
				idle_slots--;

				// Add the worker to the next group
				if (per_queue_slots > 1)
					target_group[(per_queue_slots - 2) * worker_count +
								 target_group_count[per_queue_slots - 2]++] =
						target_group[idx];
			}
		} else if (avail_slots) {
			for (i = per_queue_slots - 2; i >= 0; i--) {
				while (pending_routed_count &&
					   (group_idx[i] < target_group_count[i])) {
					idx = i * worker_count + group_idx[i]++;
					send_from_pending_routed(&targets[target_group[idx]]);
					sent[target_group[idx]]++;
					avail_slots--;

					// Add the worker to the next group
					if (i > 0)
						target_group[(i - 1) * worker_count +
									 target_group_count[i - 1]++] =
							target_group[idx];
				}
				if (!pending_routed_count)
					break;
			}
		}
	} while (!force_quit);
}

static void basic_main(void)
{
	/* Start polling loop */
	do {
		net_poll();
	} while (!force_quit);
}

void app_main(void)
{
	srand(time(NULL));

	configure_fdir();
	if (RTE_PER_LCORE(queue_id) % 2)
		basic_main();
	else {
		if (policy == FC) {
			pending_routed_head = NULL;
			pending_routed_tail = NULL;
			pending_routed_count = 0;
			pending_direct_head = NULL;
			pending_direct_tail = NULL;
			pending_direct_count = 0;
			fc_fw_main();
		} else {
			curr_idx = 0;
			jsq_idle_count = 0;
			basic_main();
		}
	}
}
