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
#include <stdio.h>

#include <dp/api.h>
#include <net/net.h>

#include <rte_cycles.h>
#include <rte_flow.h>
#include <rte_timer.h>

#include <r2p2/api-internal.h>
#include <r2p2/api.h>
#include <r2p2/cfg.h>
#include <r2p2/mempool.h>
#ifdef WITH_RAFT
#include <r2p2/hovercraft.h>
#endif
#define TIMER_POOL_SIZE 4096

static __thread uint16_t local_port;
static __thread struct r2p2_host_tuple local_host;
static __thread struct fixed_mempool *client_req_timers;
static __thread uint32_t loop_count;
#ifdef WITH_RAFT
static __thread struct rte_timer raft_timer;
static __thread long raft_timer_last = 0;
#endif

static void dpdk_on_client_pair_free(void *data)
{
	free_object(data);
}

static void handle_timer_for_client_req(struct rte_timer *req_timer, void *arg)
{
	struct r2p2_client_pair *cp = (struct r2p2_client_pair *)arg;

	rte_timer_stop(req_timer);
	timer_triggered(cp);
}

#ifdef FDIR
static int configure_fdir(int queue_id)
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

	attr.ingress = 1;
	// Allow all eth packets
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	/*// Allow all IP packets*/
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4;
	pattern[1].mask = &ipv4_mask;

	/*// Filter UDP based on port*/
	udp.hdr.dst_port = rte_cpu_to_be_16(local_port);
	udp_mask.hdr.dst_port = 0xFFFF;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp;
	pattern[2].mask = &udp_mask;

	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

	queue.index = queue_id;
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue;
	actions[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(0, &attr, pattern, actions, &err);
	if (ret) {
		printf("Error: %s\n", err.message);
		return ret;
	}
	f = rte_flow_create(0, &attr, pattern, actions, &err);
	assert(f);

	return 0;
}
#else
static int configure_fdir(__attribute__((unused)) int queue_id)
{
	return 0;
}
#endif

static struct net_ops app_ops;

static void r2p2lib_udp_recv(struct net_sge *entry, struct ip_tuple *id)
{
	/*struct r2p2_header *r2p2h = entry->payload;*/
	/*if (!is_first(r2p2h)) {*/
	/*pkt_dump(entry->handle);*/
	/*}*/
	/*assert(is_first(r2p2h));*/
	struct rte_mbuf *pkt_buf;
	struct r2p2_host_tuple source;

	source.ip = id->src_ip;
	source.port = id->src_port;
	pkt_buf = entry->handle;
	pkt_buf->userdata = NULL;
	handle_incoming_pck((generic_buffer)entry, entry->len, &source,
						&local_host);
}

#ifdef WITH_RAFT
static void raft_timer_cb(__attribute__((unused)) struct rte_timer *tim,
		__attribute__((unused)) void *arg)
{
	long now = time_us();
	if (now - raft_timer_last < 1000)
		goto OUT;
	r2p2_raft_tick();
OUT:
	raft_timer_last = now;
}
#endif

/*
 * R2P2 public API
 */
int r2p2_init(__attribute__((unused)) int local_port)
{
	app_ops.udp_recv = r2p2lib_udp_recv;
	set_net_ops(&app_ops);

#ifdef WITH_RAFT
	assert(rte_lcore_count() == 2);
	r2p2_raft_init();
#endif

	return 0;
}

int r2p2_init_per_core(int queue_id, __attribute__((unused)) int core_count)
{
#ifdef FDIR
	local_port = get_local_port() + queue_id;
#else
	local_port = get_local_port();
#endif
	local_host.ip = get_local_ip();
	local_host.port = local_port;

	configure_fdir(queue_id);

	// Allocate timers
	client_req_timers =
		create_mempool(TIMER_POOL_SIZE, sizeof(struct rte_timer));
	assert(client_req_timers);

#ifdef WITH_RAFT
	uint64_t hz;

	// Allocate raft timer in raft peers
	rte_timer_init(&raft_timer);
	hz = rte_get_timer_hz();

	/* Start a 1000 Hz timer for raft related ops. */
	rte_timer_reset(&raft_timer, hz / 1000, PERIODICAL, rte_lcore_id(),
			raft_timer_cb, NULL);
#endif

	r2p2_backend_init_per_core();

	return 0;
}

void r2p2_poll(void)
{
	net_poll();
	if (loop_count++ % 256 == 0)
		rte_timer_manage();
#ifdef WITH_RAFT
	do_raft_duties();
#endif
}

/*
 * Generic buffer API
 */
void free_buffer(generic_buffer buffer)
{
	struct net_sge *entry;

	entry = (struct net_sge *)buffer;
	rte_pktmbuf_free(entry->handle);
}

generic_buffer get_buffer(void)
{
	struct net_sge *entry;

	entry = alloc_net_sge();
	assert(entry);

	return (generic_buffer)entry;
}

void *get_buffer_payload(generic_buffer gb)
{
	struct net_sge *entry = (struct net_sge *)gb;
	return entry->payload;
}

uint32_t get_buffer_payload_size(generic_buffer gb)
{
	struct net_sge *entry = (struct net_sge *)gb;
	return entry->len;
}

int set_buffer_payload_size(generic_buffer gb, uint32_t payload_size)
{
	struct net_sge *entry = (struct net_sge *)gb;
	entry->len = payload_size;
	return 0;
}

int chain_buffers(generic_buffer first, generic_buffer second)
{
	struct net_sge *entry = (struct net_sge *)first;
	struct rte_mbuf *pkt_buf = entry->handle;

	pkt_buf->userdata = second;

	return 0;
}

generic_buffer get_buffer_next(generic_buffer gb)
{
	struct net_sge *entry = (struct net_sge *)gb;
	struct rte_mbuf *pkt_buf = entry->handle;

	return pkt_buf->userdata;
}

/*
 * R2P2 internal API
 */

int prepare_to_send(struct r2p2_client_pair *cp)
{
	struct rte_timer *req_timer;
	uint64_t hz;
	double timer_sec;

	req_timer = alloc_object(client_req_timers);
	assert(req_timer);

	rte_timer_init(req_timer);
	hz = rte_get_timer_hz(); // cycles in a second
	timer_sec = cp->ctx->timeout / 1000000.0;

	rte_timer_reset(req_timer, timer_sec * hz, SINGLE, rte_lcore_id(),
					handle_timer_for_client_req, cp);

	cp->timer = req_timer;
	cp->impl_data = (void *)req_timer;
	cp->on_free = dpdk_on_client_pair_free;
	cp->request.sender = local_host;

	return 0;
}

int buf_list_send(generic_buffer first_buf, struct r2p2_host_tuple *dest,
				  __attribute__((unused)) void *socket_info)
{
	generic_buffer gb;
	struct ip_tuple id;
	struct net_sge *entry;

	id.src_ip = get_local_ip();
	id.src_port = local_port;
	id.dst_ip = dest->ip;
	id.dst_port = dest->port;

	gb = first_buf;
	while (gb) {
		entry = (struct net_sge *)gb;
		/* Get next before sending because udp destroys the entry */
		gb = get_buffer_next(gb);
		udp_send(entry, &id);
	}
	return 0;
}

int disarm_timer(void *timer)
{
	struct rte_timer *req_timer = (struct rte_timer *)timer;
	rte_timer_stop(req_timer);
	return 0;
}

void router_notify(uint32_t ip, uint16_t port, uint16_t rid)
{
#if defined(FDIR) || defined(ACCELERATED)
	struct r2p2_host_tuple dest;
	generic_buffer gb;

	dest.ip = CFG.router_addr;
	dest.port = CFG.router_port;

	gb = get_buffer();
	assert(gb);
	set_buffer_payload_size(gb, sizeof(struct r2p2_header) +
			sizeof(struct r2p2_feedback));
	r2p2_prepare_feedback(get_buffer_payload(gb), ip, port, rid);

	buf_list_send(gb, &dest, NULL);
#else
	(void)ip;
	(void)port;
	(void)rid;

#endif
}
