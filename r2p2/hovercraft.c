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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>


#include <r2p2/api-internal.h>
#include <r2p2/utils.h>
#include <r2p2/cfg.h>
#include <r2p2/raft-log.h>
#include <r2p2/mempool.h>
#include <r2p2/raft-stats.h>
#include <r2p2/hovercraft.h>

#include <raft.h>
#include <raft_private.h>

#define MAX_ENTRIES_PER_MSG 30
#define FC_THRESHOLD (1<<14)
#define GB_TRHRESHOLD 1000000
#define BOUNDED_QUEUE 32
#define CTX_POOL_SIZE 8192

extern volatile int force_quit;

// Assume there is only one
static void *raft_impl;
static uint8_t local_raft_id;
static struct r2p2_raft_log *log;
static struct r2p2_server_pair *pending_replicated_reqs[128];
static uint32_t pending_rr_count = 0;
static int real_peer_cnt;
static int done = 0;
static struct r2p2_raft_peer switch_info;
static  struct fixed_mempool *ctx_pool;

#ifdef LB_REPLIES
static uint64_t assigned_log_idx = 0;
static uint32_t announced_commit_idx = 0;
#endif

#ifdef ACCELERATED
#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#define UNORDERED_SIZE 4096
static struct rte_hash *unordered_reqs = NULL;
static uint32_t unordered_count = 0;
#endif

#ifdef SWITCH_AGG
static int switch_is_available = 0;
static struct fixed_linked_list pending_switch_ae_reqs = {0};
#endif

static inline struct r2p2_raft_peer *get_peer_from_id(int id)
{
	// Assume ids are idx in the table
#ifdef SWITCH_AGG
	if (id == 0xFF)
		return &CFG.raft_peers[real_peer_cnt];
	return &CFG.raft_peers[id];
#else
	if (id == 0xFF)
		return &switch_info;
	return &CFG.raft_peers[id];
#endif
};

#ifdef LB_REPLIES
static uint8_t smart_lb(void)
{
	// Find elligible nodes and randomly select among them
	int i, idx = local_raft_id;
	struct r2p2_raft_peer *peer;
	uint32_t min = BOUNDED_QUEUE, local_done, diff;

	for (i=0;i<real_peer_cnt;i++) {
		peer = &CFG.raft_peers[i];
		if (peer->id == local_raft_id)
			local_done = done;
		else
			local_done = peer->done;
		diff = peer->assigned - local_done;
		if (diff < min) {
			min = diff;
			idx = peer->id;
		}
	}

	return idx;
}

static uint8_t bounded_rand(void)
{
	uint8_t candidates[64];
	int idx, candidate_cnt=0, local_done, diff, i;
	struct r2p2_raft_peer *peer;

	for (i=0;i<real_peer_cnt;i++) {
		peer = &CFG.raft_peers[i];
		if (peer->id == local_raft_id)
			local_done = done;
		else
			local_done = peer->done;
		diff = peer->assigned - local_done;
		if (diff < 2*BOUNDED_QUEUE)
			candidates[candidate_cnt++] = i;
	}
	assert(candidate_cnt > 0);
	idx = rand() % candidate_cnt;

	return candidates[idx];
}

static int check_available_slots(void)
{
	int i;
	struct r2p2_raft_peer *peer;
	uint32_t local_done, diff;

	for (i=0;i<real_peer_cnt;i++) {
		peer = &CFG.raft_peers[i];
		if (peer->id == local_raft_id)
			local_done = done;
		else
			local_done = peer->done;
		diff = peer->assigned - local_done;
		if (diff < BOUNDED_QUEUE)
			return 1;
	}

	return 0;
}
#endif

static inline uint8_t pick_replier(void)
{
#ifdef LB_REPLIES
#ifdef SMART_LB
	return smart_lb();
#else
	return bounded_rand();
#endif
#else
	return 0;
#endif
}

/*
 * Flow control
 */
static inline int should_keep_new_entry(void)
{
	return raft_get_current_idx(raft_impl) - raft_get_last_applied_idx(raft_impl) < FC_THRESHOLD;
}

static int entries_to_iov(struct iovec *msg_iov, msg_appendentries_t *ae);
static int msg_to_entries(msg_entry_t *entries, struct gbuffer_reader *gbr,
		int count);
#ifdef ACCELERATED
static int entries_to_iov_accel(struct iovec *msg_iov, msg_appendentries_t *ae);
static int msg_to_entries_accel(msg_entry_t *entries,
		struct gbuffer_reader *gbr, int count);
#endif

/*
 * Raft callbacks
 */
static int r2p2_send_requestvote(raft_server_t* raft, void *user_data,
		raft_node_t* node, msg_requestvote_t* msg);
static int r2p2_send_appendentries(raft_server_t* raft, void *user_data,
    raft_node_t* node, msg_appendentries_t* msg);
static int r2p2_applylog(raft_server_t* raft, void *user_data,
		raft_entry_t *entry, raft_index_t entry_idx);
static int r2p2_persist_vote(raft_server_t* raft, void *user_data,
    raft_node_id_t vote);
static int r2p2_persist_term(raft_server_t* raft, void *user_data,
		raft_term_t term, raft_node_id_t vote);
static int r2p2_log_offer(raft_server_t* raft, void *user_data,
		raft_entry_t *entry, raft_index_t entry_idx);
static int r2p2_log_pop(raft_server_t* raft, void *user_data,
		raft_entry_t *entry, raft_index_t entry_idx);
static void r2p2_became_leader(raft_server_t *raft, void *user_data);
static void r2p2_became_follower(raft_server_t *raft, void *user_data);

#ifdef ACCELERATED
static void garbage_collect_unordered(void)
{
}

static int add_to_unordered_reqs(struct r2p2_server_pair *sp)
{
	int ret;
	hash_sig_t hash;
	struct r2p2_server_pair *old_sp;

	sp->received_at = time_us();
	garbage_collect_unordered();

	hash = rte_hash_hash(unordered_reqs, (char *)&sp->request.sender);
	ret = rte_hash_lookup_with_hash_data(unordered_reqs,
			(char *)&sp->request.sender, hash, (void **)&old_sp);
	if (ret >= 0) {
		if (time_us() - old_sp->received_at > GB_TRHRESHOLD) {
			ret = rte_hash_del_key_with_hash(unordered_reqs,
					(char *)&sp->request.sender, hash);
			free_server_pair(old_sp);
			unordered_count--;
		} else
			return -1;
	}
	ret = rte_hash_add_key_with_hash_data(unordered_reqs, &sp->request.sender,
			hash, sp);
	if (ret)
		return -1;

	unordered_count++;

	return 0;
}

static struct r2p2_server_pair *find_in_unordered_reqs(struct r2p2_msg *in_msg)
{
	struct r2p2_server_pair *sp = NULL;
	int ret;
	hash_sig_t hash;

	hash = rte_hash_hash(unordered_reqs, (char *)in_msg);
	ret = rte_hash_lookup_with_hash_data(unordered_reqs, (char *)in_msg,
	              hash, (void **)&sp);
	if (ret >= 0) {
		ret = rte_hash_del_key_with_hash(unordered_reqs, (char *)in_msg, hash);
		unordered_count--;
	}

	return sp;
}
#endif

static void order_one_req(struct r2p2_server_pair *sp)
{
	struct r2p2_header *r2p2h;
	msg_entry_t ety = {0};
	msg_entry_response_t r;
	int e, total_len;
	generic_buffer gb;

	ety.data.buf = sp;
	total_len = 0;
	gb = sp->request.head_buffer;
	r2p2h = (struct r2p2_header *)get_buffer_payload(gb);
	while (gb) {
		total_len += get_buffer_payload_size(gb);
		gb = get_buffer_next(gb);
	}
	ety.data.len = total_len;

	if (get_policy(r2p2h) == REPLICATED_ROUTE)
		ety.type = RAFT_LOGTYPE_NORMAL;
	else
		ety.type = RAFT_LOGTYPE_NORMAL_NO_SIDE_EFFECTS;
	ety.replier = local_raft_id;
	e = raft_recv_entry(raft_impl, &ety, &r);
	if (e) {
		printf("Raft error is %d\n", e);
		assert(0);
	}
}

static void	send_raft_msg(int to_id, union generic_raft_msg *msg,
		int msg_type, void *pair);

static void raft_reply_recved(long handle, void *arg,
		__attribute__((unused))struct iovec *iov,
		__attribute__((unused))int iovcnt)
{
	struct r2p2_client_pair *cp = (struct r2p2_client_pair *)handle;
	struct r2p2_ctx *ctx;
	struct r2p2_raft_peer **peer;
	int *ctx_msg_type;

	ctx = (struct r2p2_ctx *) arg;
	peer = (struct r2p2_raft_peer **)(ctx+1);
	ctx_msg_type = (int *)(peer+1);

	if (*ctx_msg_type == APPEND_ENTRIES_REQ)
		(*peer)->pending_ae = 0;

	free_object(arg);

	raft_process(&cp->reply);
	r2p2_recv_resp_done(handle);
}

static void raft_request_err(__attribute__((unused))void *arg,
		__attribute__((unused))int err)
{
	assert(0);
}

static void raft_request_timeout(void *arg)
{
	struct r2p2_ctx *ctx;
	struct r2p2_raft_peer **peer;
	int *ctx_msg_type;

	ctx = (struct r2p2_ctx *) arg;
	peer = (struct r2p2_raft_peer **)(ctx+1);
	ctx_msg_type = (int *)(peer+1);

	if (*ctx_msg_type == APPEND_ENTRIES_REQ)
		(*peer)->pending_ae = 0;

	printf("Request timeout for req type: %d to %x\n", *ctx_msg_type,
			ctx->destination->ip);
	free_object(arg);
}

raft_cbs_t callbacks = {
	.send_requestvote   = r2p2_send_requestvote,
	.send_appendentries = r2p2_send_appendentries,
	.applylog           = r2p2_applylog,
	.persist_vote       = r2p2_persist_vote,
	.persist_term       = r2p2_persist_term,
	.log_offer          = r2p2_log_offer,
	.log_pop            = r2p2_log_pop,
	.became_leader      = r2p2_became_leader,
	.became_follower    = r2p2_became_follower,
};

static int r2p2_send_requestvote(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data,
		raft_node_t* node, msg_requestvote_t* msg)
{
	struct r2p2_raft_peer *peer = raft_node_get_udata(node);
	send_raft_msg(peer->id, (union generic_raft_msg *)msg, VOTE_REQUEST, NULL);

	return 0;
}

static int r2p2_send_appendentries(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data, raft_node_t* node,
		msg_appendentries_t* msg)
{
	struct r2p2_raft_peer *peer = raft_node_get_udata(node);

	// Check if outstanding append entries. If yes leave
	if (peer->pending_ae)
		return 0;

	if (msg->n_entries > MAX_ENTRIES_PER_MSG)
		msg->n_entries = MAX_ENTRIES_PER_MSG;
#ifdef LB_REPLIES
	if ((msg->prev_log_idx + msg->n_entries > raft_get_commit_idx(raft_impl)) &&
			!check_available_slots())
		msg->n_entries = 1;

	uint64_t start, end, i;
	struct r2p2_server_pair *sp;
	start = msg->prev_log_idx + 1;
	end = msg->prev_log_idx + msg->n_entries;
	while (assigned_log_idx < end) {
		i = ++assigned_log_idx - start;
		msg->entries[i].replier = pick_replier();
		if (msg->entries[i].replier != local_raft_id) {
			sp = msg->entries[i].data.buf;
			sp->flags &= ~SHOULD_REPLY;
		}
		if (msg->entries[i].type == RAFT_LOGTYPE_NORMAL)
			for (int j=0;j<real_peer_cnt;j++)
				get_peer_from_id(j)->assigned++;
		else
			get_peer_from_id(msg->entries[i].replier)->assigned++;
	}
#endif

	peer->pending_ae = 1;
	send_raft_msg(peer->id, (union generic_raft_msg *)msg, APPEND_ENTRIES_REQ,
			NULL);

	return 0;
}

static int r2p2_applylog(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data, raft_entry_t *entry,
		__attribute__((unused))raft_index_t entry_idx)
{
	struct r2p2_server_pair *sp;

	sp = entry->data.buf;
	assert(sp);
#ifdef SKIP_NO_SE
	if ((entry->type == RAFT_LOGTYPE_NORMAL_NO_SIDE_EFFECTS) &&
			(entry->replier != local_raft_id))
		return 0;
#endif
#ifdef RAFT_STATS
	struct raft_stats rs;
	rs.type = entry->type;
	long before = time_us();
#endif
	forward_request(sp);
#ifdef RAFT_STATS
	long after = time_us();
	rs.duration = after - before;
	raft_stats_log(&rs);
#endif
	done++;

	return 0;
}

static int r2p2_persist_vote(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data,
		__attribute__((unused))raft_node_id_t vote)
{
	return 0;
}

static int r2p2_persist_term(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data,
		__attribute__((unused))raft_term_t term,
		__attribute__((unused))raft_node_id_t vote)
{
	return 0;
}

static int r2p2_log_offer(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data, raft_entry_t *entry,
		__attribute__((unused))raft_index_t entry_idx)
{
	int res;
	struct r2p2_server_pair *sp;

	sp = entry->data.buf;
	if (entry->replier == local_raft_id)
		sp->flags |= SHOULD_REPLY;
	res = r2p2_raft_log_add(entry);
	assert(!res);

	return 0;
}

static int r2p2_log_pop(__attribute__((unused))raft_server_t* raft,
		__attribute__((unused))void *user_data,
		__attribute__((unused))raft_entry_t *entry,
		__attribute__((unused))raft_index_t entry_idx)
{
	assert(0);
	return 0;
}

static void r2p2_became_leader(__attribute__((unused))raft_server_t *raft,
		__attribute__((unused))void *user_data)
{
	printf("\n\n\n\n I'm the new leader\n\n\n\n");
#ifdef LB_REPLIES
	struct r2p2_raft_peer *peer;
	int i;

	assigned_log_idx = raft_get_current_idx(raft_impl);
	done = 0;
	for (i=0;i<real_peer_cnt;i++) {
		peer = &CFG.raft_peers[i];
		peer->assigned = 0;
		peer->done = 0;
	}
#endif
#ifndef SWITCH_AGG
	msg_appendentries_t ae_req = {0};

	// Notify the vanilla switch that the leader changed
	send_raft_msg(0xFF, (union generic_raft_msg *)&ae_req, APPEND_ENTRIES_REQ,
			NULL);
	printf("Notified the switch\n");
#endif
#ifdef ACCELERATED
	// Try freeing the unordered count too
	struct r2p2_server_pair *sp = NULL;
	char *key;
	uint32_t it=0;

	if (!unordered_count)
		return;

	while (rte_hash_iterate(unordered_reqs, (const void **)&key, (void **)&sp, &it) > 0) {
		assert(sp);
		find_in_unordered_reqs(&sp->request);
		free_server_pair(sp);
	}
#endif
}

static void r2p2_became_follower(__attribute__((unused))raft_server_t *raft,
		__attribute__((unused))void *user_data)
{
#ifdef LB_REPLIES
	done = 0;
#endif
#ifdef ACCELERATED
	struct r2p2_server_pair *sp = NULL;
	char *key;
	uint32_t it=0;

	if (!unordered_count)
		return;

	while (rte_hash_iterate(unordered_reqs, (const void **)&key, (void **)&sp, &it) > 0) {
		assert(sp);
		find_in_unordered_reqs(&sp->request);
		free_server_pair(sp);
	}
#endif
}

static void	send_raft_msg(int to_id, union generic_raft_msg *msg, int msg_type,
		void *pair)
{
	// Raft messages are single packet messages
	struct iovec msg_iov[2048];
	char buf[1500];
	struct raft_generic_header *gr_h;
	struct raft_generic_req_header *gr_req_h;
	struct raft_vote_rep_header *vt_rep_h;
	struct raft_append_entries_req_header *ae_req_h;
	struct raft_append_entries_rep_header *ae_rep_h;
	int e_iov_cnt = 0;
	struct r2p2_ctx *ctx;
	struct r2p2_raft_peer **peer;
	int *ctx_msg_type;

	// if it's a request
	if (!pair) {
		ctx = alloc_object(ctx_pool);
		assert(ctx);
		ctx->success_cb     = raft_reply_recved,
		ctx->error_cb       = raft_request_err,
		ctx->timeout_cb     = raft_request_timeout,
		ctx->timeout        = 1000,
		ctx->routing_policy = FIXED_ROUTE,
		ctx->destination = &get_peer_from_id(to_id)->host;
		ctx->arg = ctx;
		peer = (struct r2p2_raft_peer **)(ctx+1);
		ctx_msg_type = (int *)(peer+1);
		*peer = get_peer_from_id(to_id);
		*ctx_msg_type = msg_type;
	} else
		ctx = NULL;

	msg_iov[0].iov_base = buf;
	gr_h = (struct raft_generic_header *)buf;
	gr_h->from_id = local_raft_id;
	gr_h->msg_type = msg_type;

	switch (msg_type) {
		case VOTE_REQUEST:
			printf("send vote request\n");
			gr_h->term = msg->vote_req.term;
			gr_h->from_id = msg->vote_req.candidate_id;
			gr_req_h = (struct raft_generic_req_header *)(gr_h+1);
			gr_req_h->last_log_idx = htonl(msg->vote_req.last_log_idx);
			gr_req_h->last_log_term = msg->vote_req.last_log_term;
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_generic_req_header);
			r2p2_send_raft_req(msg_iov, 1, ctx);
			break;
		case VOTE_REPLY:
			gr_h->term = msg->vote_rep.term;
			vt_rep_h = (struct raft_vote_rep_header *)(gr_h+1);
			vt_rep_h->granted = msg->vote_rep.vote_granted;
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_vote_rep_header);
			r2p2_send_raft_response((long)pair, msg_iov, 1);
			break;
		case APPEND_ENTRIES_REQ:
			gr_h->term = msg->ae_req.term;
			gr_req_h = (struct raft_generic_req_header *)(gr_h+1);
			gr_req_h->last_log_idx = htonl(msg->ae_req.prev_log_idx);
			gr_req_h->last_log_term = msg->ae_req.prev_log_term;
			ae_req_h = (struct raft_append_entries_req_header *)(gr_req_h+1);
			ae_req_h->leader_commit_idx = htonl(msg->ae_req.leader_commit);
			ae_req_h->entries_count = htonl(msg->ae_req.n_entries);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_generic_req_header) +
				sizeof(struct raft_append_entries_req_header);
#ifdef ACCELERATED
			e_iov_cnt = entries_to_iov_accel(&msg_iov[1], &msg->ae_req);
#else
			e_iov_cnt = entries_to_iov(&msg_iov[1], &msg->ae_req);
#endif
			if (e_iov_cnt > 2048)
				printf("There are %d entries to send\n", msg->ae_req.n_entries);
			assert(e_iov_cnt <= 2048);
			r2p2_send_raft_req(msg_iov, 1+e_iov_cnt, ctx);
			break;
		case APPEND_ENTRIES_REP:
			gr_h->term = msg->ae_rep.term;
			ae_rep_h = (struct raft_append_entries_rep_header *)(gr_h+1);
			ae_rep_h->success = msg->ae_rep.success;
			ae_rep_h->last_log_idx = htonl(msg->ae_rep.current_idx);
			ae_rep_h->first_idx = htonl(msg->ae_rep.first_idx);
			ae_rep_h->done = htonl(done);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_append_entries_rep_header);
#ifdef SWITCH_AGG
			if (!pair)
				r2p2_send_raft_msg(&get_peer_from_id(to_id)->host, msg_iov, 1);
			else
				r2p2_send_raft_response((long)pair, msg_iov, 1);
#else
			r2p2_send_raft_response((long)pair, msg_iov, 1);
#endif
			break;
		case ANNOUNCE_COMMIT_REQ:
			gr_h->term = msg->ae_req.term;
			gr_req_h = (struct raft_generic_req_header *)(gr_h+1);
			gr_req_h->last_log_idx = htonl(msg->ae_req.prev_log_idx);
			gr_req_h->last_log_term = msg->ae_req.prev_log_term;
			ae_req_h = (struct raft_append_entries_req_header *)(gr_req_h+1);
			ae_req_h->leader_commit_idx = htonl(msg->ae_req.leader_commit);
			ae_req_h->entries_count = htonl(msg->ae_req.n_entries);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_generic_req_header) +
				sizeof(struct raft_append_entries_req_header);
			r2p2_send_raft_req(msg_iov, 1, ctx);
			break;
		case ANNOUNCE_COMMIT_REP:
			ae_rep_h = (struct raft_append_entries_rep_header *)(gr_h+1);
			ae_rep_h->done = htonl(done);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_append_entries_rep_header);
			r2p2_send_raft_response((long)pair, msg_iov, 1);
			break;
#ifdef ACCELERATED
		case RECOVERY_REQ:
			gr_h->term = msg->ae_rep.term;
			ae_rep_h = (struct raft_append_entries_rep_header *)(gr_h+1);
			ae_rep_h->success = msg->ae_rep.success;
			ae_rep_h->last_log_idx = htonl(msg->ae_rep.current_idx);
			ae_rep_h->first_idx = htonl(msg->ae_rep.first_idx);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_append_entries_rep_header);
			r2p2_send_raft_req(msg_iov, 1, ctx);

			break;
		case RECOVERY_REP:
			gr_h->term = msg->ae_req.term;
			gr_req_h = (struct raft_generic_req_header *)(gr_h+1);
			gr_req_h->last_log_idx = htonl(msg->ae_req.prev_log_idx);
			gr_req_h->last_log_term = msg->ae_req.prev_log_term;
			ae_req_h = (struct raft_append_entries_req_header *)(gr_req_h+1);
			ae_req_h->leader_commit_idx = htonl(msg->ae_req.leader_commit);
			ae_req_h->entries_count = htonl(msg->ae_req.n_entries);
			msg_iov[0].iov_len = sizeof(struct raft_generic_header) +
				sizeof(struct raft_generic_req_header) +
				sizeof(struct raft_append_entries_req_header);
			e_iov_cnt = entries_to_iov(&msg_iov[1], &msg->ae_req);
			r2p2_send_raft_response((long)pair, msg_iov, 1+e_iov_cnt);
			break;
#endif
		default:
			assert(0);
			break;
	}
}

static int entries_to_iov(struct iovec *msg_iov, msg_appendentries_t *ae)
{
	int i, count;
	struct r2p2_server_pair *sp;
	generic_buffer gb;


	count = 0;
	for (i=0;i<ae->n_entries;i++) {
		//msg_entry
		msg_iov[count].iov_base = &ae->entries[i];
		msg_iov[count++].iov_len = sizeof(raft_entry_t);

		sp = ae->entries[i].data.buf;
        if (!sp) {
			printf("Entry without server pair. Asked for %ld entries\n",
                    raft_get_current_idx(raft_impl) - ae->prev_log_idx);
            printf("Leader is at %ld log idx\n",
                    raft_get_current_idx(raft_impl));
			for (int i=0;i<real_peer_cnt;i++) {
				printf("Node %d next idx %ld\n", i,
						raft_node_get_next_idx(CFG.raft_peers[i].node));
			}
		}
		assert(sp);
		// struct r2p2_msg
		msg_iov[count].iov_base = &sp->request;
		msg_iov[count++].iov_len = sizeof(struct r2p2_msg);

		// actual payload
		gb = sp->request.head_buffer;
		while(gb) {
			msg_iov[count].iov_base = get_buffer_payload(gb);
			msg_iov[count++].iov_len = get_buffer_payload_size(gb);
			gb = get_buffer_next(gb);
		}
	}

	return count;
}

static int msg_to_entries(msg_entry_t *entries, struct gbuffer_reader *gbr,
		int count)
{
	int i, res;
	struct r2p2_server_pair *sp = NULL;
	struct r2p2_header *r2p2h;
	generic_buffer new_buffer;
	int payload_left, to_copy;
	char *dst;

	for (i=0;i<count;i++) {
		// Read entry
		res = gbuffer_read(gbr, (char *)&entries[i], sizeof(raft_entry_t));
		assert(res == sizeof(raft_entry_t));

		// Read msg
		sp = alloc_server_pair();
		entries[i].data.buf = sp;
		res = gbuffer_read(gbr, (char *)&sp->request, sizeof(struct r2p2_msg));
		assert(res == sizeof(struct r2p2_msg));
		sp->request.head_buffer = NULL;
		sp->request.tail_buffer = NULL;

		// Read payload
		// Check if multi or single packet msg
		payload_left = entries[i].data.len;
		new_buffer = get_buffer();
		assert(new_buffer);
		dst = get_buffer_payload(new_buffer);
		res = gbuffer_read(gbr, dst, sizeof(struct r2p2_header));
		assert(res == sizeof(struct r2p2_header));
		r2p2h = (struct r2p2_header *)dst;
		assert(r2p2h->magic == MAGIC);
		dst += sizeof(struct r2p2_header);
		payload_left -= sizeof(struct r2p2_header);
		if (is_last(r2p2h)) {
			// single-packet request
			gbuffer_read(gbr, dst, payload_left);
			set_buffer_payload_size(new_buffer, entries[i].data.len);
			r2p2_msg_add_payload(&sp->request, new_buffer);
		} else {
			assert(0);
			// multi-packet request
			// first read the first small packet
			gbuffer_read(gbr, dst, MIN_PAYLOAD_SIZE);
			set_buffer_payload_size(new_buffer,
					MIN_PAYLOAD_SIZE+sizeof(struct r2p2_header));
			r2p2_msg_add_payload(&sp->request, new_buffer);
			payload_left -= get_buffer_payload_size(new_buffer);
			while(payload_left) {
				to_copy = min(payload_left, (int)(PAYLOAD_SIZE+sizeof(struct r2p2_header)));
				new_buffer = get_buffer();
				assert(new_buffer);
				dst = get_buffer_payload(new_buffer);
				res = gbuffer_read(gbr, dst, to_copy);
				assert(res == to_copy);
				set_buffer_payload_size(new_buffer, to_copy);
				r2p2_msg_add_payload(&sp->request, new_buffer);
				payload_left -= to_copy;
			}
		}
	}
	return count;
}

#ifdef ACCELERATED
static int entries_to_iov_accel(struct iovec *msg_iov, msg_appendentries_t *ae)
{
	int i, count;
	struct r2p2_server_pair *sp;
	raft_entry_t *ety;

	count = 0;
	for (i=0;i<ae->n_entries;i++) {
		ety = &ae->entries[i];
		// term, id, type, replier
		msg_iov[count].iov_base = ety;
		msg_iov[count++].iov_len = (sizeof(long int) + sizeof(int) + sizeof(int)) + sizeof(char);

		sp = ety->data.buf;
        if (!sp) {
			printf("Entry without server pair. Asked for %ld entries\n",
                    raft_get_current_idx(raft_impl) - ae->prev_log_idx);
            printf("Leader is at %ld log idx\n",
                    raft_get_current_idx(raft_impl));
			for (int i=0;i<real_peer_cnt;i++) {
				printf("Node %d next idx %ld\n", i,
						raft_node_get_next_idx(CFG.raft_peers[i].node));
			}
		}
		assert(sp);
		msg_iov[count].iov_base = &sp->request;
		msg_iov[count++].iov_len = sizeof(struct r2p2_host_tuple)
			+ sizeof(uint16_t);
	}

	return count;
}

static int msg_to_entries_accel(msg_entry_t *entries,
		struct gbuffer_reader *gbr, int count)
{
	int i, res, total_len;
	struct r2p2_server_pair *sp = NULL;
	struct r2p2_msg msg;
	generic_buffer gb;

	for (i=0;i<count;i++) {
		// Read term, id and type
		res = gbuffer_read(gbr, (char *)&entries[i],
				sizeof(long int) + 2*sizeof(int) + sizeof(char));
		assert(res == sizeof(long int)+2*sizeof(int)+sizeof(char));

		// Read sender and rid
		res = gbuffer_read(gbr, (char *)&msg,
				sizeof(struct r2p2_host_tuple)+sizeof(uint16_t));
		assert(res == sizeof(struct r2p2_host_tuple)+sizeof(uint16_t));

		/*
		 * Find request. The request might be missing and sp will be node
		 * Raft code will handle this accordingly
		 */
		sp = find_in_unordered_reqs(&msg);
		entries[i].data.buf = sp;
		total_len = 0;
		if (sp) {
			// Add the total length too
			gb = sp->request.head_buffer;
			while (gb) {
				total_len += get_buffer_payload_size(gb);
				gb = get_buffer_next(gb);
			}
		}
		entries[i].data.len = total_len;
	}
	return count;
}
#endif

static void leader_order_requests(void)
{
	uint32_t i;
	struct r2p2_server_pair *sp;

	for (i=0;i<pending_rr_count;i++) {
		sp = pending_replicated_reqs[i];
		order_one_req(sp);
		// We can free the server pair because the ones in the log are used
		free_object(sp);
	}
	pending_rr_count = 0;
}

#ifdef SWITCH_AGG
static int check_switch_ae_req_compatibility(struct r2p2_server_pair *sp)
{
	struct r2p2_header *r2p2h;
	struct raft_generic_header *gr_h;
	struct raft_generic_req_header *gr_req_h;
	uint32_t prev_log_idx;

	assert(sp);
	printf("Check req from %x %d\n", sp->request.sender.ip, sp->request.sender.port);
	r2p2h = get_buffer_payload(sp->request.head_buffer);
	assert(r2p2h);
	gr_h = (struct raft_generic_header *)(r2p2h+1);
	gr_req_h = (struct raft_generic_req_header *)(gr_h+1);

	prev_log_idx = ntohl(gr_req_h->last_log_idx);

	printf("Check compatibility: prev %d mine %d. %d\n", prev_log_idx,
			raft_get_current_idx(raft_impl),
			prev_log_idx <= raft_get_current_idx(raft_impl)
		  );
	return prev_log_idx <= raft_get_current_idx(raft_impl);
}

static int check_switch_ae_req_compatibility_top(void)
{
	struct r2p2_server_pair *sp;
	struct fixed_obj *fo;

	fo = peek_from_list(&pending_switch_ae_reqs);
	assert(fo);

	sp = (struct r2p2_server_pair *)fo->elem;
	return check_switch_ae_req_compatibility(sp);
}

static int pending_switch_ae_req_is_empty(void)
{
	return pending_switch_ae_reqs.head == NULL;
}

static void follower_recover(void)
{
	struct r2p2_server_pair *sp;
	struct fixed_obj *fo;

	fo = peek_from_list(&pending_switch_ae_reqs);
	if (fo) {
		sp = (struct r2p2_server_pair *)fo->elem;
		if (check_switch_ae_req_compatibility(sp)) {
			remove_from_list(&pending_switch_ae_reqs, fo);
			raft_process(&sp->request);
		}
	}
}
#endif

#ifdef LB_REPLIES
static void announce_increased_commit(void)
{
#ifdef SWITCH_AGG
#else
	int i;
	//printf("Announce commit %d\n", announced_commit_idx);
	msg_appendentries_t msg;
	struct r2p2_raft_peer *peer;
	raft_index_t next_idx;
	raft_entry_t* prev_ety;

	msg.term = raft_get_current_term(raft_impl);
	msg.leader_commit = raft_get_commit_idx(raft_impl);
	msg.n_entries = 0;
	msg.entries = NULL;
	for (i=0;i<real_peer_cnt;i++) {
		if (i == local_raft_id)
			continue;
		peer = get_peer_from_id(i);
		next_idx = raft_node_get_next_idx(peer->node);
		if (next_idx > 1){
			prev_ety = raft_get_entry_from_idx(raft_impl, next_idx - 1);
			assert(prev_ety);
			// assume no snapshoting
			msg.prev_log_idx = next_idx - 1;
			msg.prev_log_term = prev_ety->term;
		} else {
			msg.prev_log_idx = 0;
			msg.prev_log_term = 0;
		}
#ifndef VIEW_CHANGE_EXP
		// FIXME: check if a node has fallen behind too much or turn this
		// to a multicast single message instead
		send_raft_msg(peer->id, (union generic_raft_msg *)&msg,
				ANNOUNCE_COMMIT_REQ, NULL);
#endif
	}
#endif
}
#endif

void r2p2_raft_tick(void)
{
	raft_periodic(raft_impl, 1);
}

int r2p2_raft_init(void)
{
	int i, is_self, no_phantom;
	struct r2p2_raft_peer *peer;

	srand (time(NULL));
	raft_impl = raft_new();

	ctx_pool = create_mempool(CTX_POOL_SIZE, sizeof(struct r2p2_ctx)
			+ sizeof(struct r2p2_raft_peer **) + sizeof(int));
	assert(ctx_pool);

	no_phantom = CFG.raft_peers_cnt % 2;
	if (no_phantom)
		real_peer_cnt = CFG.raft_peers_cnt;
	else
		real_peer_cnt = CFG.raft_peers_cnt - 1;
	for (i=0;i<real_peer_cnt;i++) {
		peer = &CFG.raft_peers[i];
		is_self = peer->host.ip == CFG.host_addr;
		if (is_self)
			local_raft_id = peer->id;
		peer->node = raft_add_node(raft_impl, peer, peer->id, is_self);
		peer->pending_ae = 0;
	}

	// Configure switch info
	switch_info.id = 0xFF;
	switch_info.host.ip = CFG.router_addr;
	switch_info.host.port = CFG.router_port;

	//raft_set_callbacks(raft_impl, &callbacks, &impl_data);
	raft_set_callbacks(raft_impl, &callbacks, NULL);

	/* initialize log */
	log = r2p2_raft_log_init();

	/* set application frow control */
	r2p2_set_app_flow_control_fn(should_keep_new_entry);
#ifdef RAFT_STATS
	/* initialise stats */
	if (raft_stats_init()) {
		fprintf(stderr, "failed to init raft stats\n");
		return -1;
	}
#endif
#ifdef ACCELERATED
	struct rte_hash_parameters pending_sp_hash_params = {
		.name = "unordered-reqs-hash-table",
		.entries = UNORDERED_SIZE,
		.key_len = sizeof(struct r2p2_host_tuple) + sizeof(uint16_t), // 3 tuple
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),

	};
	unordered_reqs = rte_hash_create(&pending_sp_hash_params);
	assert(unordered_reqs);
#endif
#ifdef SWITCH_AGG
	CFG.raft_peers[real_peer_cnt].id = 0xFF;
	CFG.raft_peers[real_peer_cnt].node = NULL;
	CFG.raft_peers[real_peer_cnt].pending_ae = 0;
	raft_set_phantom_udata(&CFG.raft_peers[real_peer_cnt]);
#endif

	return 0;
}

static void process_ae_req_vanilla(msg_appendentries_t *msg,
		struct gbuffer_reader *gbr, struct raft_generic_header *gr_h,
		struct r2p2_server_pair *raft_req_pair)
{
	int res, i;
	msg_appendentries_response_t ae_rep;
	msg_entry_t entries[1024];
	struct r2p2_server_pair *sp;

	msg_to_entries(entries, gbr, msg->n_entries);
	msg->entries = entries;

	res = raft_recv_appendentries(raft_impl,
			get_peer_from_id(gr_h->from_id)->node, msg, &ae_rep);
	assert(res == 0);

	// Send the reply
	send_raft_msg(gr_h->from_id, (union generic_raft_msg *)&ae_rep,
			APPEND_ENTRIES_REP, raft_req_pair);

	// Free
	for (i=0;i<msg->n_entries;i++) {
		sp = entries[i].data.buf;
		// if entry was used free only the server pair
		if (entries[i].data.len == 0)
			free_object(sp);
		else
			free_server_pair(sp);
	}
}

#ifdef ACCELERATED
static void process_ae_req_accel(msg_appendentries_t *msg,
		struct gbuffer_reader *gbr, struct raft_generic_header *gr_h,
		struct r2p2_server_pair *raft_req_pair)
{
	int res, i;
	msg_appendentries_response_t ae_rep;
	msg_appendentries_response_t req_recovery;
	msg_entry_t entries[1024];
	struct r2p2_server_pair *sp;

	msg_to_entries_accel(entries, gbr, msg->n_entries);
	msg->entries = entries;

	res = raft_recv_appendentries(raft_impl,
			get_peer_from_id(gr_h->from_id)->node, msg, &ae_rep);
	assert(res == 0);

	// Handle partial succes (missing request)
	if (ae_rep.success == AE_PARTIAL_SUCCESS_MISSING) {
		// set reply to success and send a recovery request to the leader
		// or anyone else
		ae_rep.success = AE_SUCCESS;

		req_recovery.term = raft_get_current_term(raft_impl);
		req_recovery.success = AE_SUCCESS;
		req_recovery.current_idx = raft_get_current_idx(raft_impl);
		req_recovery.first_idx = 0;

		send_raft_msg(raft_get_current_leader(raft_impl),
				(union generic_raft_msg *)&req_recovery, RECOVERY_REQ, NULL);
	}

	// Send the reply
	send_raft_msg(gr_h->from_id, (union generic_raft_msg *)&ae_rep,
			APPEND_ENTRIES_REP, raft_req_pair);

	// Free
	for (i=0;i<msg->n_entries;i++) {
		sp = entries[i].data.buf;
		// if there was a missing entry continue
		if (!sp)
			continue;
		// if entry was used free only the server pair
		if (entries[i].data.len == 0)
			free_object(sp);
		else {
			// Put the unused entries back in the unordered set
			if (add_to_unordered_reqs(entries[i].data.buf))
				assert(0);
		}
	}
}

#ifdef SWITCH_AGG
static void process_ae_req_switch_accel(msg_appendentries_t *msg,
		struct gbuffer_reader *gbr, struct raft_generic_header *gr_h,
		struct r2p2_server_pair *raft_req_pair)
{
	int res, i, added_to_pending = 0;
	msg_appendentries_response_t ae_rep;
	msg_entry_t entries[1024];
	struct r2p2_server_pair *sp;


	if (msg->prev_log_idx > raft_get_current_idx(raft_impl)) {
		// node has fallen behind. Keep request and send a failure
		add_to_list(&pending_switch_ae_reqs, get_object_meta(raft_req_pair));
		msg->n_entries = 0;
		msg->entries = NULL;
		added_to_pending = 1;
	} else {
		msg_to_entries_accel(entries, gbr, msg->n_entries);
		msg->entries = entries;
	}

	res = raft_recv_appendentries(raft_impl,
			get_peer_from_id(gr_h->from_id)->node, msg, &ae_rep);
	assert(res == 0);

	// Handle partial succes (missing request)
	if (ae_rep.success == AE_PARTIAL_SUCCESS_MISSING) {
		// send a recovery request to the leader or anyone
		assert(0);
		ae_rep.success = AE_SUCCESS;
	} else if (ae_rep.success == AE_FAILURE) {
		printf("Append entries failed. Sent from %d\n", gr_h->from_id);
		if (!added_to_pending)
			free_server_pair(raft_req_pair);
		send_raft_msg(gr_h->from_id, (union generic_raft_msg *)&ae_rep,
				APPEND_ENTRIES_REP, NULL);
	} else {
		/*
		 * It's a success. If the sender is the master try to recover
		 * missing ae_reqs by sending a failure indestead. If no need to
		 * recover or request comes from the switch reply success
		 */
		if ((raft_req_pair->request.sender.ip !=
					get_peer_from_id(0xFF)->host.ip) &&
				!pending_switch_ae_req_is_empty() &&
				!check_switch_ae_req_compatibility_top()) {
			printf("Will ask for the missing\n");
			ae_rep.success = AE_SUCCESS_NEED_MORE;
		}
		send_raft_msg(gr_h->from_id, (union generic_raft_msg *)&ae_rep,
				APPEND_ENTRIES_REP, raft_req_pair);
	}

	// Free
	for (i=0;i<msg->n_entries;i++) {
		sp = entries[i].data.buf;
		// if there was a missing entry continue
		if (!sp)
			continue;
		// if entry was used free only the server pair
		if (entries[i].data.len == 0)
			free_object(sp);
		else {
			// Put the unused entries back in the unordered set
			if (add_to_unordered_reqs(entries[i].data.buf))
				assert(0);
		}
	}

	if (ae_rep.success)
		follower_recover();
}
#endif
#endif

void raft_process(struct r2p2_msg *in_msg)
{
	// Process raft messages
	union generic_raft_msg msg;
	union generic_raft_msg resp;
	struct raft_generic_header gr_h;
	struct raft_generic_req_header gr_req_h;
	struct raft_vote_rep_header vt_rep_h;
	struct raft_append_entries_req_header ae_req_h;
	struct raft_append_entries_rep_header ae_rep_h;
	struct gbuffer_reader gbr;
	int res;
	struct r2p2_raft_peer *peer;
	struct r2p2_server_pair *raft_req_pair;
#ifdef ACCELERATED
	msg_entry_t *missing_entry;
	msg_entry_t recovered_entry;
	union generic_raft_msg recovery_rep;
#endif

	bzero(&msg, sizeof(union generic_raft_msg));
	bzero(&resp, sizeof(union generic_raft_msg));
	gbuffer_reader_init(&gbr, in_msg->head_buffer);

	res = gbuffer_read(&gbr, (char *)&gr_h, sizeof(struct raft_generic_header));
	assert(res == sizeof(struct raft_generic_header));
	switch (gr_h.msg_type) {
		case VOTE_REQUEST:
			res = gbuffer_read(&gbr, (char *)&gr_req_h, sizeof(struct raft_generic_req_header));
			assert(res == sizeof(struct raft_generic_req_header));
			msg.vote_req.term = gr_h.term;
			msg.vote_req.candidate_id = gr_h.from_id;
			msg.vote_req.last_log_idx = ntohl(gr_req_h.last_log_idx);
			msg.vote_req.last_log_term = gr_req_h.last_log_term;
			res = raft_recv_requestvote(raft_impl,
					get_peer_from_id(gr_h.from_id)->node, &msg.vote_req,
					&resp.vote_rep);
			assert(res == 0);

			/* Send the reply */
			send_raft_msg(gr_h.from_id, &resp, VOTE_REPLY,
					container_of(in_msg, struct r2p2_server_pair, request));
			break;
		case VOTE_REPLY:
#ifdef SWITCH_AGG
			if (gr_h.from_id == 0xFF) {
				switch_is_available = 1;
				break;
			}
#endif
			res = gbuffer_read(&gbr, (char *)&vt_rep_h, sizeof(struct raft_vote_rep_header));
			assert(res == sizeof(struct raft_vote_rep_header));
			msg.vote_rep.term = gr_h.term;
			msg.vote_rep.vote_granted = vt_rep_h.granted;
			res = raft_recv_requestvote_response(raft_impl,
					get_peer_from_id(gr_h.from_id)->node, &msg.vote_rep);
			assert(res == 0);
			break;
		case APPEND_ENTRIES_REQ:
			res = gbuffer_read(&gbr, (char *)&gr_req_h, sizeof(struct raft_generic_req_header));
			assert(res == sizeof(struct raft_generic_req_header));
			res = gbuffer_read(&gbr, (char *)&ae_req_h, sizeof(struct raft_append_entries_req_header));
			assert(res == sizeof(struct raft_append_entries_req_header));

			msg.ae_req.n_entries = ntohl(ae_req_h.entries_count);
			msg.ae_req.term = gr_h.term;
			msg.ae_req.prev_log_idx = ntohl(gr_req_h.last_log_idx);
			msg.ae_req.prev_log_term = gr_req_h.last_log_term;
			msg.ae_req.leader_commit = ntohl(ae_req_h.leader_commit_idx);

			raft_req_pair = container_of(in_msg, struct r2p2_server_pair,
					request);
#ifdef ACCELERATED
#ifdef SWITCH_AGG
			process_ae_req_switch_accel(&msg.ae_req, &gbr, &gr_h,
					raft_req_pair);
#else
			process_ae_req_accel(&msg.ae_req, &gbr, &gr_h, raft_req_pair);
#endif
#else
			process_ae_req_vanilla(&msg.ae_req, &gbr, &gr_h, raft_req_pair);
#endif

			break;
		case APPEND_ENTRIES_REP:
			res = gbuffer_read(&gbr, (char *)&ae_rep_h, sizeof(struct raft_append_entries_rep_header));
			assert(res == sizeof(struct raft_append_entries_rep_header));
			msg.ae_rep.term = gr_h.term;
			msg.ae_rep.success = ae_rep_h.success;
			msg.ae_rep.current_idx = ntohl(ae_rep_h.last_log_idx);
			msg.ae_rep.first_idx = ntohl(ae_rep_h.first_idx);
			peer = get_peer_from_id(gr_h.from_id);
			peer->done = ntohl(ae_rep_h.done);
			res = raft_recv_appendentries_response(raft_impl,
					get_peer_from_id(gr_h.from_id)->node, &msg.ae_rep);
			if (res)
				printf("AE response is %d\n", res);
			assert(res == 0);
#ifdef LB_REPLIES
			uint32_t commit_idx = raft_get_commit_idx(raft_impl);
			if (announced_commit_idx < commit_idx) {
				announce_increased_commit();
				announced_commit_idx = commit_idx;
			}
#endif
			break;
		case ANNOUNCE_COMMIT_REQ:
			res = gbuffer_read(&gbr, (char *)&gr_req_h, sizeof(struct raft_generic_req_header));
			assert(res == sizeof(struct raft_generic_req_header));
			res = gbuffer_read(&gbr, (char *)&ae_req_h, sizeof(struct raft_append_entries_req_header));
			assert(res == sizeof(struct raft_append_entries_req_header));

			msg.ae_req.n_entries = ntohl(ae_req_h.entries_count);
			msg.ae_req.term = gr_h.term;
			msg.ae_req.prev_log_idx = ntohl(gr_req_h.last_log_idx);
			msg.ae_req.prev_log_term = gr_req_h.last_log_term;
			msg.ae_req.leader_commit = ntohl(ae_req_h.leader_commit_idx);
			msg.ae_req.entries = NULL;
			res = raft_recv_appendentries(raft_impl,
					get_peer_from_id(gr_h.from_id)->node, &msg.ae_req,
					&resp.ae_rep);
			assert(res == 0);
			send_raft_msg(gr_h.from_id, &resp, ANNOUNCE_COMMIT_REP,
					container_of(in_msg, struct r2p2_server_pair, request));
			break;
		case ANNOUNCE_COMMIT_REP:
			res = gbuffer_read(&gbr, (char *)&ae_rep_h, sizeof(struct raft_append_entries_rep_header));
			assert(res == sizeof(struct raft_append_entries_rep_header));
			peer = get_peer_from_id(gr_h.from_id);
			peer->done = ntohl(ae_rep_h.done);
			break;
#ifdef ACCELERATED
		case RECOVERY_REQ:
			res = gbuffer_read(&gbr, (char *)&ae_rep_h, sizeof(struct raft_append_entries_rep_header));
			assert(res == sizeof(struct raft_append_entries_rep_header));
			msg.ae_rep.current_idx = ntohl(ae_rep_h.last_log_idx);

			missing_entry = raft_get_entry_from_idx(raft_impl,
					msg.ae_rep.current_idx+1);
			assert(missing_entry);
			// Compile the recovery reply as an append_entries request
			recovery_rep.ae_req.term = raft_get_current_term(raft_impl);
			recovery_rep.ae_req.prev_log_idx = msg.ae_rep.current_idx;
			recovery_rep.ae_req.prev_log_term = raft_get_current_term(raft_impl);
			recovery_rep.ae_req.leader_commit = raft_get_commit_idx(raft_impl);
			recovery_rep.ae_req.n_entries = 1;
			recovery_rep.ae_req.entries = missing_entry;
			send_raft_msg(gr_h.from_id,
					(union generic_raft_msg *)&recovery_rep, RECOVERY_REP,
					container_of(in_msg, struct r2p2_server_pair, request));
			break;
		case RECOVERY_REP:
			res = gbuffer_read(&gbr, (char *)&gr_req_h, sizeof(struct raft_generic_req_header));
			assert(res == sizeof(struct raft_generic_req_header));
			res = gbuffer_read(&gbr, (char *)&ae_req_h, sizeof(struct raft_append_entries_req_header));
			assert(res == sizeof(struct raft_append_entries_req_header));

			msg.ae_req.n_entries = ntohl(ae_req_h.entries_count);
			assert(msg.ae_req.n_entries == 1);
			msg_to_entries(&recovered_entry, &gbr, 1);
			assert(recovered_entry.data.buf);
			if (add_to_unordered_reqs(recovered_entry.data.buf))
				assert(0);
			break;
#endif
		default:
			printf("Unknown message type: %d\n", gr_h.msg_type);
			assert(0);
	}
}

void handle_replicated_req(struct r2p2_server_pair *sp)
{
#ifdef ACCELERATED
	if (!is_raft_leader()) {
		if (unordered_count < 3000) {
			if (add_to_unordered_reqs(sp)) {
				printf("Failed to add to unordered reqs\n");
				free_server_pair(sp);
			}
		} else {
			//printf("Unordered is full\n");
			//assert(0);
			free_server_pair(sp);
		}
		return;
	}
#else
	// FIXME: if received and not leader forward to leader
	if (!is_raft_leader())
		assert(0);
#endif

	assert(pending_rr_count < 128);
	pending_replicated_reqs[pending_rr_count++] = sp;
}

void raft_handle_single_msg(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
						 struct r2p2_host_tuple *local_host)
{
#ifdef SWITCH_AGG
	struct raft_generic_header gr_h;
	struct raft_append_entries_rep_header ae_rep_h;
	struct raft_generic_header *tmph;
	struct gbuffer_reader gbr;
	struct r2p2_header *r2p2h;
	struct r2p2_msg msg;
	raft_entry_t *ety;
	int res;
	msg_appendentries_t ae_req;
	msg_appendentries_response_t r;

	gbuffer_reader_init(&gbr, gb);

	res = gbuffer_read(&gbr, (char *)&gr_h, sizeof(struct raft_generic_header));
	assert(res == sizeof(struct raft_generic_header));

	switch (gr_h.msg_type) {
		case APPEND_ENTRIES_REP_GROUP:
			if (is_raft_leader()) {
				r2p2h = get_buffer_payload(gb);
				r2p2h->type_policy = (RAFT_REP << 4);
				tmph = (struct raft_generic_header *)(r2p2h + 1);
				tmph->msg_type = APPEND_ENTRIES_REP;

				// Read the done counters
				struct raft_append_entries_rep_header *ae_rep;
				struct raft_done_info *di;
				int i;
				struct r2p2_raft_peer *peer;

				ae_rep = (struct raft_append_entries_rep_header *)(tmph + 1);
				di = (struct raft_done_info *)(ae_rep + 1);
				for (i=0;i<real_peer_cnt;i++) {
					if (i != local_raft_id) {
						peer = &CFG.raft_peers[i];
						peer->done = ntohl(di->done);
					}
					di++;
				}

				return handle_incoming_pck(gb, len, source, local_host);
			} else {
				res = gbuffer_read(&gbr, (char *)&ae_rep_h, sizeof(struct raft_append_entries_rep_header));
				assert(res == sizeof(struct raft_append_entries_rep_header));
				ae_req.term = gr_h.term;
				ae_req.prev_log_idx = raft_get_current_idx(raft_impl);
				ety = raft_get_entry_from_idx(raft_impl, ae_req.prev_log_idx);
				if (!ety) {
					free_buffer(gb);
					break;
				}
				ae_req.prev_log_term = ety->term;
				ae_req.leader_commit = ntohl(ae_rep_h.last_log_idx);
				ae_req.n_entries = 0;
				ae_req.entries = NULL;
				res = raft_recv_appendentries(raft_impl,
						get_peer_from_id(raft_get_current_leader(raft_impl))->node,
						&ae_req, &r);
				assert(res == 0);
				free_buffer(gb);
			}
			break;
		case APPEND_ENTRIES_REP:
			// construct an artificial msg and call raft_process
			msg.head_buffer = gb;
			msg.tail_buffer = gb;
			raft_process(&msg);
			free_buffer(gb);
			break;
	}
#else
	(void)(len);
	(void)(gb);
	(void)(source);
	(void)(local_host);
	assert(0);
#endif
}

void do_raft_duties(void)
{
	if (!CFG.raft_peers)
		return;

	if (is_raft_leader())
		leader_order_requests();
}

int is_raft_leader(void)
{
	return raft_is_leader(raft_impl);
}

void raft_apply_one(void)
{
	raft_apply_entry(raft_impl);
}

void *raft_worker(void)
{
	do {
		raft_apply_all(raft_impl);
	} while (!force_quit);

	return NULL;
}
