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

#pragma once

#include <raft.h>

struct __attribute__((packed)) r2p2_raft_peer {
	struct r2p2_host_tuple host;
	uint8_t id;
	uint32_t assigned;
	uint32_t done;
	uint8_t pending_ae;
	raft_node_t *node;
};

enum {
	VOTE_REQUEST = 0,
	VOTE_REPLY,
	APPEND_ENTRIES_REQ,
	APPEND_ENTRIES_REP,
	APPEND_ENTRIES_REP_GROUP,
	ANNOUNCE_COMMIT_REQ,
	ANNOUNCE_COMMIT_REP,
	RECOVERY_REQ,
	RECOVERY_REP,
};

union generic_raft_msg {
	msg_requestvote_t vote_req;
	msg_requestvote_response_t vote_rep;
	msg_appendentries_t ae_req;
	msg_appendentries_response_t ae_rep;
};

struct __attribute__((__packed__)) raft_generic_header {
	uint8_t msg_type;
	uint8_t from_id;
	uint8_t term;
};

struct __attribute__((__packed__)) raft_generic_req_header {
	uint32_t last_log_idx;
	uint8_t last_log_term;
};

struct __attribute__((__packed__)) raft_append_entries_req_header {
	uint32_t leader_commit_idx;
	uint32_t entries_count;
};

struct __attribute__((__packed__)) raft_append_entries_rep_header {
	uint8_t success;
	uint32_t last_log_idx;
	uint32_t first_idx;
	uint32_t done;
};

struct __attribute__((__packed__)) raft_vote_rep_header {
	uint8_t granted;
};

struct __attribute__((__packed__)) raft_done_info {
	uint8_t peer;
	uint32_t done;
};

int r2p2_raft_init(void);
void r2p2_raft_tick(void);
void r2p2_send_raft_req(struct iovec *iov, int iovcnt, struct r2p2_ctx *ctx);
void raft_process(struct r2p2_msg *in_msg);
void handle_replicated_req(struct r2p2_server_pair *sp);
int is_raft_leader(void);
void raft_apply_one(void);
void r2p2_send_raft_response(long handle, struct iovec *iov, int iovcnt);
// used only in switch aggregation
void r2p2_send_raft_msg(struct r2p2_host_tuple *dst, struct iovec *iov, int iovcnt);
void raft_handle_single_msg(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
						 struct r2p2_host_tuple *local_host);
void do_raft_duties(void);
void *raft_worker(void);
