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

#include <r2p2/api.h>
#include <stdint.h>

#define PER_MSG_PCK 128
#define PAYLOAD_SIZE                                                           \
	(1472 - sizeof(struct r2p2_header)) // 1500 - 20 (IP) - 8 (UDP) - (r2p2_HDR)
#define MIN_PAYLOAD_SIZE                                                       \
	(22 -                                                                      \
	 sizeof(                                                                   \
		 struct r2p2_header)) // 64 - 14 (ETH) - 20 (IP) - 8 (UDP ) - r2p2_HDR
#define F_FLAG 0x80
#define L_FLAG 0x40
#define MAGIC 0xCC

#define EXCT_ONCE_FLAG 0x02
#define EO_MAX_RETRY_REQUEST 5
#define EO_MAX_RETRY_REPLY 5
#define EO_TO_REPLY 2500000
#define EO_TO_NETWORK_FLUSH 5000000
#define ACK_NOT_RECEIVED UINT16_MAX

#define MIN_HEADER_SIZE (sizeof(struct r2p2_header))// - sizeof(uint16_t))

enum {
	REQUEST_MSG = 0,
	RESPONSE_MSG,
	CONTROL_MSG,
	ACK_MSG,
	DROP_MSG,
	REQUEST_EXCT_ONCE,
	RESPONSE_EXCT_ONCE,
	ACK_EXCT_ONCE
};

typedef void *generic_buffer;

struct r2p2_header {
	uint8_t magic;
	uint8_t header_size;
	uint8_t type_policy; // 4 bytes message type 4 bytes policy
	uint8_t flags;
	uint16_t rid;
	uint16_t p_order;
//	uint16_t extended_rid;
	// add session ID?
};

struct r2p2_msg {
	struct r2p2_host_tuple sender;
	uint16_t req_id;
	generic_buffer head_buffer;
	generic_buffer tail_buffer;
};

struct r2p2_cp_exct_once_info {
  // extended rid
  uint16_t req_resent;
};

struct r2p2_client_pair {
	struct r2p2_msg request;
	struct r2p2_msg reply;
	uint16_t reply_expected_packets;
	uint16_t reply_received_packets;
	struct r2p2_ctx *ctx;
	enum {
		R2P2_W_ACK,
		R2P2_W_RESPONSE,
	} state;
	void *timer;
	void *impl_data; // Used to hold the socket used in linux
	void (*on_free)(void *impl_data);
	struct r2p2_cp_exct_once_info *eo_info;
};


struct r2p2_sp_exct_once_info {
  // extended rid
  uint16_t req_received;
  uint16_t req_resent;
  uint16_t reply_resent;
  void *timer;
};

struct r2p2_server_pair {
	struct r2p2_msg request;
	struct r2p2_msg reply;
	uint16_t request_expected_packets;
	uint16_t request_received_packets;
	struct r2p2_sp_exct_once_info *eo_info;
	// Add here fields for garbage collection, e.g. last received
};

enum {
  EO_NEW = 0,
  EO_IN_PROGRESS,
  EO_COMPLETED,
  EO_STALE
};

struct r2p2_eo_client_info {
    uint16_t next_seq;
//    uint16_t extended_rid; // exclusive
};

static inline int is_response(struct r2p2_header *h)
{
	return ((h->type_policy & 0xF0) == (RESPONSE_MSG << 4)) ||
		((h->type_policy & 0xF0) == (RESPONSE_EXCT_ONCE << 4)) ||
		((h->type_policy & 0xF0) == (ACK_MSG << 4)) ||
		((h->type_policy & 0xF0) == (DROP_MSG << 4));
}

static inline int is_first(struct r2p2_header *h)
{
	return h->flags & F_FLAG;
}

static inline int is_last(struct r2p2_header *h)
{
	return h->flags & L_FLAG;
}

static inline uint8_t get_msg_type(struct r2p2_header *h)
{
	return (h->type_policy & 0xF0) >> 4;
}

static inline unsigned int get_header_size(const char* buf)
{
  return ((struct r2p2_header*) buf)->header_size;
}

/*
 * Generic buffer API
 */
void free_buffer(generic_buffer buffer);

generic_buffer get_buffer(void);

void *get_buffer_payload(generic_buffer gb);

uint32_t get_buffer_payload_size(generic_buffer gb);

int set_buffer_payload_size(generic_buffer gb, uint32_t payload_size);

int chain_buffers(generic_buffer first, generic_buffer second);

generic_buffer get_buffer_next(generic_buffer gb);

/*
 * Implementation agnostic
 */
int r2p2_backend_init_per_core(void);
#ifdef WITH_TIMESTAMPING
void handle_incoming_pck(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
						 struct r2p2_host_tuple *local_host,
						 const struct timespec *rx_timestamp);
#else
void handle_incoming_pck(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
						 struct r2p2_host_tuple *local_host);
#endif
void timer_triggered(struct r2p2_client_pair *cp);
void sp_timer_triggered(struct r2p2_server_pair *sp);
/* Exposed only for lancet */
void r2p2_prepare_msg(struct r2p2_msg *msg, struct iovec *iov, int iovcnt,
					  uint8_t req_type, uint8_t policy, uint16_t req_id);

/*
 * Implementation specific
 */
int prepare_to_send(struct r2p2_client_pair *cp);
int buf_list_send(generic_buffer first_buf, struct r2p2_host_tuple *dest,
				  void *socket_info);
int disarm_timer(void *timer);
int cp_restart_timer(struct r2p2_client_pair *cp, long timeout);

void sp_get_timer(struct r2p2_server_pair *sp);
int sp_restart_timer(struct r2p2_server_pair *sp, long timeout);
void sp_free_timer(struct r2p2_server_pair *sp);

void router_notify(void);

/*
 * Exactly Once specific
 */
static inline int is_exct_once(struct r2p2_ctx *ctx)
{
  return (ctx->routing_policy & EXCT_ONCE_FLAG) != 0;
}

static inline int is_ack_exct_once(struct r2p2_header *h)
{
  return ((h->type_policy & 0xF0) == (ACK_EXCT_ONCE << 4));
}

void send_eo_ack(struct r2p2_client_pair *cp);

void handle_ack_eo(generic_buffer gb, int len, struct r2p2_header *r2p2h,
                   struct r2p2_host_tuple *source);

int eo_try_garbage_collect(struct r2p2_server_pair *sp);


#define DEBUG 1

#if DEBUG
void __debug_dump();
#endif
