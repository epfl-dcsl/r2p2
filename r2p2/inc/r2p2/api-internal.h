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

enum {
	REQUEST_MSG = 0,
	RESPONSE_MSG = 1,
	CONTROL_MSG = 2,
	ACK_MSG = 3,
};

typedef void *generic_buffer;

struct r2p2_header {
	uint8_t magic;
	uint8_t header_size;
	uint8_t type_policy; // 4 bytes message type 4 bytes policy
	uint8_t flags;
	uint16_t rid;
	uint16_t p_order;
};

struct r2p2_msg {
	struct r2p2_host_tuple sender;
	uint16_t req_id;
	generic_buffer head_buffer;
	generic_buffer tail_buffer;
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
};

struct r2p2_server_pair {
	struct r2p2_msg request;
	struct r2p2_msg reply;
	uint16_t request_expected_packets;
	uint16_t request_received_packets;
	// Add here fields for garbage collection, e.g. last received
};

static inline int is_response(struct r2p2_header *h)
{
	return (h->type_policy & 0xF0) & (RESPONSE_MSG << 4);
}

static inline int is_first(struct r2p2_header *h)
{
	return h->flags & F_FLAG;
}

static inline int is_last(struct r2p2_header *h)
{
	return h->flags & L_FLAG;
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
void router_notify(void);
