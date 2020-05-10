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
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <r2p2/api-internal.h>
#include <r2p2/mempool.h>
#ifdef WITH_TIMESTAMPING
static_assert(LINUX, "Timestamping supported only in Linux");
#include <r2p2/r2p2-linux.h>
#include <r2p2/timestamping.h>
#endif

#define POOL_SIZE 1024
#define min(a, b) ((a) < (b)) ? (a) : (b)

static recv_fn rfn;
static app_flow_control afc_fn = NULL;

static __thread struct fixed_mempool *client_pairs;
static __thread struct fixed_mempool *server_pairs;
static __thread struct fixed_linked_list pending_client_pairs = {0};
static __thread struct fixed_linked_list pending_server_pairs = {0};
static __thread struct iovec to_app_iovec[0xFF]; // change this to 0xFF;

static __thread struct r2p2_eo_client_info eo_client_info = {0}; // possible improvement: alloc only for client

#if DEBUG
static void print_cp(void* __cp) {
  struct r2p2_client_pair* cp = (struct r2p2_client_pair*) __cp;
  if (cp->eo_info)
    printf("{req_id: %d, retries: %d}", cp->request.req_id, cp->eo_info->req_resent);
}

static void print_sp(void* __sp) {
  struct r2p2_server_pair* sp = (struct r2p2_server_pair*) __sp;
  if (sp->eo_info)
    printf("{req_id: %d, retries: %d, req_received: %d}", sp->request.req_id, sp->eo_info->req_resent, sp->eo_info->req_received);
}

static void print_linked_list(const char* str, struct fixed_linked_list *ll, void(*print_fun)(void*)) {
  printf("%s: ", str);
  for (struct fixed_obj *obj = ll->head; obj; obj = obj->next) {
    print_fun(obj->elem);
  }
  printf("\n");
}

void __debug_dump()
{
  if (pending_client_pairs.head != NULL) print_linked_list("cp", &pending_client_pairs, print_cp);
  else if (pending_server_pairs.head != NULL) print_linked_list("sp", &pending_server_pairs, print_sp);
  else printf("empty debug\n");
}
#endif

static struct r2p2_client_pair *alloc_client_pair(int with_eo_info)
{
	struct r2p2_client_pair *cp;

	cp = alloc_object(client_pairs);
	assert(cp);

	bzero(cp, sizeof(struct r2p2_client_pair));

	if (with_eo_info) {
	  cp->eo_info = malloc(sizeof(struct r2p2_cp_exct_once_info)); // TODO: use alloc_object
	  assert(cp->eo_info);
	}

	return cp;
}

static void free_client_pair(struct r2p2_client_pair *cp)
{
	generic_buffer gb;

	// Free the received reply
	gb = cp->reply.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}

#ifdef LINUX
	// Free the request sent
	gb = cp->request.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}
#endif

	// Free the socket in linux on anything implementation specific
	if (cp->on_free)
		cp->on_free(cp->impl_data);

	if (cp->eo_info) {
	  free(cp->eo_info); // TODO: use free_object
	  cp->eo_info = NULL;
	}

	free_object(cp);
}

static struct r2p2_server_pair *alloc_server_pair(int with_eo_info)
{
	struct r2p2_server_pair *sp;

	sp = alloc_object(server_pairs);
	assert(sp);

	bzero(sp, sizeof(struct r2p2_server_pair));

  if (with_eo_info) {
    sp->eo_info = malloc(sizeof(struct r2p2_sp_exct_once_info)); // TODO: use alloc_object
    assert(sp->eo_info);
  }

	return sp;
}

static void free_server_pair(struct r2p2_server_pair *sp)
{
	generic_buffer gb;

	// Free the recv message buffers
	gb = sp->request.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}

// Free the reply sent
#ifdef LINUX
	gb = sp->reply.head_buffer;
	while (gb != NULL) {
		free_buffer(gb);
		gb = get_buffer_next(gb);
	}
#endif

  if (sp->eo_info) {
    sp_free_timer(sp);
    free(sp->eo_info); // TODO: use free_object
    sp->eo_info = NULL;
  }

	free_object(sp);
}

static void add_to_pending_client_pairs(struct r2p2_client_pair *cp)
{
	struct fixed_obj *fo = get_object_meta(cp);
	add_to_list(&pending_client_pairs, fo);
}

static void add_to_pending_server_pairs(struct r2p2_server_pair *sp)
{
	struct fixed_obj *fo = get_object_meta(sp);
	add_to_list(&pending_server_pairs, fo);
}

static void remove_from_pending_server_pairs(struct r2p2_server_pair *sp)
{
	struct fixed_obj *fo = get_object_meta(sp);
	remove_from_list(&pending_server_pairs, fo);
}

static void remove_from_pending_client_pairs(struct r2p2_client_pair *cp)
{
	struct fixed_obj *fo = get_object_meta(cp);
	remove_from_list(&pending_client_pairs, fo);
}

static struct r2p2_server_pair *
find_in_pending_server_pairs(uint16_t req_id, struct r2p2_host_tuple *sender)
{
	struct r2p2_server_pair *sp;
	struct fixed_obj *fo;

	fo = pending_server_pairs.head;
	while (fo) {
		sp = (struct r2p2_server_pair *)fo->elem;
		if ((sp->request.sender.ip == sender->ip) &&
			(sp->request.sender.port == sender->port) &&
			(sp->request.req_id == req_id))
			return sp;
		fo = (struct fixed_obj *)fo->next;
	}
	return NULL;
}

static struct r2p2_client_pair *
find_in_pending_client_pairs(uint16_t req_id, struct r2p2_host_tuple *sender)
{
	struct r2p2_client_pair *cp;
	struct fixed_obj *fo;

	fo = pending_client_pairs.head;
	// FIXME: inlcude ip too
	while (fo) {
		cp = (struct r2p2_client_pair *)fo->elem;
		if ((cp->request.sender.port == sender->port) &&
			(cp->request.req_id == req_id))
			return cp;
		fo = (struct fixed_obj *)fo->next;
	}
	printf("Request not found\n");
	return NULL;
}

static int prepare_to_app_iovec(struct r2p2_msg *msg)
{
	generic_buffer gb;
	char *buf;
	int len, iovcnt = 0;

	gb = msg->head_buffer;
	while (gb != NULL) {
		buf = get_buffer_payload(gb);
		assert(buf);
		len = get_buffer_payload_size(gb);
		to_app_iovec[iovcnt].iov_base = buf + get_header_size(buf);
		to_app_iovec[iovcnt++].iov_len = len - get_header_size(buf);
		gb = get_buffer_next(gb);
		assert(iovcnt < 0xFF);
	}
	return iovcnt;
}

static void handle_drop_msg(struct r2p2_client_pair *cp)
{
	cp->ctx->error_cb(cp->ctx->arg, -ERR_DROP_MSG);

	remove_from_pending_client_pairs(cp);
	free_client_pair(cp);
}

static void forward_request(struct r2p2_server_pair *sp)
{
	int iovcnt;

	iovcnt = prepare_to_app_iovec(&sp->request);
	rfn((long)sp, to_app_iovec, iovcnt);
}

static void r2p2_msg_add_payload(struct r2p2_msg *msg, generic_buffer gb)
{
	if (msg->tail_buffer) {
		chain_buffers(msg->tail_buffer, gb);
		msg->tail_buffer = gb;
	} else {
		assert(msg->head_buffer == NULL);
		assert(msg->tail_buffer == NULL);
		msg->head_buffer = gb;
		msg->tail_buffer = gb;
	}
}

void r2p2_prepare_msg(struct r2p2_msg *msg, struct iovec *iov, int iovcnt,
					  uint8_t req_type, uint8_t policy, uint16_t req_id)
{
	unsigned int iov_idx, bufferleft, copied, tocopy, buffer_cnt, total_payload,
		single_packet_msg, is_first, should_small_first, header_size;
	struct r2p2_header *r2p2h;
	generic_buffer gb, new_gb;
	char *target, *src;

  header_size =  MIN_HEADER_SIZE;

	// Compute the total payload
	total_payload = 0;
	for (int i = 0; i < iovcnt; i++)
		total_payload += iov[i].iov_len;

	if (total_payload <= PAYLOAD_SIZE)
		single_packet_msg = 1;
	else
		single_packet_msg = 0;

	if (!single_packet_msg && (req_type == REQUEST_MSG))
		should_small_first = 1;
	else should_small_first = 0;

	iov_idx = 0;
	bufferleft = 0;
	copied = 0;
	gb = NULL;
	buffer_cnt = 0;
	is_first = 1;
	while (iov_idx < (unsigned int)iovcnt) {
		if (!bufferleft) {
			// Set the last buffer to full size
			if (gb) {
				if (is_first && should_small_first) {
					set_buffer_payload_size(gb, MIN_PAYLOAD_SIZE + header_size);
					is_first = 0;
				} else
					set_buffer_payload_size(gb, PAYLOAD_SIZE + header_size);
			}
			new_gb = get_buffer();
			assert(new_gb);
			r2p2_msg_add_payload(msg, new_gb);
			gb = new_gb;
			target = get_buffer_payload(gb);
			if (is_first && should_small_first)
				bufferleft = MIN_PAYLOAD_SIZE;
			else
				bufferleft = PAYLOAD_SIZE;
			// FIX the header
			r2p2h = (struct r2p2_header *)target;
      bzero(r2p2h, header_size);

			r2p2h->magic = MAGIC;
			r2p2h->rid = req_id;
			r2p2h->header_size = header_size;
			r2p2h->type_policy = (req_type << 4) | (0x0F & policy);
			r2p2h->p_order = buffer_cnt++;
			r2p2h->flags = 0;
			target += header_size;
		}
		src = iov[iov_idx].iov_base;
		tocopy = min(bufferleft, iov[iov_idx].iov_len - copied);
		memcpy(target, &src[copied], tocopy);
		copied += tocopy;
		bufferleft -= tocopy;
		target += tocopy;
		if (copied == iov[iov_idx].iov_len) {
			iov_idx++;
			copied = 0;
		}
	}

	// Set the len of the last buffer
	set_buffer_payload_size(gb, PAYLOAD_SIZE + header_size - bufferleft);

	// Fix the header of the first and last packet
	r2p2h = (struct r2p2_header *)get_buffer_payload(msg->head_buffer);
	r2p2h->flags |= F_FLAG;
	r2p2h->p_order = buffer_cnt;
	r2p2h = (struct r2p2_header *)get_buffer_payload(msg->tail_buffer);
	r2p2h->flags |= L_FLAG;

	msg->req_id = req_id;
}

static int should_keep_req(__attribute__((unused))struct r2p2_server_pair *sp)
{
	if (afc_fn)
		return afc_fn();
	else
		return 1;
}

static void send_drop_msg(struct r2p2_server_pair *sp)
{
	char drop_payload[] = "DROP";
	struct iovec ack;
	struct r2p2_msg drop_msg = {0};

	ack.iov_base = drop_payload;
	ack.iov_len = 4;
	r2p2_prepare_msg(&drop_msg, &ack, 1, DROP_MSG, FIXED_ROUTE,
			sp->request.req_id);
	buf_list_send(drop_msg.head_buffer, &sp->request.sender, NULL);
#ifdef LINUX
	free_buffer(drop_msg.head_buffer);
#endif

}

static void handle_response(generic_buffer gb, int len,
							struct r2p2_header *r2p2h,
							struct r2p2_host_tuple *source,
#ifdef WITH_TIMESTAMPING
							struct r2p2_host_tuple *local_host,
							const struct timespec *last_rx_timestamp)
#else
							struct r2p2_host_tuple *local_host)
#endif
{
	struct r2p2_client_pair *cp;
	int iovcnt;
	generic_buffer rest_to_send;

	cp = find_in_pending_client_pairs(r2p2h->rid, local_host);
	if (!cp) {
		printf("No client pair found. RID = %d ORDER = %d\n", r2p2h->rid, r2p2h->p_order);
		free_buffer(gb);
		return;
	}

#ifdef WITH_TIMESTAMPING
	// Update ctx rx_timestamp if bigger than the current one.
	if (last_rx_timestamp != NULL && last_rx_timestamp->tv_sec != 0 &&
		is_smaller_than(&cp->ctx->rx_timestamp, last_rx_timestamp)) {
		cp->ctx->rx_timestamp = *last_rx_timestamp;
	}
#endif

	cp->reply.sender = *source;

	switch(get_msg_type(r2p2h)) {
    case RESPONSE_EXCT_ONCE:
      // todo: handle already received response
	    assert(cp->eo_info);
	    send_eo_ack(cp);
  	  // no break, continue like regular response
		case RESPONSE_MSG:
			assert(cp->state == R2P2_W_RESPONSE);
			set_buffer_payload_size(gb, len);
			r2p2_msg_add_payload(&cp->reply, gb);

			if (is_first(r2p2h)) {
				cp->reply_expected_packets = r2p2h->p_order;
				cp->reply_received_packets = 1;

			} else {
				if (r2p2h->p_order != cp->reply_received_packets++) {
					printf("OOF in response\n");
					cp->ctx->error_cb(cp->ctx->arg, -1);
					remove_from_pending_client_pairs(cp);
					free_client_pair(cp);
					return;

				}
			}

			// Is it full msg? Should I call the application?
			if (!is_last(r2p2h))
				return;

			if (cp->reply_received_packets != cp->reply_expected_packets) {
				printf("Wrong total size in response\n");
				cp->ctx->error_cb(cp->ctx->arg, -1);
				remove_from_pending_client_pairs(cp);
				free_client_pair(cp);
				return;

			}
			if (cp->timer)
				disarm_timer(cp->timer);
			iovcnt = prepare_to_app_iovec(&cp->reply);

#ifdef WITH_TIMESTAMPING
			// Extract tx timestamp if it wasn't there (due to packet order)
			if (cp->ctx->rx_timestamp.tv_sec != 0 &&
					cp->ctx->tx_timestamp.tv_sec == 0) {
				extract_tx_timestamp(((struct r2p2_socket *)cp->impl_data)->fd,
						&cp->ctx->tx_timestamp);

			}
#endif

			cp->ctx->success_cb((long)cp, cp->ctx->arg, to_app_iovec, iovcnt);
			break;
		case ACK_MSG:
			// Send the rest packets
			assert(cp->state == R2P2_W_ACK);
			if (len != (MIN_HEADER_SIZE + 3))
				printf("ACK msg size is %d\n", len);
			assert(len == (MIN_HEADER_SIZE + 3));
			free_buffer(gb);
#ifdef LINUX
			rest_to_send = get_buffer_next(cp->request.head_buffer);
#else
			rest_to_send = cp->request.head_buffer;
#endif
			buf_list_send(rest_to_send, &cp->reply.sender, cp->impl_data);
			cp->state = R2P2_W_RESPONSE;
			break;
		case DROP_MSG:
			handle_drop_msg(cp);
			free_buffer(gb);
			break;
		default:
			fprintf(stderr, "Unknown msg type %d for response\n",
					get_msg_type(r2p2h));
			assert(0);
	}
}

static void handle_request(generic_buffer gb, int len,
						   struct r2p2_header *r2p2h,
						   struct r2p2_host_tuple *source)
{
  printf("handle_request start: "); __debug_dump();
	struct r2p2_server_pair *sp;
	uint16_t req_id;
	char ack_payload[] = "ACK";
	struct iovec ack;
	struct r2p2_msg ack_msg = {0};
  int exct_once;

  exct_once = get_msg_type(r2p2h) == REQUEST_EXCT_ONCE;
	req_id = r2p2h->rid;

	if (exct_once) {
	  sp = find_in_pending_server_pairs(req_id, source);
	  if (sp != NULL) {
      assert(sp->eo_info);
      if (is_first(r2p2h)) {
        sp->eo_info->req_received++;
//        buf_list_send(sp->reply.head_buffer, &sp->request.sender, NULL);
        eo_try_garbage_collect(sp);
      }
      free_buffer(gb);
      return;
	  }
	}

	if (is_first(r2p2h)) {
		/*
		 * FIXME
		 * Consider the case that an old request with the same id and
		 * src ip port is already there
		 * remove before starting the new one
		 */
		sp = alloc_server_pair(exct_once);
		assert(sp);
		sp->request.sender = *source;
		sp->request.req_id = req_id;
		sp->request_expected_packets = r2p2h->p_order;
		sp->request_received_packets = 1;
		if (exct_once) {
		  sp->eo_info->req_received = 1;
		  sp->eo_info->req_resent = ACK_NOT_RECEIVED;
		  sp->eo_info->reply_resent = 0;
		  sp_get_timer(sp);
		}

		if (!should_keep_req(sp)) {
			set_buffer_payload_size(gb, len);
			r2p2_msg_add_payload(&sp->request, gb);
			send_drop_msg(sp);
			free_server_pair(sp);
			return;
		}

		if (!is_last(r2p2h)) {
			// add to pending request
			add_to_pending_server_pairs(sp);

			// send ACK
			ack.iov_base = ack_payload;
			ack.iov_len = 3;
			r2p2_prepare_msg(&ack_msg, &ack, 1, ACK_MSG, FIXED_ROUTE, req_id);
			buf_list_send(ack_msg.head_buffer, source, NULL);
#ifdef LINUX
			free_buffer(ack_msg.head_buffer);
#endif
		} else if (exct_once) {
      // add to pending request
      add_to_pending_server_pairs(sp);
		}
	} else {
		// find in pending msgs
		sp = find_in_pending_server_pairs(req_id, source);
		assert(sp);
		if (r2p2h->p_order != sp->request_received_packets++) {
			printf("OOF in request\n");
			remove_from_pending_server_pairs(sp);
			free_server_pair(sp);
			free_buffer(gb);
			return;
		}
	}
	set_buffer_payload_size(gb, len);
	r2p2_msg_add_payload(&sp->request, gb);

	if (!is_last(r2p2h))
		return;

	if (sp->request_received_packets != sp->request_expected_packets) {
		printf("Wrong total size in request\n");
		remove_from_pending_server_pairs(sp);
		free_server_pair(sp);
		return;
	}
	assert(rfn);
	forward_request(sp);
}

void handle_incoming_pck(generic_buffer gb, int len,
						 struct r2p2_host_tuple *source,
#ifdef WITH_TIMESTAMPING
						 struct r2p2_host_tuple *local_host,
						 const struct timespec *last_rx_timestamp)
#else
						 struct r2p2_host_tuple *local_host)
#endif
{
	struct r2p2_header *r2p2h;
	char *buf;

	if ((unsigned)len < MIN_HEADER_SIZE)
		printf("I received %d\n", len);
	assert((unsigned)len >= MIN_HEADER_SIZE);

  buf = get_buffer_payload(gb);
  r2p2h = (struct r2p2_header *)buf;
  printf("\nReceived packet from %d:%d, seq=%d, len=%d\n", source->ip, source->port, r2p2h->rid, len);
//  assert(r2p2h->header_size == (get_msg_type(r2p2h) == REQUEST_EXCT_ONCE ? sizeof(struct r2p2_header) : MIN_HEADER_SIZE));

	if (is_response(r2p2h))
#ifdef WITH_TIMESTAMPING
		handle_response(gb, len, r2p2h, source, local_host, last_rx_timestamp);
#else
		handle_response(gb, len, r2p2h, source, local_host);
#endif
	else if (is_ack_exct_once(r2p2h))
	  handle_ack_eo(gb, len, r2p2h, source);
	else
		handle_request(gb, len, r2p2h, source);
}

int r2p2_backend_init_per_core(void)
{
	time_t t;

	client_pairs = create_mempool(POOL_SIZE, sizeof(struct r2p2_client_pair));
	assert(client_pairs);
	server_pairs = create_mempool(POOL_SIZE, sizeof(struct r2p2_server_pair));
	assert(server_pairs);

	srand((unsigned)time(&t));

	return 0;
}

void timer_triggered(struct r2p2_client_pair *cp)
{
  struct fixed_obj *fo = get_object_meta(cp);
  if (!fo->taken)
    return;

  if (cp->eo_info) {
    if (cp->eo_info->req_resent < EO_MAX_RETRY_REQUEST) {
	    printf("EO timeout, retry\n");
      cp_restart_timer(cp, cp->ctx->timeout);
      buf_list_send(cp->request.head_buffer, cp->ctx->destination, cp->impl_data);
	  } else {
      cp->ctx->timeout_cb(cp->ctx->arg);
	    // Flush the data
      remove_from_pending_client_pairs(cp);
      free_client_pair(cp);
      return;
    }
    cp->eo_info->req_resent++;

	} else {
    assert(cp->ctx->timeout_cb);
    cp->ctx->timeout_cb(cp->ctx->arg);
    //printf("Timer triggered: received packets %d expected %d\n",
    //		cp->reply_received_packets, cp->reply_expected_packets);

    remove_from_pending_client_pairs(cp);
    free_client_pair(cp);
  }
}

/*
 * API
 */
void r2p2_send_response(long handle, struct iovec *iov, int iovcnt)
{
	struct r2p2_server_pair *sp;

	sp = (struct r2p2_server_pair *)handle;

	printf("send response for %d\n", sp->request.req_id);

	int exct_once = sp->eo_info != NULL;

  r2p2_prepare_msg(&sp->reply, iov, iovcnt,
                   exct_once ? RESPONSE_EXCT_ONCE : RESPONSE_MSG,
                   FIXED_ROUTE, sp->request.req_id);

  buf_list_send(sp->reply.head_buffer, &sp->request.sender, NULL);

	// Notify router
	router_notify();

	if (!exct_once) {
    remove_from_pending_server_pairs(sp);
    free_server_pair(sp);
	} else {
	  sp->eo_info->reply_resent = 0;
	  sp_restart_timer(sp, EO_TO_REPLY);
	}
}

void r2p2_send_req(struct iovec *iov, int iovcnt, struct r2p2_ctx *ctx)
{
	generic_buffer second_buffer;
	struct r2p2_client_pair *cp;
	uint16_t rid;
  uint8_t req_type;

	cp = alloc_client_pair(is_exct_once(ctx));
	assert(cp);
	cp->ctx = ctx;

	if (prepare_to_send(cp)) {
		free_client_pair(cp);
		return;
	}

	if (is_exct_once(ctx)) {
	  cp->eo_info->req_resent = 0;
    rid = eo_client_info.next_seq++;
    req_type = REQUEST_EXCT_ONCE;
    printf("send exct once request. rid=%d\n", rid);
  } else {
    rid = rand();
    req_type = REQUEST_MSG;
  }

  r2p2_prepare_msg(&cp->request, iov, iovcnt, req_type,
          ctx->routing_policy, rid);
  cp->state = cp->request.head_buffer == cp->request.tail_buffer
					? R2P2_W_RESPONSE
					: R2P2_W_ACK;

	add_to_pending_client_pairs(cp);

	// Send only the first packet
	second_buffer = get_buffer_next(cp->request.head_buffer);
	chain_buffers(cp->request.head_buffer, NULL);
	buf_list_send(cp->request.head_buffer, ctx->destination, cp->impl_data);
#ifdef LINUX
	chain_buffers(cp->request.head_buffer, second_buffer);
#else
	cp->request.head_buffer = second_buffer;
#endif
}

void r2p2_recv_resp_done(long handle)
{
	struct r2p2_client_pair *cp = (struct r2p2_client_pair *)handle;

	remove_from_pending_client_pairs(cp);
	free_client_pair(cp);
}

void r2p2_set_recv_cb(recv_fn fn)
{
	rfn = fn;
}

void r2p2_set_app_flow_control_fn(app_flow_control fn)
{
	afc_fn = fn;
}

void use_exct_once(struct r2p2_ctx *ctx)
{
  ctx->routing_policy |= EXCT_ONCE_FLAG;
}

void send_eo_ack(struct r2p2_client_pair *cp)
{
  assert(cp->eo_info);
  struct iovec ack;
  struct r2p2_msg ack_msg = {0};

  ack.iov_base = &(cp->eo_info->req_resent);
  ack.iov_len = sizeof(uint16_t);
  r2p2_prepare_msg(&ack_msg, &ack, 1, ACK_EXCT_ONCE, FIXED_ROUTE,
                   cp->request.req_id);
  buf_list_send(ack_msg.head_buffer, &cp->reply.sender, cp->impl_data);
#ifdef LINUX
  free_buffer(ack_msg.head_buffer);
#endif
}

void handle_ack_eo(generic_buffer gb, int len,
                   struct r2p2_header *r2p2h,
                   struct r2p2_host_tuple *source)
{
  struct r2p2_server_pair *sp;
  uint16_t nb_retries;
  assert(len == r2p2h->header_size + sizeof(uint16_t));

  nb_retries = *(uint16_t *) (get_buffer_payload(gb) + r2p2h->header_size);
  printf("Received ack from %d for %d with %d retries\n", source->port, r2p2h->rid, nb_retries);

  sp = find_in_pending_server_pairs(r2p2h->rid, source);
  assert(sp && sp->eo_info);
  sp->eo_info->req_resent = nb_retries;
  if (!eo_try_garbage_collect(sp)) {
    sp_restart_timer(sp, EO_TO_NETWORK_FLUSH);
  }
}

int eo_try_garbage_collect(struct r2p2_server_pair *sp)
{
  assert(sp != NULL || sp->eo_info != NULL);

  if (sp->eo_info->req_received > sp->eo_info->req_resent) {
    printf("GC early for req %d, received %d/%d\n", sp->request.req_id, sp->eo_info->req_received, sp->eo_info->req_resent);
    remove_from_pending_server_pairs(sp);
    free_server_pair(sp);
    return 1;
  } else return 0;

}

void sp_timer_triggered(struct r2p2_server_pair *sp)
{
  int timeout;
  assert(sp && sp->eo_info);

  if (sp->eo_info->req_resent == ACK_NOT_RECEIVED && sp->eo_info->reply_resent < EO_MAX_RETRY_REPLY) {
    printf("Retransmits based on timeout "); __debug_dump();
    buf_list_send(sp->reply.head_buffer, &sp->request.sender, NULL);
    timeout = ++sp->eo_info->reply_resent == EO_MAX_RETRY_REPLY ?
            EO_TO_NETWORK_FLUSH : EO_TO_REPLY;
    sp_restart_timer(sp, timeout);
  } else {
    printf("GC by timeout for req %d, received %d/%d\n", sp->request.req_id, sp->eo_info->req_received, sp->eo_info->req_resent);
    remove_from_pending_server_pairs(sp);
    free_server_pair(sp);
  }

}
