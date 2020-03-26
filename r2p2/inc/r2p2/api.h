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

#include <stdint.h>
#include <sys/uio.h>

typedef void (*success_cb_f)(long handle, void *arg, struct iovec *iov,
							 int iovcnt);
typedef void (*error_cb_f)(void *arg, int err);
typedef void (*timeout_cb_f)(void *arg);
typedef void (*recv_fn)(long handle, struct iovec *iov, int iovcnt);
typedef int (*app_flow_control)(void);

struct __attribute__((packed)) r2p2_host_tuple {
	uint32_t ip;
	uint16_t port;
};

enum {
	LB_ROUTE = 0,
	FIXED_ROUTE,
	REPLICATED_ROUTE,
	REPLICATED_ROUTE_NO_SE, // replicated route no side effects
};

enum {
	ERR_NO_SOCKET=1,
	ERR_DROP_MSG,
};

struct __attribute__((packed)) r2p2_ctx {
	success_cb_f success_cb;
	error_cb_f error_cb;
	timeout_cb_f timeout_cb;
	void *arg;
	long timeout;
	int routing_policy;
	struct r2p2_host_tuple *destination;
#ifdef WITH_TIMESTAMPING
	struct timespec tx_timestamp;
	struct timespec rx_timestamp;
#endif
};

/* Functions called by the application */
/*
 * Implementation specific
 */
int r2p2_init(int listen_port);
int r2p2_init_per_core(int core_id, int core_count);
void r2p2_poll(void);

/*
 * Implementation agnostic
 */
void r2p2_set_recv_cb(recv_fn fn);
void r2p2_set_app_flow_control_fn(app_flow_control fn);
void r2p2_send_req(struct iovec *iov, int iovcnt, struct r2p2_ctx *ctx);
void r2p2_send_response(long handle, struct iovec *iov, int iovcnt);
void r2p2_recv_resp_done(long handle);
