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

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <r2p2/api.h>

#define THREAD_COUNT 1
#define RPC_TO_SEND 10

struct r2p2_host_tuple destination;
static int __thread should_send;

void test_success_cb(long handle, void *arg, struct iovec *iov, int iovcnt)
{
	printf("r2p2 was successful. Arg: %lx\n", (unsigned long)arg);
	printf("Received msg: %s\n", (char *)iov[0].iov_base);

	r2p2_recv_resp_done(handle);
	should_send = 1;
}

void test_error_cb(void *arg, int err)
{
	printf("r2p2 error\n");
}

void test_timeout_cb(void *arg)
{
	printf("r2p2 timeout\n");
}

static void *thread_main(void *arg)
{
	struct r2p2_ctx ctx;
	struct iovec local_iov;
	char msg[] = "1234";
	int count = 0;
	int core_id = (int)(long)arg;

	// configure r2p2 context
	ctx.success_cb = test_success_cb;
	ctx.error_cb = test_error_cb;
	ctx.timeout_cb = test_timeout_cb;
	ctx.arg = (void *)0xDEADBEEF;
	ctx.destination = &destination;
	ctx.timeout = 10000000;
	ctx.routing_policy = LB_ROUTE;

	// configure the message iov
	local_iov.iov_len = 4; // sizeof(long);
	local_iov.iov_base = msg;

	if (r2p2_init_per_core(core_id, THREAD_COUNT)) {
		printf("Error initialising per core\n");
		exit(1);
	}

	should_send = 1;
	while (count < RPC_TO_SEND) {
		// send message
		if (should_send) {
			printf("Sending msg: %s\n", (char *)local_iov.iov_base);
			r2p2_send_req(&local_iov, 1, &ctx);
			should_send = 0;
			count++;
		}

		// poll for response
		r2p2_poll();
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int i;
	struct sockaddr_in sa;
	pthread_t tid;

	if (argc != 3) {
		printf("Usage: ./linux_client <dst_ip> <dst_port>\n");
		return -1;
	}

	if (r2p2_init(8000)) {
		printf("Error initialising\n");
		exit(1);
	}

	// configure server destination
	inet_pton(AF_INET, argv[1], &(sa.sin_addr));
	destination.port = atoi(argv[2]);
	destination.ip = ntohl(sa.sin_addr.s_addr);

	for (i = 1; i < THREAD_COUNT; i++) {
		if (pthread_create(&tid, NULL, thread_main, (void *)(long)i)) {
			fprintf(stderr, "failed to spawn thread %d\n", i);
			exit(-1);
		}
	}

	thread_main((void *)(long)0);
}
