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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <r2p2/api.h>

extern void init_thread();
extern void search_lucene(char *request, struct iovec *response);

struct iovec response;

static void lucene_recv_fn(long handle, struct iovec *iov, int iovcnt)
{
	assert(iovcnt == 1);
	((char *)iov->iov_base)[iov->iov_len] = '\0';
	search_lucene(iov->iov_base, &response);
	r2p2_send_response(handle, &response, 1);
}

static void *thread_main(void *arg)
{
	int core_id = (int)(long)arg;

	if (r2p2_init_per_core(core_id, 2)) {
		printf("Error initialising per core\n");
		exit(1);
	}

	while (1)
		r2p2_poll();

	return NULL;
}

int main(int argc, char **argv)
{
	int i, listen_port, replica_id;
	pthread_t tid;

	assert(argc == 4);
	listen_port = atoi(argv[1]);
	replica_id = atoi(argv[2]);

	printf("Will listen at: %d\n", listen_port);
	response.iov_base = NULL;
	if (r2p2_init(listen_port)) {
		printf("Error initialising\n");
		exit(1);
	}
	r2p2_set_recv_cb(lucene_recv_fn);

	init_thread();
	thread_main((void *)(long)replica_id);
}
