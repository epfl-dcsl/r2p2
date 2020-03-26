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
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <dp/api.h>
#include <dp/core.h>

#include <r2p2/api.h>
#include <r2p2/api-internal.h>

#include <rte_eal.h>

static inline long time_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (long)tv.tv_sec * 1000000 + (long)tv.tv_usec;
}

static void spin(long usec)
{
	long start;
	start = time_us();
	//if (is_raft_leader())
	//	usec /= 2;
	while (time_us() < start + usec)
		;
}

static void synthetic_recv_fn(long handle, struct iovec *iov,
							  __attribute__((unused)) int iovcnt)
{
	long *to_spin;
	long reply = 42;
	struct iovec local_iov[1];

	to_spin = (long *)iov->iov_base;
	spin(*to_spin);

	// reply
	local_iov[0].iov_base = &reply;
	local_iov[0].iov_len = sizeof(long);

	r2p2_send_response(handle, local_iov, 1);
}

int app_init(__attribute__((unused)) int argc,
			 __attribute__((unused)) char **argv)
{
	printf("Hello r2p2lib synthetic server \n");

	if (r2p2_init(8000)) { // this port number is not used
		printf("Error initialising\n");
		return -1;
	}

	r2p2_set_recv_cb(synthetic_recv_fn);

	return 0;
}

void app_main(void)
{
	if (r2p2_init_per_core(RTE_PER_LCORE(queue_id), rte_lcore_count())) {
		printf("Error initialising per core\n");
		exit(1);
	}

	do {
		r2p2_poll();
	} while (!force_quit);

	return;
}
