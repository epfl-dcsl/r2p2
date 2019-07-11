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

#include <rte_eal.h>


static void synthetic_recv_fn(long handle, struct iovec *iov,
							  __attribute__((unused)) int iovcnt)
{
	struct iovec local_iov;
	char rcv_msg[64];

	memcpy(rcv_msg, iov[0].iov_base, iov[0].iov_len);

	printf("Received: %s\n", (char *)iov[0].iov_base);

	local_iov.iov_len = iov[0].iov_len;
	local_iov.iov_base = rcv_msg;
	r2p2_send_response(handle, &local_iov, 1);
}

int app_init(__attribute__((unused)) int argc,
			 __attribute__((unused)) char **argv)
{
	printf("Hello r2p2 echo\n");

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
