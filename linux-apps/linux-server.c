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
#include <string.h>

#include <r2p2/api.h>

static void linux_recv_fn(long handle, struct iovec *iov, int iovcnt)
{
	struct iovec local_iov;
	char rcv_msg[64];

	memcpy(rcv_msg, iov[0].iov_base, iov[0].iov_len);

	printf("Received: %s\n", (char *)iov[0].iov_base);

	local_iov.iov_len = iov[0].iov_len;
	local_iov.iov_base = rcv_msg;
	r2p2_send_response(handle, &local_iov, 1);
}

int main()
{
	if (r2p2_init(8000)) {
		printf("Error initialising\n");
		exit(1);
	}
	r2p2_set_recv_cb(linux_recv_fn);

	if (r2p2_init_per_core(0, 1)) {
		printf("Error initialising per core\n");
		exit(1);
	}

	while (1)
		r2p2_poll();
}
