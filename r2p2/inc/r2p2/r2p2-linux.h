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

#include <r2p2/api-internal.h>
#include <r2p2/api.h>

#define BUFPOOL_SIZE 1024
#define SOCKPOOL_SIZE 128
#define MAX_EVENTS 128
#define BUFLEN 2048 //(PAYLOAD_SIZE + sizeof(struct r2p2_header) + sizeof(struct
					// linux_buf_hdr)) half a page

struct __attribute__((packed)) linux_buf_hdr {
	uint32_t payload_size;
	struct linux_buf_hdr *next;
	uint32_t pad;
	void *payload[];
};

struct __attribute__((packed)) r2p2_socket {
	int fd;
	int tfd;
	struct r2p2_host_tuple local_host;
	uint16_t taken;
	struct r2p2_client_pair *cp;
	uint16_t pad;
} __attribute__((aligned(32)));

struct socket_pool {
	uint32_t count;
	uint32_t idx;
	struct r2p2_socket sockets[SOCKPOOL_SIZE];
};
