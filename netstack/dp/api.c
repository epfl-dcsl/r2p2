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
#include <stdio.h>

#include <rte_config.h>
#include <rte_mbuf.h>

#include <dp/api.h>
#include <dp/api_internal.h>
#include <dp/dpdk_api.h>
#include <dp/dpdk_config.h>
#include <net/net.h>

struct net_ops *global_ops;

void set_net_ops(struct net_ops *ops)
{
	global_ops = ops;
}

struct net_sge *alloc_net_sge(void)
{
	struct net_sge *e;
	struct rte_mbuf *pkt_buf = rte_pktmbuf_alloc(pktmbuf_pool);
	assert(pkt_buf);
	pkt_buf->userdata = NULL;
	e = rte_pktmbuf_mtod(pkt_buf, struct net_sge *);
	e->len = 0;

	e->payload = rte_pktmbuf_mtod_offset(pkt_buf, void *, UDP_HDRS_LEN);
	e->handle = pkt_buf;
	return e;
}

void net_poll(void)
{
	dpdk_net_poll();
	/* Process events here if different design */
}
