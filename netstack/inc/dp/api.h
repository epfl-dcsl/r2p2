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

#include <stdbool.h>
#include <stdint.h>

#include <net/net.h>

/* Net entry to be communicated by the stack to the application */
struct net_sge {
	void *payload;
	uint32_t len;
	void *handle; /* Not to be used by applications */
};
/* Callback functions to be implemented by the application */
struct net_ops {
	void (*udp_recv)(struct net_sge *entry, struct ip_tuple *id);
};

/* Bool to know when to stop the run to completion loop in the app*/
extern volatile bool force_quit;

/*
 * Every app should define app_init function executed on *one* core when the
 * application launches
 * */
int app_init(__attribute__((unused)) int argc, char **argv);
/* Every app should define app_main that each core executes */
void app_main(void);
void set_net_ops(struct net_ops *ops);
void net_poll(void);
struct net_sge *alloc_net_sge(void);

/* UDP application calls */
static inline int udp_send(struct net_sge *entry, struct ip_tuple *id)
{
	if (entry->len > UDP_MAX_LEN)
		return -1;
	return udp_out(entry->handle, id, entry->len);
}

static inline void udp_recv_done(struct net_sge *entry)
{
	struct rte_mbuf *pkt_buf = entry->handle;
	rte_pktmbuf_free(pkt_buf);
}
