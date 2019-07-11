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

#include <stdio.h>
#include <string.h>

#include <dp/api.h>

static struct ip_tuple local_id;
void echo_udp_recv(struct net_sge *entry, struct ip_tuple *id);
struct net_ops app_ops;

int app_init(__attribute__((unused)) int argc,
			 __attribute__((unused)) char **argv)
{
	printf("Hello udp_echo\n");
	app_ops.udp_recv = echo_udp_recv;
	set_net_ops(&app_ops);

	return 0;
}

void app_main(void)
{
	/* Start polling loop */
	do {
		net_poll();
	} while (!force_quit);
}

void echo_udp_recv(struct net_sge *entry, struct ip_tuple *id)
{
	struct net_sge *new_e = alloc_net_sge();
	memcpy(new_e->payload, entry->payload, entry->len);
	local_id.src_ip = id->dst_ip;
	local_id.dst_ip = id->src_ip;
	local_id.src_port = id->dst_port;
	local_id.dst_port = id->src_port;
	new_e->len = entry->len;
	udp_recv_done(entry);
	udp_send(new_e, &local_id);
}
