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
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <dp/api.h>
#include <dp/core.h>
#ifdef SHOULD_TRACE
#include <dp/queue_trace.h>
#endif

#include <net/net.h>

RTE_DEFINE_PER_LCORE(int, queue_id);
RTE_DEFINE_PER_LCORE(struct wnd_stats *, rtcl_stats);

int core_main(void *arg)
{
#ifdef SHOULD_TRACE
	trace_init();
#endif
	int q_id = (int)(long)arg;

	printf("Hello from core : %u with queue %d\n", rte_lcore_id(), q_id);
	RTE_PER_LCORE(queue_id) = q_id;

	/* Init run-to-completion stats */
	RTE_PER_LCORE(rtcl_stats) = wnd_stats_init(RTC_WND);

	/* initialise network per core */
	net_init_per_core();
	app_main();

#ifdef SHOULD_TRACE
#ifdef CONN_TIME
	tcp_dump_conn_stats();
#endif
	trace_end();
#endif

	return 0;
}
