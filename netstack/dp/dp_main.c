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

//#define ENABLE_PCAP 1
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#ifdef ENABLE_PCAP
#include <rte_pdump.h>
#endif

#include <dp/api.h>
#include <dp/core.h>
#include <dp/dpdk_api.h>

#include <net/net.h>

#include <r2p2/cfg.h>

volatile bool force_quit;

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
#ifdef ENABLE_PCAP
		rte_pdump_uninit();
#endif
	}
}

int main(int argc, char **argv)
{
	int ret, count;
	unsigned lcore_id;

	/* set signal handler for proper exiting */
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (parse_config()) {
		printf("cfg error\n");
		return -1;
	}

	/*initialise dpdk*/
	dpdk_init(&argc, &argv);
	/*parse any other input args*/

#ifdef ENABLE_PCAP
	rte_pdump_init(NULL);
#endif

	/*initialise network*/
	if (net_init()) {
		printf("Error initializing network\n");
		goto OUT;
	}

	/* Run the application initialisation function */
	if (app_init(argc, argv)) {
		printf("Error initializing application\n");
		goto OUT;
	}

	/* launch main function on all cores */
	count = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		rte_eal_remote_launch(core_main, (void *)(long)count, lcore_id);
		count++;
	}
	core_main((void *)(long)count);
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

OUT:
	dpdk_close();
	printf("Bye...\n");
	return ret;
}
