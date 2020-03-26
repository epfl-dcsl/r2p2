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
#include <rte_ethdev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <dp/dpdk_api.h>
#include <dp/dpdk_config.h>
#include <net/net.h>
#include <net/utils.h>

int net_init(void)
{
	igmp_init();
	return 0;
}

int net_init_per_core(void)
{
#ifndef NO_BATCH
	RTE_PER_LCORE(tx_buf) =
		rte_malloc(NULL, RTE_ETH_TX_BUFFER_SIZE(4 * ETH_DEV_TX_QUEUE_SZ), 0);
	rte_eth_tx_buffer_init(RTE_PER_LCORE(tx_buf), 4 * ETH_DEV_TX_QUEUE_SZ);
#endif

	return 0;
}
