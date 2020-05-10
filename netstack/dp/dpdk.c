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

// Must be before all DPDK includes
#include <rte_config.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <dp/core.h>
#include <dp/dpdk_api.h>
#include <dp/dpdk_config.h>
#include <dp/utils.h>
#ifdef SHOULD_TRACE
#include <dp/queue_trace.h>
#endif
#include <net/net.h>

RTE_DEFINE_PER_LCORE(struct rte_eth_dev_tx_buffer *, tx_buf);
struct rte_mempool *pktmbuf_pool;
#ifndef NO_BATCH
static RTE_DEFINE_PER_LCORE(int, packet_count);
#endif
static uint8_t nb_ports;

static const struct rte_eth_conf port_conf = {
	.rxmode =
		{
			.split_hdr_size = 0,
			.header_split = 0,   /**< Header Split disabled */
			.hw_ip_checksum = 1, /**< IP checksum offload disabled */
			.hw_vlan_filter = 0, /**< VLAN filtering disabled */
			.jumbo_frame = 0,	/**< Jumbo Frame Support disabled */
			.hw_strip_crc = 1,   /**< CRC stripped by hardware */
			.mq_mode = ETH_MQ_RX_RSS,
		},
	.rx_adv_conf =
		{
			.rss_conf =
				{
					.rss_hf =
						ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP,
				},
		},
	.txmode =
		{
			.mq_mode = ETH_MQ_TX_NONE,
		},
};

void dpdk_init(int *argc, char ***argv)
{
	int ret;
	unsigned int i;
	uint8_t port_id = 0;
	uint16_t nb_rx_q;
	uint16_t nb_tx_q;
	uint16_t nb_tx_desc = ETH_DEV_TX_QUEUE_SZ; // 4096
	uint16_t nb_rx_desc = ETH_DEV_RX_QUEUE_SZ; // 512
	struct rte_eth_link link;

	/* init EAL */
	ret = rte_eal_init(*argc, *argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	*argc -= ret;
	*argv += ret;

#ifdef WITH_RAFT
	nb_rx_q = 1;
	nb_tx_q = 2;
#else
	nb_rx_q = rte_lcore_count();
	nb_tx_q = rte_lcore_count();
#endif

	/* create the mbuf pool */
	pktmbuf_pool =
		rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MEMPOOL_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	printf("I found %" PRIu8 " ports\n", nb_ports);

	printf("Configuring port...\n");
	ret = rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &port_conf);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "rte_eth_dev_configure:err=%d, port=%u\n",
				ret, (unsigned)port_id);
	}

	/* enable multicast */
	rte_eth_allmulticast_enable(port_id);

#ifdef WITH_RAFT
	(void)i;
	ret = rte_eth_dev_configure(0, nb_rx_q, nb_tx_q, &port_conf);
	/* enable multicast */
	rte_eth_allmulticast_enable(0);

	ret = rte_eth_tx_queue_setup(0, 0, nb_tx_desc,
			rte_eth_dev_socket_id(0), NULL);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_tx_queue_setup:err=%d\n", ret);
	}

	ret = rte_eth_tx_queue_setup(0, 1, nb_tx_desc,
			rte_eth_dev_socket_id(0), NULL);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_tx_queue_setup:err=%d\n", ret);
	}

	ret = rte_eth_rx_queue_setup(0, 0, nb_rx_desc,
			rte_eth_dev_socket_id(0), NULL,
			pktmbuf_pool);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
				(unsigned)port_id);
	}
#else
	/* initialize one queue per cpu */
	for (i = 0; i < rte_lcore_count(); i++) {
		printf("setting up TX and RX queues...\n");
		ret = rte_eth_tx_queue_setup(port_id, i, nb_tx_desc,
				rte_eth_dev_socket_id(port_id), NULL);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
					(unsigned)port_id);
		}

		ret = rte_eth_rx_queue_setup(port_id, i, nb_rx_desc,
				rte_eth_dev_socket_id(port_id), NULL,
				pktmbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
					"rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
					(unsigned)port_id);
		}
	}
#endif

	/* start the device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		printf("ERROR starting device at port %d\n", port_id);
	} else {
		printf("started device at port %d\n", port_id);
	}

	/* check the link */
	rte_eth_link_get(port_id, &link);

	if (!link.link_status) {
		printf("eth:\tlink appears to be down, check connection.\n");
	} else {
		printf("eth:\tlink up - speed %u Mbps, %s\n",
				(uint32_t)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX)
				? ("full-duplex")
				: ("half-duplex\n"));
	}
}

void dpdk_close(void)
{
	uint8_t portid;

	for (portid = 0; portid < nb_ports; portid++) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
}

int dpdk_eth_send(struct rte_mbuf *pkt_buf, uint16_t len)
{
	int ret = 0;

	/* get mbuf from user data */
	pkt_buf->pkt_len = len;
	pkt_buf->data_len = len;

#ifdef NO_BATCH
	while (1) {
		ret = rte_eth_tx_burst(0, RTE_PER_LCORE(queue_id), &pkt_buf, 1);
		if (ret == 1)
			break;
	}
#else
	ret = rte_eth_tx_buffer(0, RTE_PER_LCORE(queue_id), RTE_PER_LCORE(tx_buf),
							pkt_buf);
	assert(ret == 0);
	if (++RTE_PER_LCORE(packet_count) == 32)
		dpdk_flush();
#endif
	return 1;
}

void dpdk_flush(void)
{
#ifndef NO_BATCH
	/* Send the responses */
	int packet_no, ret;

	if (RTE_PER_LCORE(packet_count)) {
		packet_no = RTE_PER_LCORE(tx_buf)->length;
		ret = rte_eth_tx_buffer_flush(0, RTE_PER_LCORE(queue_id),
									  RTE_PER_LCORE(tx_buf));
		if (ret != packet_no) {
			printf("Packet no = %d, ret = %d\n", packet_no, ret);
		}
		// assert(ret == packet_no);
	}
	RTE_PER_LCORE(packet_count) = 0;
#endif
}

void dpdk_net_poll(void)
{
	int ret, i;
	struct rte_mbuf *rx_pkts[BATCH_SIZE];
	// long start, end, rtc_duration;

	ret = rte_eth_rx_burst(0, RTE_PER_LCORE(queue_id), rx_pkts, BATCH_SIZE);
#if defined(SHOULD_TRACE) && defined(TRACE_QUEUE)
	uint32_t pending;
	pending = rte_eth_rx_queue_count(0, RTE_PER_LCORE(queue_id));
	long before = rdtsc();
#endif

	// start = get_time_now();
	for (i = 0; i < ret; i++)
		eth_in(rx_pkts[i]);
// end = get_time_now();

// rtc_duration = end - start;
// if (rtc_duration)
//	wnd_stats_add_el(RTE_PER_LCORE(rtcl_stats), rtc_duration);

#if defined(SHOULD_TRACE) && defined(TRACE_QUEUE)
	uint32_t cycles = rdtsc() - before;
	if (ret)
		log_queue(pending, ret, cycles);
#endif

#ifndef NO_BATCH
	dpdk_flush();
#endif
}
