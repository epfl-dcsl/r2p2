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

#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

#include <rte_eal.h>

#define LOGSIZE 3000000

struct trace_info {
	int fd;
	uint32_t *maddr;
	unsigned long count;
};

RTE_DECLARE_PER_LCORE(struct trace_info, ti);

int trace_init(void);
void log_queue(uint32_t queue_len, uint32_t received, uint32_t cycles);
void log_pkt_len(uint32_t pktlen);
void log_conn_stats(long acc_time, long invocations);

static inline int trace_end(void)
{
	close(RTE_PER_LCORE(ti).fd);
	return 0;
}

#if 0
static inline unsigned long rdtsc(void)
{
	//unsigned int a, d;
	//asm volatile("rdtsc" : "=a"(a), "=d"(d));
	//return ((unsigned long) a) | (((unsigned long) d) << 32);
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (long) tv.tv_sec * 1000000 + (long) tv.tv_usec;
};
#endif
