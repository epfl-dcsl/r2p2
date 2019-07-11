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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_lcore.h>

#include <dp/queue_trace.h>

RTE_DEFINE_PER_LCORE(struct trace_info, ti);

int trace_init(void)
{
	printf("Initializing tracing...\n");
	int ret;
	char fname[64];

	sprintf(fname, "/dp%u", rte_lcore_id());
	RTE_PER_LCORE(ti).fd = shm_open(fname, O_RDWR | O_CREAT | O_TRUNC, 0660);
	if (RTE_PER_LCORE(ti).fd == -1)
		return -1;

	ret = ftruncate(RTE_PER_LCORE(ti).fd, LOGSIZE * sizeof(uint32_t));
	if (ret)
		return ret;

	RTE_PER_LCORE(ti)
		.maddr = mmap(NULL, LOGSIZE * sizeof(uint32_t), PROT_READ | PROT_WRITE,
					  MAP_SHARED, RTE_PER_LCORE(ti).fd, 0);
	if (RTE_PER_LCORE(ti).maddr == MAP_FAILED)
		return -1;

	*RTE_PER_LCORE(ti).maddr = 0xDEADBEEF;
	return 0;
}

void log_queue(uint32_t queue_len, uint32_t received, uint32_t cycles)
{
	uint32_t *p1 = RTE_PER_LCORE(ti).maddr;

	if (RTE_PER_LCORE(ti).count >= LOGSIZE)
		return;
	*p1++ = queue_len;
	*p1++ = received;
	*p1++ = cycles;
	*p1 = 0xDEADBEEF;

	RTE_PER_LCORE(ti).count += 3;
	RTE_PER_LCORE(ti).maddr += 3;
}

void log_pkt_len(uint32_t pktlen)
{
	uint32_t *p1 = RTE_PER_LCORE(ti).maddr;

	if (RTE_PER_LCORE(ti).count >= LOGSIZE)
		return;
	*p1++ = pktlen;
	*p1 = 0xDEADBEEF;

	RTE_PER_LCORE(ti).count++;
	RTE_PER_LCORE(ti).maddr++;
}

void log_conn_stats(long acc_time, long invocations)
{
	long *p1 = (long *)RTE_PER_LCORE(ti).maddr;

	if (RTE_PER_LCORE(ti).count >= LOGSIZE)
		return;
	*p1++ = acc_time;
	*p1++ = invocations;
	*p1 = 0xDEADBEEF;

	RTE_PER_LCORE(ti).count += 4;
	RTE_PER_LCORE(ti).maddr += 4;
}
