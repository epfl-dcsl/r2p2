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
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <dp/wnd_stats.h>

struct wnd_stats *wnd_stats_init(int size)
{
	assert(size % 2 == 0);
	struct wnd_stats *stats = calloc(1, sizeof(struct wnd_stats));
	stats->size = size;
	stats->samples = calloc(size, sizeof(long));

	return stats;
}

void wnd_stats_add_el(struct wnd_stats *stats, long el)
{
	int idx = stats->count++ & (stats->size - 1);
	stats->sum -= stats->samples[idx];
	stats->sum_of_squares -= stats->samples[idx] * stats->samples[idx];
	stats->samples[idx] = el;
	stats->sum += el;
	stats->sum_of_squares += el * el;
	if (el > stats->max)
		stats->max = el;
}

long wnd_stats_get_avg(struct wnd_stats *stats)
{
	uint32_t denom = (stats->count < stats->size) ? stats->count : stats->size;
	if (!denom)
		return 0;
	return stats->sum / denom;
}

static long wnd_stats_get_sqr_avg(struct wnd_stats *stats)
{
	uint32_t denom = (stats->count < stats->size) ? stats->count : stats->size;
	if (!denom)
		return 0;
	return stats->sum_of_squares / denom;
}

long wnd_stats_get_max(struct wnd_stats *stats)
{
	long max = 0;
	for (unsigned int i = 0; i < stats->size; i++)
		if (max < stats->samples[i])
			max = stats->samples[i];
	// return stats->max;
	return max;
}

double wnd_stats_get_std(struct wnd_stats *stats)
{
	return sqrt(wnd_stats_get_sqr_avg(stats) - wnd_stats_get_avg(stats));
}
