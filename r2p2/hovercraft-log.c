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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <r2p2/raft-log.h>
#include <r2p2/mempool.h>

static struct r2p2_raft_log *log;


int r2p2_raft_log_add(raft_entry_t *entry)
{
	struct r2p2_server_pair *sp;
	struct log_item *it;
	generic_buffer gb;

	it = &log->items[log->head++ % LOG_ENTRY_COUNT];
	sp = entry->data.buf;

	// Make old entry buf NULL to know log is overwritten
	// and free request buffers
	if (it->entry) {
		it->entry->data.buf = NULL;

		gb = it->sp.request.head_buffer;
		while (gb != NULL) {
			free_buffer(gb);
			gb = get_buffer_next(gb);
		}
	}

	//copy
	memcpy(&it->sp, sp, sizeof(struct r2p2_server_pair));
	it->entry = entry;
	entry->data.buf = &it->sp;

	return 0;
}

struct r2p2_raft_log *r2p2_raft_log_init(void)
{
	log = malloc(sizeof(struct r2p2_raft_log));
	assert(log);
	bzero(log, sizeof(struct r2p2_raft_log));
	return log;
}
