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

#include <stddef.h>
#include <stdint.h>

#include <r2p2/utils.h>

struct fixed_mempool {
	uint32_t size;
	uint32_t count;
	uint32_t idx;
	uint32_t elem_size;
	void *elems[];
} __attribute__((packed));

struct fixed_obj {
	uint32_t taken;
	struct fixed_mempool *owner;
	struct fixed_obj *next;
	struct fixed_obj *prev;
	void *elem[];
} __attribute__((packed));

struct fixed_linked_list {
	struct fixed_obj *head;
	struct fixed_obj *tail;
};

struct fixed_mempool *create_mempool(int pool_size, int object_size);
void *alloc_object(struct fixed_mempool *mpool);
void free_object(void *obj);

static inline struct fixed_obj *get_object_meta(void *obj)
{
	return container_of(obj, struct fixed_obj, elem);
}

static inline struct fixed_obj *peek_from_list(struct fixed_linked_list *l)
{
	return l->head;
}

void add_to_list(struct fixed_linked_list *l, struct fixed_obj *obj);
void remove_from_list(struct fixed_linked_list *l, struct fixed_obj *obj);
