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
#include <stdlib.h>

#include <r2p2/mempool.h>

struct fixed_mempool *create_mempool(int pool_size, int object_size)
{
	/*
	 * FIXME!!! Make sure pool_size is a power of 2
	 */
	struct fixed_mempool *mpool =
		malloc(sizeof(struct fixed_mempool) +
			   pool_size * sizeof(struct fixed_obj) + pool_size * object_size);
	mpool->idx = 0;
	mpool->count = 0;
	mpool->size = pool_size;
	mpool->elem_size = object_size;
	assert(mpool);

	return mpool;
}

void *alloc_object(struct fixed_mempool *mpool)
{
	char *p;
	struct fixed_obj *elem;
	uint32_t idx, step_size;

	if (mpool->count >= mpool->size)
		return NULL;

	step_size = sizeof(struct fixed_obj) + mpool->elem_size;
	p = (char *)mpool->elems;
	idx = mpool->idx++ & (mpool->size - 1);
	elem = (struct fixed_obj *)(p + idx * step_size);
	while (elem->taken) {
		idx = mpool->idx++ & (mpool->size - 1);
		elem = (struct fixed_obj *)(p + idx * step_size);
	}
	elem->taken = 1;
	elem->owner = mpool;
	elem->next = NULL;
	elem->prev = NULL;
	mpool->count++;

	return &elem->elem;
}

void free_object(void *obj)
{
	struct fixed_obj *fo;
	fo = get_object_meta(obj);

	fo->taken = 0;
	fo->next = NULL;
	fo->prev = NULL;
	assert(fo->owner->count);
	fo->owner->count--;
}

void add_to_list(struct fixed_linked_list *l, struct fixed_obj *obj)
{
	if (l->tail) {
		l->tail->next = obj;
		obj->prev = l->tail;
		l->tail = obj;
	} else {
		// list is empty
		l->tail = obj;
		l->head = obj;
		obj->prev = NULL;
	}
	obj->next = NULL;
}

void remove_from_list(struct fixed_linked_list *l, struct fixed_obj *obj)
{
	struct fixed_obj *obj2;

	if (obj == l->head)
		l->head = obj->next;
	if (obj == l->tail)
		l->tail = obj->prev;
	if (obj->prev) {
		obj2 = obj->prev;
		obj2->next = obj->next;
	}
	if (obj->next) {
		obj2 = obj->next;
		obj2->prev = obj->prev;
	}
}
