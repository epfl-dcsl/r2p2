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

#define MEMPOOL_CACHE_SIZE 64
#define NB_MBUF 65536 - 1
#ifdef ROUTER
#define ETH_DEV_RX_QUEUE_SZ 4096
#define ETH_DEV_TX_QUEUE_SZ 2048
#define BATCH_SIZE 64
#else
#ifdef WITH_RAFT
#define ETH_DEV_RX_QUEUE_SZ 4096
#define ETH_DEV_TX_QUEUE_SZ 4096
#define BATCH_SIZE 128
#else
#define ETH_DEV_RX_QUEUE_SZ 1024
#define ETH_DEV_TX_QUEUE_SZ 512
#define BATCH_SIZE 32
#endif
#endif
