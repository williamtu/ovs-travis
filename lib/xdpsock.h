/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef XDPSOCK_H
#define XDPSOCK_H 1

#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "openvswitch/thread.h"
#include "ovs-atomic.h"

#define FRAME_HEADROOM  XDP_PACKET_HEADROOM
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      NETDEV_MAX_BURST
#define FRAME_SHIFT     XSK_UMEM__DEFAULT_FRAME_SHIFT
#define FRAME_SHIFT_MASK    ((1 << FRAME_SHIFT) - 1)

#define NUM_FRAMES      4096
#define PROD_NUM_DESCS  512
#define CONS_NUM_DESCS  512

#ifdef USE_XSK_DEFAULT
#define PROD_NUM_DESCS XSK_RING_PROD__DEFAULT_NUM_DESCS
#define CONS_NUM_DESCS XSK_RING_CONS__DEFAULT_NUM_DESCS
#endif

typedef struct {
    atomic_int locked;
} ovs_spinlock_t;

/* LIFO ptr_array */
struct umem_pool {
    int index;      /* point to top */
    unsigned int size;
    ovs_spinlock_t mutex;
    void **array;   /* a pointer array, point to umem buf */
};

/* array-based dp_packet_afxdp */
struct xpacket_pool {
    unsigned int size;
    struct dp_packet_afxdp **array;
};

struct xsk_umem_info {
    struct umem_pool mpool;
    struct xpacket_pool xpool;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
    uint32_t outstanding_tx;
};

struct umem_elem {
    struct umem_elem *next;
};

void __umem_elem_push(struct umem_pool *umemp, void *addr);
void umem_elem_push(struct umem_pool *umemp, void *addr);
int __umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs);
int umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs);

void *__umem_elem_pop(struct umem_pool *umemp);
void *umem_elem_pop(struct umem_pool *umemp);
int __umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs);
int umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs);

void **__umem_pool_alloc(unsigned int size);
int umem_pool_init(struct umem_pool *umemp, unsigned int size);
void umem_pool_cleanup(struct umem_pool *umemp);
unsigned int umem_elem_count(struct umem_pool *mpool);
int xpacket_pool_init(struct xpacket_pool *xp, unsigned int size);
void xpacket_pool_cleanup(struct xpacket_pool *xp);

#endif
