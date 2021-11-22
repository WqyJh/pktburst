#ifndef PKTBURST_ALLOCATOR_H
#define PKTBURST_ALLOCATOR_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_atomic.h>

struct allocator_core_stats {
    uint64_t allocated;
    uint64_t enqueued;
    uint64_t dequeued;
    uint64_t queues;
};

struct allocator_core_config {
    unsigned int socket;
    struct rte_mempool *pool;
    struct rte_mbuf **mbufs_;
    uint16_t burst_size;
    uint16_t off_;
    pthread_t th;
    cpu_set_t *cpuset;
    int nb_ring_pairs;
    struct ring_pair *ring_pairs;
    struct allocator_core_stats *stats;
};

int allocator_core(struct allocator_core_config *config);

#endif // PKTBURST_ALLOCATOR_H
