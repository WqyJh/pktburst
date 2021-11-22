#ifndef PKTBURST_LOADER_H
#define PKTBURST_LOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_atomic.h>

struct loader_core_stats {
    rte_atomic64_t bytes;
    rte_atomic64_t packets;
    rte_atomic32_t files;
};

struct loader_core_config {
    char *file;
    unsigned int socket;
    int worker_id;
    uint32_t runstart;
    uint32_t nbruns;
    struct rte_mempool *pool;
    struct rte_ring *ring;
    struct rte_mbuf **mbufs_;
    uint16_t burst_size;
    uint16_t off_;
    pthread_t th;
    cpu_set_t *cpuset;
    struct ring_pair *ring_pairs;
    struct ring_pair *ring_pairs_;
    struct loader_core_stats *stats;
};

int loader_core(struct loader_core_config *config);

#endif // PKTBURST_LOADER_H
