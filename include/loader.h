#ifndef PKTBURST_LOADER_H
#define PKTBURST_LOADER_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_atomic.h>

struct loader_core_stats {
    uint64_t bytes;
    uint64_t packets;
    uint64_t files;
};

struct loader_core_config {
    char **pcap_files;
    int nb_files;
    unsigned int socket;
    int dynfield_offset;
    uint32_t nbruns;
    struct rte_mempool *pool;
    struct rte_ring *ring;
    struct rte_mbuf **mbufs_;
    uint16_t burst_size;
    uint16_t off_;
    struct loader_core_stats stats;
};

int loader_core(struct loader_core_config *config);

#endif // PKTBURST_LOADER_H
