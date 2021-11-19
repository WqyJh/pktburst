#ifndef PKTBURST_CORE_WRITE_H
#define PKTBURST_CORE_WRITE_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_atomic.h>


#define PKTBURST_OUTPUT_FILE_LENGTH 100
#define PKTBURST_WRITE_BURST_SIZE 256

struct tx_core_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t drop;
};

struct tx_core_config {
    struct rte_ring *ring;
    uint32_t core_id;
    uint32_t socket;
    uint16_t burst_size;
    uint16_t port;
    uint16_t queue_min;
    uint16_t queue_num;
    struct tx_core_stats stats;
};

int tx_core(struct tx_core_config *config);

#endif
