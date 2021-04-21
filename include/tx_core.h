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
    char *filename;
    bool volatile *stop_condition;
    struct rte_mempool *pool;
    struct rte_mbuf **mbufs;
    rte_atomic16_t *core_counter;
    struct rte_mbuf **mbufs_;
    struct rte_mbuf **pkts_;
    uint64_t nbruns;
    uint64_t nbruns_;
    uint32_t prepare_off_;
    uint32_t link_speed;
    uint32_t nb_pkts;
    uint32_t core_id;
    uint32_t batch_;
    uint32_t nb_pkts_;
    uint16_t burst_size;
    uint16_t port;
    uint16_t queue_min;
    uint16_t queue_num;
    uint16_t txd;
    uint16_t qid_;
    uint16_t qmax_;
    uint16_t off_;
    uint16_t burst_;
    struct tx_core_stats stats;
};

int tx_core(struct tx_core_config *config);

#endif
