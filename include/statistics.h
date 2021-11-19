#ifndef PKTBURST_STATISTICS_H
#define PKTBURST_STATISTICS_H

#include <stdint.h>
#include <time.h>

#include <rte_atomic.h>
#include <rte_mempool.h>

#include <tx_core.h>
#include <loader.h>

struct port_stats_ {
    uint64_t packets;
    uint64_t bytes;
    uint64_t drop;
    struct timespec start, end;
};

struct stats_config {
    struct tx_core_config *tx_core_config_list;
    struct loader_core_config *loader_config;
    struct rte_ring *tx_ring;
    struct rte_mempool *mbuf_pool;
    uint64_t portmask;
    uint64_t interval;
    uint16_t txq;
    uint16_t nb_tx_cores;
    uint16_t nb_ports;
    uint16_t watch;
    struct port_stats_ *stats_;
};

/*
 * Starts a non blocking statistics display
 */
void start_stats_display(struct stats_config * data);

void stats_print(struct stats_config *config);

void stats_init(struct stats_config *config);

void stats_fini(struct stats_config *config);

#endif // PKTBURST_STATISTICS_H
