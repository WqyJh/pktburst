#ifndef PKTBURST_STATISTICS_H
#define PKTBURST_STATISTICS_H

#include <stdint.h>
#include <time.h>

#include <rte_atomic.h>

#include <tx_core.h>


struct stats_config {
    struct tx_core_config *tx_core_config_list;
    bool volatile *stop_condition;
    rte_atomic16_t *core_counter;
    uint64_t portmask;
    uint64_t interval;
    uint64_t last_packets_;
    uint64_t last_bytes_;
    uint64_t last_drop_;
    uint16_t txq;
    uint16_t nb_tx_cores;
    struct timespec start_, end_;
};

/*
 * Starts a non blocking statistics display
 */
void start_stats_display(struct stats_config * data);

#endif // PKTBURST_STATISTICS_H
