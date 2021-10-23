#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_cycles.h>

#include <tx_core.h>
#include <statistics.h>

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define STATS_PERIOD_MS 1000
#define ROTATING_CHAR "-\\|/"
static unsigned int nb_stat_update = 0;

const char * bytes_unit[] = { "B", "KB", "MB", "GB", "TB" };
const char * units[] = { "", "K", "M", "G", "T" };
char result[50];

char *bytes_format(uint64_t bytes) {
    int i;
    double converted_bytes = bytes;
    for (i = 0; i < 5 && bytes >= 1024; i++, bytes /= 1024) {
        converted_bytes = bytes / 1024.0;
    }

    sprintf(result, "%.3f %s", converted_bytes, units[i]);
    return result;
}

char *kilo_format(double n, char *output, int len) {
    int i = 0;
    double d = n;
    for (; i < sizeof(units) && n >= 1000; i++, n /= 1000) {
        d = n / 1000.0;
    }

    snprintf(output, len, "%.3f %s", d, units[i]);
    return output;
}

double timespec_diff_to_double(const struct timespec start, const struct timespec end)
{
    struct timespec diff;
    double duration;

    diff.tv_sec = end.tv_sec - start.tv_sec;
    if (end.tv_nsec > start.tv_nsec)
        diff.tv_nsec = end.tv_nsec - start.tv_nsec;
    else {
        diff.tv_nsec = end.tv_nsec - start.tv_nsec + 1000000000;
        diff.tv_sec--;
    }
    duration = diff.tv_sec + ((double)diff.tv_nsec / 1000000000);
    return (duration);
}

static void print_port_stats(struct stats_config *config, uint16_t port, int idx)
{
    printf("-- PORT %u --\n", port);
    struct rte_eth_stats port_stats;
    rte_eth_stats_get(port, &port_stats);
    struct port_stats_ *stats_ = &config->stats_[idx];
    int ret = clock_gettime(CLOCK_TYPE_ID, &stats_->end);

    double avg_bytes = 0;
    double line_rate = 0;

    // struct tx_core_stats tx_stats;
    // memset(&tx_stats, 0, sizeof(struct tx_core_stats));
    for (int i = 0; i < config->nb_tx_cores; i++) {
        // Copy stats
        struct tx_core_config *tx_config = &config->tx_core_config_list[i];
        if (tx_config->port != port) continue;
        struct tx_core_stats stats = tx_config->stats;
        // // Accumulate stats
        // tx_stats.packets += stats.packets;
        // tx_stats.bytes += stats.bytes;
        // tx_stats.drop += stats.drop;
        // Print stats
        printf("Tx core %u port %u queue %u-%u\n", tx_config->core_id, tx_config->port,
            tx_config->queue_min, tx_config->queue_min + tx_config->queue_num - 1);
        printf("\tpackets=%lu\tbytes=%lu\terror=%lu\n",
            stats.packets, stats.bytes, stats.drop);
    }
    // // Print accumulated stats
    // printf("Tx core summary\n");
    // printf("\tpackets=%lu\tbytes=%lu\terror=%lu\n",
    //     tx_stats.packets, tx_stats.bytes, tx_stats.drop);


    if (unlikely(ret)) {
        fprintf(stderr, "clock_gettime failed on start: %s\n",
                strerror(errno));
    } else {
        uint32_t link_speed = config->tx_core_config_list[idx].link_speed;
        uint64_t tx_packets = port_stats.opackets - stats_->packets;
        uint64_t tx_bytes = port_stats.obytes - stats_->bytes;

        if (tx_packets > 0) {
            avg_bytes = (double)tx_bytes / tx_packets;
            line_rate = link_speed * 1000 * 1000.0 / (8 * (avg_bytes + 8 + 12));
        }

        double seconds = timespec_diff_to_double(stats_->start, stats_->end);
        double pps = tx_packets / seconds;
        double bps = tx_bytes / seconds;
        stats_->packets = port_stats.opackets;
        stats_->bytes = port_stats.obytes;
        stats_->start = stats_->end;
#define BUF_LEN 16
        char pps_buf[BUF_LEN];
        char line_rate_buf[BUF_LEN];
        printf("\tspeed\t%spps\t%sBps\tlinerate=%spps\t\n",
            kilo_format(pps, pps_buf, BUF_LEN),
            bytes_format(bps),
            kilo_format(line_rate, line_rate_buf, BUF_LEN));
    }
    printf("\tBuilt-in counters:\n" \
    "\tTX Successful packets: %lu\n" \
    "\tTX Successful bytes: %s (avg: %.2lf bytes/pkt)\n" \
    "\tTX Unsuccessful packets: %lu\n",
        port_stats.opackets,
        bytes_format(port_stats.obytes),
        avg_bytes,
        port_stats.oerrors);
}

static void print_stats(struct stats_config *config)
{
    if (config->watch) {
        printf("\e[1;1H\e[2J");
    }
    printf("=== Packet burst statistics %c ===\n", ROTATING_CHAR[nb_stat_update++ % 4]);
    uint16_t port;
    uint16_t port_idx = 0;
    RTE_ETH_FOREACH_DEV(port) {
        if ((1ULL << port) & config->portmask) {
            print_port_stats(config, port, port_idx++);
        }
    }
    printf("===================================\n\n");
}


void start_stats_display(struct stats_config *config)
{
    config->stats_ = rte_zmalloc(NULL, sizeof(struct port_stats_) * config->nb_ports, 0);
    struct port_stats_ *stats = config->stats_;
    int ret = clock_gettime(CLOCK_MONOTONIC, &stats[0].start);
    if (unlikely(ret)) {
        fprintf(stderr, "clock_gettime failed on start: %s\n",
                strerror(errno));
    }
    for (int i = 1; i < config->nb_ports; i++) {
        stats[i].start = stats[0].start;
    }
    for (;;) {
        if (unlikely(*(config->stop_condition) ||
            rte_atomic16_read(config->core_counter) == 0)) {
            break;
        }
        print_stats(config);
        rte_delay_ms(config->interval);
    }
    rte_free(config->stats_);
}
