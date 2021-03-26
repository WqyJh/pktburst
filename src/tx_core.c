#include <errno.h>
#include <generic/rte_atomic.h>
#include <generic/rte_cycles.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_ring.h>
#include <rte_version.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include <pcap.h>
#include <tx_core.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER1

#define RETRIES 10000

int tx_core(struct tx_core_config *config)
{
    struct tx_core_stats *stats = &config->stats;
    int qid = config->queue_min;
    int qmax = config->queue_min + config->queue_num - 1;

    RTE_LOG(INFO, TX, "Tx core %u is running for port %u queue %u-%u\n",
        rte_lcore_id(), config->port, qid, qmax);

    struct rte_mbuf **mbufs;

    // Repeat for nbruns
    for (int i = 0; i < config->nbruns; i++) {
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        mbufs = config->mbufs;

        // Send all
        int total_pkts = config->nb_pkts;
        int tries = 0;
        while (total_pkts) {
            int burst = MIN(total_pkts, config->burst_size);
            int nb_tx = rte_eth_tx_burst(config->port, qid, mbufs, burst);
            if (++qid > qmax) qid = config->queue_min;

            if (likely(nb_tx > 0)) {
                for (int j = 0; j < nb_tx; j++) {
                    stats->bytes += rte_pktmbuf_pkt_len(mbufs[j]);
                }
                total_pkts -= nb_tx;
                mbufs += nb_tx;
                stats->packets += nb_tx;
                tries = 0;
            } else {
                rte_delay_us_block(1000);
                if (++tries > RETRIES) {
                    total_pkts -= burst;
                    mbufs += burst;
                    stats->drop += burst;
                    tries = 0;
                }
            }
        }
    }
    rte_atomic16_dec(config->core_counter);
    RTE_LOG(INFO, TX, "Tx core %u stopped\n", rte_lcore_id());
    return 0;
}
