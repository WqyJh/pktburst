#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <common.h>
#include <tx_core.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER1

int tx_core(struct tx_core_config *config) {
    RTE_LOG(INFO, TX, "Tx core %u started\n", rte_lcore_id());
    uint32_t off = 0;
    uint16_t qid = config->queue_min;
    uint16_t qmax = config->queue_min + config->queue_num - 1;
    struct rte_mbuf **bufs =
        rte_malloc_socket(NULL, sizeof(struct rte_mbuf *) * config->burst_size,
                          0, config->socket);

    for (;;) {
        if (unlikely(global_stop)) {
            break;
        }

        uint16_t nb_rx =
            rte_ring_dequeue_burst(config->ring, (void **)(bufs + off),
                                   config->burst_size - off, NULL);
        off += nb_rx;

        if (unlikely(off == 0)) { // tx_ring is empty
            if (rte_atomic32_read(&global_loader_counter) ==
                0) {             // loaders finished
                rte_delay_ms(1); // wait for packets in tx queue to be sent
                global_stop = true;
                break;
            }
        }

        uint16_t nb_tx = rte_eth_tx_burst(config->port, qid, bufs, off);
        if (++qid > qmax)
            qid = config->queue_min;
        config->stats.packets += nb_tx;

        off -= nb_tx;
        if (unlikely(off > 0)) {
            memmove(bufs, bufs + nb_tx, off * sizeof(struct rte_mbuf *));
        }
    }
    rte_free(bufs);
    RTE_LOG(INFO, TX, "Tx core %u stopped\n", rte_lcore_id());
    return 0;
}
