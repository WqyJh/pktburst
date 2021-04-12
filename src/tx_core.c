#include <errno.h>
#include <rte_atomic.h>
#include <rte_mempool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
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
#define EXTEND_PACKETS_THRESH 128

static inline void modify_inc_ip_n(struct tx_core_config *config, struct rte_mbuf *mbuf, uint32_t n)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ipv4_hdr->src_addr += n;
    ipv4_hdr->dst_addr += n;
    rte_mb();
}

static inline void extend_packets(struct tx_core_config *config)
{
    uint32_t batch = config->txd * config->queue_num / config->nb_pkts + 1;
    if (batch > config->nbruns) {
        batch = config->nbruns;
    }
    uint32_t old_nb_pkts = config->nb_pkts;
    uint32_t nb_pkts = config->nb_pkts * batch;
    struct rte_mbuf **mbufs = rte_malloc(NULL, sizeof(struct rte_mbuf *) * nb_pkts, 0);
    struct rte_mempool *pool = config->mbufs[0]->pool;
    rte_memcpy(mbufs, config->mbufs, sizeof(struct rte_mbuf *) * old_nb_pkts);
    for (int i = 1; i < batch; i++) {
        for (int j = 0; j < old_nb_pkts; j++) {
            struct rte_mbuf *old = mbufs[j];
            struct rte_mbuf *mbuf = rte_pktmbuf_copy(old, pool, 0, rte_pktmbuf_pkt_len(old));
            modify_inc_ip_n(config, mbuf, i);
            mbufs[i * old_nb_pkts + j] = mbuf;
        }
    }
    config->batch_ = batch;
    config->nb_pkts = nb_pkts;
    config->old_nb_pkts_ = old_nb_pkts;
    config->old_mbufs_ = config->mbufs;
    config->mbufs = mbufs;
}

static inline uint16_t prepare_small_nb_pkts(struct tx_core_config *config, struct rte_mbuf **bufs, uint16_t nb_pkts) 
{
    uint16_t n = 0;

#define PREFETCH_NUM 8
    for (int i = 0; i < nb_pkts; i += PREFETCH_NUM) {
        for (int j = config->pos_; j < config->pos_ + PREFETCH_NUM; j++) {
            if (unlikely(j >= config->nb_pkts)) {
                rte_prefetch0(rte_pktmbuf_mtod(config->mbufs[j - config->nb_pkts], void *));
            } else {
                rte_prefetch0(rte_pktmbuf_mtod(config->mbufs[j], void *));
            }
        }
        for (int j = i; j < i + PREFETCH_NUM && j < nb_pkts; j++) {
            struct rte_mbuf *mbuf = config->mbufs[config->pos_];
            if (likely(!config->first_run_)) {
                modify_inc_ip_n(config, mbuf, config->batch_);
            }

            bufs[n++] = mbuf;
            if (unlikely(++config->pos_ == config->nb_pkts)) {
                config->pos_ = 0;
                if (unlikely(config->first_run_))
                    config->first_run_ = false;
            }
            if (unlikely(++config->pkt_prepared_ == config->old_nb_pkts_)) {
                config->pkt_prepared_ = 0;
                if (unlikely(--config->nbruns == 0)) {
                    goto end;
                }
            }
        }
    }
end:
    return n;
}

static inline uint16_t prepare_packets(struct tx_core_config *config, struct rte_mbuf **bufs, uint16_t nb_pkts) 
{
    uint16_t n = 0;

#define PREFETCH_NUM 8
    for (int i = 0; i < nb_pkts; i += PREFETCH_NUM) {
        for (int j = config->pos_; j < config->pos_ + PREFETCH_NUM && n < nb_pkts; j++) {
            if (unlikely(j >= config->nb_pkts)) {
                rte_prefetch0(rte_pktmbuf_mtod(config->mbufs[j - config->nb_pkts], void *));
            } else {
                rte_prefetch0(rte_pktmbuf_mtod(config->mbufs[j], void *));
            }
        }
        for (int j = i; j < i + PREFETCH_NUM && j < nb_pkts; j++) {
            struct rte_mbuf *mbuf = config->mbufs[config->pos_];
            if (likely(!config->first_run_)) {
                modify_inc_ip_n(config, mbuf, 1);
            }

            bufs[n++] = mbuf;
            if (unlikely(++config->pos_ == config->nb_pkts)) {
                config->pos_ = 0;
                if (unlikely(config->first_run_))
                    config->first_run_ = false;
                if (--config->nbruns == 0) {
                    goto end;
                }
            }
        }
    }
end:
    return n;
}

/**
* Send packets loaded from pcap file for `nbruns` times.
* Modify packets after each run.
*
* small_nb_pkts: packets number less than number of nic descriptors.
*
* When packets are more than nic descriptors, an tx bursted mbuf won't
* be modified by packet preparing because the mbufs might be reused before
* successfully sent by nic.
* |1|2|3|4|5|6|7|8|
*
* When packets are less than nic descriptors, copy packets to mutiple times
* each of which called a batch, ensuring the total number of packets are
* greater than nic descriptors.
* |1|2|3|4|1|2|3|4|
**/
int tx_core(struct tx_core_config *config)
{
    const bool small_nb_pkts = config->nb_pkts < config->txd * config->queue_num;
    if (small_nb_pkts) {
        extend_packets(config);
    }

    const uint16_t burst = config->burst_size;
    struct rte_mbuf **bufs = (struct rte_mbuf **)rte_malloc(NULL, sizeof(struct rte_mbuf*) * burst, 0);
    struct tx_core_stats *stats = &config->stats;
    int qid = config->queue_min;
    int qmax = config->queue_min + config->queue_num - 1;
    config->first_run_ = true;
    config->pos_ = 0; // pos to config->mbufs
    uint16_t tail = 0; // pos to bufs

    RTE_LOG(INFO, TX, "Tx core %u is running for port %u queue %u-%u\n",
        rte_lcore_id(), config->port, qid, qmax);

    for (;;) {
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        uint16_t nb_prepared;
        if (small_nb_pkts) {
            nb_prepared = prepare_small_nb_pkts(config, bufs + tail, MIN(burst, config->nb_pkts) - tail);
        } else {
            nb_prepared = prepare_packets(config, bufs + tail, MIN(burst, config->nb_pkts) - tail);
        }
        tail += nb_prepared;

        if (unlikely(config->nbruns == 0)) {
            // All packets has been prepared, drain them
            while (tail) {
                struct rte_mbuf **pos = bufs;
                uint16_t nb_tx = rte_eth_tx_burst(config->port, qid, pos, tail);
                if (++qid > qmax) qid = config->queue_min;
                stats->packets += nb_tx;
                for (int i = 0; i < nb_tx; i++) {
                    stats->bytes += rte_pktmbuf_pkt_len(bufs[i]);
                }
                pos += nb_tx;
                tail -= nb_tx;
            }
            break;
        }

        uint16_t nb_tx = rte_eth_tx_burst(config->port, qid, bufs, tail);
        if (++qid > qmax) qid = config->queue_min;
        if (unlikely(nb_tx == 0)) continue;

        stats->packets += nb_tx;
        for (int i = 0; i < nb_tx; i++) {
            stats->bytes += rte_pktmbuf_pkt_len(bufs[i]);
        }

        if (unlikely(nb_tx < tail)) {
            tail -= nb_tx;
            rte_memcpy(bufs, bufs + nb_tx, sizeof(struct rte_mbuf *) * tail);
        } else {
            tail = 0;
        }
    }
    if (small_nb_pkts) {
        rte_free(config->mbufs);
        config->mbufs = config->old_mbufs_;
        config->old_mbufs_ = NULL;
    }
    rte_free(bufs);
    rte_atomic16_dec(config->core_counter);
    RTE_LOG(INFO, TX, "Tx core %u stopped: %lu pkts sent\n", rte_lcore_id(), stats->packets);
    return 0;
}
