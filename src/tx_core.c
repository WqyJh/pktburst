#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_branch_prediction.h>
#include <rte_atomic.h>
#include <rte_mempool.h>
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

#include <tx_core.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER1
#define PREFETCH_NUM 4

static inline void modify_inc_ip_n(struct tx_core_config *config, struct rte_mbuf *mbuf, uint32_t n)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ipv4_hdr->src_addr += n;
    ipv4_hdr->dst_addr += n;
}

static inline void extend_packets(struct tx_core_config *config)
{
    uint32_t batch = config->txd * config->queue_num / config->nb_pkts;
    uint32_t old_nb_pkts = config->nb_pkts;
    uint32_t nb_pkts_ = config->nb_pkts * batch;
    struct rte_mbuf **mbufs = rte_malloc(NULL, sizeof(struct rte_mbuf *) * nb_pkts_, 0);
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
    config->nb_pkts_ = nb_pkts_;
    config->mbufs_ = mbufs;
}

static inline void restore_extended_packets(struct tx_core_config *config)
{
    rte_pktmbuf_free_bulk(config->mbufs_ + config->nb_pkts, config->nb_pkts_ - config->nb_pkts);
    rte_free(config->mbufs_);
    config->nb_pkts_ = 0;
}

static inline void modify_packet(struct tx_core_config *config, struct rte_mbuf *mbuf)
{
    modify_inc_ip_n(config, mbuf, config->batch_);
}

static inline void flush_packets(struct tx_core_config *config)
{
    struct tx_core_stats *stats = &config->stats;
    struct rte_mbuf **pos = config->pkts_;
    uint32_t to_sent = config->off_;
    while (to_sent) {
        uint16_t nb_tx = rte_eth_tx_burst(config->port, config->qid_, pos, to_sent);
        if (++config->qid_ > config->qmax_) config->qid_ = config->queue_min;
        // // Collect stats
        stats->packets += nb_tx;
        for (int i = 0; i < nb_tx; i++) {
            stats->bytes += rte_pktmbuf_pkt_len(pos[i]);
        }
        // Adjust pos
        to_sent -= nb_tx;
        pos += nb_tx;
    }
}

static inline bool process_packet(struct tx_core_config *config, struct rte_mbuf *mbuf)
{
    struct tx_core_stats *stats = &config->stats;

    // Buffer fulled
    if (config->off_ == config->burst_) {
        // Sent packets
        uint16_t nb_tx = rte_eth_tx_burst(config->port, config->qid_, config->pkts_, config->burst_);
        if (++config->qid_ > config->qmax_) config->qid_ = config->queue_min;
        if (unlikely(nb_tx == 0)) return false;

        // Collect stats
        stats->packets += nb_tx;
        for (int i = nb_tx; i < config->burst_; i++) {
            stats->bytes += rte_pktmbuf_pkt_len(config->pkts_[i]);
        }

        // Move the unsent packets to front of bufs
        if (nb_tx < config->burst_) {
            uint16_t remain = config->burst_ - nb_tx;
            rte_memcpy(config->pkts_, config->pkts_ + nb_tx, remain * sizeof(struct rte_mbuf *));
        }

        config->off_ -= nb_tx;
    }

    // Modify packet
    if (likely(config->nbruns_ > config->batch_)) {
        modify_packet(config, mbuf);
    }

    // Enq packet to buffer
    config->pkts_[config->off_++] = mbuf;
    config->prepare_off_++;
    if (config->prepare_off_ == config->nb_pkts) {
        config->prepare_off_ = 0;
        config->nbruns_++;
    }

    return true;
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
    const bool small_nb_pkts_ = config->nb_pkts < config->txd * config->queue_num;
    if (small_nb_pkts_) {
        extend_packets(config);
    } else {
        config->mbufs_ = config->mbufs;
        config->nb_pkts_ = config->nb_pkts;
        config->batch_ = 1;
    }

    config->burst_ = MIN(config->burst_size, config->nb_pkts_);
    config->pkts_ = (struct rte_mbuf **)rte_malloc(NULL, sizeof(struct rte_mbuf*) * config->burst_, 0);

    int qid = config->queue_min;
    int qmax = config->queue_min + config->queue_num - 1;

    RTE_LOG(INFO, TX, "Tx core %u is running for port %u queue %u-%u\n",
        rte_lcore_id(), config->port, qid, qmax);

    int i = 0;
    for (;;) {
        if (unlikely(*(config->stop_condition))) {
            break;
        }

        // Prefetch packets: quite the same with non prefetch
        // Prefetch: 11.467 Mpps
        // Non prefetch: 11.467 Mpps
        if ((i & (PREFETCH_NUM - 1)) == 0) {
            for (int j = i; j < i + PREFETCH_NUM; j++) {
                if (likely(j < config->nb_pkts_)) {
                    rte_prefetch0(rte_pktmbuf_mtod(config->mbufs_[j], void *));
                } else {
                    rte_prefetch0(rte_pktmbuf_mtod(config->mbufs_[j - config->nb_pkts_], void *));
                }
            }
        }

        // Process packets
        bool processed = process_packet(config, config->mbufs_[i]);
        if (unlikely(!processed)) continue;
        if (++i == config->nb_pkts_) {
            i = 0;
        }
        if (unlikely(config->nbruns_ == config->nbruns)) {
            flush_packets(config);
            break;
        }
    }

    if (small_nb_pkts_) {
        restore_extended_packets(config);
    }

    rte_free(config->pkts_);
    rte_atomic16_dec(config->core_counter);
    RTE_LOG(INFO, TX, "Tx core %u stopped\n", rte_lcore_id());
    return 0;
}
