#include <rte_malloc.h>
#include <rte_mbuf_dyn.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <loader.h>
#include <common.h>


#define RTE_LOGTYPE_LOADER RTE_LOGTYPE_USER1

static inline bool flush_buffered_packets(struct loader_core_config *config) {
    uint16_t off = config->off_;
    uint16_t burst = config->burst_size;
    struct rte_mbuf **mbufs = config->mbufs_;
    if (unlikely(off == 0)) return true;

    uint32_t nb_rx = rte_ring_enqueue_burst(config->ring, (void **)mbufs, off, NULL);
    if (unlikely(nb_rx == 0)) return false;

    // Move the unsent packets to front of bufs
    if (nb_rx < burst) {
        uint16_t remain = burst - nb_rx;
        rte_memcpy(mbufs, mbufs + nb_rx, remain * sizeof(struct rte_mbuf *));
    }

    off -= nb_rx;
    config->off_ = off;
    return off == 0;
}

static inline bool process_packet(struct loader_core_config *config, struct rte_mbuf *mbuf) {
    uint16_t off = config->off_;
    uint16_t burst = config->burst_size;
    struct rte_mbuf **mbufs = config->mbufs_;
    if (off == config->burst_size) {
        // Sent packets
        uint32_t nb_rx = rte_ring_enqueue_burst(config->ring, (void **)mbufs, burst, NULL);
        if (unlikely(nb_rx == 0)) return false;

        // Move the unsent packets to front of bufs
        if (nb_rx < burst) {
            uint16_t remain = burst - nb_rx;
            memmove(mbufs, mbufs + nb_rx, remain * sizeof(struct rte_mbuf *));
        }

        off -= nb_rx;
    }

    RTE_ASSERT(off > 0);
    mbufs[off++] = mbuf;
    config->off_ = off;
    return true;
}

static inline void modify_inc_ip_n(struct loader_core_config *config, char *buf, uint32_t n)
{
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buf;
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ipv4_hdr->src_addr += n;
    ipv4_hdr->dst_addr += n;
}

static inline void process_file(struct loader_core_config *config, pcap_t *pcap, int runid) {
    int pkt_idx = 0;
    struct pcap_pkthdr *packet_header;
    const u_char *packet;
    while (!global_stop) {
        int ret = pcap_next_ex(pcap, &packet_header, &packet);
        if (ret == -1) { // error occurred while reading the packet
            RTE_LOG(INFO, LOADER, "Failed to read packet[%d] from %s: %s\n", pkt_idx, config->file, pcap_geterr(pcap));
            break;
        } else if (ret == -2) { // EOF
            return;
        }
        RTE_ASSERT(ret == 1); // Read packet success

        do {
            struct rte_mbuf *mbuf = rte_pktmbuf_alloc(config->pool);
            if (mbuf == NULL) {
                RTE_LOG(ERR, LOADER, "Failed to alloc mbuf, please enlarge pktmbuf pool size\n");
                rte_delay_us_sleep(1000); // delay 1ms
                continue;
            }
            rte_atomic32_inc(&global_alloc_counter);
            
            int len = packet_header->caplen;
            if (unlikely(len > mbuf->buf_len)) {
                RTE_LOG(INFO, LOADER, "Packet length %d exceeds the mbuf size %d, packet will be truncated\n",
                    len, mbuf->buf_len);
                len = mbuf->buf_len;
            }
            RTE_ASSERT(len <= 1514);
            mbuf->data_off = RTE_PKTMBUF_HEADROOM;
            mbuf->data_len = mbuf->pkt_len = len;
            mbuf->nb_segs = 1;
            mbuf->next = NULL;
            char *dst = rte_pktmbuf_mtod(mbuf, char *);
            memcpy(dst, packet, len);
            modify_inc_ip_n(config, dst, runid);

            // struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)dst;
            // if (ntohs(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
            //     fprintf(stderr, "file: %s ether_type: 0x%4x ipv6:%d\n", config->file, eth_hdr->ether_type,
            //     ntohs(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6
            //     );
            //     uint8_t *buf = rte_pktmbuf_mtod(mbuf, uint8_t*);
            //     for (int i = 0; i < rte_pktmbuf_data_len(mbuf); i++) {
            //         fprintf(stderr, "%02x ", buf[i]);
            //     }
            //     fprintf(stderr, "\n");
            // }
            // *RTE_MBUF_DYNFIELD(mbuf, config->dynfield_offset, uint32_t*) = 0;
            // mbuf->dynfield1[0] = 0; // TODO: register dynfield

            rte_atomic64_inc(&config->stats->packets);
            rte_atomic64_add(&config->stats->bytes, len);

            while(!global_stop && !process_packet(config, mbuf));
            break;
        } while (!global_stop);
    }
}

int reset_pcap(pcap_t *pcap) {
    FILE *f = pcap_file(pcap);
    return fseek(f, sizeof(struct pcap_file_header), SEEK_SET);
}

int loader_core(struct loader_core_config *config) {
    set_thread_attrs(config->th, "loader", config->worker_id, config->cpuset);
    RTE_LOG(INFO, LOADER, "Loader core %u started\n", config->worker_id);

    config->mbufs_ = rte_malloc_socket(NULL, sizeof(struct rte_mbuf *) * config->burst_size, 0, config->socket);
    config->off_ = 0;

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    pcap = pcap_open_offline(config->file, ebuf);
    if (pcap == NULL) {
        RTE_LOG(ERR, LOADER, "Failed to open pcap file %s: %s, skip it\n", config->file, ebuf);
        goto end;
    }
    rte_atomic32_inc(&config->stats->files);

    for (int i = config->runstart; i < config->runstart + config->nbruns && !global_stop; i++) {
        process_file(config, pcap, i);

        if (reset_pcap(pcap) == -1) {
            RTE_LOG(ERR, LOADER, "Failed to reset pcap file %s: %s, close it\n", config->file, strerror(errno));
            break;
        }
    }

    while (!global_stop && !flush_buffered_packets(config));

    pcap_close(pcap);
end:
    rte_free(config->mbufs_);
    rte_atomic32_dec(&global_loader_counter);
    RTE_LOG(INFO, LOADER, "Loader core %u stopped\n", config->worker_id);
    return 0;
}
