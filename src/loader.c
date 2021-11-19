#include <rte_malloc.h>
#include <rte_mbuf_dyn.h>
#include <rte_ether.h>

#include <pcap/pcap.h>
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

static inline void load_file(struct loader_core_config *config, char *filename) {

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_file = NULL;
    pcap_file = pcap_open_offline(filename, ebuf);
    if (pcap_file == NULL) {
        RTE_LOG(ERR, LOADER, "Failed to open pcap file: %s, skip it\n", ebuf);
        return;
    }
    config->stats.files++;

    int pkt_idx = 0;
    struct pcap_pkthdr *packet_header;
    const u_char *packet;
    while (!global_stop) {
        int ret = pcap_next_ex(pcap_file, &packet_header, &packet);
        if (ret == -1) { // error occurred while reading the packet
            RTE_LOG(INFO, LOADER, "Failed to read packet[%d] from %s: %s\n", pkt_idx, filename, pcap_geterr(pcap_file));
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
            uint8_t *dst = rte_pktmbuf_mtod(mbuf, uint8_t *);
            memcpy(dst, packet, len);

            struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)dst;
            if (ntohs(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                fprintf(stderr, "file: %s ether_type: 0x%4x ipv6:%d\n", filename, eth_hdr->ether_type,
                ntohs(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6
                );
                uint8_t *buf = rte_pktmbuf_mtod(mbuf, uint8_t*);
                for (int i = 0; i < rte_pktmbuf_data_len(mbuf); i++) {
                    fprintf(stderr, "%02x ", buf[i]);
                }
                fprintf(stderr, "\n");
            }
            // *RTE_MBUF_DYNFIELD(mbuf, config->dynfield_offset, uint32_t*) = 0;
            // mbuf->dynfield1[0] = 0; // TODO: register dynfield

            config->stats.bytes += len;
            config->stats.packets++;

            while(!global_stop && !process_packet(config, mbuf));
            break;
        } while (!global_stop);
    }
}

int loader_core(struct loader_core_config *config) {
    RTE_LOG(INFO, LOADER, "Loader core %u started\n", 0);

    config->mbufs_ = rte_malloc_socket(NULL, sizeof(struct rte_mbuf *) * config->burst_size, 0, config->socket);
    config->off_ = 0;

    for (int j = 0; j < config->nbruns; j++) {
        for (int i = 0; i < config->nb_files && !global_stop; i++) {
            load_file(config, config->pcap_files[i]);
        }
    }

    while (!global_stop && !flush_buffered_packets(config));
    rte_free(config->mbufs_);
    rte_atomic32_dec(&global_loader_counter);
    RTE_LOG(INFO, LOADER, "Loader core %u stopped\n", 0);
    return 0;
}
