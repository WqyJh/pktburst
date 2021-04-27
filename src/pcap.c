#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_branch_prediction.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>

#include <pcap/pcap.h>

#define RTE_LOGTYPE_PCAP RTE_LOGTYPE_USER1

#define MIN(a, b) ((a) < (b) ? (a) : (b))


int load_pcap(const char *filename, struct rte_mempool *pool,
              struct rte_mbuf **mbufs, int *nb_pkts)
{
    int ret = -1;
    int n = 0;

	char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_file = NULL;
    pcap_file = pcap_open_offline(filename, ebuf);
    if (pcap_file == NULL) {
        fprintf(stderr, "Failed to open pcap file: %s\n", ebuf);
        goto end;
    }

    uint64_t bytes = 0;
    int max_len = 0;
    struct pcap_pkthdr packet_header;
    while (1) {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool);
        if (!mbuf) {
            RTE_LOG(ERR, PCAP, "Failed to alloc mbuf, please enlarge pktmbuf pool size\n");
            goto end;
        }
        do {
            const u_char *packet = pcap_next(pcap_file, &packet_header);
            if (packet == NULL) {
                rte_pktmbuf_free(mbuf);
                RTE_LOG(INFO, PCAP, "Failed to read packet: %s\n", pcap_geterr(pcap_file));
                goto end;
            }
            if (unlikely(packet_header.len > mbuf->buf_len)) {
                RTE_LOG(INFO, PCAP, "Packet length %d exceeds the mbuf size %d, skip this packet\n",
                    packet_header.len, mbuf->buf_len);
                break;
            }
            rte_memcpy(mbuf->buf_addr, packet, packet_header.len);
            mbuf->data_off = 0;
            mbuf->data_len = mbuf->pkt_len = packet_header.len;
            mbuf->nb_segs = 1;
            mbuf->next = NULL;
            mbufs[n++] = mbuf;
            if (packet_header.len > max_len) {
                max_len = packet_header.len;
            }
            bytes += packet_header.len;
            break;
        } while (1);
    }

end:
    if (n > 0) {
        RTE_LOG(INFO, PCAP, "Read %d pkts (for a total of %lu bytes), max packet length = %d bytes.\n", n, bytes, max_len);
        *nb_pkts = n;
        ret = 0;
    }

    if (pcap_file > 0) {
        pcap_close(pcap_file);
    }
    return ret;
}
