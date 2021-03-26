#ifndef PKTBURST_PCAP_H
#define PKTBURST_PCAP_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>


#define PCAP_SNAPLEN_DEFAULT 65535

struct pcap_header {
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct pcap_packet_header {
    uint32_t timestamp;
    uint32_t microseconds;
    uint32_t packet_length;
    uint32_t packet_length_wire;
};

void pcap_header_init(struct pcap_header *header, uint32_t snaplen);

int load_pcap(const char *filename, struct rte_mempool *pool,
              struct rte_mbuf **mbufs, int *nb_pkts);

#endif
