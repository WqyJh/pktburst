#include <asm-generic/errno-base.h>
#include <fcntl.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_branch_prediction.h>
#include <rte_eal.h>

#include <pcap.h>

#define RTE_LOGTYPE_PCAP RTE_LOGTYPE_USER1


void pcap_header_init(struct pcap_header *header, uint32_t snaplen)
{
    header->magic = 0xa1b2c3d4;
    header->major = 0x0002;
    header->minor = 0x0004;
    header->thiszone = 0;
    header->sigfigs = 0;
    header->snaplen = snaplen;
    header->linktype = 0x00000001; // Ethernet and Linux loopback
}

#define RTE_LOGTYPE_PCAP RTE_LOGTYPE_USER1

int open_pcap(const char *fn)
{
    int fd;
    fd = open(fn, O_RDONLY);
    if (unlikely(fd < 0)) {
        RTE_LOG(ERR, PCAP, "Failed to open %s: %s\n", fn, strerror(errno));
    }
    return fd;
}

int read_pcap_header(int fd, struct pcap_header *header)
{
    int ret = read(fd, header, sizeof(struct pcap_header));
    if (unlikely(ret < sizeof(struct pcap_header))) {
        RTE_LOG(ERR, PCAP, "Failed to read pcap file header: %s\n", strerror(errno));
        return ret;
    }
    return 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int read_next_packet(int fd, void *buf, int len)
{
    struct pcap_packet_header header;
    int ret = read(fd, &header, sizeof(struct pcap_packet_header));

    if (unlikely(ret < sizeof(struct pcap_packet_header))) {
        RTE_LOG(ERR, PCAP, "Failed to read packet header: %s\n", strerror(errno));
        return ret;
    }
    int n = MIN(len, header.packet_length);
    ret = read(fd, buf, n);
    if (ret < n) {
        RTE_LOG(ERR, PCAP, "Failed to read packet content: %s\n", strerror(errno));
        return -1;
    }
    if (len < header.packet_length) { // drop packet longer than len
        lseek(fd, header.packet_length - len, SEEK_CUR);
    }
    return ret;
}

int close_pcap(int fd)
{
    int ret = close(fd);
    if (unlikely(ret < 0)) {
        RTE_LOG(ERR, PCAP, "Failed to close file: %s\n", strerror(errno));
        return ret;
    }
    return 0;
}

int load_pcap(const char *filename, struct rte_mempool *pool,
              struct rte_mbuf **mbufs, int *nb_pkts)
{
    int fd = -1;
    int ret = -1;
    struct pcap_header pcap_header;

    fd = open_pcap(filename);

    if (unlikely(fd < 0)) {
        goto end;
    }

    ret = read_pcap_header(fd, &pcap_header);
    if (unlikely(ret < 0)) {
        goto end;
    }

    int i = 0;
    uint64_t bytes = 0;
    int max_len = 0;
    while (1) {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool);
        if (!mbuf) {
            RTE_LOG(ERR, PCAP, "Failed to alloc mbuf, please adjust pktmbuf pool size\n");
            goto end;
        }
        ret = read_next_packet(fd, mbuf->buf_addr, mbuf->buf_len);
        if (unlikely(ret < 0)) {
            rte_pktmbuf_free(mbuf);
            RTE_LOG(INFO, PCAP, "Failed to read packet: %s\n", strerror(errno));
            goto end;
        } else if (unlikely(ret == 0)) {
            rte_pktmbuf_free(mbuf);
            RTE_LOG(INFO, PCAP, "Finished loading pcap\n");
            ret = 0;
            break;
        }
        mbuf->data_off = 0;
        mbuf->data_len = mbuf->pkt_len = ret;
        mbuf->nb_segs = 1;
        mbuf->next = NULL;
        mbufs[i++] = mbuf;
        if (ret> max_len) {
            max_len = ret;
        }
        bytes += ret;
    }
    RTE_LOG(INFO, PCAP, "Read %d pkts (for a total of %lu bytes), max packet length = %d bytes.\n", i, bytes, max_len);
    *nb_pkts = i;
end:
    if (fd > 0) {
        close(fd);
    }
    return ret;
}
