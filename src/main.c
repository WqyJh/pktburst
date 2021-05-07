/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <argp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>
#include <rte_hash.h>

#include <tx_core.h>
#include <statistics.h>

#define MAX_PKT_BURST 512
#define MBUF_CACHE_SIZE 256
#define RTE_LOGTYPE_PKTBURST RTE_LOGTYPE_USER1

// ------------------------- Arguments Parsing -------------------------

#define _S(x) #x

#define ARG_PORTMASK 1
#define ARG_TX_DESCS 4
#define ARG_BURST_SIZE 5
#define ARG_NUM_MBUFS 7
#define ARG_STATISTICS 8
#define ARG_FILENAME 9
#define ARG_CORES_PER_PORT 10
#define ARG_TXQ_PER_CORE 11
#define ARG_NB_RUNS 12

#define PORTMASK_DEFAULT 0x1
#define NB_TX_CORES_DEFAULT 1
#define NB_TX_DESCS_DEFAULT 512
#define NB_BURST_SIZE_DEFAULT 512
#define NUM_MBUFS_DEFAULT 65536
#define STATS_INTERVAL_DEFAULT 1000
#define FILENAME_DEFAULT ""
#define TXQ_PER_CORE_DEFAULT 1
#define CORES_PER_PORT_DEFAULT 1
#define NB_RUNS_DEFAULT 1

const char *argp_program_version = "pktburst 1.0";
const char *argp_program_bug_address = "781345688@qq.com";
static char doc[] = "A DPDK-based program load and send pcap packets.";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"portmask", ARG_PORTMASK, "PORTMASK", 0,
     "Portmask. (default: "_S(PORTMASK_DEFAULT) ")", 0},
    {"cores", ARG_CORES_PER_PORT, "CORES_PER_PORT", 0,
     "Number of tx cores per port. (default: "_S(CORES_PER_PORT_DEFAULT) ")", 0},
    {"txq", ARG_TXQ_PER_CORE, "TXQ_PER_CORE", 0,
     "Number of tx queues per core. (default: "_S(TXQ_PER_CORE_DEFAULT) ")", 0},
    {"txd", ARG_TX_DESCS, "TX_DESCS", 0,
     "Number of tx descs per queue. (default: "_S(NB_TX_DESCS_DEFAULT) ")", 0},
    {"burst", ARG_BURST_SIZE, "BURST_SIZE", 0,
     "Burst size for rx/tx and ring enqueue/dequeue. (default: "_S(
         NB_BURST_SIZE_DEFAULT) ")",
     0},
    {"mbufs", ARG_NUM_MBUFS, "NUM_MBUFS", 0,
     "Number of mbufs in mempool. (default: "_S(NUM_MBUFS_DEFAULT) "s)", 0},
    {"nbruns", ARG_NB_RUNS, "NB_RUNS", 0,
     "Repeat times. (default: "_S(NB_RUNS_DEFAULT) "s)", 0},
    {"stats", ARG_STATISTICS, "STATS_INTERVAL", 0,
     "Show statistics interval (ms). (default: 0 not show)", 0},
    {"pcap", ARG_FILENAME, "FILENAME", 0,
     "Pcap file name. (required)", 0},
    {0}};

struct arguments {
    char *args[2];
    uint64_t portmask;
    uint64_t nbruns;
    uint32_t statistics;
    uint32_t num_mbufs;
    uint16_t txd;
    uint16_t txq_per_core;
    uint16_t cores_per_port;
    uint16_t burst_size;
    char filename[PATH_MAX];
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    char *end;
    errno = 0;
    end = NULL;
    switch (key) {
    case ARG_PORTMASK:
        arguments->portmask = strtoul(arg, &end, 16);
        if (arguments->portmask == 0) {
            RTE_LOG(ERR, PKTBURST, "Invalid portmask '%s', no port used\n",
                    arg);
            return -EINVAL;
        }
        break;
    case ARG_CORES_PER_PORT:
        arguments->cores_per_port = strtoul(arg, &end, 10);
        break;
    case ARG_TXQ_PER_CORE:
        arguments->txq_per_core = strtoul(arg, &end, 10);
        break;
    case ARG_TX_DESCS:
        arguments->txd = strtoul(arg, &end, 10);
        break;
    case ARG_BURST_SIZE:
        arguments->burst_size = strtoul(arg, &end, 10);
        break;
    case ARG_NUM_MBUFS:
        arguments->num_mbufs = strtoul(arg, &end, 10);
        break;
    case ARG_STATISTICS:
        arguments->statistics = strtoul(arg, &end, 10);
        break;
    case ARG_FILENAME:
        strncpy(arguments->filename, arg, PATH_MAX - 1);
        break;
    case ARG_NB_RUNS:
        arguments->nbruns = strtoul(arg, &end, 10);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    if (errno || (end != NULL && *end != '\0')) {
        RTE_LOG(ERR, PKTBURST, "Invalid value '%s'\n", arg);
        return -EINVAL;
    }
    return 0;
}

// ------------------------- Port Init -------------------------

static int port_init(uint8_t port, uint16_t rx_rings, uint16_t tx_rings,
                     uint16_t num_rxdesc, uint16_t num_txdesc,
                     struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,  // Multi queue packet routing mode.
        }
    };
    struct rte_eth_dev_info dev_info;
    int ret;
    uint16_t dev_count;

#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 3, 16)
    dev_count = rte_eth_dev_count_avail();
#else
    dev_count = rte_eth_dev_count();
#endif

    if (rte_eth_dev_is_valid_port(port) == 0) {
        RTE_LOG(ERR, PKTBURST,
                "Port identifier %d out of range (0 to %d) or not attached.\n",
                port, dev_count);
        return -EINVAL;
    }

    rte_eth_dev_info_get(port, &dev_info);

    if (tx_rings == 0 || num_txdesc == 0) {
        tx_rings = 1;
        num_txdesc = dev_info.tx_desc_lim.nb_min * 2;
    }
    if (rx_rings == 0 || num_rxdesc == 0) {
        rx_rings = 1;
        num_rxdesc = dev_info.rx_desc_lim.nb_min * 2;
    }

    RTE_LOG(ERR, PKTBURST, "Port %d has %u rx queues (%u requested) and %u tx queues (%u requested).\n",
        port, dev_info.max_rx_queues, rx_rings, dev_info.max_tx_queues, tx_rings);

    if (rx_rings > dev_info.max_rx_queues) {
        RTE_LOG(ERR, PKTBURST,
                "Port %d can only handle up to %d rx queues (%d requested).\n",
                port, dev_info.max_rx_queues, rx_rings);
        return -EINVAL;
    }
    RTE_LOG(INFO, PKTBURST, "Port %d driver_name: %s\n", port,
            dev_info.driver_name);

    if (tx_rings > dev_info.max_tx_queues) {
        RTE_LOG(ERR, PKTBURST,
                "Port %d can only handle up to %d tx queues (%d requested).\n",
                port, dev_info.max_rx_queues, rx_rings);
        return -EINVAL;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    RTE_LOG(INFO, PKTBURST,
            "Port %d RX descriptors limits (min:%d, max:%d, align:%d)\n", port,
            dev_info.rx_desc_lim.nb_min, dev_info.rx_desc_lim.nb_max,
            dev_info.rx_desc_lim.nb_align);
    RTE_LOG(INFO, PKTBURST,
            "Port %d TX descriptors limits (min:%d, max:%d, align:%d)\n", port,
            dev_info.tx_desc_lim.nb_min, dev_info.tx_desc_lim.nb_max,
            dev_info.tx_desc_lim.nb_align);

    if (num_rxdesc > dev_info.rx_desc_lim.nb_max ||
        num_rxdesc < dev_info.rx_desc_lim.nb_min ||
        num_rxdesc % dev_info.rx_desc_lim.nb_align != 0) {
        RTE_LOG(ERR, PKTBURST,
                "Port %d cannot be configured with %d RX descriptors per queue "
                "(min:%d, max:%d, align:%d)\n",
                port, num_rxdesc, dev_info.rx_desc_lim.nb_min,
                dev_info.rx_desc_lim.nb_max, dev_info.rx_desc_lim.nb_align);
        return -EINVAL;
    }

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret) {
        RTE_LOG(ERR, PKTBURST, "rte_eth_dev_configure(...): %s\n",
                rte_strerror(-ret));
        return ret;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &num_rxdesc, &num_txdesc);
    if (ret) {
        RTE_LOG(ERR, PKTBURST, "rte_eth_dev_adjust_nb_rx_tx_desc(...): %s\n",
                rte_strerror(-ret));
        return ret;
    }

    for (uint16_t q = 0; q < rx_rings; q++) {
        ret = rte_eth_rx_queue_setup(
            port, q, num_rxdesc, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (ret) {
            RTE_LOG(ERR, PKTBURST,
                "rte_eth_rx_queue_setup(port=%u, queue_id=%u, rxd=%u): %s\n",
                port, q, num_rxdesc, rte_strerror(-ret));
            return ret;
        }
        RTE_LOG(INFO, PKTBURST,
            "rte_eth_rx_queue_setup(port=%u, queue_id=%u, rxd=%u)\n",
            port, q, num_rxdesc);
    }

    struct rte_eth_txconf txconf;
    txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        ret = rte_eth_tx_queue_setup(port, q, num_txdesc,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (ret < 0) {
            RTE_LOG(ERR, PKTBURST,
                "rte_eth_tx_queue_setup(port=%u, queue_id=%u, rxd=%u): %s\n",
                port, q, num_txdesc, rte_strerror(-ret));
            return ret;
        }
        RTE_LOG(DEBUG, PKTBURST,
            "rte_eth_tx_queue_setup(port=%u, queue_id=%u, txd=%u)\n",
            port, q, num_txdesc);
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        RTE_LOG(ERR, PKTBURST, "Cannot start port %" PRIu8 ": %s\n", port,
                rte_strerror(-ret));
        return ret;
    }

    // Display the port MAC address
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    RTE_LOG(INFO, PKTBURST,
            "Port %u: MAC=%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
            ":%02" PRIx8 ":%02" PRIx8 ", RXdesc/queue=%u TXdesc/queue=%u\n",
            port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
            addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5],
            num_rxdesc, num_txdesc);
    return 0;
}

// ------------------------- Signal Handler -------------------------

static volatile bool should_stop = false;
static void signal_handler(int sig) {
    RTE_LOG(NOTICE, PKTBURST, "Caught signal %s on core %u%s\n", strsignal(sig),
            rte_lcore_id(),
            rte_get_main_lcore() == rte_lcore_id() ? " (MASTER CORE)" : "");
    should_stop = true;
}

// ------------------------- Main -------------------------

int load_pcap(const char *filename, struct rte_mempool *pool,
              struct rte_mbuf **mbufs, int *nb_pkts);

static inline void copy_mbufs(struct rte_mbuf **dst, struct rte_mbuf **src, int n)
{
    for (int i = 0; i < n; i++) {
        dst[i] = rte_pktmbuf_copy(src[i], src[i]->pool, 0, rte_pktmbuf_pkt_len(src[i]));
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    rte_atomic16_t core_counter;
    struct tx_core_config *tx_core_config_list;
    uint16_t nb_ports = 0;
    uint16_t nb_tx_cores = 0;
    unsigned int required_cores;
    struct rte_mempool *mbuf_pool;
    struct rte_mbuf ***mbufs_list;
    int nb_pkts = 0;

    static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};
    struct arguments arguments;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;

    // set arguments defaults
    arguments = (struct arguments){
        .portmask = PORTMASK_DEFAULT,
        .cores_per_port = CORES_PER_PORT_DEFAULT,
        .txq_per_core = TXQ_PER_CORE_DEFAULT,
        .txd = NB_TX_DESCS_DEFAULT,
        .burst_size = NB_BURST_SIZE_DEFAULT,
        .num_mbufs = NUM_MBUFS_DEFAULT,
        .nbruns = NB_RUNS_DEFAULT,
        .statistics = STATS_INTERVAL_DEFAULT,
    };
    bzero(arguments.filename, PATH_MAX);
    // parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
    rte_log_set_level(RTE_LOG_DEBUG, RTE_LOG_DEBUG);
#else
    rte_set_log_type(RTE_LOGTYPE_PKTBURST, 1);
    rte_set_log_level(RTE_LOG_DEBUG);
#endif

    if (strlen(arguments.filename) == 0) {
        rte_exit(EXIT_FAILURE, "Pcap file not specified\n"); 
    }

    uint16_t port;
    RTE_ETH_FOREACH_DEV(port) {
        uint64_t port_bit = 1ULL << port;
        if (port_bit & arguments.portmask) {
            nb_ports++;
        }
    }

    // Checks core number
    nb_tx_cores = nb_ports * arguments.cores_per_port;
    required_cores = 1 + nb_tx_cores;
    if (rte_lcore_count() < required_cores) {
        rte_exit(EXIT_FAILURE, "Please assign at least %d cores.\n",
                 required_cores);
    }
    RTE_LOG(INFO, PKTBURST, "Using %u cores out of %d allocated\n",
            required_cores, rte_lcore_count());

    // Create mbuf pool
    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", arguments.num_mbufs, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    RTE_LOG(INFO, PKTBURST, "Create MBUF_POOL size=%u\n", arguments.num_mbufs);
    mbufs_list = rte_malloc(NULL, sizeof(struct rte_mbuf **) * nb_ports, 0);
    for (int i = 0; i < nb_ports; i++) {
        mbufs_list[i] = rte_zmalloc(NULL, sizeof(struct rte_mbuf *) * arguments.num_mbufs, 0);
    }

    ret = load_pcap(arguments.filename, mbuf_pool, mbufs_list[0], &nb_pkts);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to load pcap\n");
    }

    for (int i = 1; i < nb_ports; i++) {
        copy_mbufs(mbufs_list[i], mbufs_list[0], nb_pkts);
    }

    uint16_t nb_txq = arguments.txq_per_core * arguments.cores_per_port;

    // Init stats/config list
    tx_core_config_list = rte_zmalloc(NULL, sizeof(struct tx_core_config) * nb_tx_cores, 0);

    // Port Init
    RTE_ETH_FOREACH_DEV(port) {
        if (!((1ULL << port) & arguments.portmask)) continue;
        int ret = port_init(port, 0, nb_txq, 0, arguments.txd, mbuf_pool);
        if (ret) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", port);
        }
    }

    // Core index
    rte_atomic16_init(&core_counter);
    int core_index = rte_get_next_lcore(-1, true, 0);
    int tx_core_idx = 0;

    RTE_ETH_FOREACH_DEV(port) {
        if (!((1ULL << port) & arguments.portmask)) continue;

        /* Get link status and display it. */
        struct rte_eth_link eth_link;
        rte_eth_link_get(port, &eth_link);
        if (eth_link.link_status) {
            RTE_LOG(INFO, PKTBURST, "Link up - speed %u Mbps - %s\n",
                eth_link.link_speed,
                (eth_link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                "full-duplex" : "half-duplex\n");
        } else {
            RTE_LOG(INFO, PKTBURST, "Link down\n");
        }

        uint16_t qid = 0;
        uint16_t nb_pkts_per_core = nb_pkts / arguments.cores_per_port;
        struct rte_mbuf **mbufs = mbufs_list[tx_core_idx];
        // Tx Cores
        for (int i = 0; i < arguments.cores_per_port; i++, qid += arguments.txq_per_core) {
            // Config core
            struct tx_core_config *config = &tx_core_config_list[tx_core_idx++];
            config->stop_condition = &should_stop;
            config->link_speed = eth_link.link_speed;
            config->core_id = core_index;
            config->filename = arguments.filename;
            config->pool = mbuf_pool;
            config->port = port;
            config->queue_min = qid;
            config->queue_num = arguments.txq_per_core;
            config->mbufs = mbufs + i * nb_pkts_per_core;
            config->nb_pkts = nb_pkts_per_core;
            if (i == arguments.cores_per_port - 1) {
                config->nb_pkts = nb_pkts - i * nb_pkts_per_core;
            }
            config->nbruns = arguments.nbruns;
            config->core_counter = &core_counter;
            config->burst_size = arguments.burst_size;
            config->txd = arguments.txd;
            rte_atomic16_inc(&core_counter);

            for (uint16_t q = config->queue_min; q < config->queue_min + config->queue_num; q++) {
                ret = rte_eth_dev_set_tx_queue_stats_mapping(port, q, i);
                if (ret) {
                    RTE_LOG(WARNING, PKTBURST,
                            "set_tx_queue_stats_mapping(port=%u, "
                            "queue_id=%u, "
                            "stat_id=%u): %s\n",
                            port, q, i, rte_strerror(-ret));
                }
            }
            // Launch core
            if (rte_eal_remote_launch((int (*)(void *))tx_core, config,
                                    core_index) < 0)
                rte_exit(EXIT_FAILURE,
                        "Could not launch tx core on lcore %d.\n", core_index);
            core_index = rte_get_next_lcore(core_index, true, 0);
        }
    }

    struct stats_config stats_config;
    memset(&stats_config, 0, sizeof(struct stats_config));

    if (arguments.statistics > 0) {
        stats_config.tx_core_config_list = tx_core_config_list;
        stats_config.stop_condition = &should_stop;
        stats_config.portmask = arguments.portmask;
        stats_config.txq = nb_txq;
        stats_config.nb_tx_cores = nb_tx_cores;
        stats_config.nb_ports = nb_ports;
        stats_config.interval = arguments.statistics;
        stats_config.core_counter = &core_counter;
        start_stats_display(&stats_config);
    }

    // Wait for all cores to complete and exit
    RTE_LOG(NOTICE, PKTBURST, "Waiting for all cores to exit\n");
    rte_eal_mp_wait_lcore();

    // Finalize
    for (int i = 0; i < nb_ports; i++) {
        rte_pktmbuf_free_bulk(mbufs_list[i], nb_pkts);
        rte_free(mbufs_list[i]);
    }
    rte_free(mbufs_list);
    rte_free(tx_core_config_list);
    rte_mempool_free(mbuf_pool);
    rte_eal_cleanup();
    return 0;
}
