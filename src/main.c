/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <argp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>

#include <statistics.h>
#include <tx_core.h>
#include <loader.h>

#define MAX_PKT_BURST 512
#define MBUF_CACHE_SIZE 256
#define RTE_LOGTYPE_PKTBURST RTE_LOGTYPE_USER1

// ------------------------- Arguments Parsing -------------------------

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define ARG_PORTMASK 1
#define ARG_TX_DESCS 4
#define ARG_BURST_SIZE 5
#define ARG_NUM_MBUFS 7
#define ARG_STATISTICS 8
#define ARG_FILENAME 9
#define ARG_CORES_PER_PORT 10
#define ARG_TXQ_PER_CORE 11
#define ARG_NB_RUNS 12
#define ARG_BITRATE 13
#define ARG_PKTRATE 14
#define ARG_WATCH 15
#define ARG_RING_SIZE 16

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
#define BIRATE_DEFAULT 0
#define PKTRATE_DEFAULT 0
#define WATCH_DEFAULT 0
#define RING_SIZE_DEFAULT 8192

const char *argp_program_version = "pktburst 1.0";
const char *argp_program_bug_address = "781345688@qq.com";
static char doc[] = "A DPDK-based program load and send pcap packets.";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"portmask", ARG_PORTMASK, "PORTMASK", 0,
     "Portmask. (default: " STR(PORTMASK_DEFAULT) ")", 0},
    {"cores", ARG_CORES_PER_PORT, "CORES_PER_PORT", 0,
     "Number of tx cores per port. (default: " STR(CORES_PER_PORT_DEFAULT) ")",
     0},
    {"txq", ARG_TXQ_PER_CORE, "TXQ_PER_CORE", 0,
     "Number of tx queues per core. (default: " STR(TXQ_PER_CORE_DEFAULT) ")",
     0},
    {"txd", ARG_TX_DESCS, "TX_DESCS", 0,
     "Number of tx descs per queue. (default: " STR(NB_TX_DESCS_DEFAULT) ")",
     0},
    {"burst", ARG_BURST_SIZE, "BURST_SIZE", 0,
     "Burst size for rx/tx and ring enqueue/dequeue. (default: " STR(
         NB_BURST_SIZE_DEFAULT) ")",
     0},
    {"ring_size", ARG_BURST_SIZE, "BURST_SIZE", 0,
     "Burst size for rx/tx and ring enqueue/dequeue. (default: " STR(
         NB_BURST_SIZE_DEFAULT) ")",
     0},
    {"mbufs", ARG_NUM_MBUFS, "NUM_MBUFS", 0,
     "Number of mbufs in mempool. (default: " STR(NUM_MBUFS_DEFAULT) "s)", 0},
    {"nbruns", ARG_NB_RUNS, "NB_RUNS", 0,
     "Repeat times. (default: " STR(NB_RUNS_DEFAULT) "s)", 0},
    {"stats", ARG_STATISTICS, "STATS_INTERVAL", 0,
     "Show statistics interval (ms). (default: " STR(
         STATS_INTERVAL_DEFAULT) "). Set to 0 to disable.",
     0},
    // {"pcap", ARG_FILENAME, "FILENAME", 0, "Pcap file name. (required)", 0},
    {"bitrate", ARG_BITRATE, "BITRATE", 0, "Rate limit in Mbps.", 0},
    {"pktrate", ARG_PKTRATE, "PKTRATE", 0, "Rate limit in Mpps.", 0},
    {"watch", ARG_WATCH, 0, 0, "Real time watch.", 0},
    {0}};

struct arguments {
    char *args[2];
    uint64_t portmask;
    uint64_t nbruns;
    uint32_t statistics;
    uint32_t num_mbufs;
    uint32_t pktrate;
    uint16_t txd;
    uint16_t txq_per_core;
    uint16_t cores_per_port;
    uint16_t burst_size;
    uint16_t ring_size;
    uint16_t bitrate;
    uint16_t watch;
};

int parse_pcap_files(char *args, char ***pcap_files,
                           char **end) {
    int n = 1;
    char *p = args;
    while (*p++) {
        if (*p == ' ')
            n++;
    }
    char **files = rte_malloc(NULL, sizeof(char *) * n, 0);
    char *token = strtok_r(args, " ", end);

    int i = 0;
    while (token != NULL && i < n) {
        char *s = strdup(token);
        fprintf(stderr, "%s\n", s);
        if (s == NULL) {
            for (int j = 0; j < i; j++) {
                free(files[i]);
            }
            rte_free(files);
            RTE_LOG(ERR, PKTBURST, "Invalid pcap file '%s'\n", token);
            return -1;
        }
        token = strtok_r(NULL, " ", end);
        i++;
    }
    if (i < n) {
        rte_realloc(files, sizeof(char *) * i, 0);
    }
    *pcap_files = files;
    return i;
}

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
    case ARG_RING_SIZE:
        arguments->ring_size = strtoul(arg, &end, 10);
        break;
    case ARG_NB_RUNS:
        arguments->nbruns = strtoul(arg, &end, 10);
        break;
    case ARG_BITRATE:
        arguments->bitrate = strtoul(arg, &end, 10);
        break;
    case ARG_PKTRATE:
        arguments->pktrate = strtoul(arg, &end, 10);
        break;
    case ARG_WATCH:
        arguments->watch = 1;
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
                     uint16_t num_rxdesc, uint16_t num_txdesc, uint16_t tx_rate,
                     struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE, // Multi queue packet routing mode.
        }};
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

    RTE_LOG(ERR, PKTBURST,
            "Port %d has %u rx queues (%u requested) and %u tx queues (%u "
            "requested).\n",
            port, dev_info.max_rx_queues, rx_rings, dev_info.max_tx_queues,
            tx_rings);

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
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

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
            RTE_LOG(
                ERR, PKTBURST,
                "rte_eth_rx_queue_setup(port=%u, queue_id=%u, rxd=%u): %s\n",
                port, q, num_rxdesc, rte_strerror(-ret));
            return ret;
        }
        RTE_LOG(INFO, PKTBURST,
                "rte_eth_rx_queue_setup(port=%u, queue_id=%u, rxd=%u)\n", port,
                q, num_rxdesc);
    }

    struct rte_eth_txconf txconf;
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        ret = rte_eth_tx_queue_setup(port, q, num_txdesc,
                                     rte_eth_dev_socket_id(port), &txconf);
        if (ret < 0) {
            RTE_LOG(
                ERR, PKTBURST,
                "rte_eth_tx_queue_setup(port=%u, queue_id=%u, rxd=%u): %s\n",
                port, q, num_txdesc, rte_strerror(-ret));
            return ret;
        }
        RTE_LOG(DEBUG, PKTBURST,
                "rte_eth_tx_queue_setup(port=%u, queue_id=%u, txd=%u)\n", port,
                q, num_txdesc);
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

    if (tx_rate > 0) {
        for (uint16_t q = 0; q < tx_rings; q++) {
            ret = rte_eth_set_queue_rate_limit(port, q, tx_rate);
            if (ret < 0) {
                RTE_LOG(ERR, PKTBURST,
                        "rte_eth_set_queue_rate_limit(port=%u, queue_id=%u, "
                        "tx_rate=%u): %s\n",
                        port, q, tx_rate, rte_strerror(-ret));
                return ret;
            }
        }
    }
    return 0;
}

// ------------------------- Signal Handler -------------------------

rte_atomic32_t global_alloc_counter;
rte_atomic32_t global_loader_counter;
volatile bool global_stop = false;

static void signal_handler(int sig) {
    RTE_LOG(NOTICE, PKTBURST, "Caught signal %s on core %u%s\n", strsignal(sig),
            rte_lcore_id(),
            rte_get_main_lcore() == rte_lcore_id() ? " (MASTER CORE)" : "");
    global_stop = true;
}

// ------------------------- Main -------------------------

int lcore_launch(lcore_function_t *f, void *arg, unsigned worker_id) {
    pthread_t th;
    return pthread_create(&th, NULL, f, arg);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    struct tx_core_config *tx_core_config_list;
    uint16_t nb_ports = 0;
    uint16_t nb_tx_cores = 0;
    unsigned int required_cores;
    struct rte_mempool *mbuf_pool;

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
        .bitrate = BIRATE_DEFAULT,
        .pktrate = PKTRATE_DEFAULT,
        .watch = WATCH_DEFAULT,
        .ring_size = RING_SIZE_DEFAULT,
    };
    // parse arguments
    int arg_index = 0;
    ret = argp_parse(&argp, argc, argv, 0, &arg_index, &arguments);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "argp_parse failed\n");
    }

    char **pcap_files = argv + arg_index;
    int nb_files = argc - arg_index;
    if (nb_files < 1) {
        rte_exit(EXIT_FAILURE, "No pcap files specified\n");
    }

#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 16)
    rte_log_set_level(RTE_LOG_DEBUG, RTE_LOG_DEBUG);
#else
    rte_set_log_type(RTE_LOGTYPE_PKTBURST, 1);
    rte_set_log_level(RTE_LOG_DEBUG);
#endif

    // if (strlen(arguments.filename) == 0) {
    //     rte_exit(EXIT_FAILURE, "Pcap file not specified\n");
    // }

    uint16_t port;
    RTE_ETH_FOREACH_DEV(port) {
        uint64_t port_bit = 1ULL << port;
        if (port_bit & arguments.portmask) {
            nb_ports++;
        }
    }

    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No port specified\n");
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

    // static const struct rte_mbuf_dynfield dynfield_desc = {
	// 	.name = "nbruns",
	// 	.size = sizeof(uint32_t),
	// 	.align = sizeof(uint32_t),
	// };

    // int dynfield_offset = rte_mbuf_dynfield_register(&dynfield_desc);
    // if (dynfield_offset < 0)
	// 	rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");
    // RTE_LOG(INFO, PKTBURST, "dynfield offset: %d\n", dynfield_offset);

    uint16_t nb_txq = arguments.txq_per_core * arguments.cores_per_port;

    // Init stats/config list
    tx_core_config_list =
        rte_zmalloc(NULL, sizeof(struct tx_core_config) * nb_tx_cores, 0);

    // Port Init
    RTE_ETH_FOREACH_DEV(port) {
        if (!((1ULL << port) & arguments.portmask))
            continue;
        int ret = port_init(port, 0, nb_txq, 0, arguments.txd,
                            arguments.bitrate, mbuf_pool);
        if (ret) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", port);
        }
    }

    struct rte_ring *tx_ring = rte_ring_create("tx_ring", arguments.ring_size, rte_socket_id(), 0);

    // Core index
    rte_atomic32_init(&global_alloc_counter);
    rte_atomic32_init(&global_loader_counter);
    int core_index = rte_get_next_lcore(-1, true, 0);
    int tx_core_idx = 0;

    struct loader_core_config loader_config;
    memset(&loader_config, 0, sizeof(struct loader_core_config));
    loader_config.burst_size = arguments.burst_size;
    // loader_config.dynfield_offset = dynfield_offset;
    loader_config.nb_files = nb_files;
    loader_config.pcap_files = pcap_files;
    loader_config.pool = mbuf_pool;
    loader_config.ring = tx_ring;
    loader_config.socket = rte_socket_id();
    loader_config.nbruns = arguments.nbruns;
    rte_atomic32_inc(&global_loader_counter);
    if (lcore_launch(loader_core, &loader_config, 0) < 0) {
        rte_exit(EXIT_FAILURE, "Could not launch loader core %d.\n", 0);
    }

    // struct recycler_core_config recycler_config;
    // memset(&recycler_config, 0, sizeof(struct recycler_core_config));
    // recycler_config.burst_size = arguments.burst_size;
    // recycler_config.dynfield_offset = dynfield_offset;
    // recycler_config.nbruns = arguments.nbruns;
    // recycler_config.free_ring = free_ring;
    // recycler_config.pool = mbuf_pool;
    // recycler_config.repeat_ring = repeat_ring;
    // recycler_config.socket = rte_socket_id();
    // if (lcore_launch(recycler_core, &recycler_config, 0) < 0) {
    //     rte_exit(EXIT_FAILURE, "Could not launch recycler core %d.\n", 0);
    // }

    RTE_ETH_FOREACH_DEV(port) {
        if (!((1ULL << port) & arguments.portmask))
            continue;

        uint16_t qid = 0;
        // Tx Cores
        for (int i = 0; i < arguments.cores_per_port;
             i++, qid += arguments.txq_per_core) {
            // Config core
            struct tx_core_config *config = &tx_core_config_list[tx_core_idx++];
            config->core_id = core_index;
            config->ring = tx_ring;
            config->port = port;
            config->queue_min = qid;
            config->queue_num = arguments.txq_per_core;
            config->burst_size = arguments.burst_size;

            for (uint16_t q = config->queue_min;
                 q < config->queue_min + config->queue_num; q++) {
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
        stats_config.portmask = arguments.portmask;
        stats_config.txq = nb_txq;
        stats_config.nb_tx_cores = nb_tx_cores;
        stats_config.nb_ports = nb_ports;
        stats_config.interval = arguments.statistics;
        stats_config.watch = arguments.watch;
        stats_config.loader_config = &loader_config;
        stats_config.tx_ring = tx_ring;
        stats_config.mbuf_pool = mbuf_pool;
        start_stats_display(&stats_config);
    }

    // Wait for all cores to complete and exit
    RTE_LOG(NOTICE, PKTBURST, "Waiting for all cores to exit\n");
    rte_eal_mp_wait_lcore();

    // Finalize
    rte_ring_free(tx_ring);
    rte_free(tx_core_config_list);
    rte_mempool_free(mbuf_pool);
    rte_eal_cleanup();
    return 0;
}
