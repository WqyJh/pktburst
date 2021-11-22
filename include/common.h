#ifndef PKTBURST_COMMON_H
#define PKTBURST_COMMON_H

#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <stdbool.h>

extern rte_atomic32_t global_alloc_counter;

extern rte_atomic32_t global_loader_counter;

extern volatile bool global_stop;

struct ring_pair {
    volatile bool *peer_alive;
    struct rte_ring *ring;
};

int parse_cpu_affinity(char *args, cpu_set_t *cpu_set, char **end);

void set_thread_attrs(pthread_t th, const char *name, int id, cpu_set_t *cpuset);

#endif // PKTBURST_COMMON_H
