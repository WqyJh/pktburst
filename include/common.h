#ifndef PKTBURST_COMMON_H
#define PKTBURST_COMMON_H

#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <stdbool.h>

extern rte_atomic32_t global_alloc_counter;

extern rte_atomic32_t global_loader_counter;

extern volatile bool global_stop;

int parse_cpu_affinity(char *args, cpu_set_t *cpu_set, char **end);

void set_thread_attrs(pthread_t th, const char *name, int id, cpu_set_t *cpuset);

#endif // PKTBURST_COMMON_H
