#ifndef PKTBURST_COMMON_H
#define PKTBURST_COMMON_H

#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <stdbool.h>

extern rte_atomic32_t global_alloc_counter;

extern rte_atomic32_t global_loader_counter;

extern volatile bool global_stop;

#endif // PKTBURST_COMMON_H
