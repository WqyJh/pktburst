#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <allocator.h>
#include <common.h>

#define RTE_LOGTYPE_ALLOCATOR RTE_LOGTYPE_USER1


int allocator_core(struct allocator_core_config *config) {
    set_thread_attrs(config->th, "allocator", 0, config->cpuset);
    RTE_LOG(INFO, ALLOCATOR, "Allocator core %u started\n", 0);

    struct rte_mbuf **bufs = rte_malloc_socket(NULL, sizeof(struct rte_mbuf *) * config->burst_size, 0, config->socket);
    uint32_t off = 0;

    int nb_ring_pairs = config->nb_ring_pairs;
    struct ring_pair *ring_pairs = rte_malloc_socket(NULL, nb_ring_pairs * sizeof(struct ring_pair), 0, config->socket);
    memcpy(ring_pairs, config->ring_pairs, nb_ring_pairs * sizeof(struct ring_pair));
    struct ring_pair *source = NULL;
    int source_idx = -1;

    int i = 0;
    for (;;i++) {
        if (unlikely(global_stop)) {
            break;
        }
        if (unlikely(nb_ring_pairs == 0)) {
            // TODO: free all mbufs in all rings
            break;
        }
        struct ring_pair *rp = &ring_pairs[i];
        if (likely(*rp->peer_alive)) { // peer still alive
            if (rte_ring_count(rp->ring) >= 32) {
                continue;
            }
            if (likely(off < 32)) { // alloc local mbuf cache
                if (unlikely(source != NULL)) {
                    // alloc from dead peer
                    uint16_t nb_dequeued = rte_ring_sc_dequeue_burst(source->ring, (void **)(bufs + off), config->burst_size - off, NULL);
                    off += nb_dequeued;
                    config->stats->dequeued += nb_dequeued;
                    if (unlikely(rte_ring_count(source->ring) == 0)) {
                        // ring of dead peer drained, delete it
                        memmove(ring_pairs + source_idx, ring_pairs + source_idx + 1, nb_ring_pairs - source_idx - 1);
                        if (i > source_idx) {
                            --i;
                        }
                        --nb_ring_pairs;
                        source = NULL;
                    }
                }
            }
            if (likely(off < 32)) { // alloc local mbuf cache
                // alloc from mempool
                uint16_t nb_allocated = rte_pktmbuf_alloc_bulk(config->pool, bufs + off, config->burst_size - off);
                off += nb_allocated;
                config->stats->allocated += nb_allocated;
            }
            // enqueue from local mbuf cache
            int burst = off > 32 ? 32 : off;
            uint32_t nb_enqueued = rte_ring_sp_enqueue_burst(rp->ring, (void **)bufs, burst, NULL);
            config->stats->enqueued += nb_enqueued;
            off -= nb_enqueued;
            memmove(bufs, bufs + nb_enqueued, off);
        } else { // peer dead
            if (likely(source == NULL)) { // no source right now, mark it as source
                source = rp;
                source_idx = i;
                continue;
            }
            // has source right now, use the source for next
        }
    }

    rte_free(config->mbufs_);
    rte_free(ring_pairs);
    RTE_LOG(INFO, ALLOCATOR, "Allocator core %u stopped\n", 0);
    return 0;
}
