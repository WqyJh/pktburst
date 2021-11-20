#define _GNU_SOURCE

#include <common.h>

#include <pthread.h>
#include <sched.h>
#include <rte_os.h>

int parse_cpu_affinity(char *args, cpu_set_t *cpu_set, char **end) {
    char *token = strtok_r(args, ",", end);

    CPU_ZERO(cpu_set);
    if (token == NULL) {
        RTE_CPU_FILL(cpu_set);
        return 0;
    }

    int i = 0;
    while (token != NULL) {
        int cpu_id = atoi(token);
        CPU_SET(cpu_id, cpu_set);
        token = strtok_r(NULL, ",", end);
        i++;
    }
    return i;
}

void set_thread_attrs(pthread_t th, const char *name, int id, cpu_set_t *cpuset) {
#define THREAD_NAME_LEN 32
    char thread_name[THREAD_NAME_LEN];
    snprintf(thread_name, THREAD_NAME_LEN, "%s/%d", name, id);
    rte_thread_setname(th, thread_name);

    int ret = pthread_setaffinity_np(th, sizeof(cpu_set_t), cpuset);
    if (ret == -1) {
        fprintf(stderr, "failed to set thread affinity for %s: %s\n",
                thread_name, strerror(-ret));
        return;
    }

#ifdef REALTIME_SCHED
    struct sched_param param = {
        .sched_priority = 99,
    };
    int ret = pthread_setschedparam(th, SCHED_FIFO, &param);
    // int tid = rte_gettid();
    // int ret = sched_setscheduler(tid, SCHED_FIFO, &param);
    if (ret == -1) {
        fprintf(stderr, "Failed to set thread sched priority for %s: %s\n",
                thread_name, strerror(-ret));
        return;
    }

    dump_thread_attrs(th, thread_name);
#endif // REALTIME_SCHED
}

