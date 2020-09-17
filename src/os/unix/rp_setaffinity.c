
/*
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_HAVE_CPUSET_SETAFFINITY)

void
rp_setaffinity(rp_cpuset_t *cpu_affinity, rp_log_t *log)
{
    rp_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            rp_log_error(RP_LOG_NOTICE, log, 0,
                          "cpuset_setaffinity(): using cpu #%ui", i);
        }
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), cpu_affinity) == -1)
    {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "cpuset_setaffinity() failed");
    }
}

#elif (RP_HAVE_SCHED_SETAFFINITY)

void
rp_setaffinity(rp_cpuset_t *cpu_affinity, rp_log_t *log)
{
    rp_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            rp_log_error(RP_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sched_setaffinity() failed");
    }
}

#endif
