
/*
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_CPUSET_SETAFFINITY)

void
rap_setaffinity(rap_cpuset_t *cpu_affinity, rap_log_t *log)
{
    rap_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            rap_log_error(RAP_LOG_NOTICE, log, 0,
                          "cpuset_setaffinity(): using cpu #%ui", i);
        }
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), cpu_affinity) == -1)
    {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "cpuset_setaffinity() failed");
    }
}

#elif (RAP_HAVE_SCHED_SETAFFINITY)

void
rap_setaffinity(rap_cpuset_t *cpu_affinity, rap_log_t *log)
{
    rap_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            rap_log_error(RAP_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sched_setaffinity() failed");
    }
}

#endif
