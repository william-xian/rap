
/*
 * Copyright (C) Rap, Inc.
 */

#ifndef _RP_SETAFFINITY_H_INCLUDED_
#define _RP_SETAFFINITY_H_INCLUDED_


#if (RP_HAVE_SCHED_SETAFFINITY || RP_HAVE_CPUSET_SETAFFINITY)

#define RP_HAVE_CPU_AFFINITY 1

#if (RP_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  rp_cpuset_t;

#elif (RP_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  rp_cpuset_t;

#endif

void rp_setaffinity(rp_cpuset_t *cpu_affinity, rp_log_t *log);

#else

#define rp_setaffinity(cpu_affinity, log)

typedef uint64_t  rp_cpuset_t;

#endif


#endif /* _RP_SETAFFINITY_H_INCLUDED_ */
