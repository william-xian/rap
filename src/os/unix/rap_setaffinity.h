
/*
 * Copyright (C) Rap, Inc.
 */

#ifndef _RAP_SETAFFINITY_H_INCLUDED_
#define _RAP_SETAFFINITY_H_INCLUDED_


#if (RAP_HAVE_SCHED_SETAFFINITY || RAP_HAVE_CPUSET_SETAFFINITY)

#define RAP_HAVE_CPU_AFFINITY 1

#if (RAP_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  rap_cpuset_t;

#elif (RAP_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  rap_cpuset_t;

#endif

void rap_setaffinity(rap_cpuset_t *cpu_affinity, rap_log_t *log);

#else

#define rap_setaffinity(cpu_affinity, log)

typedef uint64_t  rap_cpuset_t;

#endif


#endif /* _RAP_SETAFFINITY_H_INCLUDED_ */
