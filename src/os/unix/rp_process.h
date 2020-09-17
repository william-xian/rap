
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PROCESS_H_INCLUDED_
#define _RP_PROCESS_H_INCLUDED_


#include <rp_setaffinity.h>
#include <rp_setproctitle.h>


typedef pid_t       rp_pid_t;

#define RP_INVALID_PID  -1

typedef void (*rp_spawn_proc_pt) (rp_cycle_t *cycle, void *data);

typedef struct {
    rp_pid_t           pid;
    int                 status;
    rp_socket_t        channel[2];

    rp_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} rp_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} rp_exec_ctx_t;


#define RP_MAX_PROCESSES         1024

#define RP_PROCESS_NORESPAWN     -1
#define RP_PROCESS_JUST_SPAWN    -2
#define RP_PROCESS_RESPAWN       -3
#define RP_PROCESS_JUST_RESPAWN  -4
#define RP_PROCESS_DETACHED      -5


#define rp_getpid   getpid
#define rp_getppid  getppid

#ifndef rp_log_pid
#define rp_log_pid  rp_pid
#endif


rp_pid_t rp_spawn_process(rp_cycle_t *cycle,
    rp_spawn_proc_pt proc, void *data, char *name, rp_int_t respawn);
rp_pid_t rp_execute(rp_cycle_t *cycle, rp_exec_ctx_t *ctx);
rp_int_t rp_init_signals(rp_log_t *log);
void rp_debug_point(void);


#if (RP_HAVE_SCHED_YIELD)
#define rp_sched_yield()  sched_yield()
#else
#define rp_sched_yield()  usleep(1)
#endif


extern int            rp_argc;
extern char         **rp_argv;
extern char         **rp_os_argv;

extern rp_pid_t      rp_pid;
extern rp_pid_t      rp_parent;
extern rp_socket_t   rp_channel;
extern rp_int_t      rp_process_slot;
extern rp_int_t      rp_last_process;
extern rp_process_t  rp_processes[RP_MAX_PROCESSES];


#endif /* _RP_PROCESS_H_INCLUDED_ */
