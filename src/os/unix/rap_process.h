
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PROCESS_H_INCLUDED_
#define _RAP_PROCESS_H_INCLUDED_


#include <rap_setaffinity.h>
#include <rap_setproctitle.h>


typedef pid_t       rap_pid_t;

#define RAP_INVALID_PID  -1

typedef void (*rap_spawn_proc_pt) (rap_cycle_t *cycle, void *data);

typedef struct {
    rap_pid_t           pid;
    int                 status;
    rap_socket_t        channel[2];

    rap_spawn_proc_pt   proc;
    void               *data;
    char               *name;

    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
} rap_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} rap_exec_ctx_t;


#define RAP_MAX_PROCESSES         1024

#define RAP_PROCESS_NORESPAWN     -1
#define RAP_PROCESS_JUST_SPAWN    -2
#define RAP_PROCESS_RESPAWN       -3
#define RAP_PROCESS_JUST_RESPAWN  -4
#define RAP_PROCESS_DETACHED      -5


#define rap_getpid   getpid
#define rap_getppid  getppid

#ifndef rap_log_pid
#define rap_log_pid  rap_pid
#endif


rap_pid_t rap_spawn_process(rap_cycle_t *cycle,
    rap_spawn_proc_pt proc, void *data, char *name, rap_int_t respawn);
rap_pid_t rap_execute(rap_cycle_t *cycle, rap_exec_ctx_t *ctx);
rap_int_t rap_init_signals(rap_log_t *log);
void rap_debug_point(void);


#if (RAP_HAVE_SCHED_YIELD)
#define rap_sched_yield()  sched_yield()
#else
#define rap_sched_yield()  usleep(1)
#endif


extern int            rap_argc;
extern char         **rap_argv;
extern char         **rap_os_argv;

extern rap_pid_t      rap_pid;
extern rap_pid_t      rap_parent;
extern rap_socket_t   rap_channel;
extern rap_int_t      rap_process_slot;
extern rap_int_t      rap_last_process;
extern rap_process_t  rap_processes[RAP_MAX_PROCESSES];


#endif /* _RAP_PROCESS_H_INCLUDED_ */
