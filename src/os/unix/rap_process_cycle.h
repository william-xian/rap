
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PROCESS_CYCLE_H_INCLUDED_
#define _RAP_PROCESS_CYCLE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_CMD_OPEN_CHANNEL   1
#define RAP_CMD_CLOSE_CHANNEL  2
#define RAP_CMD_QUIT           3
#define RAP_CMD_TERMINATE      4
#define RAP_CMD_REOPEN         5


#define RAP_PROCESS_SINGLE     0
#define RAP_PROCESS_MASTER     1
#define RAP_PROCESS_SIGNALLER  2
#define RAP_PROCESS_WORKER     3
#define RAP_PROCESS_HELPER     4


typedef struct {
    rap_event_handler_pt       handler;
    char                      *name;
    rap_msec_t                 delay;
} rap_cache_manager_ctx_t;


void rap_master_process_cycle(rap_cycle_t *cycle);
void rap_single_process_cycle(rap_cycle_t *cycle);


extern rap_uint_t      rap_process;
extern rap_uint_t      rap_worker;
extern rap_pid_t       rap_pid;
extern rap_pid_t       rap_new_binary;
extern rap_uint_t      rap_inherited;
extern rap_uint_t      rap_daemonized;
extern rap_uint_t      rap_exiting;

extern sig_atomic_t    rap_reap;
extern sig_atomic_t    rap_sigio;
extern sig_atomic_t    rap_sigalrm;
extern sig_atomic_t    rap_quit;
extern sig_atomic_t    rap_debug_quit;
extern sig_atomic_t    rap_terminate;
extern sig_atomic_t    rap_noaccept;
extern sig_atomic_t    rap_reconfigure;
extern sig_atomic_t    rap_reopen;
extern sig_atomic_t    rap_change_binary;


#endif /* _RAP_PROCESS_CYCLE_H_INCLUDED_ */
