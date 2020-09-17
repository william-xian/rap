
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PROCESS_CYCLE_H_INCLUDED_
#define _RP_PROCESS_CYCLE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_CMD_OPEN_CHANNEL   1
#define RP_CMD_CLOSE_CHANNEL  2
#define RP_CMD_QUIT           3
#define RP_CMD_TERMINATE      4
#define RP_CMD_REOPEN         5


#define RP_PROCESS_SINGLE     0
#define RP_PROCESS_MASTER     1
#define RP_PROCESS_SIGNALLER  2
#define RP_PROCESS_WORKER     3
#define RP_PROCESS_HELPER     4


typedef struct {
    rp_event_handler_pt       handler;
    char                      *name;
    rp_msec_t                 delay;
} rp_cache_manager_ctx_t;


void rp_master_process_cycle(rp_cycle_t *cycle);
void rp_single_process_cycle(rp_cycle_t *cycle);


extern rp_uint_t      rp_process;
extern rp_uint_t      rp_worker;
extern rp_pid_t       rp_pid;
extern rp_pid_t       rp_new_binary;
extern rp_uint_t      rp_inherited;
extern rp_uint_t      rp_daemonized;
extern rp_uint_t      rp_exiting;

extern sig_atomic_t    rp_reap;
extern sig_atomic_t    rp_sigio;
extern sig_atomic_t    rp_sigalrm;
extern sig_atomic_t    rp_quit;
extern sig_atomic_t    rp_debug_quit;
extern sig_atomic_t    rp_terminate;
extern sig_atomic_t    rp_noaccept;
extern sig_atomic_t    rp_reconfigure;
extern sig_atomic_t    rp_reopen;
extern sig_atomic_t    rp_change_binary;


#endif /* _RP_PROCESS_CYCLE_H_INCLUDED_ */
