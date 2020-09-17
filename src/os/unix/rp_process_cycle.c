
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_channel.h>


static void rp_start_worker_processes(rp_cycle_t *cycle, rp_int_t n,
    rp_int_t type);
static void rp_start_cache_manager_processes(rp_cycle_t *cycle,
    rp_uint_t respawn);
static void rp_pass_open_channel(rp_cycle_t *cycle, rp_channel_t *ch);
static void rp_signal_worker_processes(rp_cycle_t *cycle, int signo);
static rp_uint_t rp_reap_children(rp_cycle_t *cycle);
static void rp_master_process_exit(rp_cycle_t *cycle);
static void rp_worker_process_cycle(rp_cycle_t *cycle, void *data);
static void rp_worker_process_init(rp_cycle_t *cycle, rp_int_t worker);
static void rp_worker_process_exit(rp_cycle_t *cycle);
static void rp_channel_handler(rp_event_t *ev);
static void rp_cache_manager_process_cycle(rp_cycle_t *cycle, void *data);
static void rp_cache_manager_process_handler(rp_event_t *ev);
static void rp_cache_loader_process_handler(rp_event_t *ev);


rp_uint_t    rp_process;
rp_uint_t    rp_worker;
rp_pid_t     rp_pid;
rp_pid_t     rp_parent;

sig_atomic_t  rp_reap;
sig_atomic_t  rp_sigio;
sig_atomic_t  rp_sigalrm;
sig_atomic_t  rp_terminate;
sig_atomic_t  rp_quit;
sig_atomic_t  rp_debug_quit;
rp_uint_t    rp_exiting;
sig_atomic_t  rp_reconfigure;
sig_atomic_t  rp_reopen;

sig_atomic_t  rp_change_binary;
rp_pid_t     rp_new_binary;
rp_uint_t    rp_inherited;
rp_uint_t    rp_daemonized;

sig_atomic_t  rp_noaccept;
rp_uint_t    rp_noaccepting;
rp_uint_t    rp_restart;


static u_char  master_process[] = "master process";


static rp_cache_manager_ctx_t  rp_cache_manager_ctx = {
    rp_cache_manager_process_handler, "cache manager process", 0
};

static rp_cache_manager_ctx_t  rp_cache_loader_ctx = {
    rp_cache_loader_process_handler, "cache loader process", 60000
};


static rp_cycle_t      rp_exit_cycle;
static rp_log_t        rp_exit_log;
static rp_open_file_t  rp_exit_log_file;


void
rp_master_process_cycle(rp_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    rp_int_t          i;
    rp_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    rp_uint_t         live;
    rp_msec_t         delay;
    rp_listening_t   *ls;
    rp_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, rp_signal_value(RP_RECONFIGURE_SIGNAL));
    sigaddset(&set, rp_signal_value(RP_REOPEN_SIGNAL));
    sigaddset(&set, rp_signal_value(RP_NOACCEPT_SIGNAL));
    sigaddset(&set, rp_signal_value(RP_TERMINATE_SIGNAL));
    sigaddset(&set, rp_signal_value(RP_SHUTDOWN_SIGNAL));
    sigaddset(&set, rp_signal_value(RP_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < rp_argc; i++) {
        size += rp_strlen(rp_argv[i]) + 1;
    }

    title = rp_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = rp_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < rp_argc; i++) {
        *p++ = ' ';
        p = rp_cpystrn(p, (u_char *) rp_argv[i], size);
    }

    rp_setproctitle(title);


    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    rp_start_worker_processes(cycle, ccf->worker_processes,
                               RP_PROCESS_RESPAWN);
    rp_start_cache_manager_processes(cycle, 0);

    rp_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for ( ;; ) {
        if (delay) {
            if (rp_sigalrm) {
                sigio = 0;
                delay *= 2;
                rp_sigalrm = 0;
            }

            rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                              "setitimer() failed");
            }
        }

        rp_log_debug0(RP_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        rp_time_update();

        rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        if (rp_reap) {
            rp_reap = 0;
            rp_log_debug0(RP_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = rp_reap_children(cycle);
        }

        if (!live && (rp_terminate || rp_quit)) {
            rp_master_process_exit(cycle);
        }

        if (rp_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                rp_signal_worker_processes(cycle, SIGKILL);
            } else {
                rp_signal_worker_processes(cycle,
                                       rp_signal_value(RP_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (rp_quit) {
            rp_signal_worker_processes(cycle,
                                        rp_signal_value(RP_SHUTDOWN_SIGNAL));

            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (rp_close_socket(ls[n].fd) == -1) {
                    rp_log_error(RP_LOG_EMERG, cycle->log, rp_socket_errno,
                                  rp_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        if (rp_reconfigure) {
            rp_reconfigure = 0;

            if (rp_new_binary) {
                rp_start_worker_processes(cycle, ccf->worker_processes,
                                           RP_PROCESS_RESPAWN);
                rp_start_cache_manager_processes(cycle, 0);
                rp_noaccepting = 0;

                continue;
            }

            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = rp_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (rp_cycle_t *) rp_cycle;
                continue;
            }

            rp_cycle = cycle;
            ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx,
                                                   rp_core_module);
            rp_start_worker_processes(cycle, ccf->worker_processes,
                                       RP_PROCESS_JUST_RESPAWN);
            rp_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            rp_msleep(100);

            live = 1;
            rp_signal_worker_processes(cycle,
                                        rp_signal_value(RP_SHUTDOWN_SIGNAL));
        }

        if (rp_restart) {
            rp_restart = 0;
            rp_start_worker_processes(cycle, ccf->worker_processes,
                                       RP_PROCESS_RESPAWN);
            rp_start_cache_manager_processes(cycle, 0);
            live = 1;
        }

        if (rp_reopen) {
            rp_reopen = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rp_reopen_files(cycle, ccf->user);
            rp_signal_worker_processes(cycle,
                                        rp_signal_value(RP_REOPEN_SIGNAL));
        }

        if (rp_change_binary) {
            rp_change_binary = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "changing binary");
            rp_new_binary = rp_exec_new_binary(cycle, rp_argv);
        }

        if (rp_noaccept) {
            rp_noaccept = 0;
            rp_noaccepting = 1;
            rp_signal_worker_processes(cycle,
                                        rp_signal_value(RP_SHUTDOWN_SIGNAL));
        }
    }
}


void
rp_single_process_cycle(rp_cycle_t *cycle)
{
    rp_uint_t  i;

    if (rp_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == RP_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        rp_log_debug0(RP_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        rp_process_events_and_timers(cycle);

        if (rp_terminate || rp_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            rp_master_process_exit(cycle);
        }

        if (rp_reconfigure) {
            rp_reconfigure = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = rp_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (rp_cycle_t *) rp_cycle;
                continue;
            }

            rp_cycle = cycle;
        }

        if (rp_reopen) {
            rp_reopen = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rp_reopen_files(cycle, (rp_uid_t) -1);
        }
    }
}


static void
rp_start_worker_processes(rp_cycle_t *cycle, rp_int_t n, rp_int_t type)
{
    rp_int_t      i;
    rp_channel_t  ch;

    rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "start worker processes");

    rp_memzero(&ch, sizeof(rp_channel_t));

    ch.command = RP_CMD_OPEN_CHANNEL;

    for (i = 0; i < n; i++) {

        rp_spawn_process(cycle, rp_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        ch.pid = rp_processes[rp_process_slot].pid;
        ch.slot = rp_process_slot;
        ch.fd = rp_processes[rp_process_slot].channel[0];

        rp_pass_open_channel(cycle, &ch);
    }
}


static void
rp_start_cache_manager_processes(rp_cycle_t *cycle, rp_uint_t respawn)
{
    rp_uint_t       i, manager, loader;
    rp_path_t     **path;
    rp_channel_t    ch;

    manager = 0;
    loader = 0;

    path = rp_cycle->paths.elts;
    for (i = 0; i < rp_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    rp_spawn_process(cycle, rp_cache_manager_process_cycle,
                      &rp_cache_manager_ctx, "cache manager process",
                      respawn ? RP_PROCESS_JUST_RESPAWN : RP_PROCESS_RESPAWN);

    rp_memzero(&ch, sizeof(rp_channel_t));

    ch.command = RP_CMD_OPEN_CHANNEL;
    ch.pid = rp_processes[rp_process_slot].pid;
    ch.slot = rp_process_slot;
    ch.fd = rp_processes[rp_process_slot].channel[0];

    rp_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    rp_spawn_process(cycle, rp_cache_manager_process_cycle,
                      &rp_cache_loader_ctx, "cache loader process",
                      respawn ? RP_PROCESS_JUST_SPAWN : RP_PROCESS_NORESPAWN);

    ch.command = RP_CMD_OPEN_CHANNEL;
    ch.pid = rp_processes[rp_process_slot].pid;
    ch.slot = rp_process_slot;
    ch.fd = rp_processes[rp_process_slot].channel[0];

    rp_pass_open_channel(cycle, &ch);
}


static void
rp_pass_open_channel(rp_cycle_t *cycle, rp_channel_t *ch)
{
    rp_int_t  i;

    for (i = 0; i < rp_last_process; i++) {

        if (i == rp_process_slot
            || rp_processes[i].pid == -1
            || rp_processes[i].channel[0] == -1)
        {
            continue;
        }

        rp_log_debug6(RP_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch->slot, ch->pid, ch->fd,
                      i, rp_processes[i].pid,
                      rp_processes[i].channel[0]);

        /* TODO: RP_AGAIN */

        rp_write_channel(rp_processes[i].channel[0],
                          ch, sizeof(rp_channel_t), cycle->log);
    }
}


static void
rp_signal_worker_processes(rp_cycle_t *cycle, int signo)
{
    rp_int_t      i;
    rp_err_t      err;
    rp_channel_t  ch;

    rp_memzero(&ch, sizeof(rp_channel_t));

#if (RP_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case rp_signal_value(RP_SHUTDOWN_SIGNAL):
        ch.command = RP_CMD_QUIT;
        break;

    case rp_signal_value(RP_TERMINATE_SIGNAL):
        ch.command = RP_CMD_TERMINATE;
        break;

    case rp_signal_value(RP_REOPEN_SIGNAL):
        ch.command = RP_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < rp_last_process; i++) {

        rp_log_debug7(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       rp_processes[i].pid,
                       rp_processes[i].exiting,
                       rp_processes[i].exited,
                       rp_processes[i].detached,
                       rp_processes[i].respawn,
                       rp_processes[i].just_spawn);

        if (rp_processes[i].detached || rp_processes[i].pid == -1) {
            continue;
        }

        if (rp_processes[i].just_spawn) {
            rp_processes[i].just_spawn = 0;
            continue;
        }

        if (rp_processes[i].exiting
            && signo == rp_signal_value(RP_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (rp_write_channel(rp_processes[i].channel[0],
                                  &ch, sizeof(rp_channel_t), cycle->log)
                == RP_OK)
            {
                if (signo != rp_signal_value(RP_REOPEN_SIGNAL)) {
                    rp_processes[i].exiting = 1;
                }

                continue;
            }
        }

        rp_log_debug2(RP_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", rp_processes[i].pid, signo);

        if (kill(rp_processes[i].pid, signo) == -1) {
            err = rp_errno;
            rp_log_error(RP_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", rp_processes[i].pid, signo);

            if (err == RP_ESRCH) {
                rp_processes[i].exited = 1;
                rp_processes[i].exiting = 0;
                rp_reap = 1;
            }

            continue;
        }

        if (signo != rp_signal_value(RP_REOPEN_SIGNAL)) {
            rp_processes[i].exiting = 1;
        }
    }
}


static rp_uint_t
rp_reap_children(rp_cycle_t *cycle)
{
    rp_int_t         i, n;
    rp_uint_t        live;
    rp_channel_t     ch;
    rp_core_conf_t  *ccf;

    rp_memzero(&ch, sizeof(rp_channel_t));

    ch.command = RP_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < rp_last_process; i++) {

        rp_log_debug7(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       rp_processes[i].pid,
                       rp_processes[i].exiting,
                       rp_processes[i].exited,
                       rp_processes[i].detached,
                       rp_processes[i].respawn,
                       rp_processes[i].just_spawn);

        if (rp_processes[i].pid == -1) {
            continue;
        }

        if (rp_processes[i].exited) {

            if (!rp_processes[i].detached) {
                rp_close_channel(rp_processes[i].channel, cycle->log);

                rp_processes[i].channel[0] = -1;
                rp_processes[i].channel[1] = -1;

                ch.pid = rp_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < rp_last_process; n++) {
                    if (rp_processes[n].exited
                        || rp_processes[n].pid == -1
                        || rp_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    rp_log_debug3(RP_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, rp_processes[n].pid);

                    /* TODO: RP_AGAIN */

                    rp_write_channel(rp_processes[n].channel[0],
                                      &ch, sizeof(rp_channel_t), cycle->log);
                }
            }

            if (rp_processes[i].respawn
                && !rp_processes[i].exiting
                && !rp_terminate
                && !rp_quit)
            {
                if (rp_spawn_process(cycle, rp_processes[i].proc,
                                      rp_processes[i].data,
                                      rp_processes[i].name, i)
                    == RP_INVALID_PID)
                {
                    rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  rp_processes[i].name);
                    continue;
                }


                ch.command = RP_CMD_OPEN_CHANNEL;
                ch.pid = rp_processes[rp_process_slot].pid;
                ch.slot = rp_process_slot;
                ch.fd = rp_processes[rp_process_slot].channel[0];

                rp_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            if (rp_processes[i].pid == rp_new_binary) {

                ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx,
                                                       rp_core_module);

                if (rp_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == RP_FILE_ERROR)
                {
                    rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                                  rp_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, rp_argv[0]);
                }

                rp_new_binary = 0;
                if (rp_noaccepting) {
                    rp_restart = 1;
                    rp_noaccepting = 0;
                }
            }

            if (i == rp_last_process - 1) {
                rp_last_process--;

            } else {
                rp_processes[i].pid = -1;
            }

        } else if (rp_processes[i].exiting || !rp_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
rp_master_process_exit(rp_cycle_t *cycle)
{
    rp_uint_t  i;

    rp_delete_pidfile(cycle);

    rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    rp_close_listening_sockets(cycle);

    /*
     * Copy rp_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard rp_cycle->log allocated from
     * rp_cycle->pool is already destroyed.
     */


    rp_exit_log = *rp_log_get_file_log(rp_cycle->log);

    rp_exit_log_file.fd = rp_exit_log.file->fd;
    rp_exit_log.file = &rp_exit_log_file;
    rp_exit_log.next = NULL;
    rp_exit_log.writer = NULL;

    rp_exit_cycle.log = &rp_exit_log;
    rp_exit_cycle.files = rp_cycle->files;
    rp_exit_cycle.files_n = rp_cycle->files_n;
    rp_cycle = &rp_exit_cycle;

    rp_destroy_pool(cycle->pool);

    exit(0);
}


static void
rp_worker_process_cycle(rp_cycle_t *cycle, void *data)
{
    rp_int_t worker = (intptr_t) data;

    rp_process = RP_PROCESS_WORKER;
    rp_worker = worker;

    rp_worker_process_init(cycle, worker);

    rp_setproctitle("worker process");

    for ( ;; ) {

        if (rp_exiting) {
            if (rp_event_no_timers_left() == RP_OK) {
                rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "exiting");
                rp_worker_process_exit(cycle);
            }
        }

        rp_log_debug0(RP_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        rp_process_events_and_timers(cycle);

        if (rp_terminate) {
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "exiting");
            rp_worker_process_exit(cycle);
        }

        if (rp_quit) {
            rp_quit = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            rp_setproctitle("worker process is shutting down");

            if (!rp_exiting) {
                rp_exiting = 1;
                rp_set_shutdown_timer(cycle);
                rp_close_listening_sockets(cycle);
                rp_close_idle_connections(cycle);
            }
        }

        if (rp_reopen) {
            rp_reopen = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rp_reopen_files(cycle, -1);
        }
    }
}


static void
rp_worker_process_init(rp_cycle_t *cycle, rp_int_t worker)
{
    sigset_t          set;
    rp_int_t         n;
    rp_time_t       *tp;
    rp_uint_t        i;
    rp_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    rp_core_conf_t  *ccf;
    rp_listening_t  *ls;

    if (rp_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != RP_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != RP_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

#if (RP_HAVE_PR_SET_KEEPCAPS && RP_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (RP_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            rp_memzero(&header, sizeof(struct __user_cap_header_struct));
            rp_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    if (worker >= 0) {
        cpu_affinity = rp_get_cpu_affinity(worker);

        if (cpu_affinity) {
            rp_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (RP_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "sigprocmask() failed");
    }

    tp = rp_timeofday();
    srandom(((unsigned) rp_pid << 16) ^ tp->sec ^ tp->msec);

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == RP_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < rp_last_process; n++) {

        if (rp_processes[n].pid == -1) {
            continue;
        }

        if (n == rp_process_slot) {
            continue;
        }

        if (rp_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(rp_processes[n].channel[1]) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "close() channel failed");
        }
    }

    if (close(rp_processes[rp_process_slot].channel[0]) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close() channel failed");
    }

#if 0
    rp_last_process = 0;
#endif

    if (rp_add_channel_event(cycle, rp_channel, RP_READ_EVENT,
                              rp_channel_handler)
        == RP_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


static void
rp_worker_process_exit(rp_cycle_t *cycle)
{
    rp_uint_t         i;
    rp_connection_t  *c;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (rp_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                rp_debug_quit = 1;
            }
        }

        if (rp_debug_quit) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0, "aborting");
            rp_debug_point();
        }
    }

    /*
     * Copy rp_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard rp_cycle->log allocated from
     * rp_cycle->pool is already destroyed.
     */

    rp_exit_log = *rp_log_get_file_log(rp_cycle->log);

    rp_exit_log_file.fd = rp_exit_log.file->fd;
    rp_exit_log.file = &rp_exit_log_file;
    rp_exit_log.next = NULL;
    rp_exit_log.writer = NULL;

    rp_exit_cycle.log = &rp_exit_log;
    rp_exit_cycle.files = rp_cycle->files;
    rp_exit_cycle.files_n = rp_cycle->files_n;
    rp_cycle = &rp_exit_cycle;

    rp_destroy_pool(cycle->pool);

    rp_log_error(RP_LOG_NOTICE, rp_cycle->log, 0, "exit");

    exit(0);
}


static void
rp_channel_handler(rp_event_t *ev)
{
    rp_int_t          n;
    rp_channel_t      ch;
    rp_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    rp_log_debug0(RP_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        n = rp_read_channel(c->fd, &ch, sizeof(rp_channel_t), ev->log);

        rp_log_debug1(RP_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == RP_ERROR) {

            if (rp_event_flags & RP_USE_EPOLL_EVENT) {
                rp_del_conn(c, 0);
            }

            rp_close_connection(c);
            return;
        }

        if (rp_event_flags & RP_USE_EVENTPORT_EVENT) {
            if (rp_add_event(ev, RP_READ_EVENT, 0) == RP_ERROR) {
                return;
            }
        }

        if (n == RP_AGAIN) {
            return;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case RP_CMD_QUIT:
            rp_quit = 1;
            break;

        case RP_CMD_TERMINATE:
            rp_terminate = 1;
            break;

        case RP_CMD_REOPEN:
            rp_reopen = 1;
            break;

        case RP_CMD_OPEN_CHANNEL:

            rp_log_debug3(RP_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            rp_processes[ch.slot].pid = ch.pid;
            rp_processes[ch.slot].channel[0] = ch.fd;
            break;

        case RP_CMD_CLOSE_CHANNEL:

            rp_log_debug4(RP_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, rp_processes[ch.slot].pid,
                           rp_processes[ch.slot].channel[0]);

            if (close(rp_processes[ch.slot].channel[0]) == -1) {
                rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                              "close() channel failed");
            }

            rp_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
rp_cache_manager_process_cycle(rp_cycle_t *cycle, void *data)
{
    rp_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    rp_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    rp_process = RP_PROCESS_HELPER;

    rp_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    rp_worker_process_init(cycle, -1);

    rp_memzero(&ev, sizeof(rp_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    rp_use_accept_mutex = 0;

    rp_setproctitle(ctx->name);

    rp_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (rp_terminate || rp_quit) {
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (rp_reopen) {
            rp_reopen = 0;
            rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rp_reopen_files(cycle, -1);
        }

        rp_process_events_and_timers(cycle);
    }
}


static void
rp_cache_manager_process_handler(rp_event_t *ev)
{
    rp_uint_t    i;
    rp_msec_t    next, n;
    rp_path_t  **path;

    next = 60 * 60 * 1000;

    path = rp_cycle->paths.elts;
    for (i = 0; i < rp_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            rp_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    rp_add_timer(ev, next);
}


static void
rp_cache_loader_process_handler(rp_event_t *ev)
{
    rp_uint_t     i;
    rp_path_t   **path;
    rp_cycle_t   *cycle;

    cycle = (rp_cycle_t *) rp_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (rp_terminate || rp_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            rp_time_update();
        }
    }

    exit(0);
}
