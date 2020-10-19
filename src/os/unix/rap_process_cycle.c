
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_channel.h>


static void rap_start_worker_processes(rap_cycle_t *cycle, rap_int_t n,
    rap_int_t type);
static void rap_start_cache_manager_processes(rap_cycle_t *cycle,
    rap_uint_t respawn);
static void rap_pass_open_channel(rap_cycle_t *cycle, rap_channel_t *ch);
static void rap_signal_worker_processes(rap_cycle_t *cycle, int signo);
static rap_uint_t rap_reap_children(rap_cycle_t *cycle);
static void rap_master_process_exit(rap_cycle_t *cycle);
static void rap_worker_process_cycle(rap_cycle_t *cycle, void *data);
static void rap_worker_process_init(rap_cycle_t *cycle, rap_int_t worker);
static void rap_worker_process_exit(rap_cycle_t *cycle);
static void rap_channel_handler(rap_event_t *ev);
static void rap_cache_manager_process_cycle(rap_cycle_t *cycle, void *data);
static void rap_cache_manager_process_handler(rap_event_t *ev);
static void rap_cache_loader_process_handler(rap_event_t *ev);


rap_uint_t    rap_process;
rap_uint_t    rap_worker;
rap_pid_t     rap_pid;
rap_pid_t     rap_parent;

sig_atomic_t  rap_reap;
sig_atomic_t  rap_sigio;
sig_atomic_t  rap_sigalrm;
sig_atomic_t  rap_terminate;
sig_atomic_t  rap_quit;
sig_atomic_t  rap_debug_quit;
rap_uint_t    rap_exiting;
sig_atomic_t  rap_reconfigure;
sig_atomic_t  rap_reopen;

sig_atomic_t  rap_change_binary;
rap_pid_t     rap_new_binary;
rap_uint_t    rap_inherited;
rap_uint_t    rap_daemonized;

sig_atomic_t  rap_noaccept;
rap_uint_t    rap_noaccepting;
rap_uint_t    rap_restart;


static u_char  master_process[] = "master process";


static rap_cache_manager_ctx_t  rap_cache_manager_ctx = {
    rap_cache_manager_process_handler, "cache manager process", 0
};

static rap_cache_manager_ctx_t  rap_cache_loader_ctx = {
    rap_cache_loader_process_handler, "cache loader process", 60000
};


static rap_cycle_t      rap_exit_cycle;
static rap_log_t        rap_exit_log;
static rap_open_file_t  rap_exit_log_file;


void
rap_master_process_cycle(rap_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    rap_int_t          i;
    rap_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    rap_uint_t         live;
    rap_msec_t         delay;
    rap_listening_t   *ls;
    rap_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, rap_signal_value(RAP_RECONFIGURE_SIGNAL));
    sigaddset(&set, rap_signal_value(RAP_REOPEN_SIGNAL));
    sigaddset(&set, rap_signal_value(RAP_NOACCEPT_SIGNAL));
    sigaddset(&set, rap_signal_value(RAP_TERMINATE_SIGNAL));
    sigaddset(&set, rap_signal_value(RAP_SHUTDOWN_SIGNAL));
    sigaddset(&set, rap_signal_value(RAP_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < rap_argc; i++) {
        size += rap_strlen(rap_argv[i]) + 1;
    }

    title = rap_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = rap_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < rap_argc; i++) {
        *p++ = ' ';
        p = rap_cpystrn(p, (u_char *) rap_argv[i], size);
    }

    rap_setproctitle(title);


    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    rap_start_worker_processes(cycle, ccf->worker_processes,
                               RAP_PROCESS_RESPAWN);
    rap_start_cache_manager_processes(cycle, 0);

    rap_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for ( ;; ) {
        if (delay) {
            if (rap_sigalrm) {
                sigio = 0;
                delay *= 2;
                rap_sigalrm = 0;
            }

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                              "setitimer() failed");
            }
        }

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        rap_time_update();

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        if (rap_reap) {
            rap_reap = 0;
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = rap_reap_children(cycle);
        }

        if (!live && (rap_terminate || rap_quit)) {
            rap_master_process_exit(cycle);
        }

        if (rap_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                rap_signal_worker_processes(cycle, SIGKILL);
            } else {
                rap_signal_worker_processes(cycle,
                                       rap_signal_value(RAP_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (rap_quit) {
            rap_signal_worker_processes(cycle,
                                        rap_signal_value(RAP_SHUTDOWN_SIGNAL));

            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (rap_close_socket(ls[n].fd) == -1) {
                    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_socket_errno,
                                  rap_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        if (rap_reconfigure) {
            rap_reconfigure = 0;

            if (rap_new_binary) {
                rap_start_worker_processes(cycle, ccf->worker_processes,
                                           RAP_PROCESS_RESPAWN);
                rap_start_cache_manager_processes(cycle, 0);
                rap_noaccepting = 0;

                continue;
            }

            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = rap_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (rap_cycle_t *) rap_cycle;
                continue;
            }

            rap_cycle = cycle;
            ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx,
                                                   rap_core_module);
            rap_start_worker_processes(cycle, ccf->worker_processes,
                                       RAP_PROCESS_JUST_RESPAWN);
            rap_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            rap_msleep(100);

            live = 1;
            rap_signal_worker_processes(cycle,
                                        rap_signal_value(RAP_SHUTDOWN_SIGNAL));
        }

        if (rap_restart) {
            rap_restart = 0;
            rap_start_worker_processes(cycle, ccf->worker_processes,
                                       RAP_PROCESS_RESPAWN);
            rap_start_cache_manager_processes(cycle, 0);
            live = 1;
        }

        if (rap_reopen) {
            rap_reopen = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rap_reopen_files(cycle, ccf->user);
            rap_signal_worker_processes(cycle,
                                        rap_signal_value(RAP_REOPEN_SIGNAL));
        }

        if (rap_change_binary) {
            rap_change_binary = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "changing binary");
            rap_new_binary = rap_exec_new_binary(cycle, rap_argv);
        }

        if (rap_noaccept) {
            rap_noaccept = 0;
            rap_noaccepting = 1;
            rap_signal_worker_processes(cycle,
                                        rap_signal_value(RAP_SHUTDOWN_SIGNAL));
        }
    }
}


void
rap_single_process_cycle(rap_cycle_t *cycle)
{
    rap_uint_t  i;

    if (rap_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == RAP_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        rap_process_events_and_timers(cycle);

        if (rap_terminate || rap_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            rap_master_process_exit(cycle);
        }

        if (rap_reconfigure) {
            rap_reconfigure = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = rap_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (rap_cycle_t *) rap_cycle;
                continue;
            }

            rap_cycle = cycle;
        }

        if (rap_reopen) {
            rap_reopen = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rap_reopen_files(cycle, (rap_uid_t) -1);
        }
    }
}


static void
rap_start_worker_processes(rap_cycle_t *cycle, rap_int_t n, rap_int_t type)
{
    rap_int_t      i;
    rap_channel_t  ch;

    rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "start worker processes");

    rap_memzero(&ch, sizeof(rap_channel_t));

    ch.command = RAP_CMD_OPEN_CHANNEL;

    for (i = 0; i < n; i++) {

        rap_spawn_process(cycle, rap_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        ch.pid = rap_processes[rap_process_slot].pid;
        ch.slot = rap_process_slot;
        ch.fd = rap_processes[rap_process_slot].channel[0];

        rap_pass_open_channel(cycle, &ch);
    }
}


static void
rap_start_cache_manager_processes(rap_cycle_t *cycle, rap_uint_t respawn)
{
    rap_uint_t       i, manager, loader;
    rap_path_t     **path;
    rap_channel_t    ch;

    manager = 0;
    loader = 0;

    path = rap_cycle->paths.elts;
    for (i = 0; i < rap_cycle->paths.nelts; i++) {

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

    rap_spawn_process(cycle, rap_cache_manager_process_cycle,
                      &rap_cache_manager_ctx, "cache manager process",
                      respawn ? RAP_PROCESS_JUST_RESPAWN : RAP_PROCESS_RESPAWN);

    rap_memzero(&ch, sizeof(rap_channel_t));

    ch.command = RAP_CMD_OPEN_CHANNEL;
    ch.pid = rap_processes[rap_process_slot].pid;
    ch.slot = rap_process_slot;
    ch.fd = rap_processes[rap_process_slot].channel[0];

    rap_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    rap_spawn_process(cycle, rap_cache_manager_process_cycle,
                      &rap_cache_loader_ctx, "cache loader process",
                      respawn ? RAP_PROCESS_JUST_SPAWN : RAP_PROCESS_NORESPAWN);

    ch.command = RAP_CMD_OPEN_CHANNEL;
    ch.pid = rap_processes[rap_process_slot].pid;
    ch.slot = rap_process_slot;
    ch.fd = rap_processes[rap_process_slot].channel[0];

    rap_pass_open_channel(cycle, &ch);
}


static void
rap_pass_open_channel(rap_cycle_t *cycle, rap_channel_t *ch)
{
    rap_int_t  i;

    for (i = 0; i < rap_last_process; i++) {

        if (i == rap_process_slot
            || rap_processes[i].pid == -1
            || rap_processes[i].channel[0] == -1)
        {
            continue;
        }

        rap_log_debug6(RAP_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch->slot, ch->pid, ch->fd,
                      i, rap_processes[i].pid,
                      rap_processes[i].channel[0]);

        /* TODO: RAP_AGAIN */

        rap_write_channel(rap_processes[i].channel[0],
                          ch, sizeof(rap_channel_t), cycle->log);
    }
}


static void
rap_signal_worker_processes(rap_cycle_t *cycle, int signo)
{
    rap_int_t      i;
    rap_err_t      err;
    rap_channel_t  ch;

    rap_memzero(&ch, sizeof(rap_channel_t));

#if (RAP_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case rap_signal_value(RAP_SHUTDOWN_SIGNAL):
        ch.command = RAP_CMD_QUIT;
        break;

    case rap_signal_value(RAP_TERMINATE_SIGNAL):
        ch.command = RAP_CMD_TERMINATE;
        break;

    case rap_signal_value(RAP_REOPEN_SIGNAL):
        ch.command = RAP_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < rap_last_process; i++) {

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       rap_processes[i].pid,
                       rap_processes[i].exiting,
                       rap_processes[i].exited,
                       rap_processes[i].detached,
                       rap_processes[i].respawn,
                       rap_processes[i].just_spawn);

        if (rap_processes[i].detached || rap_processes[i].pid == -1) {
            continue;
        }

        if (rap_processes[i].just_spawn) {
            rap_processes[i].just_spawn = 0;
            continue;
        }

        if (rap_processes[i].exiting
            && signo == rap_signal_value(RAP_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (rap_write_channel(rap_processes[i].channel[0],
                                  &ch, sizeof(rap_channel_t), cycle->log)
                == RAP_OK)
            {
                if (signo != rap_signal_value(RAP_REOPEN_SIGNAL)) {
                    rap_processes[i].exiting = 1;
                }

                continue;
            }
        }

        rap_log_debug2(RAP_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", rap_processes[i].pid, signo);

        if (kill(rap_processes[i].pid, signo) == -1) {
            err = rap_errno;
            rap_log_error(RAP_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", rap_processes[i].pid, signo);

            if (err == RAP_ESRCH) {
                rap_processes[i].exited = 1;
                rap_processes[i].exiting = 0;
                rap_reap = 1;
            }

            continue;
        }

        if (signo != rap_signal_value(RAP_REOPEN_SIGNAL)) {
            rap_processes[i].exiting = 1;
        }
    }
}


static rap_uint_t
rap_reap_children(rap_cycle_t *cycle)
{
    rap_int_t         i, n;
    rap_uint_t        live;
    rap_channel_t     ch;
    rap_core_conf_t  *ccf;

    rap_memzero(&ch, sizeof(rap_channel_t));

    ch.command = RAP_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < rap_last_process; i++) {

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       rap_processes[i].pid,
                       rap_processes[i].exiting,
                       rap_processes[i].exited,
                       rap_processes[i].detached,
                       rap_processes[i].respawn,
                       rap_processes[i].just_spawn);

        if (rap_processes[i].pid == -1) {
            continue;
        }

        if (rap_processes[i].exited) {

            if (!rap_processes[i].detached) {
                rap_close_channel(rap_processes[i].channel, cycle->log);

                rap_processes[i].channel[0] = -1;
                rap_processes[i].channel[1] = -1;

                ch.pid = rap_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < rap_last_process; n++) {
                    if (rap_processes[n].exited
                        || rap_processes[n].pid == -1
                        || rap_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    rap_log_debug3(RAP_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, rap_processes[n].pid);

                    /* TODO: RAP_AGAIN */

                    rap_write_channel(rap_processes[n].channel[0],
                                      &ch, sizeof(rap_channel_t), cycle->log);
                }
            }

            if (rap_processes[i].respawn
                && !rap_processes[i].exiting
                && !rap_terminate
                && !rap_quit)
            {
                if (rap_spawn_process(cycle, rap_processes[i].proc,
                                      rap_processes[i].data,
                                      rap_processes[i].name, i)
                    == RAP_INVALID_PID)
                {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  rap_processes[i].name);
                    continue;
                }


                ch.command = RAP_CMD_OPEN_CHANNEL;
                ch.pid = rap_processes[rap_process_slot].pid;
                ch.slot = rap_process_slot;
                ch.fd = rap_processes[rap_process_slot].channel[0];

                rap_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            if (rap_processes[i].pid == rap_new_binary) {

                ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx,
                                                       rap_core_module);

                if (rap_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == RAP_FILE_ERROR)
                {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                                  rap_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, rap_argv[0]);
                }

                rap_new_binary = 0;
                if (rap_noaccepting) {
                    rap_restart = 1;
                    rap_noaccepting = 0;
                }
            }

            if (i == rap_last_process - 1) {
                rap_last_process--;

            } else {
                rap_processes[i].pid = -1;
            }

        } else if (rap_processes[i].exiting || !rap_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
rap_master_process_exit(rap_cycle_t *cycle)
{
    rap_uint_t  i;

    rap_delete_pidfile(cycle);

    rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    rap_close_listening_sockets(cycle);

    /*
     * Copy rap_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard rap_cycle->log allocated from
     * rap_cycle->pool is already destroyed.
     */


    rap_exit_log = *rap_log_get_file_log(rap_cycle->log);

    rap_exit_log_file.fd = rap_exit_log.file->fd;
    rap_exit_log.file = &rap_exit_log_file;
    rap_exit_log.next = NULL;
    rap_exit_log.writer = NULL;

    rap_exit_cycle.log = &rap_exit_log;
    rap_exit_cycle.files = rap_cycle->files;
    rap_exit_cycle.files_n = rap_cycle->files_n;
    rap_cycle = &rap_exit_cycle;

    rap_destroy_pool(cycle->pool);

    exit(0);
}


static void
rap_worker_process_cycle(rap_cycle_t *cycle, void *data)
{
    rap_int_t worker = (intptr_t) data;

    rap_process = RAP_PROCESS_WORKER;
    rap_worker = worker;

    rap_worker_process_init(cycle, worker);

    rap_setproctitle("worker process");

    for ( ;; ) {

        if (rap_exiting) {
            if (rap_event_no_timers_left() == RAP_OK) {
                rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "exiting");
                rap_worker_process_exit(cycle);
            }
        }

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        rap_process_events_and_timers(cycle);

        if (rap_terminate) {
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "exiting");
            rap_worker_process_exit(cycle);
        }

        if (rap_quit) {
            rap_quit = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            rap_setproctitle("worker process is shutting down");

            if (!rap_exiting) {
                rap_exiting = 1;
                rap_set_shutdown_timer(cycle);
                rap_close_listening_sockets(cycle);
                rap_close_idle_connections(cycle);
            }
        }

        if (rap_reopen) {
            rap_reopen = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rap_reopen_files(cycle, -1);
        }
    }
}


static void
rap_worker_process_init(rap_cycle_t *cycle, rap_int_t worker)
{
    sigset_t          set;
    rap_int_t         n;
    rap_time_t       *tp;
    rap_uint_t        i;
    rap_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    rap_core_conf_t  *ccf;
    rap_listening_t  *ls;

    if (rap_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != RAP_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != RAP_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

#if (RAP_HAVE_PR_SET_KEEPCAPS && RAP_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (RAP_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            rap_memzero(&header, sizeof(struct __user_cap_header_struct));
            rap_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    if (worker >= 0) {
        cpu_affinity = rap_get_cpu_affinity(worker);

        if (cpu_affinity) {
            rap_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (RAP_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "sigprocmask() failed");
    }

    tp = rap_timeofday();
    srandom(((unsigned) rap_pid << 16) ^ tp->sec ^ tp->msec);

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
            if (cycle->modules[i]->init_process(cycle) == RAP_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < rap_last_process; n++) {

        if (rap_processes[n].pid == -1) {
            continue;
        }

        if (n == rap_process_slot) {
            continue;
        }

        if (rap_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(rap_processes[n].channel[1]) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "close() channel failed");
        }
    }

    if (close(rap_processes[rap_process_slot].channel[0]) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "close() channel failed");
    }

#if 0
    rap_last_process = 0;
#endif

    if (rap_add_channel_event(cycle, rap_channel, RAP_READ_EVENT,
                              rap_channel_handler)
        == RAP_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


static void
rap_worker_process_exit(rap_cycle_t *cycle)
{
    rap_uint_t         i;
    rap_connection_t  *c;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (rap_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                rap_debug_quit = 1;
            }
        }

        if (rap_debug_quit) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0, "aborting");
            rap_debug_point();
        }
    }

    /*
     * Copy rap_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard rap_cycle->log allocated from
     * rap_cycle->pool is already destroyed.
     */

    rap_exit_log = *rap_log_get_file_log(rap_cycle->log);

    rap_exit_log_file.fd = rap_exit_log.file->fd;
    rap_exit_log.file = &rap_exit_log_file;
    rap_exit_log.next = NULL;
    rap_exit_log.writer = NULL;

    rap_exit_cycle.log = &rap_exit_log;
    rap_exit_cycle.files = rap_cycle->files;
    rap_exit_cycle.files_n = rap_cycle->files_n;
    rap_cycle = &rap_exit_cycle;

    rap_destroy_pool(cycle->pool);

    rap_log_error(RAP_LOG_NOTICE, rap_cycle->log, 0, "exit");

    exit(0);
}


static void
rap_channel_handler(rap_event_t *ev)
{
    rap_int_t          n;
    rap_channel_t      ch;
    rap_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        n = rap_read_channel(c->fd, &ch, sizeof(rap_channel_t), ev->log);

        rap_log_debug1(RAP_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == RAP_ERROR) {

            if (rap_event_flags & RAP_USE_EPOLL_EVENT) {
                rap_del_conn(c, 0);
            }

            rap_close_connection(c);
            return;
        }

        if (rap_event_flags & RAP_USE_EVENTPORT_EVENT) {
            if (rap_add_event(ev, RAP_READ_EVENT, 0) == RAP_ERROR) {
                return;
            }
        }

        if (n == RAP_AGAIN) {
            return;
        }

        rap_log_debug1(RAP_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case RAP_CMD_QUIT:
            rap_quit = 1;
            break;

        case RAP_CMD_TERMINATE:
            rap_terminate = 1;
            break;

        case RAP_CMD_REOPEN:
            rap_reopen = 1;
            break;

        case RAP_CMD_OPEN_CHANNEL:

            rap_log_debug3(RAP_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            rap_processes[ch.slot].pid = ch.pid;
            rap_processes[ch.slot].channel[0] = ch.fd;
            break;

        case RAP_CMD_CLOSE_CHANNEL:

            rap_log_debug4(RAP_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, rap_processes[ch.slot].pid,
                           rap_processes[ch.slot].channel[0]);

            if (close(rap_processes[ch.slot].channel[0]) == -1) {
                rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                              "close() channel failed");
            }

            rap_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
rap_cache_manager_process_cycle(rap_cycle_t *cycle, void *data)
{
    rap_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    rap_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    rap_process = RAP_PROCESS_HELPER;

    rap_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    rap_worker_process_init(cycle, -1);

    rap_memzero(&ev, sizeof(rap_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    rap_use_accept_mutex = 0;

    rap_setproctitle(ctx->name);

    rap_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (rap_terminate || rap_quit) {
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (rap_reopen) {
            rap_reopen = 0;
            rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "reopening logs");
            rap_reopen_files(cycle, -1);
        }

        rap_process_events_and_timers(cycle);
    }
}


static void
rap_cache_manager_process_handler(rap_event_t *ev)
{
    rap_uint_t    i;
    rap_msec_t    next, n;
    rap_path_t  **path;

    next = 60 * 60 * 1000;

    path = rap_cycle->paths.elts;
    for (i = 0; i < rap_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            rap_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    rap_add_timer(ev, next);
}


static void
rap_cache_loader_process_handler(rap_event_t *ev)
{
    rap_uint_t     i;
    rap_path_t   **path;
    rap_cycle_t   *cycle;

    cycle = (rap_cycle_t *) rap_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (rap_terminate || rap_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            rap_time_update();
        }
    }

    exit(0);
}
