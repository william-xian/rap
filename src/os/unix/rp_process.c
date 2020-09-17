
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_channel.h>


typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} rp_signal_t;



static void rp_execute_proc(rp_cycle_t *cycle, void *data);
static void rp_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
static void rp_process_get_status(void);
static void rp_unlock_mutexes(rp_pid_t pid);


int              rp_argc;
char           **rp_argv;
char           **rp_os_argv;

rp_int_t        rp_process_slot;
rp_socket_t     rp_channel;
rp_int_t        rp_last_process;
rp_process_t    rp_processes[RP_MAX_PROCESSES];


rp_signal_t  signals[] = {
    { rp_signal_value(RP_RECONFIGURE_SIGNAL),
      "SIG" rp_value(RP_RECONFIGURE_SIGNAL),
      "reload",
      rp_signal_handler },

    { rp_signal_value(RP_REOPEN_SIGNAL),
      "SIG" rp_value(RP_REOPEN_SIGNAL),
      "reopen",
      rp_signal_handler },

    { rp_signal_value(RP_NOACCEPT_SIGNAL),
      "SIG" rp_value(RP_NOACCEPT_SIGNAL),
      "",
      rp_signal_handler },

    { rp_signal_value(RP_TERMINATE_SIGNAL),
      "SIG" rp_value(RP_TERMINATE_SIGNAL),
      "stop",
      rp_signal_handler },

    { rp_signal_value(RP_SHUTDOWN_SIGNAL),
      "SIG" rp_value(RP_SHUTDOWN_SIGNAL),
      "quit",
      rp_signal_handler },

    { rp_signal_value(RP_CHANGEBIN_SIGNAL),
      "SIG" rp_value(RP_CHANGEBIN_SIGNAL),
      "",
      rp_signal_handler },

    { SIGALRM, "SIGALRM", "", rp_signal_handler },

    { SIGINT, "SIGINT", "", rp_signal_handler },

    { SIGIO, "SIGIO", "", rp_signal_handler },

    { SIGCHLD, "SIGCHLD", "", rp_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

    { 0, NULL, "", NULL }
};


rp_pid_t
rp_spawn_process(rp_cycle_t *cycle, rp_spawn_proc_pt proc, void *data,
    char *name, rp_int_t respawn)
{
    u_long     on;
    rp_pid_t  pid;
    rp_int_t  s;

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < rp_last_process; s++) {
            if (rp_processes[s].pid == -1) {
                break;
            }
        }

        if (s == RP_MAX_PROCESSES) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          RP_MAX_PROCESSES);
            return RP_INVALID_PID;
        }
    }


    if (respawn != RP_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, rp_processes[s].channel) == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return RP_INVALID_PID;
        }

        rp_log_debug2(RP_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       rp_processes[s].channel[0],
                       rp_processes[s].channel[1]);

        if (rp_nonblocking(rp_processes[s].channel[0]) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          rp_nonblocking_n " failed while spawning \"%s\"",
                          name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        if (rp_nonblocking(rp_processes[s].channel[1]) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          rp_nonblocking_n " failed while spawning \"%s\"",
                          name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        on = 1;
        if (ioctl(rp_processes[s].channel[0], FIOASYNC, &on) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        if (fcntl(rp_processes[s].channel[0], F_SETOWN, rp_pid) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        if (fcntl(rp_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        if (fcntl(rp_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            rp_close_channel(rp_processes[s].channel, cycle->log);
            return RP_INVALID_PID;
        }

        rp_channel = rp_processes[s].channel[1];

    } else {
        rp_processes[s].channel[0] = -1;
        rp_processes[s].channel[1] = -1;
    }

    rp_process_slot = s;


    pid = fork();

    switch (pid) {

    case -1:
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "fork() failed while spawning \"%s\"", name);
        rp_close_channel(rp_processes[s].channel, cycle->log);
        return RP_INVALID_PID;

    case 0:
        rp_parent = rp_pid;
        rp_pid = rp_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    rp_processes[s].pid = pid;
    rp_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    rp_processes[s].proc = proc;
    rp_processes[s].data = data;
    rp_processes[s].name = name;
    rp_processes[s].exiting = 0;

    switch (respawn) {

    case RP_PROCESS_NORESPAWN:
        rp_processes[s].respawn = 0;
        rp_processes[s].just_spawn = 0;
        rp_processes[s].detached = 0;
        break;

    case RP_PROCESS_JUST_SPAWN:
        rp_processes[s].respawn = 0;
        rp_processes[s].just_spawn = 1;
        rp_processes[s].detached = 0;
        break;

    case RP_PROCESS_RESPAWN:
        rp_processes[s].respawn = 1;
        rp_processes[s].just_spawn = 0;
        rp_processes[s].detached = 0;
        break;

    case RP_PROCESS_JUST_RESPAWN:
        rp_processes[s].respawn = 1;
        rp_processes[s].just_spawn = 1;
        rp_processes[s].detached = 0;
        break;

    case RP_PROCESS_DETACHED:
        rp_processes[s].respawn = 0;
        rp_processes[s].just_spawn = 0;
        rp_processes[s].detached = 1;
        break;
    }

    if (s == rp_last_process) {
        rp_last_process++;
    }

    return pid;
}


rp_pid_t
rp_execute(rp_cycle_t *cycle, rp_exec_ctx_t *ctx)
{
    return rp_spawn_process(cycle, rp_execute_proc, ctx, ctx->name,
                             RP_PROCESS_DETACHED);
}


static void
rp_execute_proc(rp_cycle_t *cycle, void *data)
{
    rp_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


rp_int_t
rp_init_signals(rp_log_t *log)
{
    rp_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        rp_memzero(&sa, sizeof(struct sigaction));

        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;

        } else {
            sa.sa_handler = SIG_IGN;
        }

        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (RP_VALGRIND)
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            rp_log_error(RP_LOG_EMERG, log, rp_errno,
                          "sigaction(%s) failed", sig->signame);
            return RP_ERROR;
#endif
        }
    }

    return RP_OK;
}


static void
rp_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    char            *action;
    rp_int_t        ignore;
    rp_err_t        err;
    rp_signal_t    *sig;

    ignore = 0;

    err = rp_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    rp_time_sigsafe_update();

    action = "";

    switch (rp_process) {

    case RP_PROCESS_MASTER:
    case RP_PROCESS_SINGLE:
        switch (signo) {

        case rp_signal_value(RP_SHUTDOWN_SIGNAL):
            rp_quit = 1;
            action = ", shutting down";
            break;

        case rp_signal_value(RP_TERMINATE_SIGNAL):
        case SIGINT:
            rp_terminate = 1;
            action = ", exiting";
            break;

        case rp_signal_value(RP_NOACCEPT_SIGNAL):
            if (rp_daemonized) {
                rp_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case rp_signal_value(RP_RECONFIGURE_SIGNAL):
            rp_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case rp_signal_value(RP_REOPEN_SIGNAL):
            rp_reopen = 1;
            action = ", reopening logs";
            break;

        case rp_signal_value(RP_CHANGEBIN_SIGNAL):
            if (rp_getppid() == rp_parent || rp_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not changed, i.e. the old binary's process is still
                 * running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            rp_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            rp_sigalrm = 1;
            break;

        case SIGIO:
            rp_sigio = 1;
            break;

        case SIGCHLD:
            rp_reap = 1;
            break;
        }

        break;

    case RP_PROCESS_WORKER:
    case RP_PROCESS_HELPER:
        switch (signo) {

        case rp_signal_value(RP_NOACCEPT_SIGNAL):
            if (!rp_daemonized) {
                break;
            }
            rp_debug_quit = 1;
            /* fall through */
        case rp_signal_value(RP_SHUTDOWN_SIGNAL):
            rp_quit = 1;
            action = ", shutting down";
            break;

        case rp_signal_value(RP_TERMINATE_SIGNAL):
        case SIGINT:
            rp_terminate = 1;
            action = ", exiting";
            break;

        case rp_signal_value(RP_REOPEN_SIGNAL):
            rp_reopen = 1;
            action = ", reopening logs";
            break;

        case rp_signal_value(RP_RECONFIGURE_SIGNAL):
        case rp_signal_value(RP_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    if (siginfo && siginfo->si_pid) {
        rp_log_error(RP_LOG_NOTICE, rp_cycle->log, 0,
                      "signal %d (%s) received from %P%s",
                      signo, sig->signame, siginfo->si_pid, action);

    } else {
        rp_log_error(RP_LOG_NOTICE, rp_cycle->log, 0,
                      "signal %d (%s) received%s",
                      signo, sig->signame, action);
    }

    if (ignore) {
        rp_log_error(RP_LOG_CRIT, rp_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        rp_process_get_status();
    }

    rp_set_errno(err);
}


static void
rp_process_get_status(void)
{
    int              status;
    char            *process;
    rp_pid_t        pid;
    rp_err_t        err;
    rp_int_t        i;
    rp_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = rp_errno;

            if (err == RP_EINTR) {
                continue;
            }

            if (err == RP_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == RP_ECHILD) {
                rp_log_error(RP_LOG_INFO, rp_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            rp_log_error(RP_LOG_ALERT, rp_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < rp_last_process; i++) {
            if (rp_processes[i].pid == pid) {
                rp_processes[i].status = status;
                rp_processes[i].exited = 1;
                process = rp_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            rp_log_error(RP_LOG_NOTICE, rp_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && rp_processes[i].respawn) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            rp_processes[i].respawn = 0;
        }

        rp_unlock_mutexes(pid);
    }
}


static void
rp_unlock_mutexes(rp_pid_t pid)
{
    rp_uint_t        i;
    rp_shm_zone_t   *shm_zone;
    rp_list_part_t  *part;
    rp_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (rp_accept_mutex_ptr) {
        (void) rp_shmtx_force_unlock(&rp_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (rp_list_part_t *) &rp_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (rp_slab_pool_t *) shm_zone[i].shm.addr;

        if (rp_shmtx_force_unlock(&sp->mutex, pid)) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
rp_debug_point(void)
{
    rp_core_conf_t  *ccf;

    ccf = (rp_core_conf_t *) rp_get_conf(rp_cycle->conf_ctx,
                                           rp_core_module);

    switch (ccf->debug_points) {

    case RP_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case RP_DEBUG_POINTS_ABORT:
        rp_abort();
    }
}


rp_int_t
rp_os_signal_process(rp_cycle_t *cycle, char *name, rp_pid_t pid)
{
    rp_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (rp_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
