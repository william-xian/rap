
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_channel.h>


typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} rap_signal_t;



static void rap_execute_proc(rap_cycle_t *cycle, void *data);
static void rap_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
static void rap_process_get_status(void);
static void rap_unlock_mutexes(rap_pid_t pid);


int              rap_argc;
char           **rap_argv;
char           **rap_os_argv;

rap_int_t        rap_process_slot;
rap_socket_t     rap_channel;
rap_int_t        rap_last_process;
rap_process_t    rap_processes[RAP_MAX_PROCESSES];


rap_signal_t  signals[] = {
    { rap_signal_value(RAP_RECONFIGURE_SIGNAL),
      "SIG" rap_value(RAP_RECONFIGURE_SIGNAL),
      "reload",
      rap_signal_handler },

    { rap_signal_value(RAP_REOPEN_SIGNAL),
      "SIG" rap_value(RAP_REOPEN_SIGNAL),
      "reopen",
      rap_signal_handler },

    { rap_signal_value(RAP_NOACCEPT_SIGNAL),
      "SIG" rap_value(RAP_NOACCEPT_SIGNAL),
      "",
      rap_signal_handler },

    { rap_signal_value(RAP_TERMINATE_SIGNAL),
      "SIG" rap_value(RAP_TERMINATE_SIGNAL),
      "stop",
      rap_signal_handler },

    { rap_signal_value(RAP_SHUTDOWN_SIGNAL),
      "SIG" rap_value(RAP_SHUTDOWN_SIGNAL),
      "quit",
      rap_signal_handler },

    { rap_signal_value(RAP_CHANGEBIN_SIGNAL),
      "SIG" rap_value(RAP_CHANGEBIN_SIGNAL),
      "",
      rap_signal_handler },

    { SIGALRM, "SIGALRM", "", rap_signal_handler },

    { SIGINT, "SIGINT", "", rap_signal_handler },

    { SIGIO, "SIGIO", "", rap_signal_handler },

    { SIGCHLD, "SIGCHLD", "", rap_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

    { 0, NULL, "", NULL }
};


rap_pid_t
rap_spawn_process(rap_cycle_t *cycle, rap_spawn_proc_pt proc, void *data,
    char *name, rap_int_t respawn)
{
    u_long     on;
    rap_pid_t  pid;
    rap_int_t  s;

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < rap_last_process; s++) {
            if (rap_processes[s].pid == -1) {
                break;
            }
        }

        if (s == RAP_MAX_PROCESSES) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          RAP_MAX_PROCESSES);
            return RAP_INVALID_PID;
        }
    }


    if (respawn != RAP_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, rap_processes[s].channel) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return RAP_INVALID_PID;
        }

        rap_log_debug2(RAP_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       rap_processes[s].channel[0],
                       rap_processes[s].channel[1]);

        if (rap_nonblocking(rap_processes[s].channel[0]) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          rap_nonblocking_n " failed while spawning \"%s\"",
                          name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        if (rap_nonblocking(rap_processes[s].channel[1]) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          rap_nonblocking_n " failed while spawning \"%s\"",
                          name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        on = 1;
        if (ioctl(rap_processes[s].channel[0], FIOASYNC, &on) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        if (fcntl(rap_processes[s].channel[0], F_SETOWN, rap_pid) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        if (fcntl(rap_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        if (fcntl(rap_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            rap_close_channel(rap_processes[s].channel, cycle->log);
            return RAP_INVALID_PID;
        }

        rap_channel = rap_processes[s].channel[1];

    } else {
        rap_processes[s].channel[0] = -1;
        rap_processes[s].channel[1] = -1;
    }

    rap_process_slot = s;


    pid = fork();

    switch (pid) {

    case -1:
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "fork() failed while spawning \"%s\"", name);
        rap_close_channel(rap_processes[s].channel, cycle->log);
        return RAP_INVALID_PID;

    case 0:
        rap_parent = rap_pid;
        rap_pid = rap_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    rap_processes[s].pid = pid;
    rap_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    rap_processes[s].proc = proc;
    rap_processes[s].data = data;
    rap_processes[s].name = name;
    rap_processes[s].exiting = 0;

    switch (respawn) {

    case RAP_PROCESS_NORESPAWN:
        rap_processes[s].respawn = 0;
        rap_processes[s].just_spawn = 0;
        rap_processes[s].detached = 0;
        break;

    case RAP_PROCESS_JUST_SPAWN:
        rap_processes[s].respawn = 0;
        rap_processes[s].just_spawn = 1;
        rap_processes[s].detached = 0;
        break;

    case RAP_PROCESS_RESPAWN:
        rap_processes[s].respawn = 1;
        rap_processes[s].just_spawn = 0;
        rap_processes[s].detached = 0;
        break;

    case RAP_PROCESS_JUST_RESPAWN:
        rap_processes[s].respawn = 1;
        rap_processes[s].just_spawn = 1;
        rap_processes[s].detached = 0;
        break;

    case RAP_PROCESS_DETACHED:
        rap_processes[s].respawn = 0;
        rap_processes[s].just_spawn = 0;
        rap_processes[s].detached = 1;
        break;
    }

    if (s == rap_last_process) {
        rap_last_process++;
    }

    return pid;
}


rap_pid_t
rap_execute(rap_cycle_t *cycle, rap_exec_ctx_t *ctx)
{
    return rap_spawn_process(cycle, rap_execute_proc, ctx, ctx->name,
                             RAP_PROCESS_DETACHED);
}


static void
rap_execute_proc(rap_cycle_t *cycle, void *data)
{
    rap_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


rap_int_t
rap_init_signals(rap_log_t *log)
{
    rap_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        rap_memzero(&sa, sizeof(struct sigaction));

        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;

        } else {
            sa.sa_handler = SIG_IGN;
        }

        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (RAP_VALGRIND)
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                          "sigaction(%s) failed", sig->signame);
            return RAP_ERROR;
#endif
        }
    }

    return RAP_OK;
}


static void
rap_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    char            *action;
    rap_int_t        ignore;
    rap_err_t        err;
    rap_signal_t    *sig;

    ignore = 0;

    err = rap_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    rap_time_sigsafe_update();

    action = "";

    switch (rap_process) {

    case RAP_PROCESS_MASTER:
    case RAP_PROCESS_SINGLE:
        switch (signo) {

        case rap_signal_value(RAP_SHUTDOWN_SIGNAL):
            rap_quit = 1;
            action = ", shutting down";
            break;

        case rap_signal_value(RAP_TERMINATE_SIGNAL):
        case SIGINT:
            rap_terminate = 1;
            action = ", exiting";
            break;

        case rap_signal_value(RAP_NOACCEPT_SIGNAL):
            if (rap_daemonized) {
                rap_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case rap_signal_value(RAP_RECONFIGURE_SIGNAL):
            rap_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case rap_signal_value(RAP_REOPEN_SIGNAL):
            rap_reopen = 1;
            action = ", reopening logs";
            break;

        case rap_signal_value(RAP_CHANGEBIN_SIGNAL):
            if (rap_getppid() == rap_parent || rap_new_binary > 0) {

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

            rap_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            rap_sigalrm = 1;
            break;

        case SIGIO:
            rap_sigio = 1;
            break;

        case SIGCHLD:
            rap_reap = 1;
            break;
        }

        break;

    case RAP_PROCESS_WORKER:
    case RAP_PROCESS_HELPER:
        switch (signo) {

        case rap_signal_value(RAP_NOACCEPT_SIGNAL):
            if (!rap_daemonized) {
                break;
            }
            rap_debug_quit = 1;
            /* fall through */
        case rap_signal_value(RAP_SHUTDOWN_SIGNAL):
            rap_quit = 1;
            action = ", shutting down";
            break;

        case rap_signal_value(RAP_TERMINATE_SIGNAL):
        case SIGINT:
            rap_terminate = 1;
            action = ", exiting";
            break;

        case rap_signal_value(RAP_REOPEN_SIGNAL):
            rap_reopen = 1;
            action = ", reopening logs";
            break;

        case rap_signal_value(RAP_RECONFIGURE_SIGNAL):
        case rap_signal_value(RAP_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    if (siginfo && siginfo->si_pid) {
        rap_log_error(RAP_LOG_NOTICE, rap_cycle->log, 0,
                      "signal %d (%s) received from %P%s",
                      signo, sig->signame, siginfo->si_pid, action);

    } else {
        rap_log_error(RAP_LOG_NOTICE, rap_cycle->log, 0,
                      "signal %d (%s) received%s",
                      signo, sig->signame, action);
    }

    if (ignore) {
        rap_log_error(RAP_LOG_CRIT, rap_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        rap_process_get_status();
    }

    rap_set_errno(err);
}


static void
rap_process_get_status(void)
{
    int              status;
    char            *process;
    rap_pid_t        pid;
    rap_err_t        err;
    rap_int_t        i;
    rap_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = rap_errno;

            if (err == RAP_EINTR) {
                continue;
            }

            if (err == RAP_ECHILD && one) {
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

            if (err == RAP_ECHILD) {
                rap_log_error(RAP_LOG_INFO, rap_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < rap_last_process; i++) {
            if (rap_processes[i].pid == pid) {
                rap_processes[i].status = status;
                rap_processes[i].exited = 1;
                process = rap_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            rap_log_error(RAP_LOG_NOTICE, rap_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && rap_processes[i].respawn) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            rap_processes[i].respawn = 0;
        }

        rap_unlock_mutexes(pid);
    }
}


static void
rap_unlock_mutexes(rap_pid_t pid)
{
    rap_uint_t        i;
    rap_shm_zone_t   *shm_zone;
    rap_list_part_t  *part;
    rap_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (rap_accept_mutex_ptr) {
        (void) rap_shmtx_force_unlock(&rap_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (rap_list_part_t *) &rap_cycle->shared_memory.part;
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

        sp = (rap_slab_pool_t *) shm_zone[i].shm.addr;

        if (rap_shmtx_force_unlock(&sp->mutex, pid)) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
rap_debug_point(void)
{
    rap_core_conf_t  *ccf;

    ccf = (rap_core_conf_t *) rap_get_conf(rap_cycle->conf_ctx,
                                           rap_core_module);

    switch (ccf->debug_points) {

    case RAP_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case RAP_DEBUG_POINTS_ABORT:
        rap_abort();
    }
}


rap_int_t
rap_os_signal_process(rap_cycle_t *cycle, char *name, rap_pid_t pid)
{
    rap_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (rap_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
