
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define DEFAULT_CONNECTIONS  512


extern rp_module_t rp_kqueue_module;
extern rp_module_t rp_eventport_module;
extern rp_module_t rp_devpoll_module;
extern rp_module_t rp_epoll_module;
extern rp_module_t rp_select_module;


static char *rp_event_init_conf(rp_cycle_t *cycle, void *conf);
static rp_int_t rp_event_module_init(rp_cycle_t *cycle);
static rp_int_t rp_event_process_init(rp_cycle_t *cycle);
static char *rp_events_block(rp_conf_t *cf, rp_command_t *cmd, void *conf);

static char *rp_event_connections(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_event_use(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_event_debug_connection(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

static void *rp_event_core_create_conf(rp_cycle_t *cycle);
static char *rp_event_core_init_conf(rp_cycle_t *cycle, void *conf);


static rp_uint_t     rp_timer_resolution;
sig_atomic_t          rp_event_timer_alarm;

static rp_uint_t     rp_event_max_module;

rp_uint_t            rp_event_flags;
rp_event_actions_t   rp_event_actions;


static rp_atomic_t   connection_counter = 1;
rp_atomic_t         *rp_connection_counter = &connection_counter;


rp_atomic_t         *rp_accept_mutex_ptr;
rp_shmtx_t           rp_accept_mutex;
rp_uint_t            rp_use_accept_mutex;
rp_uint_t            rp_accept_events;
rp_uint_t            rp_accept_mutex_held;
rp_msec_t            rp_accept_mutex_delay;
rp_int_t             rp_accept_disabled;


#if (RP_STAT_STUB)

static rp_atomic_t   rp_stat_accepted0;
rp_atomic_t         *rp_stat_accepted = &rp_stat_accepted0;
static rp_atomic_t   rp_stat_handled0;
rp_atomic_t         *rp_stat_handled = &rp_stat_handled0;
static rp_atomic_t   rp_stat_requests0;
rp_atomic_t         *rp_stat_requests = &rp_stat_requests0;
static rp_atomic_t   rp_stat_active0;
rp_atomic_t         *rp_stat_active = &rp_stat_active0;
static rp_atomic_t   rp_stat_reading0;
rp_atomic_t         *rp_stat_reading = &rp_stat_reading0;
static rp_atomic_t   rp_stat_writing0;
rp_atomic_t         *rp_stat_writing = &rp_stat_writing0;
static rp_atomic_t   rp_stat_waiting0;
rp_atomic_t         *rp_stat_waiting = &rp_stat_waiting0;

#endif



static rp_command_t  rp_events_commands[] = {

    { rp_string("events"),
      RP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_events_block,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_events_module_ctx = {
    rp_string("events"),
    NULL,
    rp_event_init_conf
};


rp_module_t  rp_events_module = {
    RP_MODULE_V1,
    &rp_events_module_ctx,                /* module context */
    rp_events_commands,                   /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t  event_core_name = rp_string("event_core");


static rp_command_t  rp_event_core_commands[] = {

    { rp_string("worker_connections"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_event_connections,
      0,
      0,
      NULL },

    { rp_string("use"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_event_use,
      0,
      0,
      NULL },

    { rp_string("multi_accept"),
      RP_EVENT_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      0,
      offsetof(rp_event_conf_t, multi_accept),
      NULL },

    { rp_string("accept_mutex"),
      RP_EVENT_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      0,
      offsetof(rp_event_conf_t, accept_mutex),
      NULL },

    { rp_string("accept_mutex_delay"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      0,
      offsetof(rp_event_conf_t, accept_mutex_delay),
      NULL },

    { rp_string("debug_connection"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_event_debug_connection,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_event_module_t  rp_event_core_module_ctx = {
    &event_core_name,
    rp_event_core_create_conf,            /* create configuration */
    rp_event_core_init_conf,              /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


rp_module_t  rp_event_core_module = {
    RP_MODULE_V1,
    &rp_event_core_module_ctx,            /* module context */
    rp_event_core_commands,               /* module directives */
    RP_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    rp_event_module_init,                 /* init module */
    rp_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


void
rp_process_events_and_timers(rp_cycle_t *cycle)
{
    rp_uint_t  flags;
    rp_msec_t  timer, delta;

    if (rp_timer_resolution) {
        timer = RP_TIMER_INFINITE;
        flags = 0;

    } else {
        timer = rp_event_find_timer();
        flags = RP_UPDATE_TIME;

#if (RP_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == RP_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

    if (rp_use_accept_mutex) {
        if (rp_accept_disabled > 0) {
            rp_accept_disabled--;

        } else {
            if (rp_trylock_accept_mutex(cycle) == RP_ERROR) {
                return;
            }

            if (rp_accept_mutex_held) {
                flags |= RP_POST_EVENTS;

            } else {
                if (timer == RP_TIMER_INFINITE
                    || timer > rp_accept_mutex_delay)
                {
                    timer = rp_accept_mutex_delay;
                }
            }
        }
    }

    if (!rp_queue_empty(&rp_posted_next_events)) {
        rp_event_move_posted_next(cycle);
        timer = 0;
    }

    delta = rp_current_msec;

    (void) rp_process_events(cycle, timer, flags);

    delta = rp_current_msec - delta;

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);

    rp_event_process_posted(cycle, &rp_posted_accept_events);

    if (rp_accept_mutex_held) {
        rp_shmtx_unlock(&rp_accept_mutex);
    }

    if (delta) {
        rp_event_expire_timers();
    }

    rp_event_process_posted(cycle, &rp_posted_events);
}


rp_int_t
rp_handle_read_event(rp_event_t *rev, rp_uint_t flags)
{
    if (rp_event_flags & RP_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (rp_add_event(rev, RP_READ_EVENT, RP_CLEAR_EVENT)
                == RP_ERROR)
            {
                return RP_ERROR;
            }
        }

        return RP_OK;

    } else if (rp_event_flags & RP_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (rp_add_event(rev, RP_READ_EVENT, RP_LEVEL_EVENT)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

            return RP_OK;
        }

        if (rev->active && (rev->ready || (flags & RP_CLOSE_EVENT))) {
            if (rp_del_event(rev, RP_READ_EVENT, RP_LEVEL_EVENT | flags)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

            return RP_OK;
        }

    } else if (rp_event_flags & RP_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (rp_add_event(rev, RP_READ_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }

            return RP_OK;
        }

        if (rev->oneshot && !rev->ready) {
            if (rp_del_event(rev, RP_READ_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }

            return RP_OK;
        }
    }

    /* iocp */

    return RP_OK;
}


rp_int_t
rp_handle_write_event(rp_event_t *wev, size_t lowat)
{
    rp_connection_t  *c;

    if (lowat) {
        c = wev->data;

        if (rp_send_lowat(c, lowat) == RP_ERROR) {
            return RP_ERROR;
        }
    }

    if (rp_event_flags & RP_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (rp_add_event(wev, RP_WRITE_EVENT,
                              RP_CLEAR_EVENT | (lowat ? RP_LOWAT_EVENT : 0))
                == RP_ERROR)
            {
                return RP_ERROR;
            }
        }

        return RP_OK;

    } else if (rp_event_flags & RP_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (rp_add_event(wev, RP_WRITE_EVENT, RP_LEVEL_EVENT)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

            return RP_OK;
        }

        if (wev->active && wev->ready) {
            if (rp_del_event(wev, RP_WRITE_EVENT, RP_LEVEL_EVENT)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

            return RP_OK;
        }

    } else if (rp_event_flags & RP_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (rp_add_event(wev, RP_WRITE_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }

            return RP_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (rp_del_event(wev, RP_WRITE_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }

            return RP_OK;
        }
    }

    /* iocp */

    return RP_OK;
}


static char *
rp_event_init_conf(rp_cycle_t *cycle, void *conf)
{
#if (RP_HAVE_REUSEPORT)
    rp_uint_t        i;
    rp_listening_t  *ls;
#endif

    if (rp_get_conf(cycle->conf_ctx, rp_events_module) == NULL) {
        rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return RP_CONF_ERROR;
    }

    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return RP_CONF_ERROR;
    }

#if (RP_HAVE_REUSEPORT)

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        if (!ls[i].reuseport || ls[i].worker != 0) {
            continue;
        }

        if (rp_clone_listening(cycle, &ls[i]) != RP_OK) {
            return RP_CONF_ERROR;
        }

        /* cloning may change cycle->listening.elts */

        ls = cycle->listening.elts;
    }

#endif

    return RP_CONF_OK;
}


static rp_int_t
rp_event_module_init(rp_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    rp_shm_t            shm;
    rp_time_t          *tp;
    rp_core_conf_t     *ccf;
    rp_event_conf_t    *ecf;

    cf = rp_get_conf(cycle->conf_ctx, rp_events_module);
    ecf = (*cf)[rp_event_core_module.ctx_index];

    if (!rp_test_config && rp_process <= RP_PROCESS_MASTER) {
        rp_log_error(RP_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    rp_timer_resolution = ccf->timer_resolution;

#if !(RP_WIN32)
    {
    rp_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        if (ecf->connections > (rp_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == RP_CONF_UNSET
                || ecf->connections > (rp_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == RP_CONF_UNSET) ?
                         (rp_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            rp_log_error(RP_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(RP_WIN32) */


    if (ccf->master == 0) {
        return RP_OK;
    }

    if (rp_accept_mutex_ptr) {
        return RP_OK;
    }


    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* rp_accept_mutex */
           + cl          /* rp_connection_counter */
           + cl;         /* rp_temp_number */

#if (RP_STAT_STUB)

    size += cl           /* rp_stat_accepted */
           + cl          /* rp_stat_handled */
           + cl          /* rp_stat_requests */
           + cl          /* rp_stat_active */
           + cl          /* rp_stat_reading */
           + cl          /* rp_stat_writing */
           + cl;         /* rp_stat_waiting */

#endif

    shm.size = size;
    rp_str_set(&shm.name, "rap_shared_zone");
    shm.log = cycle->log;

    if (rp_shm_alloc(&shm) != RP_OK) {
        return RP_ERROR;
    }

    shared = shm.addr;

    rp_accept_mutex_ptr = (rp_atomic_t *) shared;
    rp_accept_mutex.spin = (rp_uint_t) -1;

    if (rp_shmtx_create(&rp_accept_mutex, (rp_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != RP_OK)
    {
        return RP_ERROR;
    }

    rp_connection_counter = (rp_atomic_t *) (shared + 1 * cl);

    (void) rp_atomic_cmp_set(rp_connection_counter, 0, 1);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   rp_connection_counter, *rp_connection_counter);

    rp_temp_number = (rp_atomic_t *) (shared + 2 * cl);

    tp = rp_timeofday();

    rp_random_number = (tp->msec << 16) + rp_pid;

#if (RP_STAT_STUB)

    rp_stat_accepted = (rp_atomic_t *) (shared + 3 * cl);
    rp_stat_handled = (rp_atomic_t *) (shared + 4 * cl);
    rp_stat_requests = (rp_atomic_t *) (shared + 5 * cl);
    rp_stat_active = (rp_atomic_t *) (shared + 6 * cl);
    rp_stat_reading = (rp_atomic_t *) (shared + 7 * cl);
    rp_stat_writing = (rp_atomic_t *) (shared + 8 * cl);
    rp_stat_waiting = (rp_atomic_t *) (shared + 9 * cl);

#endif

    return RP_OK;
}


#if !(RP_WIN32)

static void
rp_timer_signal_handler(int signo)
{
    rp_event_timer_alarm = 1;

#if 1
    rp_log_debug0(RP_LOG_DEBUG_EVENT, rp_cycle->log, 0, "timer signal");
#endif
}

#endif


static rp_int_t
rp_event_process_init(rp_cycle_t *cycle)
{
    rp_uint_t           m, i;
    rp_event_t         *rev, *wev;
    rp_listening_t     *ls;
    rp_connection_t    *c, *next, *old;
    rp_core_conf_t     *ccf;
    rp_event_conf_t    *ecf;
    rp_event_module_t  *module;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);
    ecf = rp_event_get_conf(cycle->conf_ctx, rp_event_core_module);

    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        rp_use_accept_mutex = 1;
        rp_accept_mutex_held = 0;
        rp_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        rp_use_accept_mutex = 0;
    }

#if (RP_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    rp_use_accept_mutex = 0;

#endif

    rp_queue_init(&rp_posted_accept_events);
    rp_queue_init(&rp_posted_next_events);
    rp_queue_init(&rp_posted_events);

    if (rp_event_timer_init(cycle->log) == RP_ERROR) {
        return RP_ERROR;
    }

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != RP_EVENT_MODULE) {
            continue;
        }

        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        if (module->actions.init(cycle, rp_timer_resolution) != RP_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(RP_WIN32)

    if (rp_timer_resolution && !(rp_event_flags & RP_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        rp_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = rp_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "sigaction(SIGALRM) failed");
            return RP_ERROR;
        }

        itv.it_interval.tv_sec = rp_timer_resolution / 1000;
        itv.it_interval.tv_usec = (rp_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = rp_timer_resolution / 1000;
        itv.it_value.tv_usec = (rp_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "setitimer() failed");
        }
    }

    if (rp_event_flags & RP_USE_FD_EVENT) {
        struct rlimit  rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return RP_ERROR;
        }

        cycle->files_n = (rp_uint_t) rlmt.rlim_cur;

        cycle->files = rp_calloc(sizeof(rp_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return RP_ERROR;
        }
    }

#else

    if (rp_timer_resolution && !(rp_event_flags & RP_USE_TIMER_EVENT)) {
        rp_log_error(RP_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        rp_timer_resolution = 0;
    }

#endif

    cycle->connections =
        rp_alloc(sizeof(rp_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return RP_ERROR;
    }

    c = cycle->connections;

    cycle->read_events = rp_alloc(sizeof(rp_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return RP_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }

    cycle->write_events = rp_alloc(sizeof(rp_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return RP_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
    }

    i = cycle->connection_n;
    next = NULL;

    do {
        i--;

        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (rp_socket_t) -1;

        next = &c[i];
    } while (i);

    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (RP_HAVE_REUSEPORT)
        if (ls[i].reuseport && ls[i].worker != rp_worker) {
            continue;
        }
#endif

        c = rp_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return RP_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;

        c->listening = &ls[i];
        ls[i].connection = c;

        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;

#if (RP_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(rp_event_flags & RP_USE_IOCP_EVENT)) {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (rp_del_event(old->read, RP_READ_EVENT, RP_CLOSE_EVENT)
                    == RP_ERROR)
                {
                    return RP_ERROR;
                }

                old->fd = (rp_socket_t) -1;
            }
        }

#if (RP_WIN32)

        if (rp_event_flags & RP_USE_IOCP_EVENT) {
            rp_iocp_conf_t  *iocpcf;

            rev->handler = rp_event_acceptex;

            if (rp_use_accept_mutex) {
                continue;
            }

            if (rp_add_event(rev, 0, RP_IOCP_ACCEPT) == RP_ERROR) {
                return RP_ERROR;
            }

            ls[i].log.handler = rp_acceptex_log_error;

            iocpcf = rp_event_get_conf(cycle->conf_ctx, rp_iocp_module);
            if (rp_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

        } else {
            rev->handler = rp_event_accept;

            if (rp_use_accept_mutex) {
                continue;
            }

            if (rp_add_event(rev, RP_READ_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }
        }

#else

        rev->handler = (c->type == SOCK_STREAM) ? rp_event_accept
                                                : rp_event_recvmsg;

#if (RP_HAVE_REUSEPORT)

        if (ls[i].reuseport) {
            if (rp_add_event(rev, RP_READ_EVENT, 0) == RP_ERROR) {
                return RP_ERROR;
            }

            continue;
        }

#endif

        if (rp_use_accept_mutex) {
            continue;
        }

#if (RP_HAVE_EPOLLEXCLUSIVE)

        if ((rp_event_flags & RP_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            if (rp_add_event(rev, RP_READ_EVENT, RP_EXCLUSIVE_EVENT)
                == RP_ERROR)
            {
                return RP_ERROR;
            }

            continue;
        }

#endif

        if (rp_add_event(rev, RP_READ_EVENT, 0) == RP_ERROR) {
            return RP_ERROR;
        }

#endif

    }

    return RP_OK;
}


rp_int_t
rp_send_lowat(rp_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (RP_HAVE_LOWAT_EVENT)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return RP_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {
        return RP_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        rp_connection_error(c, rp_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return RP_ERROR;
    }

    c->sndlowat = 1;

    return RP_OK;
}


static char *
rp_events_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    rp_uint_t            i;
    rp_conf_t            pcf;
    rp_event_module_t   *m;

    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    rp_event_max_module = rp_count_modules(cf->cycle, RP_EVENT_MODULE);

    ctx = rp_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    *ctx = rp_pcalloc(cf->pool, rp_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return RP_CONF_ERROR;
    }

    *(void **) conf = ctx;

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                                                     m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return RP_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = RP_EVENT_MODULE;
    cf->cmd_type = RP_EVENT_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RP_CONF_OK) {
        return rv;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != RP_CONF_OK) {
                return rv;
            }
        }
    }

    return RP_CONF_OK;
}


static char *
rp_event_connections(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_event_conf_t  *ecf = conf;

    rp_str_t  *value;

    if (ecf->connections != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ecf->connections = rp_atoi(value[1].data, value[1].len);
    if (ecf->connections == (rp_uint_t) RP_ERROR) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return RP_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return RP_CONF_OK;
}


static char *
rp_event_use(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_event_conf_t  *ecf = conf;

    rp_int_t             m;
    rp_str_t            *value;
    rp_event_conf_t     *old_ecf;
    rp_event_module_t   *module;

    if (ecf->use != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = rp_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     rp_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_EVENT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (rp_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = cf->cycle->modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (rp_process == RP_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return RP_CONF_ERROR;
                }

                return RP_CONF_OK;
            }
        }
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return RP_CONF_ERROR;
}


static char *
rp_event_debug_connection(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
#if (RP_DEBUG)
    rp_event_conf_t  *ecf = conf;

    rp_int_t             rc;
    rp_str_t            *value;
    rp_url_t             u;
    rp_cidr_t            c, *cidr;
    rp_uint_t            i;
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (RP_HAVE_UNIX_DOMAIN)

    if (rp_strcmp(value[1].data, "unix:") == 0) {
        cidr = rp_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return RP_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return RP_CONF_OK;
    }

#endif

    rc = rp_ptocidr(&value[1], &c);

    if (rc != RP_ERROR) {
        if (rc == RP_DONE) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = rp_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return RP_CONF_ERROR;
        }

        *cidr = c;

        return RP_CONF_OK;
    }

    rp_memzero(&u, sizeof(rp_url_t));
    u.host = value[1];

    if (rp_inet_resolve_host(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return RP_CONF_ERROR;
    }

    cidr = rp_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(cidr, u.naddrs * sizeof(rp_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            rp_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "rap using --with-debug option to enable it");

#endif

    return RP_CONF_OK;
}


static void *
rp_event_core_create_conf(rp_cycle_t *cycle)
{
    rp_event_conf_t  *ecf;

    ecf = rp_palloc(cycle->pool, sizeof(rp_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = RP_CONF_UNSET_UINT;
    ecf->use = RP_CONF_UNSET_UINT;
    ecf->multi_accept = RP_CONF_UNSET;
    ecf->accept_mutex = RP_CONF_UNSET;
    ecf->accept_mutex_delay = RP_CONF_UNSET_MSEC;
    ecf->name = (void *) RP_CONF_UNSET;

#if (RP_DEBUG)

    if (rp_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(rp_cidr_t)) == RP_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
rp_event_core_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_event_conf_t  *ecf = conf;

#if (RP_HAVE_EPOLL) && !(RP_TEST_BUILD_EPOLL)
    int                  fd;
#endif
    rp_int_t            i;
    rp_module_t        *module;
    rp_event_module_t  *event_module;

    module = NULL;

#if (RP_HAVE_EPOLL) && !(RP_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &rp_epoll_module;

    } else if (rp_errno != RP_ENOSYS) {
        module = &rp_epoll_module;
    }

#endif

#if (RP_HAVE_DEVPOLL) && !(RP_TEST_BUILD_DEVPOLL)

    module = &rp_devpoll_module;

#endif

#if (RP_HAVE_KQUEUE)

    module = &rp_kqueue_module;

#endif

#if (RP_HAVE_SELECT)

    if (module == NULL) {
        module = &rp_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != RP_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            if (rp_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = cycle->modules[i];
            break;
        }
    }

    if (module == NULL) {
        rp_log_error(RP_LOG_EMERG, cycle->log, 0, "no events module found");
        return RP_CONF_ERROR;
    }

    rp_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;

    rp_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    rp_conf_init_ptr_value(ecf->name, event_module->name->data);

    rp_conf_init_value(ecf->multi_accept, 0);
    rp_conf_init_value(ecf->accept_mutex, 0);
    rp_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return RP_CONF_OK;
}
