
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define DEFAULT_CONNECTIONS  512


extern rap_module_t rap_kqueue_module;
extern rap_module_t rap_eventport_module;
extern rap_module_t rap_devpoll_module;
extern rap_module_t rap_epoll_module;
extern rap_module_t rap_select_module;


static char *rap_event_init_conf(rap_cycle_t *cycle, void *conf);
static rap_int_t rap_event_module_init(rap_cycle_t *cycle);
static rap_int_t rap_event_process_init(rap_cycle_t *cycle);
static char *rap_events_block(rap_conf_t *cf, rap_command_t *cmd, void *conf);

static char *rap_event_connections(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_event_use(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_event_debug_connection(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

static void *rap_event_core_create_conf(rap_cycle_t *cycle);
static char *rap_event_core_init_conf(rap_cycle_t *cycle, void *conf);


static rap_uint_t     rap_timer_resolution;
sig_atomic_t          rap_event_timer_alarm;

static rap_uint_t     rap_event_max_module;

rap_uint_t            rap_event_flags;
rap_event_actions_t   rap_event_actions;


static rap_atomic_t   connection_counter = 1;
rap_atomic_t         *rap_connection_counter = &connection_counter;


rap_atomic_t         *rap_accept_mutex_ptr;
rap_shmtx_t           rap_accept_mutex;
rap_uint_t            rap_use_accept_mutex;
rap_uint_t            rap_accept_events;
rap_uint_t            rap_accept_mutex_held;
rap_msec_t            rap_accept_mutex_delay;
rap_int_t             rap_accept_disabled;


#if (RAP_STAT_STUB)

static rap_atomic_t   rap_stat_accepted0;
rap_atomic_t         *rap_stat_accepted = &rap_stat_accepted0;
static rap_atomic_t   rap_stat_handled0;
rap_atomic_t         *rap_stat_handled = &rap_stat_handled0;
static rap_atomic_t   rap_stat_requests0;
rap_atomic_t         *rap_stat_requests = &rap_stat_requests0;
static rap_atomic_t   rap_stat_active0;
rap_atomic_t         *rap_stat_active = &rap_stat_active0;
static rap_atomic_t   rap_stat_reading0;
rap_atomic_t         *rap_stat_reading = &rap_stat_reading0;
static rap_atomic_t   rap_stat_writing0;
rap_atomic_t         *rap_stat_writing = &rap_stat_writing0;
static rap_atomic_t   rap_stat_waiting0;
rap_atomic_t         *rap_stat_waiting = &rap_stat_waiting0;

#endif



static rap_command_t  rap_events_commands[] = {

    { rap_string("events"),
      RAP_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_NOARGS,
      rap_events_block,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_events_module_ctx = {
    rap_string("events"),
    NULL,
    rap_event_init_conf
};


rap_module_t  rap_events_module = {
    RAP_MODULE_V1,
    &rap_events_module_ctx,                /* module context */
    rap_events_commands,                   /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_str_t  event_core_name = rap_string("event_core");


static rap_command_t  rap_event_core_commands[] = {

    { rap_string("worker_connections"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_event_connections,
      0,
      0,
      NULL },

    { rap_string("use"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_event_use,
      0,
      0,
      NULL },

    { rap_string("multi_accept"),
      RAP_EVENT_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      0,
      offsetof(rap_event_conf_t, multi_accept),
      NULL },

    { rap_string("accept_mutex"),
      RAP_EVENT_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      0,
      offsetof(rap_event_conf_t, accept_mutex),
      NULL },

    { rap_string("accept_mutex_delay"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      0,
      offsetof(rap_event_conf_t, accept_mutex_delay),
      NULL },

    { rap_string("debug_connection"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_event_debug_connection,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_event_module_t  rap_event_core_module_ctx = {
    &event_core_name,
    rap_event_core_create_conf,            /* create configuration */
    rap_event_core_init_conf,              /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


rap_module_t  rap_event_core_module = {
    RAP_MODULE_V1,
    &rap_event_core_module_ctx,            /* module context */
    rap_event_core_commands,               /* module directives */
    RAP_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    rap_event_module_init,                 /* init module */
    rap_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


void
rap_process_events_and_timers(rap_cycle_t *cycle)
{
    rap_uint_t  flags;
    rap_msec_t  timer, delta;

    if (rap_timer_resolution) {
        timer = RAP_TIMER_INFINITE;
        flags = 0;

    } else {
        timer = rap_event_find_timer();
        flags = RAP_UPDATE_TIME;

#if (RAP_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == RAP_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

    if (rap_use_accept_mutex) {
        if (rap_accept_disabled > 0) {
            rap_accept_disabled--;

        } else {
            if (rap_trylock_accept_mutex(cycle) == RAP_ERROR) {
                return;
            }

            if (rap_accept_mutex_held) {
                flags |= RAP_POST_EVENTS;

            } else {
                if (timer == RAP_TIMER_INFINITE
                    || timer > rap_accept_mutex_delay)
                {
                    timer = rap_accept_mutex_delay;
                }
            }
        }
    }

    if (!rap_queue_empty(&rap_posted_next_events)) {
        rap_event_move_posted_next(cycle);
        timer = 0;
    }

    delta = rap_current_msec;

    (void) rap_process_events(cycle, timer, flags);

    delta = rap_current_msec - delta;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);

    rap_event_process_posted(cycle, &rap_posted_accept_events);

    if (rap_accept_mutex_held) {
        rap_shmtx_unlock(&rap_accept_mutex);
    }

    if (delta) {
        rap_event_expire_timers();
    }

    rap_event_process_posted(cycle, &rap_posted_events);
}


rap_int_t
rap_handle_read_event(rap_event_t *rev, rap_uint_t flags)
{
    if (rap_event_flags & RAP_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (rap_add_event(rev, RAP_READ_EVENT, RAP_CLEAR_EVENT)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }
        }

        return RAP_OK;

    } else if (rap_event_flags & RAP_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (rap_add_event(rev, RAP_READ_EVENT, RAP_LEVEL_EVENT)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

        if (rev->active && (rev->ready || (flags & RAP_CLOSE_EVENT))) {
            if (rap_del_event(rev, RAP_READ_EVENT, RAP_LEVEL_EVENT | flags)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

    } else if (rap_event_flags & RAP_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (rap_add_event(rev, RAP_READ_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

        if (rev->oneshot && !rev->ready) {
            if (rap_del_event(rev, RAP_READ_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }

            return RAP_OK;
        }
    }

    /* iocp */

    return RAP_OK;
}


rap_int_t
rap_handle_write_event(rap_event_t *wev, size_t lowat)
{
    rap_connection_t  *c;

    if (lowat) {
        c = wev->data;

        if (rap_send_lowat(c, lowat) == RAP_ERROR) {
            return RAP_ERROR;
        }
    }

    if (rap_event_flags & RAP_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (rap_add_event(wev, RAP_WRITE_EVENT,
                              RAP_CLEAR_EVENT | (lowat ? RAP_LOWAT_EVENT : 0))
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }
        }

        return RAP_OK;

    } else if (rap_event_flags & RAP_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (rap_add_event(wev, RAP_WRITE_EVENT, RAP_LEVEL_EVENT)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

        if (wev->active && wev->ready) {
            if (rap_del_event(wev, RAP_WRITE_EVENT, RAP_LEVEL_EVENT)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

    } else if (rap_event_flags & RAP_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (rap_add_event(wev, RAP_WRITE_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (rap_del_event(wev, RAP_WRITE_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }

            return RAP_OK;
        }
    }

    /* iocp */

    return RAP_OK;
}


static char *
rap_event_init_conf(rap_cycle_t *cycle, void *conf)
{
#if (RAP_HAVE_REUSEPORT)
    rap_uint_t        i;
    rap_listening_t  *ls;
#endif

    if (rap_get_conf(cycle->conf_ctx, rap_events_module) == NULL) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return RAP_CONF_ERROR;
    }

    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return RAP_CONF_ERROR;
    }

#if (RAP_HAVE_REUSEPORT)

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        if (!ls[i].reuseport || ls[i].worker != 0) {
            continue;
        }

        if (rap_clone_listening(cycle, &ls[i]) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        /* cloning may change cycle->listening.elts */

        ls = cycle->listening.elts;
    }

#endif

    return RAP_CONF_OK;
}


static rap_int_t
rap_event_module_init(rap_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    rap_shm_t            shm;
    rap_time_t          *tp;
    rap_core_conf_t     *ccf;
    rap_event_conf_t    *ecf;

    cf = rap_get_conf(cycle->conf_ctx, rap_events_module);
    ecf = (*cf)[rap_event_core_module.ctx_index];

    if (!rap_test_config && rap_process <= RAP_PROCESS_MASTER) {
        rap_log_error(RAP_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    rap_timer_resolution = ccf->timer_resolution;

#if !(RAP_WIN32)
    {
    rap_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        if (ecf->connections > (rap_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == RAP_CONF_UNSET
                || ecf->connections > (rap_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == RAP_CONF_UNSET) ?
                         (rap_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            rap_log_error(RAP_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(RAP_WIN32) */


    if (ccf->master == 0) {
        return RAP_OK;
    }

    if (rap_accept_mutex_ptr) {
        return RAP_OK;
    }


    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* rap_accept_mutex */
           + cl          /* rap_connection_counter */
           + cl;         /* rap_temp_number */

#if (RAP_STAT_STUB)

    size += cl           /* rap_stat_accepted */
           + cl          /* rap_stat_handled */
           + cl          /* rap_stat_requests */
           + cl          /* rap_stat_active */
           + cl          /* rap_stat_reading */
           + cl          /* rap_stat_writing */
           + cl;         /* rap_stat_waiting */

#endif

    shm.size = size;
    rap_str_set(&shm.name, "rap_shared_zone");
    shm.log = cycle->log;

    if (rap_shm_alloc(&shm) != RAP_OK) {
        return RAP_ERROR;
    }

    shared = shm.addr;

    rap_accept_mutex_ptr = (rap_atomic_t *) shared;
    rap_accept_mutex.spin = (rap_uint_t) -1;

    if (rap_shmtx_create(&rap_accept_mutex, (rap_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    rap_connection_counter = (rap_atomic_t *) (shared + 1 * cl);

    (void) rap_atomic_cmp_set(rap_connection_counter, 0, 1);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   rap_connection_counter, *rap_connection_counter);

    rap_temp_number = (rap_atomic_t *) (shared + 2 * cl);

    tp = rap_timeofday();

    rap_random_number = (tp->msec << 16) + rap_pid;

#if (RAP_STAT_STUB)

    rap_stat_accepted = (rap_atomic_t *) (shared + 3 * cl);
    rap_stat_handled = (rap_atomic_t *) (shared + 4 * cl);
    rap_stat_requests = (rap_atomic_t *) (shared + 5 * cl);
    rap_stat_active = (rap_atomic_t *) (shared + 6 * cl);
    rap_stat_reading = (rap_atomic_t *) (shared + 7 * cl);
    rap_stat_writing = (rap_atomic_t *) (shared + 8 * cl);
    rap_stat_waiting = (rap_atomic_t *) (shared + 9 * cl);

#endif

    return RAP_OK;
}


#if !(RAP_WIN32)

static void
rap_timer_signal_handler(int signo)
{
    rap_event_timer_alarm = 1;

#if 1
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, rap_cycle->log, 0, "timer signal");
#endif
}

#endif


static rap_int_t
rap_event_process_init(rap_cycle_t *cycle)
{
    rap_uint_t           m, i;
    rap_event_t         *rev, *wev;
    rap_listening_t     *ls;
    rap_connection_t    *c, *next, *old;
    rap_core_conf_t     *ccf;
    rap_event_conf_t    *ecf;
    rap_event_module_t  *module;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);
    ecf = rap_event_get_conf(cycle->conf_ctx, rap_event_core_module);

    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        rap_use_accept_mutex = 1;
        rap_accept_mutex_held = 0;
        rap_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        rap_use_accept_mutex = 0;
    }

#if (RAP_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    rap_use_accept_mutex = 0;

#endif

    rap_queue_init(&rap_posted_accept_events);
    rap_queue_init(&rap_posted_next_events);
    rap_queue_init(&rap_posted_events);

    if (rap_event_timer_init(cycle->log) == RAP_ERROR) {
        return RAP_ERROR;
    }

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != RAP_EVENT_MODULE) {
            continue;
        }

        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        if (module->actions.init(cycle, rap_timer_resolution) != RAP_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(RAP_WIN32)

    if (rap_timer_resolution && !(rap_event_flags & RAP_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        rap_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = rap_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "sigaction(SIGALRM) failed");
            return RAP_ERROR;
        }

        itv.it_interval.tv_sec = rap_timer_resolution / 1000;
        itv.it_interval.tv_usec = (rap_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = rap_timer_resolution / 1000;
        itv.it_value.tv_usec = (rap_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "setitimer() failed");
        }
    }

    if (rap_event_flags & RAP_USE_FD_EVENT) {
        struct rlimit  rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return RAP_ERROR;
        }

        cycle->files_n = (rap_uint_t) rlmt.rlim_cur;

        cycle->files = rap_calloc(sizeof(rap_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return RAP_ERROR;
        }
    }

#else

    if (rap_timer_resolution && !(rap_event_flags & RAP_USE_TIMER_EVENT)) {
        rap_log_error(RAP_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        rap_timer_resolution = 0;
    }

#endif

    cycle->connections =
        rap_alloc(sizeof(rap_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return RAP_ERROR;
    }

    c = cycle->connections;

    cycle->read_events = rap_alloc(sizeof(rap_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return RAP_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }

    cycle->write_events = rap_alloc(sizeof(rap_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return RAP_ERROR;
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
        c[i].fd = (rap_socket_t) -1;

        next = &c[i];
    } while (i);

    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (RAP_HAVE_REUSEPORT)
        if (ls[i].reuseport && ls[i].worker != rap_worker) {
            continue;
        }
#endif

        c = rap_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return RAP_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;

        c->listening = &ls[i];
        ls[i].connection = c;

        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;

#if (RAP_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(rap_event_flags & RAP_USE_IOCP_EVENT)) {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (rap_del_event(old->read, RAP_READ_EVENT, RAP_CLOSE_EVENT)
                    == RAP_ERROR)
                {
                    return RAP_ERROR;
                }

                old->fd = (rap_socket_t) -1;
            }
        }

#if (RAP_WIN32)

        if (rap_event_flags & RAP_USE_IOCP_EVENT) {
            rap_iocp_conf_t  *iocpcf;

            rev->handler = rap_event_acceptex;

            if (rap_use_accept_mutex) {
                continue;
            }

            if (rap_add_event(rev, 0, RAP_IOCP_ACCEPT) == RAP_ERROR) {
                return RAP_ERROR;
            }

            ls[i].log.handler = rap_acceptex_log_error;

            iocpcf = rap_event_get_conf(cycle->conf_ctx, rap_iocp_module);
            if (rap_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

        } else {
            rev->handler = rap_event_accept;

            if (rap_use_accept_mutex) {
                continue;
            }

            if (rap_add_event(rev, RAP_READ_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }
        }

#else

        rev->handler = (c->type == SOCK_STREAM) ? rap_event_accept
                                                : rap_event_recvmsg;

#if (RAP_HAVE_REUSEPORT)

        if (ls[i].reuseport) {
            if (rap_add_event(rev, RAP_READ_EVENT, 0) == RAP_ERROR) {
                return RAP_ERROR;
            }

            continue;
        }

#endif

        if (rap_use_accept_mutex) {
            continue;
        }

#if (RAP_HAVE_EPOLLEXCLUSIVE)

        if ((rap_event_flags & RAP_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            if (rap_add_event(rev, RAP_READ_EVENT, RAP_EXCLUSIVE_EVENT)
                == RAP_ERROR)
            {
                return RAP_ERROR;
            }

            continue;
        }

#endif

        if (rap_add_event(rev, RAP_READ_EVENT, 0) == RAP_ERROR) {
            return RAP_ERROR;
        }

#endif

    }

    return RAP_OK;
}


rap_int_t
rap_send_lowat(rap_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (RAP_HAVE_LOWAT_EVENT)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return RAP_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {
        return RAP_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        rap_connection_error(c, rap_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return RAP_ERROR;
    }

    c->sndlowat = 1;

    return RAP_OK;
}


static char *
rap_events_block(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    rap_uint_t            i;
    rap_conf_t            pcf;
    rap_event_module_t   *m;

    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    rap_event_max_module = rap_count_modules(cf->cycle, RAP_EVENT_MODULE);

    ctx = rap_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    *ctx = rap_pcalloc(cf->pool, rap_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    *(void **) conf = ctx;

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                                                     m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return RAP_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = RAP_EVENT_MODULE;
    cf->cmd_type = RAP_EVENT_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != RAP_CONF_OK) {
                return rv;
            }
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_event_connections(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_event_conf_t  *ecf = conf;

    rap_str_t  *value;

    if (ecf->connections != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ecf->connections = rap_atoi(value[1].data, value[1].len);
    if (ecf->connections == (rap_uint_t) RAP_ERROR) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return RAP_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return RAP_CONF_OK;
}


static char *
rap_event_use(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_event_conf_t  *ecf = conf;

    rap_int_t             m;
    rap_str_t            *value;
    rap_event_conf_t     *old_ecf;
    rap_event_module_t   *module;

    if (ecf->use != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = rap_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     rap_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RAP_EVENT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (rap_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = cf->cycle->modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (rap_process == RAP_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return RAP_CONF_ERROR;
                }

                return RAP_CONF_OK;
            }
        }
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return RAP_CONF_ERROR;
}


static char *
rap_event_debug_connection(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#if (RAP_DEBUG)
    rap_event_conf_t  *ecf = conf;

    rap_int_t             rc;
    rap_str_t            *value;
    rap_url_t             u;
    rap_cidr_t            c, *cidr;
    rap_uint_t            i;
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (RAP_HAVE_UNIX_DOMAIN)

    if (rap_strcmp(value[1].data, "unix:") == 0) {
        cidr = rap_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return RAP_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return RAP_CONF_OK;
    }

#endif

    rc = rap_ptocidr(&value[1], &c);

    if (rc != RAP_ERROR) {
        if (rc == RAP_DONE) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = rap_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return RAP_CONF_ERROR;
        }

        *cidr = c;

        return RAP_CONF_OK;
    }

    rap_memzero(&u, sizeof(rap_url_t));
    u.host = value[1];

    if (rap_inet_resolve_host(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return RAP_CONF_ERROR;
    }

    cidr = rap_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(cidr, u.naddrs * sizeof(rap_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            rap_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
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

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "rap using --with-debug option to enable it");

#endif

    return RAP_CONF_OK;
}


static void *
rap_event_core_create_conf(rap_cycle_t *cycle)
{
    rap_event_conf_t  *ecf;

    ecf = rap_palloc(cycle->pool, sizeof(rap_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = RAP_CONF_UNSET_UINT;
    ecf->use = RAP_CONF_UNSET_UINT;
    ecf->multi_accept = RAP_CONF_UNSET;
    ecf->accept_mutex = RAP_CONF_UNSET;
    ecf->accept_mutex_delay = RAP_CONF_UNSET_MSEC;
    ecf->name = (void *) RAP_CONF_UNSET;

#if (RAP_DEBUG)

    if (rap_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(rap_cidr_t)) == RAP_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
rap_event_core_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_event_conf_t  *ecf = conf;

#if (RAP_HAVE_EPOLL) && !(RAP_TEST_BUILD_EPOLL)
    int                  fd;
#endif
    rap_int_t            i;
    rap_module_t        *module;
    rap_event_module_t  *event_module;

    module = NULL;

#if (RAP_HAVE_EPOLL) && !(RAP_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &rap_epoll_module;

    } else if (rap_errno != RAP_ENOSYS) {
        module = &rap_epoll_module;
    }

#endif

#if (RAP_HAVE_DEVPOLL) && !(RAP_TEST_BUILD_DEVPOLL)

    module = &rap_devpoll_module;

#endif

#if (RAP_HAVE_KQUEUE)

    module = &rap_kqueue_module;

#endif

#if (RAP_HAVE_SELECT)

    if (module == NULL) {
        module = &rap_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != RAP_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            if (rap_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = cycle->modules[i];
            break;
        }
    }

    if (module == NULL) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, 0, "no events module found");
        return RAP_CONF_ERROR;
    }

    rap_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;

    rap_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    rap_conf_init_ptr_value(ecf->name, event_module->name->data);

    rap_conf_init_value(ecf->multi_accept, 0);
    rap_conf_init_value(ecf->accept_mutex, 0);
    rap_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return RAP_CONF_OK;
}
