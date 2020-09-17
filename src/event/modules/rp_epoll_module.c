
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if (RP_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLERR       0x008
#define EPOLLHUP       0x010
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400

#define EPOLLRDHUP     0x2000

#define EPOLLEXCLUSIVE 0x10000000
#define EPOLLONESHOT   0x40000000
#define EPOLLET        0x80000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (RP_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (RP_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* RP_TEST_BUILD_EPOLL */


typedef struct {
    rp_uint_t  events;
    rp_uint_t  aio_requests;
} rp_epoll_conf_t;


static rp_int_t rp_epoll_init(rp_cycle_t *cycle, rp_msec_t timer);
#if (RP_HAVE_EVENTFD)
static rp_int_t rp_epoll_notify_init(rp_log_t *log);
static void rp_epoll_notify_handler(rp_event_t *ev);
#endif
#if (RP_HAVE_EPOLLRDHUP)
static void rp_epoll_test_rdhup(rp_cycle_t *cycle);
#endif
static void rp_epoll_done(rp_cycle_t *cycle);
static rp_int_t rp_epoll_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_epoll_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_epoll_add_connection(rp_connection_t *c);
static rp_int_t rp_epoll_del_connection(rp_connection_t *c,
    rp_uint_t flags);
#if (RP_HAVE_EVENTFD)
static rp_int_t rp_epoll_notify(rp_event_handler_pt handler);
#endif
static rp_int_t rp_epoll_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags);

#if (RP_HAVE_FILE_AIO)
static void rp_epoll_eventfd_handler(rp_event_t *ev);
#endif

static void *rp_epoll_create_conf(rp_cycle_t *cycle);
static char *rp_epoll_init_conf(rp_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static rp_uint_t           nevents;

#if (RP_HAVE_EVENTFD)
static int                  notify_fd = -1;
static rp_event_t          notify_event;
static rp_connection_t     notify_conn;
#endif

#if (RP_HAVE_FILE_AIO)

int                         rp_eventfd = -1;
aio_context_t               rp_aio_ctx = 0;

static rp_event_t          rp_eventfd_event;
static rp_connection_t     rp_eventfd_conn;

#endif

#if (RP_HAVE_EPOLLRDHUP)
rp_uint_t                  rp_use_epoll_rdhup;
#endif

static rp_str_t      epoll_name = rp_string("epoll");

static rp_command_t  rp_epoll_commands[] = {

    { rp_string("epoll_events"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_epoll_conf_t, events),
      NULL },

    { rp_string("worker_aio_requests"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_epoll_conf_t, aio_requests),
      NULL },

      rp_null_command
};


static rp_event_module_t  rp_epoll_module_ctx = {
    &epoll_name,
    rp_epoll_create_conf,               /* create configuration */
    rp_epoll_init_conf,                 /* init configuration */

    {
        rp_epoll_add_event,             /* add an event */
        rp_epoll_del_event,             /* delete an event */
        rp_epoll_add_event,             /* enable an event */
        rp_epoll_del_event,             /* disable an event */
        rp_epoll_add_connection,        /* add an connection */
        rp_epoll_del_connection,        /* delete an connection */
#if (RP_HAVE_EVENTFD)
        rp_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        rp_epoll_process_events,        /* process the events */
        rp_epoll_init,                  /* init the events */
        rp_epoll_done,                  /* done the events */
    }
};

rp_module_t  rp_epoll_module = {
    RP_MODULE_V1,
    &rp_epoll_module_ctx,               /* module context */
    rp_epoll_commands,                  /* module directives */
    RP_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    RP_MODULE_V1_PADDING
};


#if (RP_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


static void
rp_epoll_aio_init(rp_cycle_t *cycle, rp_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (RP_HAVE_SYS_EVENTFD_H)
    rp_eventfd = eventfd(0, 0);
#else
    rp_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (rp_eventfd == -1) {
        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                      "eventfd() failed");
        rp_file_aio = 0;
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", rp_eventfd);

    n = 1;

    if (ioctl(rp_eventfd, FIONBIO, &n) == -1) {
        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &rp_aio_ctx) == -1) {
        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                      "io_setup() failed");
        goto failed;
    }

    rp_eventfd_event.data = &rp_eventfd_conn;
    rp_eventfd_event.handler = rp_epoll_eventfd_handler;
    rp_eventfd_event.log = cycle->log;
    rp_eventfd_event.active = 1;
    rp_eventfd_conn.fd = rp_eventfd;
    rp_eventfd_conn.read = &rp_eventfd_event;
    rp_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &rp_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, rp_eventfd, &ee) != -1) {
        return;
    }

    rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(rp_aio_ctx) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(rp_eventfd) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "eventfd close() failed");
    }

    rp_eventfd = -1;
    rp_aio_ctx = 0;
    rp_file_aio = 0;
}

#endif


static rp_int_t
rp_epoll_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    rp_epoll_conf_t  *epcf;

    epcf = rp_event_get_conf(cycle->conf_ctx, rp_epoll_module);

    if (ep == -1) {
        ep = epoll_create(cycle->connection_n / 2);

        if (ep == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "epoll_create() failed");
            return RP_ERROR;
        }

#if (RP_HAVE_EVENTFD)
        if (rp_epoll_notify_init(cycle->log) != RP_OK) {
            rp_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (RP_HAVE_FILE_AIO)
        rp_epoll_aio_init(cycle, epcf);
#endif

#if (RP_HAVE_EPOLLRDHUP)
        rp_epoll_test_rdhup(cycle);
#endif
    }

    if (nevents < epcf->events) {
        if (event_list) {
            rp_free(event_list);
        }

        event_list = rp_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return RP_ERROR;
        }
    }

    nevents = epcf->events;

    rp_io = rp_os_io;

    rp_event_actions = rp_epoll_module_ctx.actions;

#if (RP_HAVE_CLEAR_EVENT)
    rp_event_flags = RP_USE_CLEAR_EVENT
#else
    rp_event_flags = RP_USE_LEVEL_EVENT
#endif
                      |RP_USE_GREEDY_EVENT
                      |RP_USE_EPOLL_EVENT;

    return RP_OK;
}


#if (RP_HAVE_EVENTFD)

static rp_int_t
rp_epoll_notify_init(rp_log_t *log)
{
    struct epoll_event  ee;

#if (RP_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "eventfd() failed");
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = rp_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                            "eventfd close() failed");
        }

        return RP_ERROR;
    }

    return RP_OK;
}


static void
rp_epoll_notify_handler(rp_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    rp_err_t             err;
    rp_event_handler_pt  handler;

    if (++ev->index == RP_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = rp_errno;

        rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            rp_log_error(RP_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif


#if (RP_HAVE_EPOLLRDHUP)

static void
rp_epoll_test_rdhup(rp_cycle_t *cycle)
{
    int                 s[2], events;
    struct epoll_event  ee;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "socketpair() failed");
        return;
    }

    ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "epoll_ctl() failed");
        goto failed;
    }

    if (close(s[1]) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close() failed");
        s[1] = -1;
        goto failed;
    }

    s[1] = -1;

    events = epoll_wait(ep, &ee, 1, 5000);

    if (events == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "epoll_wait() failed");
        goto failed;
    }

    if (events) {
        rp_use_epoll_rdhup = ee.events & EPOLLRDHUP;

    } else {
        rp_log_error(RP_LOG_ALERT, cycle->log, RP_ETIMEDOUT,
                      "epoll_wait() timed out");
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "testing the EPOLLRDHUP flag: %s",
                   rp_use_epoll_rdhup ? "success" : "fail");

failed:

    if (s[1] != -1 && close(s[1]) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close() failed");
    }

    if (close(s[0]) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close() failed");
    }
}

#endif


static void
rp_epoll_done(rp_cycle_t *cycle)
{
    if (close(ep) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (RP_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (RP_HAVE_FILE_AIO)

    if (rp_eventfd != -1) {

        if (io_destroy(rp_aio_ctx) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "io_destroy() failed");
        }

        if (close(rp_eventfd) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "eventfd close() failed");
        }

        rp_eventfd = -1;
    }

    rp_aio_ctx = 0;

#endif

    rp_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static rp_int_t
rp_epoll_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    rp_event_t         *e;
    rp_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    events = (uint32_t) event;

    if (event == RP_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (RP_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (RP_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

#if (RP_HAVE_EPOLLEXCLUSIVE && RP_HAVE_EPOLLRDHUP)
    if (flags & RP_EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    ee.events = events | (uint32_t) flags;
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RP_ERROR;
    }

    ev->active = 1;
#if 0
    ev->oneshot = (flags & RP_ONESHOT_EVENT) ? 1 : 0;
#endif

    return RP_OK;
}


static rp_int_t
rp_epoll_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    rp_event_t         *e;
    rp_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & RP_CLOSE_EVENT) {
        ev->active = 0;
        return RP_OK;
    }

    c = ev->data;

    if (event == RP_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RP_ERROR;
    }

    ev->active = 0;

    return RP_OK;
}


static rp_int_t
rp_epoll_add_connection(rp_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        rp_log_error(RP_LOG_ALERT, c->log, rp_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return RP_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return RP_OK;
}


static rp_int_t
rp_epoll_del_connection(rp_connection_t *c, rp_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & RP_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rp_log_error(RP_LOG_ALERT, c->log, rp_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RP_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return RP_OK;
}


#if (RP_HAVE_EVENTFD)

static rp_int_t
rp_epoll_notify(rp_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        rp_log_error(RP_LOG_ALERT, notify_event.log, rp_errno,
                      "write() to eventfd %d failed", notify_fd);
        return RP_ERROR;
    }

    return RP_OK;
}

#endif


static rp_int_t
rp_epoll_process_events(rp_cycle_t *cycle, rp_msec_t timer, rp_uint_t flags)
{
    int                events;
    uint32_t           revents;
    rp_int_t          instance, i;
    rp_uint_t         level;
    rp_err_t          err;
    rp_event_t       *rev, *wev;
    rp_queue_t       *queue;
    rp_connection_t  *c;

    /* RP_TIMER_INFINITE == INFTIM */

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? rp_errno : 0;

    if (flags & RP_UPDATE_TIME || rp_event_timer_alarm) {
        rp_time_update();
    }

    if (err) {
        if (err == RP_EINTR) {

            if (rp_event_timer_alarm) {
                rp_event_timer_alarm = 0;
                return RP_OK;
            }

            level = RP_LOG_INFO;

        } else {
            level = RP_LOG_ALERT;
        }

        rp_log_error(level, cycle->log, err, "epoll_wait() failed");
        return RP_ERROR;
    }

    if (events == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return RP_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (rp_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        rp_log_debug3(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        if ((revents & EPOLLIN) && rev->active) {

#if (RP_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;
            rev->available = -1;

            if (flags & RP_POST_EVENTS) {
                queue = rev->accept ? &rp_posted_accept_events
                                    : &rp_posted_events;

                rp_post_event(rev, queue);

            } else {
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;
#if (RP_THREADS)
            wev->complete = 1;
#endif

            if (flags & RP_POST_EVENTS) {
                rp_post_event(wev, &rp_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return RP_OK;
}


#if (RP_HAVE_FILE_AIO)

static void
rp_epoll_eventfd_handler(rp_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    rp_err_t         err;
    rp_event_t      *e;
    rp_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(rp_eventfd, &ready, 8);

    err = rp_errno;

    rp_log_debug1(RP_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == RP_EAGAIN) {
                return;
            }

            rp_log_error(RP_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(rp_aio_ctx, 1, 64, event, &ts);

        rp_log_debug1(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                rp_log_debug4(RP_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (rp_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                rp_post_event(e, &rp_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


static void *
rp_epoll_create_conf(rp_cycle_t *cycle)
{
    rp_epoll_conf_t  *epcf;

    epcf = rp_palloc(cycle->pool, sizeof(rp_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = RP_CONF_UNSET;
    epcf->aio_requests = RP_CONF_UNSET;

    return epcf;
}


static char *
rp_epoll_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_epoll_conf_t *epcf = conf;

    rp_conf_init_uint_value(epcf->events, 512);
    rp_conf_init_uint_value(epcf->aio_requests, 32);

    return RP_CONF_OK;
}
