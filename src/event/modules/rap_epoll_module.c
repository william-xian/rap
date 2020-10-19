
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#if (RAP_TEST_BUILD_EPOLL)

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

#if (RAP_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

#if (RAP_HAVE_FILE_AIO)

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
#endif /* RAP_TEST_BUILD_EPOLL */


typedef struct {
    rap_uint_t  events;
    rap_uint_t  aio_requests;
} rap_epoll_conf_t;


static rap_int_t rap_epoll_init(rap_cycle_t *cycle, rap_msec_t timer);
#if (RAP_HAVE_EVENTFD)
static rap_int_t rap_epoll_notify_init(rap_log_t *log);
static void rap_epoll_notify_handler(rap_event_t *ev);
#endif
#if (RAP_HAVE_EPOLLRDHUP)
static void rap_epoll_test_rdhup(rap_cycle_t *cycle);
#endif
static void rap_epoll_done(rap_cycle_t *cycle);
static rap_int_t rap_epoll_add_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_epoll_del_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_epoll_add_connection(rap_connection_t *c);
static rap_int_t rap_epoll_del_connection(rap_connection_t *c,
    rap_uint_t flags);
#if (RAP_HAVE_EVENTFD)
static rap_int_t rap_epoll_notify(rap_event_handler_pt handler);
#endif
static rap_int_t rap_epoll_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags);

#if (RAP_HAVE_FILE_AIO)
static void rap_epoll_eventfd_handler(rap_event_t *ev);
#endif

static void *rap_epoll_create_conf(rap_cycle_t *cycle);
static char *rap_epoll_init_conf(rap_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static rap_uint_t           nevents;

#if (RAP_HAVE_EVENTFD)
static int                  notify_fd = -1;
static rap_event_t          notify_event;
static rap_connection_t     notify_conn;
#endif

#if (RAP_HAVE_FILE_AIO)

int                         rap_eventfd = -1;
aio_context_t               rap_aio_ctx = 0;

static rap_event_t          rap_eventfd_event;
static rap_connection_t     rap_eventfd_conn;

#endif

#if (RAP_HAVE_EPOLLRDHUP)
rap_uint_t                  rap_use_epoll_rdhup;
#endif

static rap_str_t      epoll_name = rap_string("epoll");

static rap_command_t  rap_epoll_commands[] = {

    { rap_string("epoll_events"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_epoll_conf_t, events),
      NULL },

    { rap_string("worker_aio_requests"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_epoll_conf_t, aio_requests),
      NULL },

      rap_null_command
};


static rap_event_module_t  rap_epoll_module_ctx = {
    &epoll_name,
    rap_epoll_create_conf,               /* create configuration */
    rap_epoll_init_conf,                 /* init configuration */

    {
        rap_epoll_add_event,             /* add an event */
        rap_epoll_del_event,             /* delete an event */
        rap_epoll_add_event,             /* enable an event */
        rap_epoll_del_event,             /* disable an event */
        rap_epoll_add_connection,        /* add an connection */
        rap_epoll_del_connection,        /* delete an connection */
#if (RAP_HAVE_EVENTFD)
        rap_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        rap_epoll_process_events,        /* process the events */
        rap_epoll_init,                  /* init the events */
        rap_epoll_done,                  /* done the events */
    }
};

rap_module_t  rap_epoll_module = {
    RAP_MODULE_V1,
    &rap_epoll_module_ctx,               /* module context */
    rap_epoll_commands,                  /* module directives */
    RAP_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    RAP_MODULE_V1_PADDING
};


#if (RAP_HAVE_FILE_AIO)

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
rap_epoll_aio_init(rap_cycle_t *cycle, rap_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (RAP_HAVE_SYS_EVENTFD_H)
    rap_eventfd = eventfd(0, 0);
#else
    rap_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (rap_eventfd == -1) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                      "eventfd() failed");
        rap_file_aio = 0;
        return;
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", rap_eventfd);

    n = 1;

    if (ioctl(rap_eventfd, FIONBIO, &n) == -1) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &rap_aio_ctx) == -1) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                      "io_setup() failed");
        goto failed;
    }

    rap_eventfd_event.data = &rap_eventfd_conn;
    rap_eventfd_event.handler = rap_epoll_eventfd_handler;
    rap_eventfd_event.log = cycle->log;
    rap_eventfd_event.active = 1;
    rap_eventfd_conn.fd = rap_eventfd;
    rap_eventfd_conn.read = &rap_eventfd_event;
    rap_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &rap_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, rap_eventfd, &ee) != -1) {
        return;
    }

    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(rap_aio_ctx) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(rap_eventfd) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "eventfd close() failed");
    }

    rap_eventfd = -1;
    rap_aio_ctx = 0;
    rap_file_aio = 0;
}

#endif


static rap_int_t
rap_epoll_init(rap_cycle_t *cycle, rap_msec_t timer)
{
    rap_epoll_conf_t  *epcf;

    epcf = rap_event_get_conf(cycle->conf_ctx, rap_epoll_module);

    if (ep == -1) {
        ep = epoll_create(cycle->connection_n / 2);

        if (ep == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "epoll_create() failed");
            return RAP_ERROR;
        }

#if (RAP_HAVE_EVENTFD)
        if (rap_epoll_notify_init(cycle->log) != RAP_OK) {
            rap_epoll_module_ctx.actions.notify = NULL;
        }
#endif

#if (RAP_HAVE_FILE_AIO)
        rap_epoll_aio_init(cycle, epcf);
#endif

#if (RAP_HAVE_EPOLLRDHUP)
        rap_epoll_test_rdhup(cycle);
#endif
    }

    if (nevents < epcf->events) {
        if (event_list) {
            rap_free(event_list);
        }

        event_list = rap_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return RAP_ERROR;
        }
    }

    nevents = epcf->events;

    rap_io = rap_os_io;

    rap_event_actions = rap_epoll_module_ctx.actions;

#if (RAP_HAVE_CLEAR_EVENT)
    rap_event_flags = RAP_USE_CLEAR_EVENT
#else
    rap_event_flags = RAP_USE_LEVEL_EVENT
#endif
                      |RAP_USE_GREEDY_EVENT
                      |RAP_USE_EPOLL_EVENT;

    return RAP_OK;
}


#if (RAP_HAVE_EVENTFD)

static rap_int_t
rap_epoll_notify_init(rap_log_t *log)
{
    struct epoll_event  ee;

#if (RAP_HAVE_SYS_EVENTFD_H)
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "eventfd() failed");
        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    notify_event.handler = rap_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    notify_conn.fd = notify_fd;
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &notify_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                            "eventfd close() failed");
        }

        return RAP_ERROR;
    }

    return RAP_OK;
}


static void
rap_epoll_notify_handler(rap_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    rap_err_t             err;
    rap_event_handler_pt  handler;

    if (++ev->index == RAP_MAX_UINT32_VALUE) {
        ev->index = 0;

        n = read(notify_fd, &count, sizeof(uint64_t));

        err = rap_errno;

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        if ((size_t) n != sizeof(uint64_t)) {
            rap_log_error(RAP_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    handler = ev->data;
    handler(ev);
}

#endif


#if (RAP_HAVE_EPOLLRDHUP)

static void
rap_epoll_test_rdhup(rap_cycle_t *cycle)
{
    int                 s[2], events;
    struct epoll_event  ee;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "socketpair() failed");
        return;
    }

    ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "epoll_ctl() failed");
        goto failed;
    }

    if (close(s[1]) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "close() failed");
        s[1] = -1;
        goto failed;
    }

    s[1] = -1;

    events = epoll_wait(ep, &ee, 1, 5000);

    if (events == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "epoll_wait() failed");
        goto failed;
    }

    if (events) {
        rap_use_epoll_rdhup = ee.events & EPOLLRDHUP;

    } else {
        rap_log_error(RAP_LOG_ALERT, cycle->log, RAP_ETIMEDOUT,
                      "epoll_wait() timed out");
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "testing the EPOLLRDHUP flag: %s",
                   rap_use_epoll_rdhup ? "success" : "fail");

failed:

    if (s[1] != -1 && close(s[1]) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "close() failed");
    }

    if (close(s[0]) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "close() failed");
    }
}

#endif


static void
rap_epoll_done(rap_cycle_t *cycle)
{
    if (close(ep) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (RAP_HAVE_EVENTFD)

    if (close(notify_fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

#if (RAP_HAVE_FILE_AIO)

    if (rap_eventfd != -1) {

        if (io_destroy(rap_aio_ctx) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "io_destroy() failed");
        }

        if (close(rap_eventfd) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "eventfd close() failed");
        }

        rap_eventfd = -1;
    }

    rap_aio_ctx = 0;

#endif

    rap_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static rap_int_t
rap_epoll_add_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    rap_event_t         *e;
    rap_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data;

    events = (uint32_t) event;

    if (event == RAP_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (RAP_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (RAP_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

#if (RAP_HAVE_EPOLLEXCLUSIVE && RAP_HAVE_EPOLLRDHUP)
    if (flags & RAP_EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    ee.events = events | (uint32_t) flags;
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RAP_ERROR;
    }

    ev->active = 1;
#if 0
    ev->oneshot = (flags & RAP_ONESHOT_EVENT) ? 1 : 0;
#endif

    return RAP_OK;
}


static rap_int_t
rap_epoll_del_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    rap_event_t         *e;
    rap_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & RAP_CLOSE_EVENT) {
        ev->active = 0;
        return RAP_OK;
    }

    c = ev->data;

    if (event == RAP_READ_EVENT) {
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

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RAP_ERROR;
    }

    ev->active = 0;

    return RAP_OK;
}


static rap_int_t
rap_epoll_add_connection(rap_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        rap_log_error(RAP_LOG_ALERT, c->log, rap_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return RAP_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return RAP_OK;
}


static rap_int_t
rap_epoll_del_connection(rap_connection_t *c, rap_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & RAP_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        rap_log_error(RAP_LOG_ALERT, c->log, rap_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return RAP_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return RAP_OK;
}


#if (RAP_HAVE_EVENTFD)

static rap_int_t
rap_epoll_notify(rap_event_handler_pt handler)
{
    static uint64_t inc = 1;

    notify_event.data = handler;

    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        rap_log_error(RAP_LOG_ALERT, notify_event.log, rap_errno,
                      "write() to eventfd %d failed", notify_fd);
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static rap_int_t
rap_epoll_process_events(rap_cycle_t *cycle, rap_msec_t timer, rap_uint_t flags)
{
    int                events;
    uint32_t           revents;
    rap_int_t          instance, i;
    rap_uint_t         level;
    rap_err_t          err;
    rap_event_t       *rev, *wev;
    rap_queue_t       *queue;
    rap_connection_t  *c;

    /* RAP_TIMER_INFINITE == INFTIM */

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? rap_errno : 0;

    if (flags & RAP_UPDATE_TIME || rap_event_timer_alarm) {
        rap_time_update();
    }

    if (err) {
        if (err == RAP_EINTR) {

            if (rap_event_timer_alarm) {
                rap_event_timer_alarm = 0;
                return RAP_OK;
            }

            level = RAP_LOG_INFO;

        } else {
            level = RAP_LOG_ALERT;
        }

        rap_log_error(level, cycle->log, err, "epoll_wait() failed");
        return RAP_ERROR;
    }

    if (events == 0) {
        if (timer != RAP_TIMER_INFINITE) {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return RAP_ERROR;
    }

    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

        instance = (uintptr_t) c & 1;
        c = (rap_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            rap_log_debug2(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
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
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        if ((revents & EPOLLIN) && rev->active) {

#if (RAP_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;
            rev->available = -1;

            if (flags & RAP_POST_EVENTS) {
                queue = rev->accept ? &rap_posted_accept_events
                                    : &rap_posted_events;

                rap_post_event(rev, queue);

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

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;
#if (RAP_THREADS)
            wev->complete = 1;
#endif

            if (flags & RAP_POST_EVENTS) {
                rap_post_event(wev, &rap_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return RAP_OK;
}


#if (RAP_HAVE_FILE_AIO)

static void
rap_epoll_eventfd_handler(rap_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    rap_err_t         err;
    rap_event_t      *e;
    rap_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(rap_eventfd, &ready, 8);

    err = rap_errno;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == RAP_EAGAIN) {
                return;
            }

            rap_log_error(RAP_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(rap_aio_ctx, 1, 64, event, &ts);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                rap_log_debug4(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (rap_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                rap_post_event(e, &rap_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


static void *
rap_epoll_create_conf(rap_cycle_t *cycle)
{
    rap_epoll_conf_t  *epcf;

    epcf = rap_palloc(cycle->pool, sizeof(rap_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = RAP_CONF_UNSET;
    epcf->aio_requests = RAP_CONF_UNSET;

    return epcf;
}


static char *
rap_epoll_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_epoll_conf_t *epcf = conf;

    rap_conf_init_uint_value(epcf->events, 512);
    rap_conf_init_uint_value(epcf->aio_requests, 32);

    return RAP_CONF_OK;
}
