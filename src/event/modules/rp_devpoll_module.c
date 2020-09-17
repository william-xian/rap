
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if (RP_TEST_BUILD_DEVPOLL)

/* Solaris declarations */

#ifndef POLLREMOVE
#define POLLREMOVE   0x0800
#endif
#define DP_POLL      0xD001
#define DP_ISPOLLED  0xD002

struct dvpoll {
    struct pollfd  *dp_fds;
    int             dp_nfds;
    int             dp_timeout;
};

#endif


typedef struct {
    rp_uint_t      changes;
    rp_uint_t      events;
} rp_devpoll_conf_t;


static rp_int_t rp_devpoll_init(rp_cycle_t *cycle, rp_msec_t timer);
static void rp_devpoll_done(rp_cycle_t *cycle);
static rp_int_t rp_devpoll_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_devpoll_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_devpoll_set_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_devpoll_process_events(rp_cycle_t *cycle,
    rp_msec_t timer, rp_uint_t flags);

static void *rp_devpoll_create_conf(rp_cycle_t *cycle);
static char *rp_devpoll_init_conf(rp_cycle_t *cycle, void *conf);

static int              dp = -1;
static struct pollfd   *change_list, *event_list;
static rp_uint_t       nchanges, max_changes, nevents;

static rp_event_t    **change_index;


static rp_str_t      devpoll_name = rp_string("/dev/poll");

static rp_command_t  rp_devpoll_commands[] = {

    { rp_string("devpoll_changes"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_devpoll_conf_t, changes),
      NULL },

    { rp_string("devpoll_events"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_devpoll_conf_t, events),
      NULL },

      rp_null_command
};


static rp_event_module_t  rp_devpoll_module_ctx = {
    &devpoll_name,
    rp_devpoll_create_conf,               /* create configuration */
    rp_devpoll_init_conf,                 /* init configuration */

    {
        rp_devpoll_add_event,             /* add an event */
        rp_devpoll_del_event,             /* delete an event */
        rp_devpoll_add_event,             /* enable an event */
        rp_devpoll_del_event,             /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rp_devpoll_process_events,        /* process the events */
        rp_devpoll_init,                  /* init the events */
        rp_devpoll_done,                  /* done the events */
    }

};

rp_module_t  rp_devpoll_module = {
    RP_MODULE_V1,
    &rp_devpoll_module_ctx,               /* module context */
    rp_devpoll_commands,                  /* module directives */
    RP_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_devpoll_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    size_t               n;
    rp_devpoll_conf_t  *dpcf;

    dpcf = rp_event_get_conf(cycle->conf_ctx, rp_devpoll_module);

    if (dp == -1) {
        dp = open("/dev/poll", O_RDWR);

        if (dp == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "open(/dev/poll) failed");
            return RP_ERROR;
        }
    }

    if (max_changes < dpcf->changes) {
        if (nchanges) {
            n = nchanges * sizeof(struct pollfd);
            if (write(dp, change_list, n) != (ssize_t) n) {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                              "write(/dev/poll) failed");
                return RP_ERROR;
            }

            nchanges = 0;
        }

        if (change_list) {
            rp_free(change_list);
        }

        change_list = rp_alloc(sizeof(struct pollfd) * dpcf->changes,
                                cycle->log);
        if (change_list == NULL) {
            return RP_ERROR;
        }

        if (change_index) {
            rp_free(change_index);
        }

        change_index = rp_alloc(sizeof(rp_event_t *) * dpcf->changes,
                                 cycle->log);
        if (change_index == NULL) {
            return RP_ERROR;
        }
    }

    max_changes = dpcf->changes;

    if (nevents < dpcf->events) {
        if (event_list) {
            rp_free(event_list);
        }

        event_list = rp_alloc(sizeof(struct pollfd) * dpcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return RP_ERROR;
        }
    }

    nevents = dpcf->events;

    rp_io = rp_os_io;

    rp_event_actions = rp_devpoll_module_ctx.actions;

    rp_event_flags = RP_USE_LEVEL_EVENT|RP_USE_FD_EVENT;

    return RP_OK;
}


static void
rp_devpoll_done(rp_cycle_t *cycle)
{
    if (close(dp) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close(/dev/poll) failed");
    }

    dp = -1;

    rp_free(change_list);
    rp_free(event_list);
    rp_free(change_index);

    change_list = NULL;
    event_list = NULL;
    change_index = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static rp_int_t
rp_devpoll_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
#if (RP_DEBUG)
    rp_connection_t *c;
#endif

#if (RP_READ_EVENT != POLLIN)
    event = (event == RP_READ_EVENT) ? POLLIN : POLLOUT;
#endif

#if (RP_DEBUG)
    c = ev->data;
    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll add event: fd:%d ev:%04Xi", c->fd, event);
#endif

    ev->active = 1;

    return rp_devpoll_set_event(ev, event, 0);
}


static rp_int_t
rp_devpoll_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_event_t       *e;
    rp_connection_t  *c;

    c = ev->data;

#if (RP_READ_EVENT != POLLIN)
    event = (event == RP_READ_EVENT) ? POLLIN : POLLOUT;
#endif

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll del event: fd:%d ev:%04Xi", c->fd, event);

    if (rp_devpoll_set_event(ev, POLLREMOVE, flags) == RP_ERROR) {
        return RP_ERROR;
    }

    ev->active = 0;

    if (flags & RP_CLOSE_EVENT) {
        e = (event == POLLIN) ? c->write : c->read;

        if (e) {
            e->active = 0;
        }

        return RP_OK;
    }

    /* restore the pair event if it exists */

    if (event == POLLIN) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e && e->active) {
        return rp_devpoll_set_event(e, event, 0);
    }

    return RP_OK;
}


static rp_int_t
rp_devpoll_set_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    size_t             n;
    rp_connection_t  *c;

    c = ev->data;

    rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll fd:%d ev:%04Xi fl:%04Xi", c->fd, event, flags);

    if (nchanges >= max_changes) {
        rp_log_error(RP_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                          "write(/dev/poll) failed");
            return RP_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].fd = c->fd;
    change_list[nchanges].events = (short) event;
    change_list[nchanges].revents = 0;

    change_index[nchanges] = ev;
    ev->index = nchanges;

    nchanges++;

    if (flags & RP_CLOSE_EVENT) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                          "write(/dev/poll) failed");
            return RP_ERROR;
        }

        nchanges = 0;
    }

    return RP_OK;
}


static rp_int_t
rp_devpoll_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags)
{
    int                 events, revents, rc;
    size_t              n;
    rp_fd_t            fd;
    rp_err_t           err;
    rp_int_t           i;
    rp_uint_t          level, instance;
    rp_event_t        *rev, *wev;
    rp_queue_t        *queue;
    rp_connection_t   *c;
    struct pollfd       pfd;
    struct dvpoll       dvp;

    /* RP_TIMER_INFINITE == INFTIM */

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "devpoll timer: %M", timer);

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "write(/dev/poll) failed");
            return RP_ERROR;
        }

        nchanges = 0;
    }

    dvp.dp_fds = event_list;
    dvp.dp_nfds = (int) nevents;
    dvp.dp_timeout = timer;
    events = ioctl(dp, DP_POLL, &dvp);

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

        rp_log_error(level, cycle->log, err, "ioctl(DP_POLL) failed");
        return RP_ERROR;
    }

    if (events == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "ioctl(DP_POLL) returned no events without timeout");
        return RP_ERROR;
    }

    for (i = 0; i < events; i++) {

        fd = event_list[i].fd;
        revents = event_list[i].revents;

        c = rp_cycle->files[fd];

        if (c == NULL || c->fd == -1) {

            pfd.fd = fd;
            pfd.events = 0;
            pfd.revents = 0;

            rc = ioctl(dp, DP_ISPOLLED, &pfd);

            switch (rc) {

            case -1:
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                    "ioctl(DP_ISPOLLED) failed for socket %d, event %04Xd",
                    fd, revents);
                break;

            case 0:
                rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                    "phantom event %04Xd for closed and removed socket %d",
                    revents, fd);
                break;

            default:
                rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                    "unexpected event %04Xd for closed and removed socket %d, "
                    "ioctl(DP_ISPOLLED) returned rc:%d, fd:%d, event %04Xd",
                    revents, fd, rc, pfd.fd, pfd.revents);

                pfd.fd = fd;
                pfd.events = POLLREMOVE;
                pfd.revents = 0;

                if (write(dp, &pfd, sizeof(struct pollfd))
                    != (ssize_t) sizeof(struct pollfd))
                {
                    rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                                  "write(/dev/poll) for %d failed", fd);
                }

                if (close(fd) == -1) {
                    rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                                  "close(%d) failed", fd);
                }

                break;
            }

            continue;
        }

        rp_log_debug3(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "devpoll: fd:%d, ev:%04Xd, rev:%04Xd",
                       fd, event_list[i].events, revents);

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
            rp_log_debug3(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                          "ioctl(DP_POLL) error fd:%d ev:%04Xd rev:%04Xd",
                          fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "strange ioctl(DP_POLL) events "
                          "fd:%d ev:%04Xd rev:%04Xd",
                          fd, event_list[i].events, revents);
        }

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

            /*
             * if the error events were returned, add POLLIN and POLLOUT
             * to handle the events at least in one active handler
             */

            revents |= POLLIN|POLLOUT;
        }

        rev = c->read;

        if ((revents & POLLIN) && rev->active) {
            rev->ready = 1;
            rev->available = -1;

            if (flags & RP_POST_EVENTS) {
                queue = rev->accept ? &rp_posted_accept_events
                                    : &rp_posted_events;

                rp_post_event(rev, queue);

            } else {
                instance = rev->instance;

                rev->handler(rev);

                if (c->fd == -1 || rev->instance != instance) {
                    continue;
                }
            }
        }

        wev = c->write;

        if ((revents & POLLOUT) && wev->active) {
            wev->ready = 1;

            if (flags & RP_POST_EVENTS) {
                rp_post_event(wev, &rp_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return RP_OK;
}


static void *
rp_devpoll_create_conf(rp_cycle_t *cycle)
{
    rp_devpoll_conf_t  *dpcf;

    dpcf = rp_palloc(cycle->pool, sizeof(rp_devpoll_conf_t));
    if (dpcf == NULL) {
        return NULL;
    }

    dpcf->changes = RP_CONF_UNSET;
    dpcf->events = RP_CONF_UNSET;

    return dpcf;
}


static char *
rp_devpoll_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_devpoll_conf_t *dpcf = conf;

    rp_conf_init_uint_value(dpcf->changes, 32);
    rp_conf_init_uint_value(dpcf->events, 32);

    return RP_CONF_OK;
}
