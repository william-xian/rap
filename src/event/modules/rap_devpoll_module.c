
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#if (RAP_TEST_BUILD_DEVPOLL)

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
    rap_uint_t      changes;
    rap_uint_t      events;
} rap_devpoll_conf_t;


static rap_int_t rap_devpoll_init(rap_cycle_t *cycle, rap_msec_t timer);
static void rap_devpoll_done(rap_cycle_t *cycle);
static rap_int_t rap_devpoll_add_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_devpoll_del_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_devpoll_set_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_devpoll_process_events(rap_cycle_t *cycle,
    rap_msec_t timer, rap_uint_t flags);

static void *rap_devpoll_create_conf(rap_cycle_t *cycle);
static char *rap_devpoll_init_conf(rap_cycle_t *cycle, void *conf);

static int              dp = -1;
static struct pollfd   *change_list, *event_list;
static rap_uint_t       nchanges, max_changes, nevents;

static rap_event_t    **change_index;


static rap_str_t      devpoll_name = rap_string("/dev/poll");

static rap_command_t  rap_devpoll_commands[] = {

    { rap_string("devpoll_changes"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_devpoll_conf_t, changes),
      NULL },

    { rap_string("devpoll_events"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_devpoll_conf_t, events),
      NULL },

      rap_null_command
};


static rap_event_module_t  rap_devpoll_module_ctx = {
    &devpoll_name,
    rap_devpoll_create_conf,               /* create configuration */
    rap_devpoll_init_conf,                 /* init configuration */

    {
        rap_devpoll_add_event,             /* add an event */
        rap_devpoll_del_event,             /* delete an event */
        rap_devpoll_add_event,             /* enable an event */
        rap_devpoll_del_event,             /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rap_devpoll_process_events,        /* process the events */
        rap_devpoll_init,                  /* init the events */
        rap_devpoll_done,                  /* done the events */
    }

};

rap_module_t  rap_devpoll_module = {
    RAP_MODULE_V1,
    &rap_devpoll_module_ctx,               /* module context */
    rap_devpoll_commands,                  /* module directives */
    RAP_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_devpoll_init(rap_cycle_t *cycle, rap_msec_t timer)
{
    size_t               n;
    rap_devpoll_conf_t  *dpcf;

    dpcf = rap_event_get_conf(cycle->conf_ctx, rap_devpoll_module);

    if (dp == -1) {
        dp = open("/dev/poll", O_RDWR);

        if (dp == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "open(/dev/poll) failed");
            return RAP_ERROR;
        }
    }

    if (max_changes < dpcf->changes) {
        if (nchanges) {
            n = nchanges * sizeof(struct pollfd);
            if (write(dp, change_list, n) != (ssize_t) n) {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                              "write(/dev/poll) failed");
                return RAP_ERROR;
            }

            nchanges = 0;
        }

        if (change_list) {
            rap_free(change_list);
        }

        change_list = rap_alloc(sizeof(struct pollfd) * dpcf->changes,
                                cycle->log);
        if (change_list == NULL) {
            return RAP_ERROR;
        }

        if (change_index) {
            rap_free(change_index);
        }

        change_index = rap_alloc(sizeof(rap_event_t *) * dpcf->changes,
                                 cycle->log);
        if (change_index == NULL) {
            return RAP_ERROR;
        }
    }

    max_changes = dpcf->changes;

    if (nevents < dpcf->events) {
        if (event_list) {
            rap_free(event_list);
        }

        event_list = rap_alloc(sizeof(struct pollfd) * dpcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return RAP_ERROR;
        }
    }

    nevents = dpcf->events;

    rap_io = rap_os_io;

    rap_event_actions = rap_devpoll_module_ctx.actions;

    rap_event_flags = RAP_USE_LEVEL_EVENT|RAP_USE_FD_EVENT;

    return RAP_OK;
}


static void
rap_devpoll_done(rap_cycle_t *cycle)
{
    if (close(dp) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "close(/dev/poll) failed");
    }

    dp = -1;

    rap_free(change_list);
    rap_free(event_list);
    rap_free(change_index);

    change_list = NULL;
    event_list = NULL;
    change_index = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static rap_int_t
rap_devpoll_add_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
#if (RAP_DEBUG)
    rap_connection_t *c;
#endif

#if (RAP_READ_EVENT != POLLIN)
    event = (event == RAP_READ_EVENT) ? POLLIN : POLLOUT;
#endif

#if (RAP_DEBUG)
    c = ev->data;
    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll add event: fd:%d ev:%04Xi", c->fd, event);
#endif

    ev->active = 1;

    return rap_devpoll_set_event(ev, event, 0);
}


static rap_int_t
rap_devpoll_del_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_event_t       *e;
    rap_connection_t  *c;

    c = ev->data;

#if (RAP_READ_EVENT != POLLIN)
    event = (event == RAP_READ_EVENT) ? POLLIN : POLLOUT;
#endif

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll del event: fd:%d ev:%04Xi", c->fd, event);

    if (rap_devpoll_set_event(ev, POLLREMOVE, flags) == RAP_ERROR) {
        return RAP_ERROR;
    }

    ev->active = 0;

    if (flags & RAP_CLOSE_EVENT) {
        e = (event == POLLIN) ? c->write : c->read;

        if (e) {
            e->active = 0;
        }

        return RAP_OK;
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
        return rap_devpoll_set_event(e, event, 0);
    }

    return RAP_OK;
}


static rap_int_t
rap_devpoll_set_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    size_t             n;
    rap_connection_t  *c;

    c = ev->data;

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "devpoll fd:%d ev:%04Xi fl:%04Xi", c->fd, event, flags);

    if (nchanges >= max_changes) {
        rap_log_error(RAP_LOG_WARN, ev->log, 0,
                      "/dev/pool change list is filled up");

        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                          "write(/dev/poll) failed");
            return RAP_ERROR;
        }

        nchanges = 0;
    }

    change_list[nchanges].fd = c->fd;
    change_list[nchanges].events = (short) event;
    change_list[nchanges].revents = 0;

    change_index[nchanges] = ev;
    ev->index = nchanges;

    nchanges++;

    if (flags & RAP_CLOSE_EVENT) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno,
                          "write(/dev/poll) failed");
            return RAP_ERROR;
        }

        nchanges = 0;
    }

    return RAP_OK;
}


static rap_int_t
rap_devpoll_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags)
{
    int                 events, revents, rc;
    size_t              n;
    rap_fd_t            fd;
    rap_err_t           err;
    rap_int_t           i;
    rap_uint_t          level, instance;
    rap_event_t        *rev, *wev;
    rap_queue_t        *queue;
    rap_connection_t   *c;
    struct pollfd       pfd;
    struct dvpoll       dvp;

    /* RAP_TIMER_INFINITE == INFTIM */

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "devpoll timer: %M", timer);

    if (nchanges) {
        n = nchanges * sizeof(struct pollfd);
        if (write(dp, change_list, n) != (ssize_t) n) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "write(/dev/poll) failed");
            return RAP_ERROR;
        }

        nchanges = 0;
    }

    dvp.dp_fds = event_list;
    dvp.dp_nfds = (int) nevents;
    dvp.dp_timeout = timer;
    events = ioctl(dp, DP_POLL, &dvp);

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

        rap_log_error(level, cycle->log, err, "ioctl(DP_POLL) failed");
        return RAP_ERROR;
    }

    if (events == 0) {
        if (timer != RAP_TIMER_INFINITE) {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "ioctl(DP_POLL) returned no events without timeout");
        return RAP_ERROR;
    }

    for (i = 0; i < events; i++) {

        fd = event_list[i].fd;
        revents = event_list[i].revents;

        c = rap_cycle->files[fd];

        if (c == NULL || c->fd == -1) {

            pfd.fd = fd;
            pfd.events = 0;
            pfd.revents = 0;

            rc = ioctl(dp, DP_ISPOLLED, &pfd);

            switch (rc) {

            case -1:
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                    "ioctl(DP_ISPOLLED) failed for socket %d, event %04Xd",
                    fd, revents);
                break;

            case 0:
                rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                    "phantom event %04Xd for closed and removed socket %d",
                    revents, fd);
                break;

            default:
                rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                    "unexpected event %04Xd for closed and removed socket %d, "
                    "ioctl(DP_ISPOLLED) returned rc:%d, fd:%d, event %04Xd",
                    revents, fd, rc, pfd.fd, pfd.revents);

                pfd.fd = fd;
                pfd.events = POLLREMOVE;
                pfd.revents = 0;

                if (write(dp, &pfd, sizeof(struct pollfd))
                    != (ssize_t) sizeof(struct pollfd))
                {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                                  "write(/dev/poll) for %d failed", fd);
                }

                if (close(fd) == -1) {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                                  "close(%d) failed", fd);
                }

                break;
            }

            continue;
        }

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "devpoll: fd:%d, ev:%04Xd, rev:%04Xd",
                       fd, event_list[i].events, revents);

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
            rap_log_debug3(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                          "ioctl(DP_POLL) error fd:%d ev:%04Xd rev:%04Xd",
                          fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
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

            if (flags & RAP_POST_EVENTS) {
                queue = rev->accept ? &rap_posted_accept_events
                                    : &rap_posted_events;

                rap_post_event(rev, queue);

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

            if (flags & RAP_POST_EVENTS) {
                rap_post_event(wev, &rap_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return RAP_OK;
}


static void *
rap_devpoll_create_conf(rap_cycle_t *cycle)
{
    rap_devpoll_conf_t  *dpcf;

    dpcf = rap_palloc(cycle->pool, sizeof(rap_devpoll_conf_t));
    if (dpcf == NULL) {
        return NULL;
    }

    dpcf->changes = RAP_CONF_UNSET;
    dpcf->events = RAP_CONF_UNSET;

    return dpcf;
}


static char *
rap_devpoll_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_devpoll_conf_t *dpcf = conf;

    rap_conf_init_uint_value(dpcf->changes, 32);
    rap_conf_init_uint_value(dpcf->events, 32);

    return RAP_CONF_OK;
}
