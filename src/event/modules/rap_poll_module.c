
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static rap_int_t rap_poll_init(rap_cycle_t *cycle, rap_msec_t timer);
static void rap_poll_done(rap_cycle_t *cycle);
static rap_int_t rap_poll_add_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_poll_del_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_poll_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags);
static char *rap_poll_init_conf(rap_cycle_t *cycle, void *conf);


static struct pollfd  *event_list;
static rap_uint_t      nevents;


static rap_str_t           poll_name = rap_string("poll");

static rap_event_module_t  rap_poll_module_ctx = {
    &poll_name,
    NULL,                                  /* create configuration */
    rap_poll_init_conf,                    /* init configuration */

    {
        rap_poll_add_event,                /* add an event */
        rap_poll_del_event,                /* delete an event */
        rap_poll_add_event,                /* enable an event */
        rap_poll_del_event,                /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rap_poll_process_events,           /* process the events */
        rap_poll_init,                     /* init the events */
        rap_poll_done                      /* done the events */
    }

};

rap_module_t  rap_poll_module = {
    RAP_MODULE_V1,
    &rap_poll_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
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
rap_poll_init(rap_cycle_t *cycle, rap_msec_t timer)
{
    struct pollfd   *list;

    if (event_list == NULL) {
        nevents = 0;
    }

    if (rap_process >= RAP_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        list = rap_alloc(sizeof(struct pollfd) * cycle->connection_n,
                         cycle->log);
        if (list == NULL) {
            return RAP_ERROR;
        }

        if (event_list) {
            rap_memcpy(list, event_list, sizeof(struct pollfd) * nevents);
            rap_free(event_list);
        }

        event_list = list;
    }

    rap_io = rap_os_io;

    rap_event_actions = rap_poll_module_ctx.actions;

    rap_event_flags = RAP_USE_LEVEL_EVENT|RAP_USE_FD_EVENT;

    return RAP_OK;
}


static void
rap_poll_done(rap_cycle_t *cycle)
{
    rap_free(event_list);

    event_list = NULL;
}


static rap_int_t
rap_poll_add_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_event_t       *e;
    rap_connection_t  *c;

    c = ev->data;

    ev->active = 1;

    if (ev->index != RAP_INVALID_INDEX) {
        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already set", c->fd, event);
        return RAP_OK;
    }

    if (event == RAP_READ_EVENT) {
        e = c->write;
#if (RAP_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (RAP_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll add event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == RAP_INVALID_INDEX) {
        event_list[nevents].fd = c->fd;
        event_list[nevents].events = (short) event;
        event_list[nevents].revents = 0;

        ev->index = nevents;
        nevents++;

    } else {
        rap_log_debug1(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll add index: %i", e->index);

        event_list[e->index].events |= (short) event;
        ev->index = e->index;
    }

    return RAP_OK;
}


static rap_int_t
rap_poll_del_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_event_t       *e;
    rap_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == RAP_INVALID_INDEX) {
        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already deleted",
                      c->fd, event);
        return RAP_OK;
    }

    if (event == RAP_READ_EVENT) {
        e = c->write;
#if (RAP_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (RAP_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll del event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == RAP_INVALID_INDEX) {
        nevents--;

        if (ev->index < nevents) {

            rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                           "index: copy event %ui to %i", nevents, ev->index);

            event_list[ev->index] = event_list[nevents];

            c = rap_cycle->files[event_list[nevents].fd];

            if (c->fd == -1) {
                rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                              "unexpected last event");

            } else {
                if (c->read->index == nevents) {
                    c->read->index = ev->index;
                }

                if (c->write->index == nevents) {
                    c->write->index = ev->index;
                }
            }
        }

    } else {
        rap_log_debug1(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll del index: %i", e->index);

        event_list[e->index].events &= (short) ~event;
    }

    ev->index = RAP_INVALID_INDEX;

    return RAP_OK;
}


static rap_int_t
rap_poll_process_events(rap_cycle_t *cycle, rap_msec_t timer, rap_uint_t flags)
{
    int                 ready, revents;
    rap_err_t           err;
    rap_uint_t          i, found, level;
    rap_event_t        *ev;
    rap_queue_t        *queue;
    rap_connection_t   *c;

    /* RAP_TIMER_INFINITE == INFTIM */

#if (RAP_DEBUG0)
    if (cycle->log->log_level & RAP_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            rap_log_debug3(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd",
                           i, event_list[i].fd, event_list[i].events);
        }
    }
#endif

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %M", timer);

    ready = poll(event_list, (u_int) nevents, (int) timer);

    err = (ready == -1) ? rap_errno : 0;

    if (flags & RAP_UPDATE_TIME || rap_event_timer_alarm) {
        rap_time_update();
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "poll ready %d of %ui", ready, nevents);

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

        rap_log_error(level, cycle->log, err, "poll() failed");
        return RAP_ERROR;
    }

    if (ready == 0) {
        if (timer != RAP_TIMER_INFINITE) {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "poll() returned no events without timeout");
        return RAP_ERROR;
    }

    for (i = 0; i < nevents && ready; i++) {

        revents = event_list[i].revents;

#if 1
        rap_log_debug4(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                       i, event_list[i].fd, event_list[i].events, revents);
#else
        if (revents) {
            rap_log_debug4(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                           i, event_list[i].fd, event_list[i].events, revents);
        }
#endif

        if (revents & POLLNVAL) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "poll() error fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "strange poll() events fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (event_list[i].fd == -1) {
            /*
             * the disabled event, a workaround for our possible bug,
             * see the comment below
             */
            continue;
        }

        c = rap_cycle->files[event_list[i].fd];

        if (c->fd == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0, "unexpected event");

            /*
             * it is certainly our fault and it should be investigated,
             * in the meantime we disable this event to avoid a CPU spinning
             */

            if (i == nevents - 1) {
                nevents--;
            } else {
                event_list[i].fd = -1;
            }

            continue;
        }

        if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

            /*
             * if the error events were returned, add POLLIN and POLLOUT
             * to handle the events at least in one active handler
             */

            revents |= POLLIN|POLLOUT;
        }

        found = 0;

        if ((revents & POLLIN) && c->read->active) {
            found = 1;

            ev = c->read;
            ev->ready = 1;
            ev->available = -1;

            queue = ev->accept ? &rap_posted_accept_events
                               : &rap_posted_events;

            rap_post_event(ev, queue);
        }

        if ((revents & POLLOUT) && c->write->active) {
            found = 1;

            ev = c->write;
            ev->ready = 1;

            rap_post_event(ev, &rap_posted_events);
        }

        if (found) {
            ready--;
            continue;
        }
    }

    if (ready != 0) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, 0, "poll ready != events");
    }

    return RAP_OK;
}


static char *
rap_poll_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_event_conf_t  *ecf;

    ecf = rap_event_get_conf(cycle->conf_ctx, rap_event_core_module);

    if (ecf->use != rap_poll_module.ctx_index) {
        return RAP_CONF_OK;
    }

    return RAP_CONF_OK;
}
