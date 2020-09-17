
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


static rp_int_t rp_poll_init(rp_cycle_t *cycle, rp_msec_t timer);
static void rp_poll_done(rp_cycle_t *cycle);
static rp_int_t rp_poll_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_poll_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_poll_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags);
static char *rp_poll_init_conf(rp_cycle_t *cycle, void *conf);


static struct pollfd  *event_list;
static rp_uint_t      nevents;


static rp_str_t           poll_name = rp_string("poll");

static rp_event_module_t  rp_poll_module_ctx = {
    &poll_name,
    NULL,                                  /* create configuration */
    rp_poll_init_conf,                    /* init configuration */

    {
        rp_poll_add_event,                /* add an event */
        rp_poll_del_event,                /* delete an event */
        rp_poll_add_event,                /* enable an event */
        rp_poll_del_event,                /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rp_poll_process_events,           /* process the events */
        rp_poll_init,                     /* init the events */
        rp_poll_done                      /* done the events */
    }

};

rp_module_t  rp_poll_module = {
    RP_MODULE_V1,
    &rp_poll_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
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
rp_poll_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    struct pollfd   *list;

    if (event_list == NULL) {
        nevents = 0;
    }

    if (rp_process >= RP_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        list = rp_alloc(sizeof(struct pollfd) * cycle->connection_n,
                         cycle->log);
        if (list == NULL) {
            return RP_ERROR;
        }

        if (event_list) {
            rp_memcpy(list, event_list, sizeof(struct pollfd) * nevents);
            rp_free(event_list);
        }

        event_list = list;
    }

    rp_io = rp_os_io;

    rp_event_actions = rp_poll_module_ctx.actions;

    rp_event_flags = RP_USE_LEVEL_EVENT|RP_USE_FD_EVENT;

    return RP_OK;
}


static void
rp_poll_done(rp_cycle_t *cycle)
{
    rp_free(event_list);

    event_list = NULL;
}


static rp_int_t
rp_poll_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_event_t       *e;
    rp_connection_t  *c;

    c = ev->data;

    ev->active = 1;

    if (ev->index != RP_INVALID_INDEX) {
        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already set", c->fd, event);
        return RP_OK;
    }

    if (event == RP_READ_EVENT) {
        e = c->write;
#if (RP_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (RP_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll add event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == RP_INVALID_INDEX) {
        event_list[nevents].fd = c->fd;
        event_list[nevents].events = (short) event;
        event_list[nevents].revents = 0;

        ev->index = nevents;
        nevents++;

    } else {
        rp_log_debug1(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll add index: %i", e->index);

        event_list[e->index].events |= (short) event;
        ev->index = e->index;
    }

    return RP_OK;
}


static rp_int_t
rp_poll_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_event_t       *e;
    rp_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == RP_INVALID_INDEX) {
        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "poll event fd:%d ev:%i is already deleted",
                      c->fd, event);
        return RP_OK;
    }

    if (event == RP_READ_EVENT) {
        e = c->write;
#if (RP_READ_EVENT != POLLIN)
        event = POLLIN;
#endif

    } else {
        e = c->read;
#if (RP_WRITE_EVENT != POLLOUT)
        event = POLLOUT;
#endif
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "poll del event: fd:%d ev:%i", c->fd, event);

    if (e == NULL || e->index == RP_INVALID_INDEX) {
        nevents--;

        if (ev->index < nevents) {

            rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                           "index: copy event %ui to %i", nevents, ev->index);

            event_list[ev->index] = event_list[nevents];

            c = rp_cycle->files[event_list[nevents].fd];

            if (c->fd == -1) {
                rp_log_error(RP_LOG_ALERT, ev->log, 0,
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
        rp_log_debug1(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "poll del index: %i", e->index);

        event_list[e->index].events &= (short) ~event;
    }

    ev->index = RP_INVALID_INDEX;

    return RP_OK;
}


static rp_int_t
rp_poll_process_events(rp_cycle_t *cycle, rp_msec_t timer, rp_uint_t flags)
{
    int                 ready, revents;
    rp_err_t           err;
    rp_uint_t          i, found, level;
    rp_event_t        *ev;
    rp_queue_t        *queue;
    rp_connection_t   *c;

    /* RP_TIMER_INFINITE == INFTIM */

#if (RP_DEBUG0)
    if (cycle->log->log_level & RP_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            rp_log_debug3(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd",
                           i, event_list[i].fd, event_list[i].events);
        }
    }
#endif

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %M", timer);

    ready = poll(event_list, (u_int) nevents, (int) timer);

    err = (ready == -1) ? rp_errno : 0;

    if (flags & RP_UPDATE_TIME || rp_event_timer_alarm) {
        rp_time_update();
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "poll ready %d of %ui", ready, nevents);

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

        rp_log_error(level, cycle->log, err, "poll() failed");
        return RP_ERROR;
    }

    if (ready == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "poll() returned no events without timeout");
        return RP_ERROR;
    }

    for (i = 0; i < nevents && ready; i++) {

        revents = event_list[i].revents;

#if 1
        rp_log_debug4(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                       i, event_list[i].fd, event_list[i].events, revents);
#else
        if (revents) {
            rp_log_debug4(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
                           i, event_list[i].fd, event_list[i].events, revents);
        }
#endif

        if (revents & POLLNVAL) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "poll() error fd:%d ev:%04Xd rev:%04Xd",
                          event_list[i].fd, event_list[i].events, revents);
        }

        if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
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

        c = rp_cycle->files[event_list[i].fd];

        if (c->fd == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0, "unexpected event");

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

            queue = ev->accept ? &rp_posted_accept_events
                               : &rp_posted_events;

            rp_post_event(ev, queue);
        }

        if ((revents & POLLOUT) && c->write->active) {
            found = 1;

            ev = c->write;
            ev->ready = 1;

            rp_post_event(ev, &rp_posted_events);
        }

        if (found) {
            ready--;
            continue;
        }
    }

    if (ready != 0) {
        rp_log_error(RP_LOG_ALERT, cycle->log, 0, "poll ready != events");
    }

    return RP_OK;
}


static char *
rp_poll_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_event_conf_t  *ecf;

    ecf = rp_event_get_conf(cycle->conf_ctx, rp_event_core_module);

    if (ecf->use != rp_poll_module.ctx_index) {
        return RP_CONF_OK;
    }

    return RP_CONF_OK;
}
