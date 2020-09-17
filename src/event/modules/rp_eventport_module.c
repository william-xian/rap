
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if (RP_TEST_BUILD_EVENTPORT)

#define ushort_t  u_short
#define uint_t    u_int

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME          0
typedef int     clockid_t;
typedef void *  timer_t;
#elif (RP_DARWIN)
typedef void *  timer_t;
#endif

/* Solaris declarations */

#define PORT_SOURCE_AIO         1
#define PORT_SOURCE_TIMER       2
#define PORT_SOURCE_USER        3
#define PORT_SOURCE_FD          4
#define PORT_SOURCE_ALERT       5
#define PORT_SOURCE_MQ          6

#ifndef ETIME
#define ETIME                   64
#endif

#define SIGEV_PORT              4

typedef struct {
    int         portev_events;  /* event data is source specific */
    ushort_t    portev_source;  /* event source */
    ushort_t    portev_pad;     /* port internal use */
    uintptr_t   portev_object;  /* source specific object */
    void       *portev_user;    /* user cookie */
} port_event_t;

typedef struct  port_notify {
    int         portnfy_port;   /* bind request(s) to port */
    void       *portnfy_user;   /* user defined */
} port_notify_t;

#if (__FreeBSD__ && __FreeBSD_version < 700005) || (RP_DARWIN)

typedef struct itimerspec {     /* definition per POSIX.4 */
    struct timespec it_interval;/* timer period */
    struct timespec it_value;   /* timer expiration */
} itimerspec_t;

#endif

int port_create(void);

int port_create(void)
{
    return -1;
}


int port_associate(int port, int source, uintptr_t object, int events,
    void *user);

int port_associate(int port, int source, uintptr_t object, int events,
    void *user)
{
    return -1;
}


int port_dissociate(int port, int source, uintptr_t object);

int port_dissociate(int port, int source, uintptr_t object)
{
    return -1;
}


int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout);

int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    struct timespec *timeout)
{
    return -1;
}

int port_send(int port, int events, void *user);

int port_send(int port, int events, void *user)
{
    return -1;
}


int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid);

int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
{
    return -1;
}


int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue);

int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
    return -1;
}


int timer_delete(timer_t timerid);

int timer_delete(timer_t timerid)
{
    return -1;
}

#endif


typedef struct {
    rp_uint_t  events;
} rp_eventport_conf_t;


static rp_int_t rp_eventport_init(rp_cycle_t *cycle, rp_msec_t timer);
static void rp_eventport_done(rp_cycle_t *cycle);
static rp_int_t rp_eventport_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_eventport_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_eventport_notify(rp_event_handler_pt handler);
static rp_int_t rp_eventport_process_events(rp_cycle_t *cycle,
    rp_msec_t timer, rp_uint_t flags);

static void *rp_eventport_create_conf(rp_cycle_t *cycle);
static char *rp_eventport_init_conf(rp_cycle_t *cycle, void *conf);

static int            ep = -1;
static port_event_t  *event_list;
static rp_uint_t     nevents;
static timer_t        event_timer = (timer_t) -1;
static rp_event_t    notify_event;

static rp_str_t      eventport_name = rp_string("eventport");


static rp_command_t  rp_eventport_commands[] = {

    { rp_string("eventport_events"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_eventport_conf_t, events),
      NULL },

      rp_null_command
};


static rp_event_module_t  rp_eventport_module_ctx = {
    &eventport_name,
    rp_eventport_create_conf,             /* create configuration */
    rp_eventport_init_conf,               /* init configuration */

    {
        rp_eventport_add_event,           /* add an event */
        rp_eventport_del_event,           /* delete an event */
        rp_eventport_add_event,           /* enable an event */
        rp_eventport_del_event,           /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        rp_eventport_notify,              /* trigger a notify */
        rp_eventport_process_events,      /* process the events */
        rp_eventport_init,                /* init the events */
        rp_eventport_done,                /* done the events */
    }

};

rp_module_t  rp_eventport_module = {
    RP_MODULE_V1,
    &rp_eventport_module_ctx,             /* module context */
    rp_eventport_commands,                /* module directives */
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
rp_eventport_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    port_notify_t          pn;
    struct itimerspec      its;
    struct sigevent        sev;
    rp_eventport_conf_t  *epcf;

    epcf = rp_event_get_conf(cycle->conf_ctx, rp_eventport_module);

    if (ep == -1) {
        ep = port_create();

        if (ep == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "port_create() failed");
            return RP_ERROR;
        }

        notify_event.active = 1;
        notify_event.log = cycle->log;
    }

    if (nevents < epcf->events) {
        if (event_list) {
            rp_free(event_list);
        }

        event_list = rp_alloc(sizeof(port_event_t) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return RP_ERROR;
        }
    }

    rp_event_flags = RP_USE_EVENTPORT_EVENT;

    if (timer) {
        rp_memzero(&pn, sizeof(port_notify_t));
        pn.portnfy_port = ep;

        rp_memzero(&sev, sizeof(struct sigevent));
        sev.sigev_notify = SIGEV_PORT;
        sev.sigev_value.sival_ptr = &pn;

        if (timer_create(CLOCK_REALTIME, &sev, &event_timer) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "timer_create() failed");
            return RP_ERROR;
        }

        its.it_interval.tv_sec = timer / 1000;
        its.it_interval.tv_nsec = (timer % 1000) * 1000000;
        its.it_value.tv_sec = timer / 1000;
        its.it_value.tv_nsec = (timer % 1000) * 1000000;

        if (timer_settime(event_timer, 0, &its, NULL) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "timer_settime() failed");
            return RP_ERROR;
        }

        rp_event_flags |= RP_USE_TIMER_EVENT;
    }

    nevents = epcf->events;

    rp_io = rp_os_io;

    rp_event_actions = rp_eventport_module_ctx.actions;

    return RP_OK;
}


static void
rp_eventport_done(rp_cycle_t *cycle)
{
    if (event_timer != (timer_t) -1) {
        if (timer_delete(event_timer) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "timer_delete() failed");
        }

        event_timer = (timer_t) -1;
    }

    if (close(ep) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "close() event port failed");
    }

    ep = -1;

    rp_free(event_list);

    event_list = NULL;
    nevents = 0;
}


static rp_int_t
rp_eventport_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_int_t          events, prev;
    rp_event_t       *e;
    rp_connection_t  *c;

    c = ev->data;

    events = event;

    if (event == RP_READ_EVENT) {
        e = c->write;
        prev = POLLOUT;
#if (RP_READ_EVENT != POLLIN)
        events = POLLIN;
#endif

    } else {
        e = c->read;
        prev = POLLIN;
#if (RP_WRITE_EVENT != POLLOUT)
        events = POLLOUT;
#endif
    }

    if (e->oneshot) {
        events |= prev;
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "eventport add event: fd:%d ev:%04Xi", c->fd, events);

    if (port_associate(ep, PORT_SOURCE_FD, c->fd, events,
                       (void *) ((uintptr_t) ev | ev->instance))
        == -1)
    {
        rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                      "port_associate() failed");
        return RP_ERROR;
    }

    ev->active = 1;
    ev->oneshot = 1;

    return RP_OK;
}


static rp_int_t
rp_eventport_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_event_t       *e;
    rp_connection_t  *c;

    /*
     * when the file descriptor is closed, the event port automatically
     * dissociates it from the port, so we do not need to dissociate explicitly
     * the event before the closing the file descriptor
     */

    if (flags & RP_CLOSE_EVENT) {
        ev->active = 0;
        ev->oneshot = 0;
        return RP_OK;
    }

    c = ev->data;

    if (event == RP_READ_EVENT) {
        e = c->write;
        event = POLLOUT;

    } else {
        e = c->read;
        event = POLLIN;
    }

    if (e->oneshot) {
        rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport change event: fd:%d ev:%04Xi", c->fd, event);

        if (port_associate(ep, PORT_SOURCE_FD, c->fd, event,
                           (void *) ((uintptr_t) ev | ev->instance))
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                          "port_associate() failed");
            return RP_ERROR;
        }

    } else {
        rp_log_debug1(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "eventport del event: fd:%d", c->fd);

        if (port_dissociate(ep, PORT_SOURCE_FD, c->fd) == -1) {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                          "port_dissociate() failed");
            return RP_ERROR;
        }
    }

    ev->active = 0;
    ev->oneshot = 0;

    return RP_OK;
}


static rp_int_t
rp_eventport_notify(rp_event_handler_pt handler)
{
    notify_event.handler = handler;

    if (port_send(ep, 0, &notify_event) != 0) {
        rp_log_error(RP_LOG_ALERT, notify_event.log, rp_errno,
                      "port_send() failed");
        return RP_ERROR;
    }

    return RP_OK;
}


static rp_int_t
rp_eventport_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags)
{
    int                 n, revents;
    u_int               events;
    rp_err_t           err;
    rp_int_t           instance;
    rp_uint_t          i, level;
    rp_event_t        *ev, *rev, *wev;
    rp_queue_t        *queue;
    rp_connection_t   *c;
    struct timespec     ts, *tp;

    if (timer == RP_TIMER_INFINITE) {
        tp = NULL;

    } else {
        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;
        tp = &ts;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventport timer: %M", timer);

    events = 1;

    n = port_getn(ep, event_list, (u_int) nevents, &events, tp);

    err = rp_errno;

    if (flags & RP_UPDATE_TIME) {
        rp_time_update();
    }

    if (n == -1) {
        if (err == ETIME) {
            if (timer != RP_TIMER_INFINITE) {
                return RP_OK;
            }

            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "port_getn() returned no events without timeout");
            return RP_ERROR;
        }

        level = (err == RP_EINTR) ? RP_LOG_INFO : RP_LOG_ALERT;
        rp_log_error(level, cycle->log, err, "port_getn() failed");
        return RP_ERROR;
    }

    if (events == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "port_getn() returned no events without timeout");
        return RP_ERROR;
    }

    for (i = 0; i < events; i++) {

        if (event_list[i].portev_source == PORT_SOURCE_TIMER) {
            rp_time_update();
            continue;
        }

        ev = event_list[i].portev_user;

        switch (event_list[i].portev_source) {

        case PORT_SOURCE_FD:

            instance = (uintptr_t) ev & 1;
            ev = (rp_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "eventport: stale event %p", ev);
                continue;
            }

            revents = event_list[i].portev_events;

            rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "eventport: fd:%d, ev:%04Xd",
                           (int) event_list[i].portev_object, revents);

            if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
                rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "port_getn() error fd:%d ev:%04Xd",
                               (int) event_list[i].portev_object, revents);
            }

            if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
                rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                              "strange port_getn() events fd:%d ev:%04Xd",
                              (int) event_list[i].portev_object, revents);
            }

            if (revents & (POLLERR|POLLHUP|POLLNVAL)) {

                /*
                 * if the error events were returned, add POLLIN and POLLOUT
                 * to handle the events at least in one active handler
                 */

                revents |= POLLIN|POLLOUT;
            }

            c = ev->data;
            rev = c->read;
            wev = c->write;

            rev->active = 0;
            wev->active = 0;

            if (revents & POLLIN) {
                rev->ready = 1;
                rev->available = -1;

                if (flags & RP_POST_EVENTS) {
                    queue = rev->accept ? &rp_posted_accept_events
                                        : &rp_posted_events;

                    rp_post_event(rev, queue);

                } else {
                    rev->handler(rev);

                    if (ev->closed || ev->instance != instance) {
                        continue;
                    }
                }

                if (rev->accept) {
                    if (rp_use_accept_mutex) {
                        rp_accept_events = 1;
                        continue;
                    }

                    if (port_associate(ep, PORT_SOURCE_FD, c->fd, POLLIN,
                                       (void *) ((uintptr_t) ev | ev->instance))
                        == -1)
                    {
                        rp_log_error(RP_LOG_ALERT, ev->log, rp_errno,
                                      "port_associate() failed");
                        return RP_ERROR;
                    }
                }
            }

            if (revents & POLLOUT) {
                wev->ready = 1;

                if (flags & RP_POST_EVENTS) {
                    rp_post_event(wev, &rp_posted_events);

                } else {
                    wev->handler(wev);
                }
            }

            continue;

        case PORT_SOURCE_USER:

            ev->handler(ev);

            continue;

        default:
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "unexpected eventport object %d",
                          (int) event_list[i].portev_object);
            continue;
        }
    }

    return RP_OK;
}


static void *
rp_eventport_create_conf(rp_cycle_t *cycle)
{
    rp_eventport_conf_t  *epcf;

    epcf = rp_palloc(cycle->pool, sizeof(rp_eventport_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = RP_CONF_UNSET;

    return epcf;
}


static char *
rp_eventport_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_eventport_conf_t *epcf = conf;

    rp_conf_init_uint_value(epcf->events, 32);

    return RP_CONF_OK;
}
