
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


typedef struct {
    rp_uint_t  changes;
    rp_uint_t  events;
} rp_kqueue_conf_t;


static rp_int_t rp_kqueue_init(rp_cycle_t *cycle, rp_msec_t timer);
#ifdef EVFILT_USER
static rp_int_t rp_kqueue_notify_init(rp_log_t *log);
#endif
static void rp_kqueue_done(rp_cycle_t *cycle);
static rp_int_t rp_kqueue_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_kqueue_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_kqueue_set_event(rp_event_t *ev, rp_int_t filter,
    rp_uint_t flags);
#ifdef EVFILT_USER
static rp_int_t rp_kqueue_notify(rp_event_handler_pt handler);
#endif
static rp_int_t rp_kqueue_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags);
static rp_inline void rp_kqueue_dump_event(rp_log_t *log,
    struct kevent *kev);

static void *rp_kqueue_create_conf(rp_cycle_t *cycle);
static char *rp_kqueue_init_conf(rp_cycle_t *cycle, void *conf);


int                    rp_kqueue = -1;

static struct kevent  *change_list;
static struct kevent  *event_list;
static rp_uint_t      max_changes, nchanges, nevents;

#ifdef EVFILT_USER
static rp_event_t     notify_event;
static struct kevent   notify_kev;
#endif


static rp_str_t      kqueue_name = rp_string("kqueue");

static rp_command_t  rp_kqueue_commands[] = {

    { rp_string("kqueue_changes"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_kqueue_conf_t, changes),
      NULL },

    { rp_string("kqueue_events"),
      RP_EVENT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_kqueue_conf_t, events),
      NULL },

      rp_null_command
};


static rp_event_module_t  rp_kqueue_module_ctx = {
    &kqueue_name,
    rp_kqueue_create_conf,                /* create configuration */
    rp_kqueue_init_conf,                  /* init configuration */

    {
        rp_kqueue_add_event,              /* add an event */
        rp_kqueue_del_event,              /* delete an event */
        rp_kqueue_add_event,              /* enable an event */
        rp_kqueue_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
#ifdef EVFILT_USER
        rp_kqueue_notify,                 /* trigger a notify */
#else
        NULL,                              /* trigger a notify */
#endif
        rp_kqueue_process_events,         /* process the events */
        rp_kqueue_init,                   /* init the events */
        rp_kqueue_done                    /* done the events */
    }

};

rp_module_t  rp_kqueue_module = {
    RP_MODULE_V1,
    &rp_kqueue_module_ctx,                /* module context */
    rp_kqueue_commands,                   /* module directives */
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
rp_kqueue_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    rp_kqueue_conf_t  *kcf;
    struct timespec     ts;
#if (RP_HAVE_TIMER_EVENT)
    struct kevent       kev;
#endif

    kcf = rp_event_get_conf(cycle->conf_ctx, rp_kqueue_module);

    if (rp_kqueue == -1) {
        rp_kqueue = kqueue();

        if (rp_kqueue == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "kqueue() failed");
            return RP_ERROR;
        }

#ifdef EVFILT_USER
        if (rp_kqueue_notify_init(cycle->log) != RP_OK) {
            return RP_ERROR;
        }
#endif
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(rp_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                              "kevent() failed");
                return RP_ERROR;
            }
            nchanges = 0;
        }

        if (change_list) {
            rp_free(change_list);
        }

        change_list = rp_alloc(kcf->changes * sizeof(struct kevent),
                                cycle->log);
        if (change_list == NULL) {
            return RP_ERROR;
        }
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            rp_free(event_list);
        }

        event_list = rp_alloc(kcf->events * sizeof(struct kevent), cycle->log);
        if (event_list == NULL) {
            return RP_ERROR;
        }
    }

    rp_event_flags = RP_USE_ONESHOT_EVENT
                      |RP_USE_KQUEUE_EVENT
                      |RP_USE_VNODE_EVENT;

#if (RP_HAVE_TIMER_EVENT)

    if (timer) {
        kev.ident = 0;
        kev.filter = EVFILT_TIMER;
        kev.flags = EV_ADD|EV_ENABLE;
        kev.fflags = 0;
        kev.data = timer;
        kev.udata = 0;

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(rp_kqueue, &kev, 1, NULL, 0, &ts) == -1) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          "kevent(EVFILT_TIMER) failed");
            return RP_ERROR;
        }

        rp_event_flags |= RP_USE_TIMER_EVENT;
    }

#endif

#if (RP_HAVE_CLEAR_EVENT)
    rp_event_flags |= RP_USE_CLEAR_EVENT;
#else
    rp_event_flags |= RP_USE_LEVEL_EVENT;
#endif

#if (RP_HAVE_LOWAT_EVENT)
    rp_event_flags |= RP_USE_LOWAT_EVENT;
#endif

    nevents = kcf->events;

    rp_io = rp_os_io;

    rp_event_actions = rp_kqueue_module_ctx.actions;

    return RP_OK;
}


#ifdef EVFILT_USER

static rp_int_t
rp_kqueue_notify_init(rp_log_t *log)
{
    notify_kev.ident = 0;
    notify_kev.filter = EVFILT_USER;
    notify_kev.data = 0;
    notify_kev.flags = EV_ADD|EV_CLEAR;
    notify_kev.fflags = 0;
    notify_kev.udata = 0;

    if (kevent(rp_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "kevent(EVFILT_USER, EV_ADD) failed");
        return RP_ERROR;
    }

    notify_event.active = 1;
    notify_event.log = log;

    notify_kev.flags = 0;
    notify_kev.fflags = NOTE_TRIGGER;
    notify_kev.udata = RP_KQUEUE_UDATA_T ((uintptr_t) &notify_event);

    return RP_OK;
}

#endif


static void
rp_kqueue_done(rp_cycle_t *cycle)
{
    if (close(rp_kqueue) == -1) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      "kqueue close() failed");
    }

    rp_kqueue = -1;

    rp_free(change_list);
    rp_free(event_list);

    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static rp_int_t
rp_kqueue_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_int_t          rc;
#if 0
    rp_event_t       *e;
    rp_connection_t  *c;
#endif

    ev->active = 1;
    ev->disabled = 0;
    ev->oneshot = (flags & RP_ONESHOT_EVENT) ? 1 : 0;

#if 0

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        if (change_list[ev->index].flags == EV_DISABLE) {

            /*
             * if the EV_DISABLE is still not passed to a kernel
             * we will not pass it
             */

            rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                           "kevent activated: %d: ft:%i",
                           rp_event_ident(ev->data), event);

            if (ev->index < --nchanges) {
                e = (rp_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
                change_list[ev->index] = change_list[nchanges];
                e->index = ev->index;
            }

            return RP_OK;
        }

        c = ev->data;

        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        return RP_ERROR;
    }

#endif

    rc = rp_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);

    return rc;
}


static rp_int_t
rp_kqueue_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_int_t     rc;
    rp_event_t  *e;

    ev->active = 0;
    ev->disabled = 0;

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent deleted: %d: ft:%i",
                       rp_event_ident(ev->data), event);

        /* if the event is still not passed to a kernel we will not pass it */

        nchanges--;

        if (ev->index < nchanges) {
            e = (rp_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return RP_OK;
    }

    /*
     * when the file descriptor is closed the kqueue automatically deletes
     * its filters so we do not need to delete explicitly the event
     * before the closing the file descriptor.
     */

    if (flags & RP_CLOSE_EVENT) {
        return RP_OK;
    }

    if (flags & RP_DISABLE_EVENT) {
        ev->disabled = 1;

    } else {
        flags |= EV_DELETE;
    }

    rc = rp_kqueue_set_event(ev, event, flags);

    return rc;
}


static rp_int_t
rp_kqueue_set_event(rp_event_t *ev, rp_int_t filter, rp_uint_t flags)
{
    struct kevent     *kev;
    struct timespec    ts;
    rp_connection_t  *c;

    c = ev->data;

    rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "kevent set event: %d: ft:%i fl:%04Xi",
                   c->fd, filter, flags);

    if (nchanges >= max_changes) {
        rp_log_error(RP_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(rp_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno, "kevent() failed");
            return RP_ERROR;
        }

        nchanges = 0;
    }

    kev = &change_list[nchanges];

    kev->ident = c->fd;
    kev->filter = (short) filter;
    kev->flags = (u_short) flags;
    kev->udata = RP_KQUEUE_UDATA_T ((uintptr_t) ev | ev->instance);

    if (filter == EVFILT_VNODE) {
        kev->fflags = NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND
                                 |NOTE_ATTRIB|NOTE_RENAME
#if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
    || __FreeBSD_version >= 500018
                                 |NOTE_REVOKE
#endif
                      ;
        kev->data = 0;

    } else {
#if (RP_HAVE_LOWAT_EVENT)
        if (flags & RP_LOWAT_EVENT) {
            kev->fflags = NOTE_LOWAT;
            kev->data = ev->available;

        } else {
            kev->fflags = 0;
            kev->data = 0;
        }
#else
        kev->fflags = 0;
        kev->data = 0;
#endif
    }

    ev->index = nchanges;
    nchanges++;

    if (flags & RP_FLUSH_EVENT) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, 0, "kevent flush");

        if (kevent(rp_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, ev->log, rp_errno, "kevent() failed");
            return RP_ERROR;
        }

        nchanges = 0;
    }

    return RP_OK;
}


#ifdef EVFILT_USER

static rp_int_t
rp_kqueue_notify(rp_event_handler_pt handler)
{
    notify_event.handler = handler;

    if (kevent(rp_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        rp_log_error(RP_LOG_ALERT, notify_event.log, rp_errno,
                      "kevent(EVFILT_USER, NOTE_TRIGGER) failed");
        return RP_ERROR;
    }

    return RP_OK;
}

#endif


static rp_int_t
rp_kqueue_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags)
{
    int               events, n;
    rp_int_t         i, instance;
    rp_uint_t        level;
    rp_err_t         err;
    rp_event_t      *ev;
    rp_queue_t      *queue;
    struct timespec   ts, *tp;

    n = (int) nchanges;
    nchanges = 0;

    if (timer == RP_TIMER_INFINITE) {
        tp = NULL;

    } else {

        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;

        /*
         * 64-bit Darwin kernel has the bug: kernel level ts.tv_nsec is
         * the int32_t while user level ts.tv_nsec is the long (64-bit),
         * so on the big endian PowerPC all nanoseconds are lost.
         */

#if (RP_DARWIN_KEVENT_BUG)
        ts.tv_nsec <<= 32;
#endif

        tp = &ts;
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent timer: %M, changes: %d", timer, n);

    events = kevent(rp_kqueue, change_list, n, event_list, (int) nevents, tp);

    err = (events == -1) ? rp_errno : 0;

    if (flags & RP_UPDATE_TIME || rp_event_timer_alarm) {
        rp_time_update();
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent events: %d", events);

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

        rp_log_error(level, cycle->log, err, "kevent() failed");
        return RP_ERROR;
    }

    if (events == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "kevent() returned no events without timeout");
        return RP_ERROR;
    }

    for (i = 0; i < events; i++) {

        rp_kqueue_dump_event(cycle->log, &event_list[i]);

        if (event_list[i].flags & EV_ERROR) {
            rp_log_error(RP_LOG_ALERT, cycle->log, event_list[i].data,
                          "kevent() error on %d filter:%d flags:%04Xd",
                          (int) event_list[i].ident, event_list[i].filter,
                          event_list[i].flags);
            continue;
        }

#if (RP_HAVE_TIMER_EVENT)

        if (event_list[i].filter == EVFILT_TIMER) {
            rp_time_update();
            continue;
        }

#endif

        ev = (rp_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (rp_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "kevent: stale event %p", ev);
                continue;
            }

            if (ev->log && (ev->log->log_level & RP_LOG_DEBUG_CONNECTION)) {
                rp_kqueue_dump_event(ev->log, &event_list[i]);
            }

            if (ev->oneshot) {
                ev->active = 0;
            }

            ev->available = event_list[i].data;

            if (event_list[i].flags & EV_EOF) {
                ev->pending_eof = 1;
                ev->kq_errno = event_list[i].fflags;
            }

            ev->ready = 1;

            break;

        case EVFILT_VNODE:
            ev->kq_vnode = 1;

            break;

        case EVFILT_AIO:
            ev->complete = 1;
            ev->ready = 1;

            break;

#ifdef EVFILT_USER
        case EVFILT_USER:
            break;
#endif

        default:
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "unexpected kevent() filter %d",
                          event_list[i].filter);
            continue;
        }

        if (flags & RP_POST_EVENTS) {
            queue = ev->accept ? &rp_posted_accept_events
                               : &rp_posted_events;

            rp_post_event(ev, queue);

            continue;
        }

        ev->handler(ev);
    }

    return RP_OK;
}


static rp_inline void
rp_kqueue_dump_event(rp_log_t *log, struct kevent *kev)
{
    if (kev->ident > 0x8000000 && kev->ident != (unsigned) -1) {
        rp_log_debug6(RP_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %p: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (void *) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);

    } else {
        rp_log_debug6(RP_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %d: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (int) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);
    }
}


static void *
rp_kqueue_create_conf(rp_cycle_t *cycle)
{
    rp_kqueue_conf_t  *kcf;

    kcf = rp_palloc(cycle->pool, sizeof(rp_kqueue_conf_t));
    if (kcf == NULL) {
        return NULL;
    }

    kcf->changes = RP_CONF_UNSET;
    kcf->events = RP_CONF_UNSET;

    return kcf;
}


static char *
rp_kqueue_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_kqueue_conf_t *kcf = conf;

    rp_conf_init_uint_value(kcf->changes, 512);
    rp_conf_init_uint_value(kcf->events, 512);

    return RP_CONF_OK;
}
