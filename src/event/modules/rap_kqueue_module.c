
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


typedef struct {
    rap_uint_t  changes;
    rap_uint_t  events;
} rap_kqueue_conf_t;


static rap_int_t rap_kqueue_init(rap_cycle_t *cycle, rap_msec_t timer);
#ifdef EVFILT_USER
static rap_int_t rap_kqueue_notify_init(rap_log_t *log);
#endif
static void rap_kqueue_done(rap_cycle_t *cycle);
static rap_int_t rap_kqueue_add_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_kqueue_del_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_kqueue_set_event(rap_event_t *ev, rap_int_t filter,
    rap_uint_t flags);
#ifdef EVFILT_USER
static rap_int_t rap_kqueue_notify(rap_event_handler_pt handler);
#endif
static rap_int_t rap_kqueue_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags);
static rap_inline void rap_kqueue_dump_event(rap_log_t *log,
    struct kevent *kev);

static void *rap_kqueue_create_conf(rap_cycle_t *cycle);
static char *rap_kqueue_init_conf(rap_cycle_t *cycle, void *conf);


int                    rap_kqueue = -1;

static struct kevent  *change_list;
static struct kevent  *event_list;
static rap_uint_t      max_changes, nchanges, nevents;

#ifdef EVFILT_USER
static rap_event_t     notify_event;
static struct kevent   notify_kev;
#endif


static rap_str_t      kqueue_name = rap_string("kqueue");

static rap_command_t  rap_kqueue_commands[] = {

    { rap_string("kqueue_changes"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_kqueue_conf_t, changes),
      NULL },

    { rap_string("kqueue_events"),
      RAP_EVENT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_kqueue_conf_t, events),
      NULL },

      rap_null_command
};


static rap_event_module_t  rap_kqueue_module_ctx = {
    &kqueue_name,
    rap_kqueue_create_conf,                /* create configuration */
    rap_kqueue_init_conf,                  /* init configuration */

    {
        rap_kqueue_add_event,              /* add an event */
        rap_kqueue_del_event,              /* delete an event */
        rap_kqueue_add_event,              /* enable an event */
        rap_kqueue_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
#ifdef EVFILT_USER
        rap_kqueue_notify,                 /* trigger a notify */
#else
        NULL,                              /* trigger a notify */
#endif
        rap_kqueue_process_events,         /* process the events */
        rap_kqueue_init,                   /* init the events */
        rap_kqueue_done                    /* done the events */
    }

};

rap_module_t  rap_kqueue_module = {
    RAP_MODULE_V1,
    &rap_kqueue_module_ctx,                /* module context */
    rap_kqueue_commands,                   /* module directives */
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
rap_kqueue_init(rap_cycle_t *cycle, rap_msec_t timer)
{
    rap_kqueue_conf_t  *kcf;
    struct timespec     ts;
#if (RAP_HAVE_TIMER_EVENT)
    struct kevent       kev;
#endif

    kcf = rap_event_get_conf(cycle->conf_ctx, rap_kqueue_module);

    if (rap_kqueue == -1) {
        rap_kqueue = kqueue();

        if (rap_kqueue == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "kqueue() failed");
            return RAP_ERROR;
        }

#ifdef EVFILT_USER
        if (rap_kqueue_notify_init(cycle->log) != RAP_OK) {
            return RAP_ERROR;
        }
#endif
    }

    if (max_changes < kcf->changes) {
        if (nchanges) {
            ts.tv_sec = 0;
            ts.tv_nsec = 0;

            if (kevent(rap_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                              "kevent() failed");
                return RAP_ERROR;
            }
            nchanges = 0;
        }

        if (change_list) {
            rap_free(change_list);
        }

        change_list = rap_alloc(kcf->changes * sizeof(struct kevent),
                                cycle->log);
        if (change_list == NULL) {
            return RAP_ERROR;
        }
    }

    max_changes = kcf->changes;

    if (nevents < kcf->events) {
        if (event_list) {
            rap_free(event_list);
        }

        event_list = rap_alloc(kcf->events * sizeof(struct kevent), cycle->log);
        if (event_list == NULL) {
            return RAP_ERROR;
        }
    }

    rap_event_flags = RAP_USE_ONESHOT_EVENT
                      |RAP_USE_KQUEUE_EVENT
                      |RAP_USE_VNODE_EVENT;

#if (RAP_HAVE_TIMER_EVENT)

    if (timer) {
        kev.ident = 0;
        kev.filter = EVFILT_TIMER;
        kev.flags = EV_ADD|EV_ENABLE;
        kev.fflags = 0;
        kev.data = timer;
        kev.udata = 0;

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(rap_kqueue, &kev, 1, NULL, 0, &ts) == -1) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          "kevent(EVFILT_TIMER) failed");
            return RAP_ERROR;
        }

        rap_event_flags |= RAP_USE_TIMER_EVENT;
    }

#endif

#if (RAP_HAVE_CLEAR_EVENT)
    rap_event_flags |= RAP_USE_CLEAR_EVENT;
#else
    rap_event_flags |= RAP_USE_LEVEL_EVENT;
#endif

#if (RAP_HAVE_LOWAT_EVENT)
    rap_event_flags |= RAP_USE_LOWAT_EVENT;
#endif

    nevents = kcf->events;

    rap_io = rap_os_io;

    rap_event_actions = rap_kqueue_module_ctx.actions;

    return RAP_OK;
}


#ifdef EVFILT_USER

static rap_int_t
rap_kqueue_notify_init(rap_log_t *log)
{
    notify_kev.ident = 0;
    notify_kev.filter = EVFILT_USER;
    notify_kev.data = 0;
    notify_kev.flags = EV_ADD|EV_CLEAR;
    notify_kev.fflags = 0;
    notify_kev.udata = 0;

    if (kevent(rap_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "kevent(EVFILT_USER, EV_ADD) failed");
        return RAP_ERROR;
    }

    notify_event.active = 1;
    notify_event.log = log;

    notify_kev.flags = 0;
    notify_kev.fflags = NOTE_TRIGGER;
    notify_kev.udata = RAP_KQUEUE_UDATA_T ((uintptr_t) &notify_event);

    return RAP_OK;
}

#endif


static void
rap_kqueue_done(rap_cycle_t *cycle)
{
    if (close(rap_kqueue) == -1) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      "kqueue close() failed");
    }

    rap_kqueue = -1;

    rap_free(change_list);
    rap_free(event_list);

    change_list = NULL;
    event_list = NULL;
    max_changes = 0;
    nchanges = 0;
    nevents = 0;
}


static rap_int_t
rap_kqueue_add_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_int_t          rc;
#if 0
    rap_event_t       *e;
    rap_connection_t  *c;
#endif

    ev->active = 1;
    ev->disabled = 0;
    ev->oneshot = (flags & RAP_ONESHOT_EVENT) ? 1 : 0;

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

            rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                           "kevent activated: %d: ft:%i",
                           rap_event_ident(ev->data), event);

            if (ev->index < --nchanges) {
                e = (rap_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
                change_list[ev->index] = change_list[nchanges];
                e->index = ev->index;
            }

            return RAP_OK;
        }

        c = ev->data;

        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "previous event on #%d were not passed in kernel", c->fd);

        return RAP_ERROR;
    }

#endif

    rc = rap_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);

    return rc;
}


static rap_int_t
rap_kqueue_del_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_int_t     rc;
    rap_event_t  *e;

    ev->active = 0;
    ev->disabled = 0;

    if (ev->index < nchanges
        && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
            == (uintptr_t) ev)
    {
        rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                       "kevent deleted: %d: ft:%i",
                       rap_event_ident(ev->data), event);

        /* if the event is still not passed to a kernel we will not pass it */

        nchanges--;

        if (ev->index < nchanges) {
            e = (rap_event_t *)
                    ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
            change_list[ev->index] = change_list[nchanges];
            e->index = ev->index;
        }

        return RAP_OK;
    }

    /*
     * when the file descriptor is closed the kqueue automatically deletes
     * its filters so we do not need to delete explicitly the event
     * before the closing the file descriptor.
     */

    if (flags & RAP_CLOSE_EVENT) {
        return RAP_OK;
    }

    if (flags & RAP_DISABLE_EVENT) {
        ev->disabled = 1;

    } else {
        flags |= EV_DELETE;
    }

    rc = rap_kqueue_set_event(ev, event, flags);

    return rc;
}


static rap_int_t
rap_kqueue_set_event(rap_event_t *ev, rap_int_t filter, rap_uint_t flags)
{
    struct kevent     *kev;
    struct timespec    ts;
    rap_connection_t  *c;

    c = ev->data;

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "kevent set event: %d: ft:%i fl:%04Xi",
                   c->fd, filter, flags);

    if (nchanges >= max_changes) {
        rap_log_error(RAP_LOG_WARN, ev->log, 0,
                      "kqueue change list is filled up");

        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        if (kevent(rap_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno, "kevent() failed");
            return RAP_ERROR;
        }

        nchanges = 0;
    }

    kev = &change_list[nchanges];

    kev->ident = c->fd;
    kev->filter = (short) filter;
    kev->flags = (u_short) flags;
    kev->udata = RAP_KQUEUE_UDATA_T ((uintptr_t) ev | ev->instance);

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
#if (RAP_HAVE_LOWAT_EVENT)
        if (flags & RAP_LOWAT_EVENT) {
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

    if (flags & RAP_FLUSH_EVENT) {
        ts.tv_sec = 0;
        ts.tv_nsec = 0;

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, 0, "kevent flush");

        if (kevent(rap_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, ev->log, rap_errno, "kevent() failed");
            return RAP_ERROR;
        }

        nchanges = 0;
    }

    return RAP_OK;
}


#ifdef EVFILT_USER

static rap_int_t
rap_kqueue_notify(rap_event_handler_pt handler)
{
    notify_event.handler = handler;

    if (kevent(rap_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
        rap_log_error(RAP_LOG_ALERT, notify_event.log, rap_errno,
                      "kevent(EVFILT_USER, NOTE_TRIGGER) failed");
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static rap_int_t
rap_kqueue_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags)
{
    int               events, n;
    rap_int_t         i, instance;
    rap_uint_t        level;
    rap_err_t         err;
    rap_event_t      *ev;
    rap_queue_t      *queue;
    struct timespec   ts, *tp;

    n = (int) nchanges;
    nchanges = 0;

    if (timer == RAP_TIMER_INFINITE) {
        tp = NULL;

    } else {

        ts.tv_sec = timer / 1000;
        ts.tv_nsec = (timer % 1000) * 1000000;

        /*
         * 64-bit Darwin kernel has the bug: kernel level ts.tv_nsec is
         * the int32_t while user level ts.tv_nsec is the long (64-bit),
         * so on the big endian PowerPC all nanoseconds are lost.
         */

#if (RAP_DARWIN_KEVENT_BUG)
        ts.tv_nsec <<= 32;
#endif

        tp = &ts;
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent timer: %M, changes: %d", timer, n);

    events = kevent(rap_kqueue, change_list, n, event_list, (int) nevents, tp);

    err = (events == -1) ? rap_errno : 0;

    if (flags & RAP_UPDATE_TIME || rap_event_timer_alarm) {
        rap_time_update();
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "kevent events: %d", events);

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

        rap_log_error(level, cycle->log, err, "kevent() failed");
        return RAP_ERROR;
    }

    if (events == 0) {
        if (timer != RAP_TIMER_INFINITE) {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "kevent() returned no events without timeout");
        return RAP_ERROR;
    }

    for (i = 0; i < events; i++) {

        rap_kqueue_dump_event(cycle->log, &event_list[i]);

        if (event_list[i].flags & EV_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, event_list[i].data,
                          "kevent() error on %d filter:%d flags:%04Xd",
                          (int) event_list[i].ident, event_list[i].filter,
                          event_list[i].flags);
            continue;
        }

#if (RAP_HAVE_TIMER_EVENT)

        if (event_list[i].filter == EVFILT_TIMER) {
            rap_time_update();
            continue;
        }

#endif

        ev = (rap_event_t *) event_list[i].udata;

        switch (event_list[i].filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:

            instance = (uintptr_t) ev & 1;
            ev = (rap_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);

            if (ev->closed || ev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "kevent: stale event %p", ev);
                continue;
            }

            if (ev->log && (ev->log->log_level & RAP_LOG_DEBUG_CONNECTION)) {
                rap_kqueue_dump_event(ev->log, &event_list[i]);
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
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "unexpected kevent() filter %d",
                          event_list[i].filter);
            continue;
        }

        if (flags & RAP_POST_EVENTS) {
            queue = ev->accept ? &rap_posted_accept_events
                               : &rap_posted_events;

            rap_post_event(ev, queue);

            continue;
        }

        ev->handler(ev);
    }

    return RAP_OK;
}


static rap_inline void
rap_kqueue_dump_event(rap_log_t *log, struct kevent *kev)
{
    if (kev->ident > 0x8000000 && kev->ident != (unsigned) -1) {
        rap_log_debug6(RAP_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %p: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (void *) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);

    } else {
        rap_log_debug6(RAP_LOG_DEBUG_EVENT, log, 0,
                       "kevent: %d: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
                       (int) kev->ident, kev->filter,
                       kev->flags, kev->fflags,
                       (int) kev->data, kev->udata);
    }
}


static void *
rap_kqueue_create_conf(rap_cycle_t *cycle)
{
    rap_kqueue_conf_t  *kcf;

    kcf = rap_palloc(cycle->pool, sizeof(rap_kqueue_conf_t));
    if (kcf == NULL) {
        return NULL;
    }

    kcf->changes = RAP_CONF_UNSET;
    kcf->events = RAP_CONF_UNSET;

    return kcf;
}


static char *
rap_kqueue_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_kqueue_conf_t *kcf = conf;

    rap_conf_init_uint_value(kcf->changes, 512);
    rap_conf_init_uint_value(kcf->events, 512);

    return RAP_CONF_OK;
}
