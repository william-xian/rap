
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


static rp_int_t rp_select_init(rp_cycle_t *cycle, rp_msec_t timer);
static void rp_select_done(rp_cycle_t *cycle);
static rp_int_t rp_select_add_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_select_del_event(rp_event_t *ev, rp_int_t event,
    rp_uint_t flags);
static rp_int_t rp_select_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags);
static void rp_select_repair_fd_sets(rp_cycle_t *cycle);
static char *rp_select_init_conf(rp_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;
static fd_set         work_except_fd_set;

static rp_uint_t     max_read;
static rp_uint_t     max_write;
static rp_uint_t     nevents;

static rp_event_t  **event_index;


static rp_str_t           select_name = rp_string("select");

static rp_event_module_t  rp_select_module_ctx = {
    &select_name,
    NULL,                                  /* create configuration */
    rp_select_init_conf,                  /* init configuration */

    {
        rp_select_add_event,              /* add an event */
        rp_select_del_event,              /* delete an event */
        rp_select_add_event,              /* enable an event */
        rp_select_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rp_select_process_events,         /* process the events */
        rp_select_init,                   /* init the events */
        rp_select_done                    /* done the events */
    }

};

rp_module_t  rp_select_module = {
    RP_MODULE_V1,
    &rp_select_module_ctx,                /* module context */
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
rp_select_init(rp_cycle_t *cycle, rp_msec_t timer)
{
    rp_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (rp_process >= RP_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        index = rp_alloc(sizeof(rp_event_t *) * 2 * cycle->connection_n,
                          cycle->log);
        if (index == NULL) {
            return RP_ERROR;
        }

        if (event_index) {
            rp_memcpy(index, event_index, sizeof(rp_event_t *) * nevents);
            rp_free(event_index);
        }

        event_index = index;
    }

    rp_io = rp_os_io;

    rp_event_actions = rp_select_module_ctx.actions;

    rp_event_flags = RP_USE_LEVEL_EVENT;

    max_read = 0;
    max_write = 0;

    return RP_OK;
}


static void
rp_select_done(rp_cycle_t *cycle)
{
    rp_free(event_index);

    event_index = NULL;
}


static rp_int_t
rp_select_add_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_connection_t  *c;

    c = ev->data;

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "select add event fd:%d ev:%i", c->fd, event);

    if (ev->index != RP_INVALID_INDEX) {
        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%i is already set", c->fd, event);
        return RP_OK;
    }

    if ((event == RP_READ_EVENT && ev->write)
        || (event == RP_WRITE_EVENT && !ev->write))
    {
        rp_log_error(RP_LOG_ALERT, ev->log, 0,
                      "invalid select %s event fd:%d ev:%i",
                      ev->write ? "write" : "read", c->fd, event);
        return RP_ERROR;
    }

    if ((event == RP_READ_EVENT && max_read >= FD_SETSIZE)
        || (event == RP_WRITE_EVENT && max_write >= FD_SETSIZE))
    {
        rp_log_error(RP_LOG_ERR, ev->log, 0,
                      "maximum number of descriptors "
                      "supported by select() is %d", FD_SETSIZE);
        return RP_ERROR;
    }

    if (event == RP_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);
        max_read++;

    } else if (event == RP_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
        max_write++;
    }

    ev->active = 1;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return RP_OK;
}


static rp_int_t
rp_select_del_event(rp_event_t *ev, rp_int_t event, rp_uint_t flags)
{
    rp_event_t       *e;
    rp_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == RP_INVALID_INDEX) {
        return RP_OK;
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

    if (event == RP_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == RP_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
        max_write--;
    }

    if (ev->index < --nevents) {
        e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = RP_INVALID_INDEX;

    return RP_OK;
}


static rp_int_t
rp_select_process_events(rp_cycle_t *cycle, rp_msec_t timer,
    rp_uint_t flags)
{
    int                ready, nready;
    rp_err_t          err;
    rp_uint_t         i, found;
    rp_event_t       *ev;
    rp_queue_t       *queue;
    struct timeval     tv, *tp;
    rp_connection_t  *c;

#if (RP_DEBUG)
    if (cycle->log->log_level & RP_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            rp_log_debug2(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }
    }
#endif

    if (timer == RP_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timer / 1000);
        tv.tv_usec = (long) ((timer % 1000) * 1000);
        tp = &tv;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select timer: %M", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;
    work_except_fd_set = master_write_fd_set;

    if (max_read || max_write) {
        ready = select(0, &work_read_fd_set, &work_write_fd_set,
                       &work_except_fd_set, tp);

    } else {

        /*
         * Winsock select() requires that at least one descriptor set must be
         * be non-null, and any non-null descriptor set must contain at least
         * one handle to a socket.  Otherwise select() returns WSAEINVAL.
         */

        rp_msleep(timer);

        ready = 0;
    }

    err = (ready == -1) ? rp_socket_errno : 0;

    if (flags & RP_UPDATE_TIME) {
        rp_time_update();
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        rp_log_error(RP_LOG_ALERT, cycle->log, err, "select() failed");

        if (err == WSAENOTSOCK) {
            rp_select_repair_fd_sets(cycle);
        }

        return RP_ERROR;
    }

    if (ready == 0) {
        if (timer != RP_TIMER_INFINITE) {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return RP_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found++;
                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

            if (FD_ISSET(c->fd, &work_except_fd_set)) {
                found++;
                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select except %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found++;
                rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select read %d", c->fd);
            }
        }

        if (found) {
            ev->ready = 1;
            ev->available = -1;

            queue = ev->accept ? &rp_posted_accept_events
                               : &rp_posted_events;

            rp_post_event(ev, queue);

            nready += found;
        }
    }

    if (ready != nready) {
        rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                      "select ready != events: %d:%d", ready, nready);

        rp_select_repair_fd_sets(cycle);
    }

    return RP_OK;
}


static void
rp_select_repair_fd_sets(rp_cycle_t *cycle)
{
    int           n;
    u_int         i;
    socklen_t     len;
    rp_err_t     err;
    rp_socket_t  s;

    for (i = 0; i < master_read_fd_set.fd_count; i++) {

        s = master_read_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = rp_socket_errno;

            rp_log_error(RP_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (i = 0; i < master_write_fd_set.fd_count; i++) {

        s = master_write_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = rp_socket_errno;

            rp_log_error(RP_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }
}


static char *
rp_select_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_event_conf_t  *ecf;

    ecf = rp_event_get_conf(cycle->conf_ctx, rp_event_core_module);

    if (ecf->use != rp_select_module.ctx_index) {
        return RP_CONF_OK;
    }

    return RP_CONF_OK;
}
