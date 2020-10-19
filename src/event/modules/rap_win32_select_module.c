
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static rap_int_t rap_select_init(rap_cycle_t *cycle, rap_msec_t timer);
static void rap_select_done(rap_cycle_t *cycle);
static rap_int_t rap_select_add_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_select_del_event(rap_event_t *ev, rap_int_t event,
    rap_uint_t flags);
static rap_int_t rap_select_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags);
static void rap_select_repair_fd_sets(rap_cycle_t *cycle);
static char *rap_select_init_conf(rap_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;
static fd_set         work_except_fd_set;

static rap_uint_t     max_read;
static rap_uint_t     max_write;
static rap_uint_t     nevents;

static rap_event_t  **event_index;


static rap_str_t           select_name = rap_string("select");

static rap_event_module_t  rap_select_module_ctx = {
    &select_name,
    NULL,                                  /* create configuration */
    rap_select_init_conf,                  /* init configuration */

    {
        rap_select_add_event,              /* add an event */
        rap_select_del_event,              /* delete an event */
        rap_select_add_event,              /* enable an event */
        rap_select_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        rap_select_process_events,         /* process the events */
        rap_select_init,                   /* init the events */
        rap_select_done                    /* done the events */
    }

};

rap_module_t  rap_select_module = {
    RAP_MODULE_V1,
    &rap_select_module_ctx,                /* module context */
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
rap_select_init(rap_cycle_t *cycle, rap_msec_t timer)
{
    rap_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (rap_process >= RAP_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        index = rap_alloc(sizeof(rap_event_t *) * 2 * cycle->connection_n,
                          cycle->log);
        if (index == NULL) {
            return RAP_ERROR;
        }

        if (event_index) {
            rap_memcpy(index, event_index, sizeof(rap_event_t *) * nevents);
            rap_free(event_index);
        }

        event_index = index;
    }

    rap_io = rap_os_io;

    rap_event_actions = rap_select_module_ctx.actions;

    rap_event_flags = RAP_USE_LEVEL_EVENT;

    max_read = 0;
    max_write = 0;

    return RAP_OK;
}


static void
rap_select_done(rap_cycle_t *cycle)
{
    rap_free(event_index);

    event_index = NULL;
}


static rap_int_t
rap_select_add_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_connection_t  *c;

    c = ev->data;

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "select add event fd:%d ev:%i", c->fd, event);

    if (ev->index != RAP_INVALID_INDEX) {
        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%i is already set", c->fd, event);
        return RAP_OK;
    }

    if ((event == RAP_READ_EVENT && ev->write)
        || (event == RAP_WRITE_EVENT && !ev->write))
    {
        rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                      "invalid select %s event fd:%d ev:%i",
                      ev->write ? "write" : "read", c->fd, event);
        return RAP_ERROR;
    }

    if ((event == RAP_READ_EVENT && max_read >= FD_SETSIZE)
        || (event == RAP_WRITE_EVENT && max_write >= FD_SETSIZE))
    {
        rap_log_error(RAP_LOG_ERR, ev->log, 0,
                      "maximum number of descriptors "
                      "supported by select() is %d", FD_SETSIZE);
        return RAP_ERROR;
    }

    if (event == RAP_READ_EVENT) {
        FD_SET(c->fd, &master_read_fd_set);
        max_read++;

    } else if (event == RAP_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
        max_write++;
    }

    ev->active = 1;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return RAP_OK;
}


static rap_int_t
rap_select_del_event(rap_event_t *ev, rap_int_t event, rap_uint_t flags)
{
    rap_event_t       *e;
    rap_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == RAP_INVALID_INDEX) {
        return RAP_OK;
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

    if (event == RAP_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);
        max_read--;

    } else if (event == RAP_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
        max_write--;
    }

    if (ev->index < --nevents) {
        e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = RAP_INVALID_INDEX;

    return RAP_OK;
}


static rap_int_t
rap_select_process_events(rap_cycle_t *cycle, rap_msec_t timer,
    rap_uint_t flags)
{
    int                ready, nready;
    rap_err_t          err;
    rap_uint_t         i, found;
    rap_event_t       *ev;
    rap_queue_t       *queue;
    struct timeval     tv, *tp;
    rap_connection_t  *c;

#if (RAP_DEBUG)
    if (cycle->log->log_level & RAP_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            rap_log_debug2(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }
    }
#endif

    if (timer == RAP_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timer / 1000);
        tv.tv_usec = (long) ((timer % 1000) * 1000);
        tp = &tv;
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
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

        rap_msleep(timer);

        ready = 0;
    }

    err = (ready == -1) ? rap_socket_errno : 0;

    if (flags & RAP_UPDATE_TIME) {
        rap_time_update();
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, err, "select() failed");

        if (err == WSAENOTSOCK) {
            rap_select_repair_fd_sets(cycle);
        }

        return RAP_ERROR;
    }

    if (ready == 0) {
        if (timer != RAP_TIMER_INFINITE) {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return RAP_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found++;
                rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

            if (FD_ISSET(c->fd, &work_except_fd_set)) {
                found++;
                rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select except %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found++;
                rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select read %d", c->fd);
            }
        }

        if (found) {
            ev->ready = 1;
            ev->available = -1;

            queue = ev->accept ? &rap_posted_accept_events
                               : &rap_posted_events;

            rap_post_event(ev, queue);

            nready += found;
        }
    }

    if (ready != nready) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                      "select ready != events: %d:%d", ready, nready);

        rap_select_repair_fd_sets(cycle);
    }

    return RAP_OK;
}


static void
rap_select_repair_fd_sets(rap_cycle_t *cycle)
{
    int           n;
    u_int         i;
    socklen_t     len;
    rap_err_t     err;
    rap_socket_t  s;

    for (i = 0; i < master_read_fd_set.fd_count; i++) {

        s = master_read_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = rap_socket_errno;

            rap_log_error(RAP_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (i = 0; i < master_write_fd_set.fd_count; i++) {

        s = master_write_fd_set.fd_array[i];
        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
            err = rap_socket_errno;

            rap_log_error(RAP_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }
}


static char *
rap_select_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_event_conf_t  *ecf;

    ecf = rap_event_get_conf(cycle->conf_ctx, rap_event_core_module);

    if (ecf->use != rap_select_module.ctx_index) {
        return RAP_CONF_OK;
    }

    return RAP_CONF_OK;
}
