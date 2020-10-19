
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_uint_t                         max_cached;
    rap_uint_t                         requests;
    rap_msec_t                         timeout;

    rap_queue_t                        cache;
    rap_queue_t                        free;

    rap_http_upstream_init_pt          original_init_upstream;
    rap_http_upstream_init_peer_pt     original_init_peer;

} rap_http_upstream_keepalive_srv_conf_t;


typedef struct {
    rap_http_upstream_keepalive_srv_conf_t  *conf;

    rap_queue_t                        queue;
    rap_connection_t                  *connection;

    socklen_t                          socklen;
    rap_sockaddr_t                     sockaddr;

} rap_http_upstream_keepalive_cache_t;


typedef struct {
    rap_http_upstream_keepalive_srv_conf_t  *conf;

    rap_http_upstream_t               *upstream;

    void                              *data;

    rap_event_get_peer_pt              original_get_peer;
    rap_event_free_peer_pt             original_free_peer;

#if (RAP_HTTP_SSL)
    rap_event_set_peer_session_pt      original_set_session;
    rap_event_save_peer_session_pt     original_save_session;
#endif

} rap_http_upstream_keepalive_peer_data_t;


static rap_int_t rap_http_upstream_init_keepalive_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_get_keepalive_peer(rap_peer_connection_t *pc,
    void *data);
static void rap_http_upstream_free_keepalive_peer(rap_peer_connection_t *pc,
    void *data, rap_uint_t state);

static void rap_http_upstream_keepalive_dummy_handler(rap_event_t *ev);
static void rap_http_upstream_keepalive_close_handler(rap_event_t *ev);
static void rap_http_upstream_keepalive_close(rap_connection_t *c);

#if (RAP_HTTP_SSL)
static rap_int_t rap_http_upstream_keepalive_set_session(
    rap_peer_connection_t *pc, void *data);
static void rap_http_upstream_keepalive_save_session(rap_peer_connection_t *pc,
    void *data);
#endif

static void *rap_http_upstream_keepalive_create_conf(rap_conf_t *cf);
static char *rap_http_upstream_keepalive(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_upstream_keepalive_commands[] = {

    { rap_string("keepalive"),
      RAP_HTTP_UPS_CONF|RAP_CONF_TAKE1,
      rap_http_upstream_keepalive,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("keepalive_timeout"),
      RAP_HTTP_UPS_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { rap_string("keepalive_requests"),
      RAP_HTTP_UPS_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_keepalive_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_keepalive_module_ctx, /* module context */
    rap_http_upstream_keepalive_commands,    /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
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
rap_http_upstream_init_keepalive(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us)
{
    rap_uint_t                               i;
    rap_http_upstream_keepalive_srv_conf_t  *kcf;
    rap_http_upstream_keepalive_cache_t     *cached;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = rap_http_conf_upstream_srv_conf(us,
                                          rap_http_upstream_keepalive_module);

    rap_conf_init_msec_value(kcf->timeout, 60000);
    rap_conf_init_uint_value(kcf->requests, 100);

    if (kcf->original_init_upstream(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    kcf->original_init_peer = us->peer.init;

    us->peer.init = rap_http_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */

    cached = rap_pcalloc(cf->pool,
                sizeof(rap_http_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return RAP_ERROR;
    }

    rap_queue_init(&kcf->cache);
    rap_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        rap_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_init_keepalive_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us)
{
    rap_http_upstream_keepalive_peer_data_t  *kp;
    rap_http_upstream_keepalive_srv_conf_t   *kcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = rap_http_conf_upstream_srv_conf(us,
                                          rap_http_upstream_keepalive_module);

    kp = rap_palloc(r->pool, sizeof(rap_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return RAP_ERROR;
    }

    if (kcf->original_init_peer(r, us) != RAP_OK) {
        return RAP_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = rap_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = rap_http_upstream_free_keepalive_peer;

#if (RAP_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = rap_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = rap_http_upstream_keepalive_save_session;
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_get_keepalive_peer(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_keepalive_peer_data_t  *kp = data;
    rap_http_upstream_keepalive_cache_t      *item;

    rap_int_t          rc;
    rap_queue_t       *q, *cache;
    rap_connection_t  *c;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != RAP_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = rap_queue_head(cache);
         q != rap_queue_sentinel(cache);
         q = rap_queue_next(q))
    {
        item = rap_queue_data(q, rap_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (rap_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            rap_queue_remove(q);
            rap_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return RAP_OK;

found:

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return RAP_DONE;
}


static void
rap_http_upstream_free_keepalive_peer(rap_peer_connection_t *pc, void *data,
    rap_uint_t state)
{
    rap_http_upstream_keepalive_peer_data_t  *kp = data;
    rap_http_upstream_keepalive_cache_t      *item;

    rap_queue_t          *q;
    rap_connection_t     *c;
    rap_http_upstream_t  *u;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & RAP_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (rap_terminate || rap_exiting) {
        goto invalid;
    }

    if (rap_handle_read_event(c->read, 0) != RAP_OK) {
        goto invalid;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (rap_queue_empty(&kp->conf->free)) {

        q = rap_queue_last(&kp->conf->cache);
        rap_queue_remove(q);

        item = rap_queue_data(q, rap_http_upstream_keepalive_cache_t, queue);

        rap_http_upstream_keepalive_close(item->connection);

    } else {
        q = rap_queue_head(&kp->conf->free);
        rap_queue_remove(q);

        item = rap_queue_data(q, rap_http_upstream_keepalive_cache_t, queue);
    }

    rap_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;

    pc->connection = NULL;

    c->read->delayed = 0;
    rap_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        rap_del_timer(c->write);
    }

    c->write->handler = rap_http_upstream_keepalive_dummy_handler;
    c->read->handler = rap_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = rap_cycle->log;
    c->read->log = rap_cycle->log;
    c->write->log = rap_cycle->log;
    c->pool->log = rap_cycle->log;

    item->socklen = pc->socklen;
    rap_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        rap_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
rap_http_upstream_keepalive_dummy_handler(rap_event_t *ev)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
rap_http_upstream_keepalive_close_handler(rap_event_t *ev)
{
    rap_http_upstream_keepalive_srv_conf_t  *conf;
    rap_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    rap_connection_t  *c;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && rap_socket_errno == RAP_EAGAIN) {
        ev->ready = 0;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    rap_http_upstream_keepalive_close(c);

    rap_queue_remove(&item->queue);
    rap_queue_insert_head(&conf->free, &item->queue);
}


static void
rap_http_upstream_keepalive_close(rap_connection_t *c)
{

#if (RAP_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (rap_ssl_shutdown(c) == RAP_AGAIN) {
            c->ssl->handler = rap_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    rap_destroy_pool(c->pool);
    rap_close_connection(c);
}


#if (RAP_HTTP_SSL)

static rap_int_t
rap_http_upstream_keepalive_set_session(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
rap_http_upstream_keepalive_save_session(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
rap_http_upstream_keepalive_create_conf(rap_conf_t *cf)
{
    rap_http_upstream_keepalive_srv_conf_t  *conf;

    conf = rap_pcalloc(cf->pool,
                       sizeof(rap_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    conf->timeout = RAP_CONF_UNSET_MSEC;
    conf->requests = RAP_CONF_UNSET_UINT;

    return conf;
}


static char *
rap_http_upstream_keepalive(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_upstream_srv_conf_t            *uscf;
    rap_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    rap_int_t    n;
    rap_str_t   *value;

    if (kcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = rap_atoi(value[1].data, value[1].len);

    if (n == RAP_ERROR || n == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return RAP_CONF_ERROR;
    }

    kcf->max_cached = n;

    /* init upstream handler */

    uscf = rap_http_conf_get_module_srv_conf(cf, rap_http_upstream_module);

    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : rap_http_upstream_init_round_robin;

    uscf->peer.init_upstream = rap_http_upstream_init_keepalive;

    return RAP_CONF_OK;
}
