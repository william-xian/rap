
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_uint_t                         max_cached;
    rp_uint_t                         requests;
    rp_msec_t                         timeout;

    rp_queue_t                        cache;
    rp_queue_t                        free;

    rp_http_upstream_init_pt          original_init_upstream;
    rp_http_upstream_init_peer_pt     original_init_peer;

} rp_http_upstream_keepalive_srv_conf_t;


typedef struct {
    rp_http_upstream_keepalive_srv_conf_t  *conf;

    rp_queue_t                        queue;
    rp_connection_t                  *connection;

    socklen_t                          socklen;
    rp_sockaddr_t                     sockaddr;

} rp_http_upstream_keepalive_cache_t;


typedef struct {
    rp_http_upstream_keepalive_srv_conf_t  *conf;

    rp_http_upstream_t               *upstream;

    void                              *data;

    rp_event_get_peer_pt              original_get_peer;
    rp_event_free_peer_pt             original_free_peer;

#if (RP_HTTP_SSL)
    rp_event_set_peer_session_pt      original_set_session;
    rp_event_save_peer_session_pt     original_save_session;
#endif

} rp_http_upstream_keepalive_peer_data_t;


static rp_int_t rp_http_upstream_init_keepalive_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us);
static rp_int_t rp_http_upstream_get_keepalive_peer(rp_peer_connection_t *pc,
    void *data);
static void rp_http_upstream_free_keepalive_peer(rp_peer_connection_t *pc,
    void *data, rp_uint_t state);

static void rp_http_upstream_keepalive_dummy_handler(rp_event_t *ev);
static void rp_http_upstream_keepalive_close_handler(rp_event_t *ev);
static void rp_http_upstream_keepalive_close(rp_connection_t *c);

#if (RP_HTTP_SSL)
static rp_int_t rp_http_upstream_keepalive_set_session(
    rp_peer_connection_t *pc, void *data);
static void rp_http_upstream_keepalive_save_session(rp_peer_connection_t *pc,
    void *data);
#endif

static void *rp_http_upstream_keepalive_create_conf(rp_conf_t *cf);
static char *rp_http_upstream_keepalive(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_upstream_keepalive_commands[] = {

    { rp_string("keepalive"),
      RP_HTTP_UPS_CONF|RP_CONF_TAKE1,
      rp_http_upstream_keepalive,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("keepalive_timeout"),
      RP_HTTP_UPS_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { rp_string("keepalive_requests"),
      RP_HTTP_UPS_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_upstream_keepalive_module = {
    RP_MODULE_V1,
    &rp_http_upstream_keepalive_module_ctx, /* module context */
    rp_http_upstream_keepalive_commands,    /* module directives */
    RP_HTTP_MODULE,                       /* module type */
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
rp_http_upstream_init_keepalive(rp_conf_t *cf,
    rp_http_upstream_srv_conf_t *us)
{
    rp_uint_t                               i;
    rp_http_upstream_keepalive_srv_conf_t  *kcf;
    rp_http_upstream_keepalive_cache_t     *cached;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = rp_http_conf_upstream_srv_conf(us,
                                          rp_http_upstream_keepalive_module);

    rp_conf_init_msec_value(kcf->timeout, 60000);
    rp_conf_init_uint_value(kcf->requests, 100);

    if (kcf->original_init_upstream(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    kcf->original_init_peer = us->peer.init;

    us->peer.init = rp_http_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */

    cached = rp_pcalloc(cf->pool,
                sizeof(rp_http_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return RP_ERROR;
    }

    rp_queue_init(&kcf->cache);
    rp_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        rp_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_init_keepalive_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us)
{
    rp_http_upstream_keepalive_peer_data_t  *kp;
    rp_http_upstream_keepalive_srv_conf_t   *kcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = rp_http_conf_upstream_srv_conf(us,
                                          rp_http_upstream_keepalive_module);

    kp = rp_palloc(r->pool, sizeof(rp_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return RP_ERROR;
    }

    if (kcf->original_init_peer(r, us) != RP_OK) {
        return RP_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = rp_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = rp_http_upstream_free_keepalive_peer;

#if (RP_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = rp_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = rp_http_upstream_keepalive_save_session;
#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_get_keepalive_peer(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_keepalive_peer_data_t  *kp = data;
    rp_http_upstream_keepalive_cache_t      *item;

    rp_int_t          rc;
    rp_queue_t       *q, *cache;
    rp_connection_t  *c;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != RP_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = rp_queue_head(cache);
         q != rp_queue_sentinel(cache);
         q = rp_queue_next(q))
    {
        item = rp_queue_data(q, rp_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (rp_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            rp_queue_remove(q);
            rp_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return RP_OK;

found:

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return RP_DONE;
}


static void
rp_http_upstream_free_keepalive_peer(rp_peer_connection_t *pc, void *data,
    rp_uint_t state)
{
    rp_http_upstream_keepalive_peer_data_t  *kp = data;
    rp_http_upstream_keepalive_cache_t      *item;

    rp_queue_t          *q;
    rp_connection_t     *c;
    rp_http_upstream_t  *u;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & RP_PEER_FAILED
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

    if (rp_terminate || rp_exiting) {
        goto invalid;
    }

    if (rp_handle_read_event(c->read, 0) != RP_OK) {
        goto invalid;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (rp_queue_empty(&kp->conf->free)) {

        q = rp_queue_last(&kp->conf->cache);
        rp_queue_remove(q);

        item = rp_queue_data(q, rp_http_upstream_keepalive_cache_t, queue);

        rp_http_upstream_keepalive_close(item->connection);

    } else {
        q = rp_queue_head(&kp->conf->free);
        rp_queue_remove(q);

        item = rp_queue_data(q, rp_http_upstream_keepalive_cache_t, queue);
    }

    rp_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;

    pc->connection = NULL;

    c->read->delayed = 0;
    rp_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        rp_del_timer(c->write);
    }

    c->write->handler = rp_http_upstream_keepalive_dummy_handler;
    c->read->handler = rp_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = rp_cycle->log;
    c->read->log = rp_cycle->log;
    c->write->log = rp_cycle->log;
    c->pool->log = rp_cycle->log;

    item->socklen = pc->socklen;
    rp_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        rp_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
rp_http_upstream_keepalive_dummy_handler(rp_event_t *ev)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
rp_http_upstream_keepalive_close_handler(rp_event_t *ev)
{
    rp_http_upstream_keepalive_srv_conf_t  *conf;
    rp_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    rp_connection_t  *c;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && rp_socket_errno == RP_EAGAIN) {
        ev->ready = 0;

        if (rp_handle_read_event(c->read, 0) != RP_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    rp_http_upstream_keepalive_close(c);

    rp_queue_remove(&item->queue);
    rp_queue_insert_head(&conf->free, &item->queue);
}


static void
rp_http_upstream_keepalive_close(rp_connection_t *c)
{

#if (RP_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (rp_ssl_shutdown(c) == RP_AGAIN) {
            c->ssl->handler = rp_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    rp_destroy_pool(c->pool);
    rp_close_connection(c);
}


#if (RP_HTTP_SSL)

static rp_int_t
rp_http_upstream_keepalive_set_session(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
rp_http_upstream_keepalive_save_session(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
rp_http_upstream_keepalive_create_conf(rp_conf_t *cf)
{
    rp_http_upstream_keepalive_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool,
                       sizeof(rp_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    conf->timeout = RP_CONF_UNSET_MSEC;
    conf->requests = RP_CONF_UNSET_UINT;

    return conf;
}


static char *
rp_http_upstream_keepalive(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_upstream_srv_conf_t            *uscf;
    rp_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    rp_int_t    n;
    rp_str_t   *value;

    if (kcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = rp_atoi(value[1].data, value[1].len);

    if (n == RP_ERROR || n == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return RP_CONF_ERROR;
    }

    kcf->max_cached = n;

    /* init upstream handler */

    uscf = rp_http_conf_get_module_srv_conf(cf, rp_http_upstream_module);

    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : rp_http_upstream_init_round_robin;

    uscf->peer.init_upstream = rp_http_upstream_init_keepalive;

    return RP_CONF_OK;
}
