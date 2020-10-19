
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_addr_t                      *addr;
    rap_stream_complex_value_t      *value;
#if (RAP_HAVE_TRANSPARENT_PROXY)
    rap_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} rap_stream_upstream_local_t;


typedef struct {
    rap_msec_t                       connect_timeout;
    rap_msec_t                       timeout;
    rap_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    rap_stream_complex_value_t      *upload_rate;
    rap_stream_complex_value_t      *download_rate;
    rap_uint_t                       requests;
    rap_uint_t                       responses;
    rap_uint_t                       next_upstream_tries;
    rap_flag_t                       next_upstream;
    rap_flag_t                       proxy_protocol;
    rap_stream_upstream_local_t     *local;
    rap_flag_t                       socket_keepalive;

#if (RAP_STREAM_SSL)
    rap_flag_t                       ssl_enable;
    rap_flag_t                       ssl_session_reuse;
    rap_uint_t                       ssl_protocols;
    rap_str_t                        ssl_ciphers;
    rap_stream_complex_value_t      *ssl_name;
    rap_flag_t                       ssl_server_name;

    rap_flag_t                       ssl_verify;
    rap_uint_t                       ssl_verify_depth;
    rap_str_t                        ssl_trusted_certificate;
    rap_str_t                        ssl_crl;
    rap_str_t                        ssl_certificate;
    rap_str_t                        ssl_certificate_key;
    rap_array_t                     *ssl_passwords;

    rap_ssl_t                       *ssl;
#endif

    rap_stream_upstream_srv_conf_t  *upstream;
    rap_stream_complex_value_t      *upstream_value;
} rap_stream_proxy_srv_conf_t;


static void rap_stream_proxy_handler(rap_stream_session_t *s);
static rap_int_t rap_stream_proxy_eval(rap_stream_session_t *s,
    rap_stream_proxy_srv_conf_t *pscf);
static rap_int_t rap_stream_proxy_set_local(rap_stream_session_t *s,
    rap_stream_upstream_t *u, rap_stream_upstream_local_t *local);
static void rap_stream_proxy_connect(rap_stream_session_t *s);
static void rap_stream_proxy_init_upstream(rap_stream_session_t *s);
static void rap_stream_proxy_resolve_handler(rap_resolver_ctx_t *ctx);
static void rap_stream_proxy_upstream_handler(rap_event_t *ev);
static void rap_stream_proxy_downstream_handler(rap_event_t *ev);
static void rap_stream_proxy_process_connection(rap_event_t *ev,
    rap_uint_t from_upstream);
static void rap_stream_proxy_connect_handler(rap_event_t *ev);
static rap_int_t rap_stream_proxy_test_connect(rap_connection_t *c);
static void rap_stream_proxy_process(rap_stream_session_t *s,
    rap_uint_t from_upstream, rap_uint_t do_write);
static rap_int_t rap_stream_proxy_test_finalize(rap_stream_session_t *s,
    rap_uint_t from_upstream);
static void rap_stream_proxy_next_upstream(rap_stream_session_t *s);
static void rap_stream_proxy_finalize(rap_stream_session_t *s, rap_uint_t rc);
static u_char *rap_stream_proxy_log_error(rap_log_t *log, u_char *buf,
    size_t len);

static void *rap_stream_proxy_create_srv_conf(rap_conf_t *cf);
static char *rap_stream_proxy_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_stream_proxy_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_proxy_bind(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

#if (RAP_STREAM_SSL)

static rap_int_t rap_stream_proxy_send_proxy_protocol(rap_stream_session_t *s);
static char *rap_stream_proxy_ssl_password_file(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static void rap_stream_proxy_ssl_init_connection(rap_stream_session_t *s);
static void rap_stream_proxy_ssl_handshake(rap_connection_t *pc);
static void rap_stream_proxy_ssl_save_session(rap_connection_t *c);
static rap_int_t rap_stream_proxy_ssl_name(rap_stream_session_t *s);
static rap_int_t rap_stream_proxy_set_ssl(rap_conf_t *cf,
    rap_stream_proxy_srv_conf_t *pscf);


static rap_conf_bitmask_t  rap_stream_proxy_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};

#endif


static rap_conf_deprecated_t  rap_conf_deprecated_proxy_downstream_buffer = {
    rap_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static rap_conf_deprecated_t  rap_conf_deprecated_proxy_upstream_buffer = {
    rap_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


static rap_command_t  rap_stream_proxy_commands[] = {

    { rap_string("proxy_pass"),
      RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_proxy_pass,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_bind"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE12,
      rap_stream_proxy_bind,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_socket_keepalive"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { rap_string("proxy_connect_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { rap_string("proxy_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, timeout),
      NULL },

    { rap_string("proxy_buffer_size"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { rap_string("proxy_downstream_buffer"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, buffer_size),
      &rap_conf_deprecated_proxy_downstream_buffer },

    { rap_string("proxy_upstream_buffer"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, buffer_size),
      &rap_conf_deprecated_proxy_upstream_buffer },

    { rap_string("proxy_upload_rate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_set_complex_value_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { rap_string("proxy_download_rate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_set_complex_value_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { rap_string("proxy_requests"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, requests),
      NULL },

    { rap_string("proxy_responses"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, responses),
      NULL },

    { rap_string("proxy_next_upstream"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { rap_string("proxy_next_upstream_tries"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { rap_string("proxy_next_upstream_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { rap_string("proxy_protocol"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, proxy_protocol),
      NULL },

#if (RAP_STREAM_SSL)

    { rap_string("proxy_ssl"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { rap_string("proxy_ssl_session_reuse"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { rap_string("proxy_ssl_protocols"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_protocols),
      &rap_stream_proxy_ssl_protocols },

    { rap_string("proxy_ssl_ciphers"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { rap_string("proxy_ssl_name"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_set_complex_value_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { rap_string("proxy_ssl_server_name"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { rap_string("proxy_ssl_verify"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { rap_string("proxy_ssl_verify_depth"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { rap_string("proxy_ssl_trusted_certificate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { rap_string("proxy_ssl_crl"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

    { rap_string("proxy_ssl_certificate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { rap_string("proxy_ssl_certificate_key"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

    { rap_string("proxy_ssl_password_file"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_proxy_ssl_password_file,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#endif

      rap_null_command
};


static rap_stream_module_t  rap_stream_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_stream_proxy_create_srv_conf,      /* create server configuration */
    rap_stream_proxy_merge_srv_conf        /* merge server configuration */
};


rap_module_t  rap_stream_proxy_module = {
    RAP_MODULE_V1,
    &rap_stream_proxy_module_ctx,          /* module context */
    rap_stream_proxy_commands,             /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static void
rap_stream_proxy_handler(rap_stream_session_t *s)
{
    u_char                           *p;
    rap_str_t                        *host;
    rap_uint_t                        i;
    rap_connection_t                 *c;
    rap_resolver_ctx_t               *ctx, temp;
    rap_stream_upstream_t            *u;
    rap_stream_core_srv_conf_t       *cscf;
    rap_stream_proxy_srv_conf_t      *pscf;
    rap_stream_upstream_srv_conf_t   *uscf, **uscfp;
    rap_stream_upstream_main_conf_t  *umcf;

    c = s->connection;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = rap_pcalloc(c->pool, sizeof(rap_stream_upstream_t));
    if (u == NULL) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = rap_stream_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = RAP_ERROR_ERR;

    if (rap_stream_proxy_set_local(s, u, pscf->local) != RAP_OK) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = rap_time();

    c->write->handler = rap_stream_proxy_downstream_handler;
    c->read->handler = rap_stream_proxy_downstream_handler;

    s->upstream_states = rap_array_create(c->pool, 1,
                                          sizeof(rap_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = rap_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        rap_post_event(c->read, &rap_posted_events);
    }

    if (pscf->upstream_value) {
        if (rap_stream_proxy_eval(s, pscf) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {

        uscf = pscf->upstream;

    } else {

#if (RAP_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = rap_stream_get_module_main_conf(s, rap_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && rap_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                rap_log_error(RAP_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rap_stream_upstream_create_round_robin_peer(s, u->resolved)
                != RAP_OK)
            {
                rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            rap_stream_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            rap_log_error(RAP_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

        ctx = rap_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == RAP_NO_RESOLVER) {
            rap_log_error(RAP_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = rap_stream_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (rap_resolve_name(ctx) != RAP_OK) {
            u->resolved->ctx = NULL;
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        rap_log_error(RAP_LOG_ALERT, c->log, 0, "no upstream configuration");
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (RAP_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(s, uscf) != RAP_OK) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = rap_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    rap_stream_proxy_connect(s);
}


static rap_int_t
rap_stream_proxy_eval(rap_stream_session_t *s,
    rap_stream_proxy_srv_conf_t *pscf)
{
    rap_str_t               host;
    rap_url_t               url;
    rap_stream_upstream_t  *u;

    if (rap_stream_complex_value(s, pscf->upstream_value, &host) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_memzero(&url, sizeof(rap_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (rap_parse_url(s->connection->pool, &url) != RAP_OK) {
        if (url.err) {
            rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RAP_ERROR;
    }

    u = s->upstream;

    u->resolved = rap_pcalloc(s->connection->pool,
                              sizeof(rap_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RAP_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return RAP_OK;
}


static rap_int_t
rap_stream_proxy_set_local(rap_stream_session_t *s, rap_stream_upstream_t *u,
    rap_stream_upstream_local_t *local)
{
    rap_int_t    rc;
    rap_str_t    val;
    rap_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return RAP_OK;
    }

#if (RAP_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return RAP_OK;
    }

    if (rap_stream_complex_value(s, local->value, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    if (val.len == 0) {
        return RAP_OK;
    }

    addr = rap_palloc(s->connection->pool, sizeof(rap_addr_t));
    if (addr == NULL) {
        return RAP_ERROR;
    }

    rc = rap_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rc != RAP_OK) {
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return RAP_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return RAP_OK;
}


static void
rap_stream_proxy_connect(rap_stream_session_t *s)
{
    rap_int_t                     rc;
    rap_connection_t             *c, *pc;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;

    if (u->state) {
        u->state->response_time = rap_current_msec - u->start_time;
    }

    u->state = rap_array_push(s->upstream_states);
    if (u->state == NULL) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_memzero(u->state, sizeof(rap_stream_upstream_state_t));

    u->start_time = rap_current_msec;

    u->state->connect_time = (rap_msec_t) -1;
    u->state->first_byte_time = (rap_msec_t) -1;
    u->state->response_time = (rap_msec_t) -1;

    rc = rap_event_connect_peer(&u->peer);

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == RAP_ERROR) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == RAP_BUSY) {
        rap_log_error(RAP_LOG_ERR, c->log, 0, "no live upstreams");
        rap_stream_proxy_finalize(s, RAP_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == RAP_DECLINED) {
        rap_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == RAP_OK || rc == RAP_AGAIN || rc == RAP_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != RAP_AGAIN) {
        rap_stream_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = rap_stream_proxy_connect_handler;
    pc->write->handler = rap_stream_proxy_connect_handler;

    rap_add_timer(pc->write, pscf->connect_timeout);
}


static void
rap_stream_proxy_init_upstream(rap_stream_session_t *s)
{
    u_char                       *p;
    rap_chain_t                  *cl;
    rap_connection_t             *c, *pc;
    rap_log_handler_pt            handler;
    rap_stream_upstream_t        *u;
    rap_stream_core_srv_conf_t   *cscf;
    rap_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && rap_tcp_nodelay(pc) != RAP_OK)
    {
        rap_stream_proxy_next_upstream(s);
        return;
    }

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

#if (RAP_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl) {

        if (u->proxy_protocol) {
            if (rap_stream_proxy_send_proxy_protocol(s) != RAP_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            rap_stream_proxy_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= RAP_LOG_INFO) {
        rap_str_t  str;
        u_char     addr[RAP_SOCKADDR_STRLEN];

        str.len = RAP_SOCKADDR_STRLEN;
        str.data = addr;

        if (rap_connection_local_sockaddr(pc, &str, 1) == RAP_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = rap_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       RAP_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = rap_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = rap_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (rap_buf_tag_t) &rap_stream_proxy_module;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (u->proxy_protocol) {
        rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        cl = rap_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = rap_pnalloc(c->pool, RAP_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = rap_proxy_protocol_write(c, p, p + RAP_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (rap_buf_tag_t) &rap_stream_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = rap_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = rap_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = rap_stream_proxy_upstream_handler;
    pc->write->handler = rap_stream_proxy_upstream_handler;

    if (pc->read->ready) {
        rap_post_event(pc->read, &rap_posted_events);
    }

    rap_stream_proxy_process(s, 0, 1);
}


#if (RAP_STREAM_SSL)

static rap_int_t
rap_stream_proxy_send_proxy_protocol(rap_stream_session_t *s)
{
    u_char                       *p;
    ssize_t                       n, size;
    rap_connection_t             *c, *pc;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;
    u_char                        buf[RAP_PROXY_PROTOCOL_MAX_HEADER];

    c = s->connection;

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = rap_proxy_protocol_write(c, buf, buf + RAP_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == RAP_AGAIN) {
        if (rap_handle_write_event(pc->write, 0) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return RAP_ERROR;
        }

        pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

        rap_add_timer(pc->write, pscf->timeout);

        pc->write->handler = rap_stream_proxy_connect_handler;

        return RAP_AGAIN;
    }

    if (n == RAP_ERROR) {
        rap_stream_proxy_finalize(s, RAP_STREAM_OK);
        return RAP_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        rap_log_error(RAP_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);

        return RAP_ERROR;
    }

    return RAP_OK;
}


static char *
rap_stream_proxy_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    rap_stream_proxy_srv_conf_t *pscf = conf;

    rap_str_t  *value;

    if (pscf->ssl_passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static void
rap_stream_proxy_ssl_init_connection(rap_stream_session_t *s)
{
    rap_int_t                     rc;
    rap_connection_t             *pc;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    pc = u->peer.connection;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    if (rap_ssl_create_connection(pscf->ssl, pc, RAP_SSL_BUFFER|RAP_SSL_CLIENT)
        != RAP_OK)
    {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (rap_stream_proxy_ssl_name(s) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = rap_stream_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = rap_ssl_handshake(pc);

    if (rc == RAP_AGAIN) {

        if (!pc->write->timer_set) {
            rap_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = rap_stream_proxy_ssl_handshake;
        return;
    }

    rap_stream_proxy_ssl_handshake(pc);
}


static void
rap_stream_proxy_ssl_handshake(rap_connection_t *pc)
{
    long                          rc;
    rap_stream_session_t         *s;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                rap_log_error(RAP_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (rap_ssl_check_host(pc, &u->ssl_name) != RAP_OK) {
                rap_log_error(RAP_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            rap_del_timer(pc->write);
        }

        rap_stream_proxy_init_upstream(s);

        return;
    }

failed:

    rap_stream_proxy_next_upstream(s);
}


static void
rap_stream_proxy_ssl_save_session(rap_connection_t *c)
{
    rap_stream_session_t   *s;
    rap_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static rap_int_t
rap_stream_proxy_ssl_name(rap_stream_session_t *s)
{
    u_char                       *p, *last;
    rap_str_t                     name;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name) {
        if (rap_stream_complex_value(s, pscf->ssl_name, &name) != RAP_OK) {
            return RAP_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = rap_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = rap_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (rap_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = rap_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return RAP_ERROR;
    }

    (void) rap_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        rap_ssl_error(RAP_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return RAP_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return RAP_OK;
}

#endif


static void
rap_stream_proxy_downstream_handler(rap_event_t *ev)
{
    rap_stream_proxy_process_connection(ev, ev->write);
}


static void
rap_stream_proxy_resolve_handler(rap_resolver_ctx_t *ctx)
{
    rap_stream_session_t            *s;
    rap_stream_upstream_t           *u;
    rap_stream_proxy_srv_conf_t     *pscf;
    rap_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rap_resolver_strerror(ctx->state));

        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (RAP_DEBUG)
    {
    u_char      text[RAP_SOCKADDR_STRLEN];
    rap_str_t   addr;
    rap_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = rap_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, RAP_SOCKADDR_STRLEN, 0);

        rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (rap_stream_upstream_create_round_robin_peer(s, ur) != RAP_OK) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = rap_current_msec;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    rap_stream_proxy_connect(s);
}


static void
rap_stream_proxy_upstream_handler(rap_event_t *ev)
{
    rap_stream_proxy_process_connection(ev, !ev->write);
}


static void
rap_stream_proxy_process_connection(rap_event_t *ev, rap_uint_t from_upstream)
{
    rap_connection_t             *c, *pc;
    rap_log_handler_pt            handler;
    rap_stream_session_t         *s;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        rap_log_error(RAP_LOG_INFO, c->log, 0, "shutdown timeout");
        rap_stream_proxy_finalize(s, RAP_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (rap_handle_read_event(ev, 0) != RAP_OK) {
                    rap_stream_proxy_finalize(s,
                                              RAP_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    rap_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (pscf->responses == RAP_MAX_INT32_VALUE
                    || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    rap_log_error(RAP_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    rap_stream_proxy_finalize(s, RAP_STREAM_OK);
                    return;
                }

                rap_connection_error(pc, RAP_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                rap_stream_proxy_finalize(s, RAP_STREAM_BAD_GATEWAY);

                return;
            }

            rap_connection_error(c, RAP_ETIMEDOUT, "connection timed out");

            rap_stream_proxy_finalize(s, RAP_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (rap_handle_read_event(ev, 0) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    rap_stream_proxy_process(s, from_upstream, ev->write);
}


static void
rap_stream_proxy_connect_handler(rap_event_t *ev)
{
    rap_connection_t      *c;
    rap_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        rap_log_error(RAP_LOG_ERR, c->log, RAP_ETIMEDOUT, "upstream timed out");
        rap_stream_proxy_next_upstream(s);
        return;
    }

    rap_del_timer(c->write);

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (rap_stream_proxy_test_connect(c) != RAP_OK) {
        rap_stream_proxy_next_upstream(s);
        return;
    }

    rap_stream_proxy_init_upstream(s);
}


static rap_int_t
rap_stream_proxy_test_connect(rap_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) rap_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return RAP_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rap_socket_errno;
        }

        if (err) {
            (void) rap_connection_error(c, err, "connect() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static void
rap_stream_proxy_process(rap_stream_session_t *s, rap_uint_t from_upstream,
    rap_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    rap_buf_t                    *b;
    rap_int_t                     rc;
    rap_uint_t                    flags, *packets;
    rap_msec_t                    delay;
    rap_chain_t                  *cl, **ll, **out, **busy;
    rap_connection_t             *c, *pc, *src, *dst;
    rap_log_handler_pt            handler;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (rap_terminate || rap_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        rap_log_error(RAP_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        rap_stream_proxy_finalize(s, RAP_STREAM_OK);
        return;
    }

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = rap_stream_top_filter(s, *out, from_upstream);

                if (rc == RAP_ERROR) {
                    rap_stream_proxy_finalize(s, RAP_STREAM_OK);
                    return;
                }

                rap_chain_update_chains(c->pool, &u->free, busy, out,
                                      (rap_buf_tag_t) &rap_stream_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed
            && !src->read->error)
        {
            if (limit_rate) {
                limit = (off_t) limit_rate * (rap_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (rap_msec_t) (- limit * 1000 / limit_rate + 1);
                    rap_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == RAP_AGAIN) {
                break;
            }

            if (n == RAP_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (rap_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        rap_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (rap_msec_t) -1) {
                        u->state->first_byte_time = rap_current_msec
                                                    - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = rap_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    rap_stream_proxy_finalize(s,
                                              RAP_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (rap_buf_tag_t) &rap_stream_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (rap_stream_proxy_test_finalize(s, from_upstream) == RAP_OK) {
        return;
    }

    flags = src->read->eof ? RAP_CLOSE_EVENT : 0;

    if (rap_handle_read_event(src->read, flags) != RAP_OK) {
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (rap_handle_write_event(dst->write, 0) != RAP_OK) {
            rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            rap_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            rap_del_timer(c->write);
        }
    }
}


static rap_int_t
rap_stream_proxy_test_finalize(rap_stream_session_t *s,
    rap_uint_t from_upstream)
{
    rap_connection_t             *c, *pc;
    rap_log_handler_pt            handler;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (pscf->requests && u->requests < pscf->requests) {
            return RAP_DECLINED;
        }

        if (pscf->requests) {
            rap_delete_udp_connection(c);
        }

        if (pscf->responses == RAP_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return RAP_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return RAP_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        rap_stream_proxy_finalize(s, RAP_STREAM_OK);

        return RAP_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return RAP_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    rap_log_error(RAP_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    rap_stream_proxy_finalize(s, RAP_STREAM_OK);

    return RAP_OK;
}


static void
rap_stream_proxy_next_upstream(rap_stream_session_t *s)
{
    rap_msec_t                    timeout;
    rap_connection_t             *pc;
    rap_stream_upstream_t        *u;
    rap_stream_proxy_srv_conf_t  *pscf;

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        rap_stream_proxy_finalize(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, RAP_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = rap_stream_get_module_srv_conf(s, rap_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && rap_current_msec - u->peer.start_time >= timeout))
    {
        rap_stream_proxy_finalize(s, RAP_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (RAP_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) rap_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        rap_close_connection(pc);
        u->peer.connection = NULL;
    }

    rap_stream_proxy_connect(s);
}


static void
rap_stream_proxy_finalize(rap_stream_session_t *s, rap_uint_t rc)
{
    rap_uint_t              state;
    rap_connection_t       *pc;
    rap_stream_upstream_t  *u;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        rap_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (rap_msec_t) -1) {
            u->state->response_time = rap_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = RAP_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (RAP_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) rap_ssl_shutdown(pc);
        }
#endif

        rap_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    rap_stream_finalize_session(s, rc);
}


static u_char *
rap_stream_proxy_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    rap_connection_t       *pc;
    rap_stream_session_t   *s;
    rap_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = rap_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = rap_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
rap_stream_proxy_create_srv_conf(rap_conf_t *cf)
{
    rap_stream_proxy_srv_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_name = NULL;
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     *
     *     conf->upload_rate = NULL;
     *     conf->download_rate = NULL;
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     *     conf->upstream_value = NULL;
     */

    conf->connect_timeout = RAP_CONF_UNSET_MSEC;
    conf->timeout = RAP_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = RAP_CONF_UNSET_MSEC;
    conf->buffer_size = RAP_CONF_UNSET_SIZE;
    conf->requests = RAP_CONF_UNSET_UINT;
    conf->responses = RAP_CONF_UNSET_UINT;
    conf->next_upstream_tries = RAP_CONF_UNSET_UINT;
    conf->next_upstream = RAP_CONF_UNSET;
    conf->proxy_protocol = RAP_CONF_UNSET;
    conf->local = RAP_CONF_UNSET_PTR;
    conf->socket_keepalive = RAP_CONF_UNSET;

#if (RAP_STREAM_SSL)
    conf->ssl_enable = RAP_CONF_UNSET;
    conf->ssl_session_reuse = RAP_CONF_UNSET;
    conf->ssl_server_name = RAP_CONF_UNSET;
    conf->ssl_verify = RAP_CONF_UNSET;
    conf->ssl_verify_depth = RAP_CONF_UNSET_UINT;
    conf->ssl_passwords = RAP_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
rap_stream_proxy_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_stream_proxy_srv_conf_t *prev = parent;
    rap_stream_proxy_srv_conf_t *conf = child;

    rap_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    rap_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    rap_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    rap_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    if (conf->upload_rate == NULL) {
        conf->upload_rate = prev->upload_rate;
    }

    if (conf->download_rate == NULL) {
        conf->download_rate = prev->download_rate;
    }

    rap_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    rap_conf_merge_uint_value(conf->responses,
                              prev->responses, RAP_MAX_INT32_VALUE);

    rap_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    rap_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    rap_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    rap_conf_merge_ptr_value(conf->local, prev->local, NULL);

    rap_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

#if (RAP_STREAM_SSL)

    rap_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    rap_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    rap_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                               |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

    rap_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    if (conf->ssl_name == NULL) {
        conf->ssl_name = prev->ssl_name;
    }

    rap_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    rap_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    rap_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    rap_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    rap_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rap_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");

    rap_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");

    rap_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_enable && rap_stream_proxy_set_ssl(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#endif

    return RAP_CONF_OK;
}


#if (RAP_STREAM_SSL)

static rap_int_t
rap_stream_proxy_set_ssl(rap_conf_t *cf, rap_stream_proxy_srv_conf_t *pscf)
{
    rap_pool_cleanup_t  *cln;

    pscf->ssl = rap_pcalloc(cf->pool, sizeof(rap_ssl_t));
    if (pscf->ssl == NULL) {
        return RAP_ERROR;
    }

    pscf->ssl->log = cf->log;

    if (rap_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != RAP_OK) {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(pscf->ssl);
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (pscf->ssl_certificate.len) {

        if (pscf->ssl_certificate_key.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &pscf->ssl_certificate);
            return RAP_ERROR;
        }

        if (rap_ssl_certificate(cf, pscf->ssl, &pscf->ssl_certificate,
                                &pscf->ssl_certificate_key, pscf->ssl_passwords)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return RAP_ERROR;
        }

        if (rap_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        if (rap_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static char *
rap_stream_proxy_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_proxy_srv_conf_t *pscf = conf;

    rap_url_t                            u;
    rap_str_t                           *value, *url;
    rap_stream_complex_value_t           cv;
    rap_stream_core_srv_conf_t          *cscf;
    rap_stream_compile_complex_value_t   ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = rap_stream_conf_get_module_srv_conf(cf, rap_stream_core_module);

    cscf->handler = rap_stream_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->upstream_value = rap_palloc(cf->pool,
                                          sizeof(rap_stream_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return RAP_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return RAP_CONF_OK;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = rap_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_stream_proxy_bind(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_proxy_srv_conf_t *pscf = conf;

    rap_int_t                            rc;
    rap_str_t                           *value;
    rap_stream_complex_value_t           cv;
    rap_stream_upstream_local_t         *local;
    rap_stream_compile_complex_value_t   ccv;

    if (pscf->local != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && rap_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return RAP_CONF_OK;
    }

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    local = rap_pcalloc(cf->pool, sizeof(rap_stream_upstream_local_t));
    if (local == NULL) {
        return RAP_CONF_ERROR;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = rap_palloc(cf->pool, sizeof(rap_stream_complex_value_t));
        if (local->value == NULL) {
            return RAP_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = rap_palloc(cf->pool, sizeof(rap_addr_t));
        if (local->addr == NULL) {
            return RAP_CONF_ERROR;
        }

        rc = rap_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case RAP_OK:
            local->addr->name = value[1];
            break;

        case RAP_DECLINED:
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return RAP_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (rap_strcmp(value[2].data, "transparent") == 0) {
#if (RAP_HAVE_TRANSPARENT_PROXY)
            rap_core_conf_t  *ccf;

            ccf = (rap_core_conf_t *) rap_get_conf(cf->cycle->conf_ctx,
                                                   rap_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}
