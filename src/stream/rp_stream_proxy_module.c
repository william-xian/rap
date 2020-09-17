
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_addr_t                      *addr;
    rp_stream_complex_value_t      *value;
#if (RP_HAVE_TRANSPARENT_PROXY)
    rp_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} rp_stream_upstream_local_t;


typedef struct {
    rp_msec_t                       connect_timeout;
    rp_msec_t                       timeout;
    rp_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    rp_stream_complex_value_t      *upload_rate;
    rp_stream_complex_value_t      *download_rate;
    rp_uint_t                       requests;
    rp_uint_t                       responses;
    rp_uint_t                       next_upstream_tries;
    rp_flag_t                       next_upstream;
    rp_flag_t                       proxy_protocol;
    rp_stream_upstream_local_t     *local;
    rp_flag_t                       socket_keepalive;

#if (RP_STREAM_SSL)
    rp_flag_t                       ssl_enable;
    rp_flag_t                       ssl_session_reuse;
    rp_uint_t                       ssl_protocols;
    rp_str_t                        ssl_ciphers;
    rp_stream_complex_value_t      *ssl_name;
    rp_flag_t                       ssl_server_name;

    rp_flag_t                       ssl_verify;
    rp_uint_t                       ssl_verify_depth;
    rp_str_t                        ssl_trusted_certificate;
    rp_str_t                        ssl_crl;
    rp_str_t                        ssl_certificate;
    rp_str_t                        ssl_certificate_key;
    rp_array_t                     *ssl_passwords;

    rp_ssl_t                       *ssl;
#endif

    rp_stream_upstream_srv_conf_t  *upstream;
    rp_stream_complex_value_t      *upstream_value;
} rp_stream_proxy_srv_conf_t;


static void rp_stream_proxy_handler(rp_stream_session_t *s);
static rp_int_t rp_stream_proxy_eval(rp_stream_session_t *s,
    rp_stream_proxy_srv_conf_t *pscf);
static rp_int_t rp_stream_proxy_set_local(rp_stream_session_t *s,
    rp_stream_upstream_t *u, rp_stream_upstream_local_t *local);
static void rp_stream_proxy_connect(rp_stream_session_t *s);
static void rp_stream_proxy_init_upstream(rp_stream_session_t *s);
static void rp_stream_proxy_resolve_handler(rp_resolver_ctx_t *ctx);
static void rp_stream_proxy_upstream_handler(rp_event_t *ev);
static void rp_stream_proxy_downstream_handler(rp_event_t *ev);
static void rp_stream_proxy_process_connection(rp_event_t *ev,
    rp_uint_t from_upstream);
static void rp_stream_proxy_connect_handler(rp_event_t *ev);
static rp_int_t rp_stream_proxy_test_connect(rp_connection_t *c);
static void rp_stream_proxy_process(rp_stream_session_t *s,
    rp_uint_t from_upstream, rp_uint_t do_write);
static rp_int_t rp_stream_proxy_test_finalize(rp_stream_session_t *s,
    rp_uint_t from_upstream);
static void rp_stream_proxy_next_upstream(rp_stream_session_t *s);
static void rp_stream_proxy_finalize(rp_stream_session_t *s, rp_uint_t rc);
static u_char *rp_stream_proxy_log_error(rp_log_t *log, u_char *buf,
    size_t len);

static void *rp_stream_proxy_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_proxy_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_stream_proxy_pass(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_proxy_bind(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

#if (RP_STREAM_SSL)

static rp_int_t rp_stream_proxy_send_proxy_protocol(rp_stream_session_t *s);
static char *rp_stream_proxy_ssl_password_file(rp_conf_t *cf,
    rp_command_t *cmd, void *conf);
static void rp_stream_proxy_ssl_init_connection(rp_stream_session_t *s);
static void rp_stream_proxy_ssl_handshake(rp_connection_t *pc);
static void rp_stream_proxy_ssl_save_session(rp_connection_t *c);
static rp_int_t rp_stream_proxy_ssl_name(rp_stream_session_t *s);
static rp_int_t rp_stream_proxy_set_ssl(rp_conf_t *cf,
    rp_stream_proxy_srv_conf_t *pscf);


static rp_conf_bitmask_t  rp_stream_proxy_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};

#endif


static rp_conf_deprecated_t  rp_conf_deprecated_proxy_downstream_buffer = {
    rp_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static rp_conf_deprecated_t  rp_conf_deprecated_proxy_upstream_buffer = {
    rp_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


static rp_command_t  rp_stream_proxy_commands[] = {

    { rp_string("proxy_pass"),
      RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_proxy_pass,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("proxy_bind"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE12,
      rp_stream_proxy_bind,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("proxy_socket_keepalive"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { rp_string("proxy_connect_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { rp_string("proxy_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, timeout),
      NULL },

    { rp_string("proxy_buffer_size"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { rp_string("proxy_downstream_buffer"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, buffer_size),
      &rp_conf_deprecated_proxy_downstream_buffer },

    { rp_string("proxy_upstream_buffer"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, buffer_size),
      &rp_conf_deprecated_proxy_upstream_buffer },

    { rp_string("proxy_upload_rate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_set_complex_value_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { rp_string("proxy_download_rate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_set_complex_value_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { rp_string("proxy_requests"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, requests),
      NULL },

    { rp_string("proxy_responses"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, responses),
      NULL },

    { rp_string("proxy_next_upstream"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { rp_string("proxy_next_upstream_tries"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { rp_string("proxy_next_upstream_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { rp_string("proxy_protocol"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, proxy_protocol),
      NULL },

#if (RP_STREAM_SSL)

    { rp_string("proxy_ssl"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { rp_string("proxy_ssl_session_reuse"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { rp_string("proxy_ssl_protocols"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_protocols),
      &rp_stream_proxy_ssl_protocols },

    { rp_string("proxy_ssl_ciphers"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { rp_string("proxy_ssl_name"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_set_complex_value_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { rp_string("proxy_ssl_server_name"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { rp_string("proxy_ssl_verify"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { rp_string("proxy_ssl_verify_depth"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { rp_string("proxy_ssl_trusted_certificate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { rp_string("proxy_ssl_crl"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

    { rp_string("proxy_ssl_certificate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { rp_string("proxy_ssl_certificate_key"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

    { rp_string("proxy_ssl_password_file"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_proxy_ssl_password_file,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#endif

      rp_null_command
};


static rp_stream_module_t  rp_stream_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_proxy_create_srv_conf,      /* create server configuration */
    rp_stream_proxy_merge_srv_conf        /* merge server configuration */
};


rp_module_t  rp_stream_proxy_module = {
    RP_MODULE_V1,
    &rp_stream_proxy_module_ctx,          /* module context */
    rp_stream_proxy_commands,             /* module directives */
    RP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static void
rp_stream_proxy_handler(rp_stream_session_t *s)
{
    u_char                           *p;
    rp_str_t                        *host;
    rp_uint_t                        i;
    rp_connection_t                 *c;
    rp_resolver_ctx_t               *ctx, temp;
    rp_stream_upstream_t            *u;
    rp_stream_core_srv_conf_t       *cscf;
    rp_stream_proxy_srv_conf_t      *pscf;
    rp_stream_upstream_srv_conf_t   *uscf, **uscfp;
    rp_stream_upstream_main_conf_t  *umcf;

    c = s->connection;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = rp_pcalloc(c->pool, sizeof(rp_stream_upstream_t));
    if (u == NULL) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = rp_stream_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = RP_ERROR_ERR;

    if (rp_stream_proxy_set_local(s, u, pscf->local) != RP_OK) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = rp_time();

    c->write->handler = rp_stream_proxy_downstream_handler;
    c->read->handler = rp_stream_proxy_downstream_handler;

    s->upstream_states = rp_array_create(c->pool, 1,
                                          sizeof(rp_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = rp_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        rp_post_event(c->read, &rp_posted_events);
    }

    if (pscf->upstream_value) {
        if (rp_stream_proxy_eval(s, pscf) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {

        uscf = pscf->upstream;

    } else {

#if (RP_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = rp_stream_get_module_main_conf(s, rp_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && rp_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                rp_log_error(RP_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rp_stream_upstream_create_round_robin_peer(s, u->resolved)
                != RP_OK)
            {
                rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            rp_stream_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            rp_log_error(RP_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

        ctx = rp_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == RP_NO_RESOLVER) {
            rp_log_error(RP_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = rp_stream_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (rp_resolve_name(ctx) != RP_OK) {
            u->resolved->ctx = NULL;
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        rp_log_error(RP_LOG_ALERT, c->log, 0, "no upstream configuration");
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (RP_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(s, uscf) != RP_OK) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = rp_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    rp_stream_proxy_connect(s);
}


static rp_int_t
rp_stream_proxy_eval(rp_stream_session_t *s,
    rp_stream_proxy_srv_conf_t *pscf)
{
    rp_str_t               host;
    rp_url_t               url;
    rp_stream_upstream_t  *u;

    if (rp_stream_complex_value(s, pscf->upstream_value, &host) != RP_OK) {
        return RP_ERROR;
    }

    rp_memzero(&url, sizeof(rp_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (rp_parse_url(s->connection->pool, &url) != RP_OK) {
        if (url.err) {
            rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RP_ERROR;
    }

    u = s->upstream;

    u->resolved = rp_pcalloc(s->connection->pool,
                              sizeof(rp_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RP_ERROR;
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

    return RP_OK;
}


static rp_int_t
rp_stream_proxy_set_local(rp_stream_session_t *s, rp_stream_upstream_t *u,
    rp_stream_upstream_local_t *local)
{
    rp_int_t    rc;
    rp_str_t    val;
    rp_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return RP_OK;
    }

#if (RP_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return RP_OK;
    }

    if (rp_stream_complex_value(s, local->value, &val) != RP_OK) {
        return RP_ERROR;
    }

    if (val.len == 0) {
        return RP_OK;
    }

    addr = rp_palloc(s->connection->pool, sizeof(rp_addr_t));
    if (addr == NULL) {
        return RP_ERROR;
    }

    rc = rp_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == RP_ERROR) {
        return RP_ERROR;
    }

    if (rc != RP_OK) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return RP_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return RP_OK;
}


static void
rp_stream_proxy_connect(rp_stream_session_t *s)
{
    rp_int_t                     rc;
    rp_connection_t             *c, *pc;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;

    if (u->state) {
        u->state->response_time = rp_current_msec - u->start_time;
    }

    u->state = rp_array_push(s->upstream_states);
    if (u->state == NULL) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_memzero(u->state, sizeof(rp_stream_upstream_state_t));

    u->start_time = rp_current_msec;

    u->state->connect_time = (rp_msec_t) -1;
    u->state->first_byte_time = (rp_msec_t) -1;
    u->state->response_time = (rp_msec_t) -1;

    rc = rp_event_connect_peer(&u->peer);

    rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == RP_ERROR) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == RP_BUSY) {
        rp_log_error(RP_LOG_ERR, c->log, 0, "no live upstreams");
        rp_stream_proxy_finalize(s, RP_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == RP_DECLINED) {
        rp_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == RP_OK || rc == RP_AGAIN || rc == RP_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != RP_AGAIN) {
        rp_stream_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = rp_stream_proxy_connect_handler;
    pc->write->handler = rp_stream_proxy_connect_handler;

    rp_add_timer(pc->write, pscf->connect_timeout);
}


static void
rp_stream_proxy_init_upstream(rp_stream_session_t *s)
{
    u_char                       *p;
    rp_chain_t                  *cl;
    rp_connection_t             *c, *pc;
    rp_log_handler_pt            handler;
    rp_stream_upstream_t        *u;
    rp_stream_core_srv_conf_t   *cscf;
    rp_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && rp_tcp_nodelay(pc) != RP_OK)
    {
        rp_stream_proxy_next_upstream(s);
        return;
    }

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

#if (RP_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl) {

        if (u->proxy_protocol) {
            if (rp_stream_proxy_send_proxy_protocol(s) != RP_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            rp_stream_proxy_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= RP_LOG_INFO) {
        rp_str_t  str;
        u_char     addr[RP_SOCKADDR_STRLEN];

        str.len = RP_SOCKADDR_STRLEN;
        str.data = addr;

        if (rp_connection_local_sockaddr(pc, &str, 1) == RP_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            rp_log_error(RP_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = rp_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       RP_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = rp_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = rp_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (rp_buf_tag_t) &rp_stream_proxy_module;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (u->proxy_protocol) {
        rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        cl = rp_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = rp_pnalloc(c->pool, RP_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = rp_proxy_protocol_write(c, p, p + RP_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (rp_buf_tag_t) &rp_stream_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = rp_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = rp_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = rp_stream_proxy_upstream_handler;
    pc->write->handler = rp_stream_proxy_upstream_handler;

    if (pc->read->ready) {
        rp_post_event(pc->read, &rp_posted_events);
    }

    rp_stream_proxy_process(s, 0, 1);
}


#if (RP_STREAM_SSL)

static rp_int_t
rp_stream_proxy_send_proxy_protocol(rp_stream_session_t *s)
{
    u_char                       *p;
    ssize_t                       n, size;
    rp_connection_t             *c, *pc;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;
    u_char                        buf[RP_PROXY_PROTOCOL_MAX_HEADER];

    c = s->connection;

    rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = rp_proxy_protocol_write(c, buf, buf + RP_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == RP_AGAIN) {
        if (rp_handle_write_event(pc->write, 0) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return RP_ERROR;
        }

        pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

        rp_add_timer(pc->write, pscf->timeout);

        pc->write->handler = rp_stream_proxy_connect_handler;

        return RP_AGAIN;
    }

    if (n == RP_ERROR) {
        rp_stream_proxy_finalize(s, RP_STREAM_OK);
        return RP_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        rp_log_error(RP_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);

        return RP_ERROR;
    }

    return RP_OK;
}


static char *
rp_stream_proxy_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    rp_stream_proxy_srv_conf_t *pscf = conf;

    rp_str_t  *value;

    if (pscf->ssl_passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static void
rp_stream_proxy_ssl_init_connection(rp_stream_session_t *s)
{
    rp_int_t                     rc;
    rp_connection_t             *pc;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    pc = u->peer.connection;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    if (rp_ssl_create_connection(pscf->ssl, pc, RP_SSL_BUFFER|RP_SSL_CLIENT)
        != RP_OK)
    {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (rp_stream_proxy_ssl_name(s) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = rp_stream_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = rp_ssl_handshake(pc);

    if (rc == RP_AGAIN) {

        if (!pc->write->timer_set) {
            rp_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = rp_stream_proxy_ssl_handshake;
        return;
    }

    rp_stream_proxy_ssl_handshake(pc);
}


static void
rp_stream_proxy_ssl_handshake(rp_connection_t *pc)
{
    long                          rc;
    rp_stream_session_t         *s;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                rp_log_error(RP_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (rp_ssl_check_host(pc, &u->ssl_name) != RP_OK) {
                rp_log_error(RP_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            rp_del_timer(pc->write);
        }

        rp_stream_proxy_init_upstream(s);

        return;
    }

failed:

    rp_stream_proxy_next_upstream(s);
}


static void
rp_stream_proxy_ssl_save_session(rp_connection_t *c)
{
    rp_stream_session_t   *s;
    rp_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static rp_int_t
rp_stream_proxy_ssl_name(rp_stream_session_t *s)
{
    u_char                       *p, *last;
    rp_str_t                     name;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name) {
        if (rp_stream_complex_value(s, pscf->ssl_name, &name) != RP_OK) {
            return RP_ERROR;
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
        p = rp_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = rp_strlchr(p, last, ':');

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

    if (rp_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = rp_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return RP_ERROR;
    }

    (void) rp_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        rp_ssl_error(RP_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return RP_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return RP_OK;
}

#endif


static void
rp_stream_proxy_downstream_handler(rp_event_t *ev)
{
    rp_stream_proxy_process_connection(ev, ev->write);
}


static void
rp_stream_proxy_resolve_handler(rp_resolver_ctx_t *ctx)
{
    rp_stream_session_t            *s;
    rp_stream_upstream_t           *u;
    rp_stream_proxy_srv_conf_t     *pscf;
    rp_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    rp_log_debug0(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rp_resolver_strerror(ctx->state));

        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (RP_DEBUG)
    {
    u_char      text[RP_SOCKADDR_STRLEN];
    rp_str_t   addr;
    rp_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = rp_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, RP_SOCKADDR_STRLEN, 0);

        rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (rp_stream_upstream_create_round_robin_peer(s, ur) != RP_OK) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = rp_current_msec;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    rp_stream_proxy_connect(s);
}


static void
rp_stream_proxy_upstream_handler(rp_event_t *ev)
{
    rp_stream_proxy_process_connection(ev, !ev->write);
}


static void
rp_stream_proxy_process_connection(rp_event_t *ev, rp_uint_t from_upstream)
{
    rp_connection_t             *c, *pc;
    rp_log_handler_pt            handler;
    rp_stream_session_t         *s;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        rp_log_error(RP_LOG_INFO, c->log, 0, "shutdown timeout");
        rp_stream_proxy_finalize(s, RP_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (rp_handle_read_event(ev, 0) != RP_OK) {
                    rp_stream_proxy_finalize(s,
                                              RP_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    rp_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (pscf->responses == RP_MAX_INT32_VALUE
                    || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    rp_log_error(RP_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    rp_stream_proxy_finalize(s, RP_STREAM_OK);
                    return;
                }

                rp_connection_error(pc, RP_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                rp_stream_proxy_finalize(s, RP_STREAM_BAD_GATEWAY);

                return;
            }

            rp_connection_error(c, RP_ETIMEDOUT, "connection timed out");

            rp_stream_proxy_finalize(s, RP_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (rp_handle_read_event(ev, 0) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    rp_stream_proxy_process(s, from_upstream, ev->write);
}


static void
rp_stream_proxy_connect_handler(rp_event_t *ev)
{
    rp_connection_t      *c;
    rp_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        rp_log_error(RP_LOG_ERR, c->log, RP_ETIMEDOUT, "upstream timed out");
        rp_stream_proxy_next_upstream(s);
        return;
    }

    rp_del_timer(c->write);

    rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (rp_stream_proxy_test_connect(c) != RP_OK) {
        rp_stream_proxy_next_upstream(s);
        return;
    }

    rp_stream_proxy_init_upstream(s);
}


static rp_int_t
rp_stream_proxy_test_connect(rp_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) rp_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return RP_ERROR;
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
            err = rp_socket_errno;
        }

        if (err) {
            (void) rp_connection_error(c, err, "connect() failed");
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static void
rp_stream_proxy_process(rp_stream_session_t *s, rp_uint_t from_upstream,
    rp_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    rp_buf_t                    *b;
    rp_int_t                     rc;
    rp_uint_t                    flags, *packets;
    rp_msec_t                    delay;
    rp_chain_t                  *cl, **ll, **out, **busy;
    rp_connection_t             *c, *pc, *src, *dst;
    rp_log_handler_pt            handler;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (rp_terminate || rp_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        rp_log_error(RP_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        rp_stream_proxy_finalize(s, RP_STREAM_OK);
        return;
    }

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

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

                rc = rp_stream_top_filter(s, *out, from_upstream);

                if (rc == RP_ERROR) {
                    rp_stream_proxy_finalize(s, RP_STREAM_OK);
                    return;
                }

                rp_chain_update_chains(c->pool, &u->free, busy, out,
                                      (rp_buf_tag_t) &rp_stream_proxy_module);

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
                limit = (off_t) limit_rate * (rp_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (rp_msec_t) (- limit * 1000 / limit_rate + 1);
                    rp_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == RP_AGAIN) {
                break;
            }

            if (n == RP_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (rp_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        rp_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (rp_msec_t) -1) {
                        u->state->first_byte_time = rp_current_msec
                                                    - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = rp_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    rp_stream_proxy_finalize(s,
                                              RP_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (rp_buf_tag_t) &rp_stream_proxy_module;

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

    if (rp_stream_proxy_test_finalize(s, from_upstream) == RP_OK) {
        return;
    }

    flags = src->read->eof ? RP_CLOSE_EVENT : 0;

    if (rp_handle_read_event(src->read, flags) != RP_OK) {
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (rp_handle_write_event(dst->write, 0) != RP_OK) {
            rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            rp_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            rp_del_timer(c->write);
        }
    }
}


static rp_int_t
rp_stream_proxy_test_finalize(rp_stream_session_t *s,
    rp_uint_t from_upstream)
{
    rp_connection_t             *c, *pc;
    rp_log_handler_pt            handler;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (pscf->requests && u->requests < pscf->requests) {
            return RP_DECLINED;
        }

        if (pscf->requests) {
            rp_delete_udp_connection(c);
        }

        if (pscf->responses == RP_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return RP_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return RP_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        rp_stream_proxy_finalize(s, RP_STREAM_OK);

        return RP_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return RP_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    rp_log_error(RP_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    rp_stream_proxy_finalize(s, RP_STREAM_OK);

    return RP_OK;
}


static void
rp_stream_proxy_next_upstream(rp_stream_session_t *s)
{
    rp_msec_t                    timeout;
    rp_connection_t             *pc;
    rp_stream_upstream_t        *u;
    rp_stream_proxy_srv_conf_t  *pscf;

    rp_log_debug0(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        rp_stream_proxy_finalize(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, RP_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = rp_stream_get_module_srv_conf(s, rp_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && rp_current_msec - u->peer.start_time >= timeout))
    {
        rp_stream_proxy_finalize(s, RP_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (RP_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) rp_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        rp_close_connection(pc);
        u->peer.connection = NULL;
    }

    rp_stream_proxy_connect(s);
}


static void
rp_stream_proxy_finalize(rp_stream_session_t *s, rp_uint_t rc)
{
    rp_uint_t              state;
    rp_connection_t       *pc;
    rp_stream_upstream_t  *u;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        rp_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (rp_msec_t) -1) {
            u->state->response_time = rp_current_msec - u->start_time;
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
            state = RP_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (RP_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) rp_ssl_shutdown(pc);
        }
#endif

        rp_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    rp_stream_finalize_session(s, rc);
}


static u_char *
rp_stream_proxy_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    rp_connection_t       *pc;
    rp_stream_session_t   *s;
    rp_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = rp_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = rp_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
rp_stream_proxy_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_proxy_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
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

    conf->connect_timeout = RP_CONF_UNSET_MSEC;
    conf->timeout = RP_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = RP_CONF_UNSET_MSEC;
    conf->buffer_size = RP_CONF_UNSET_SIZE;
    conf->requests = RP_CONF_UNSET_UINT;
    conf->responses = RP_CONF_UNSET_UINT;
    conf->next_upstream_tries = RP_CONF_UNSET_UINT;
    conf->next_upstream = RP_CONF_UNSET;
    conf->proxy_protocol = RP_CONF_UNSET;
    conf->local = RP_CONF_UNSET_PTR;
    conf->socket_keepalive = RP_CONF_UNSET;

#if (RP_STREAM_SSL)
    conf->ssl_enable = RP_CONF_UNSET;
    conf->ssl_session_reuse = RP_CONF_UNSET;
    conf->ssl_server_name = RP_CONF_UNSET;
    conf->ssl_verify = RP_CONF_UNSET;
    conf->ssl_verify_depth = RP_CONF_UNSET_UINT;
    conf->ssl_passwords = RP_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
rp_stream_proxy_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_proxy_srv_conf_t *prev = parent;
    rp_stream_proxy_srv_conf_t *conf = child;

    rp_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    rp_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    rp_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    rp_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    if (conf->upload_rate == NULL) {
        conf->upload_rate = prev->upload_rate;
    }

    if (conf->download_rate == NULL) {
        conf->download_rate = prev->download_rate;
    }

    rp_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    rp_conf_merge_uint_value(conf->responses,
                              prev->responses, RP_MAX_INT32_VALUE);

    rp_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    rp_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    rp_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    rp_conf_merge_ptr_value(conf->local, prev->local, NULL);

    rp_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

#if (RP_STREAM_SSL)

    rp_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    rp_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    rp_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                               |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

    rp_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    if (conf->ssl_name == NULL) {
        conf->ssl_name = prev->ssl_name;
    }

    rp_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    rp_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    rp_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    rp_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    rp_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rp_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");

    rp_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");

    rp_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_enable && rp_stream_proxy_set_ssl(cf, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

#endif

    return RP_CONF_OK;
}


#if (RP_STREAM_SSL)

static rp_int_t
rp_stream_proxy_set_ssl(rp_conf_t *cf, rp_stream_proxy_srv_conf_t *pscf)
{
    rp_pool_cleanup_t  *cln;

    pscf->ssl = rp_pcalloc(cf->pool, sizeof(rp_ssl_t));
    if (pscf->ssl == NULL) {
        return RP_ERROR;
    }

    pscf->ssl->log = cf->log;

    if (rp_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != RP_OK) {
        return RP_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rp_ssl_cleanup_ctx(pscf->ssl);
        return RP_ERROR;
    }

    cln->handler = rp_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (pscf->ssl_certificate.len) {

        if (pscf->ssl_certificate_key.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &pscf->ssl_certificate);
            return RP_ERROR;
        }

        if (rp_ssl_certificate(cf, pscf->ssl, &pscf->ssl_certificate,
                                &pscf->ssl_certificate_key, pscf->ssl_passwords)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    if (rp_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != RP_OK) {
        return RP_ERROR;
    }

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return RP_ERROR;
        }

        if (rp_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != RP_OK)
        {
            return RP_ERROR;
        }

        if (rp_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (rp_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
        != RP_OK)
    {
        return RP_ERROR;
    }

    return RP_OK;
}

#endif


static char *
rp_stream_proxy_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_proxy_srv_conf_t *pscf = conf;

    rp_url_t                            u;
    rp_str_t                           *value, *url;
    rp_stream_complex_value_t           cv;
    rp_stream_core_srv_conf_t          *cscf;
    rp_stream_compile_complex_value_t   ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = rp_stream_conf_get_module_srv_conf(cf, rp_stream_core_module);

    cscf->handler = rp_stream_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->upstream_value = rp_palloc(cf->pool,
                                          sizeof(rp_stream_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return RP_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return RP_CONF_OK;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = rp_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_stream_proxy_bind(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_proxy_srv_conf_t *pscf = conf;

    rp_int_t                            rc;
    rp_str_t                           *value;
    rp_stream_complex_value_t           cv;
    rp_stream_upstream_local_t         *local;
    rp_stream_compile_complex_value_t   ccv;

    if (pscf->local != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && rp_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return RP_CONF_OK;
    }

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    local = rp_pcalloc(cf->pool, sizeof(rp_stream_upstream_local_t));
    if (local == NULL) {
        return RP_CONF_ERROR;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = rp_palloc(cf->pool, sizeof(rp_stream_complex_value_t));
        if (local->value == NULL) {
            return RP_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = rp_palloc(cf->pool, sizeof(rp_addr_t));
        if (local->addr == NULL) {
            return RP_CONF_ERROR;
        }

        rc = rp_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case RP_OK:
            local->addr->name = value[1];
            break;

        case RP_DECLINED:
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return RP_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (rp_strcmp(value[2].data, "transparent") == 0) {
#if (RP_HAVE_TRANSPARENT_PROXY)
            rp_core_conf_t  *ccf;

            ccf = (rp_core_conf_t *) rp_get_conf(cf->cycle->conf_ctx,
                                                   rp_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}
