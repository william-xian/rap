
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef rp_int_t (*rp_ssl_variable_handler_pt)(rp_connection_t *c,
    rp_pool_t *pool, rp_str_t *s);


#define RP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RP_DEFAULT_ECDH_CURVE  "auto"

#define RP_HTTP_NPN_ADVERTISE  "\x08http/1.1"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int rp_http_ssl_alpn_select(rp_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
static int rp_http_ssl_npn_advertised(rp_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg);
#endif

static rp_int_t rp_http_ssl_static_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_ssl_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_ssl_add_variables(rp_conf_t *cf);
static void *rp_http_ssl_create_srv_conf(rp_conf_t *cf);
static char *rp_http_ssl_merge_srv_conf(rp_conf_t *cf,
    void *parent, void *child);

static rp_int_t rp_http_ssl_compile_certificates(rp_conf_t *cf,
    rp_http_ssl_srv_conf_t *conf);

static char *rp_http_ssl_enable(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

static rp_int_t rp_http_ssl_init(rp_conf_t *cf);


static rp_conf_bitmask_t  rp_http_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_http_ssl_verify[] = {
    { rp_string("off"), 0 },
    { rp_string("on"), 1 },
    { rp_string("optional"), 2 },
    { rp_string("optional_no_ca"), 3 },
    { rp_null_string, 0 }
};


static rp_conf_deprecated_t  rp_http_ssl_deprecated = {
    rp_conf_deprecated, "ssl", "listen ... ssl"
};


static rp_command_t  rp_http_ssl_commands[] = {

    { rp_string("ssl"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_http_ssl_enable,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, enable),
      &rp_http_ssl_deprecated },

    { rp_string("ssl_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, certificates),
      NULL },

    { rp_string("ssl_certificate_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, certificate_keys),
      NULL },

    { rp_string("ssl_password_file"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_ssl_password_file,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_dhparam"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, dhparam),
      NULL },

    { rp_string("ssl_ecdh_curve"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { rp_string("ssl_protocols"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, protocols),
      &rp_http_ssl_protocols },

    { rp_string("ssl_ciphers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, ciphers),
      NULL },

    { rp_string("ssl_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, buffer_size),
      NULL },

    { rp_string("ssl_verify_client"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, verify),
      &rp_http_ssl_verify },

    { rp_string("ssl_verify_depth"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { rp_string("ssl_client_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { rp_string("ssl_trusted_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { rp_string("ssl_prefer_server_ciphers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { rp_string("ssl_session_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE12,
      rp_http_ssl_session_cache,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_session_tickets"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, session_tickets),
      NULL },

    { rp_string("ssl_session_ticket_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, session_ticket_keys),
      NULL },

    { rp_string("ssl_session_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_sec_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { rp_string("ssl_crl"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, crl),
      NULL },

    { rp_string("ssl_stapling"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, stapling),
      NULL },

    { rp_string("ssl_stapling_file"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { rp_string("ssl_stapling_responder"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { rp_string("ssl_stapling_verify"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, stapling_verify),
      NULL },

    { rp_string("ssl_early_data"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_ssl_srv_conf_t, early_data),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_ssl_module_ctx = {
    rp_http_ssl_add_variables,            /* preconfiguration */
    rp_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_http_ssl_create_srv_conf,          /* create server configuration */
    rp_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_ssl_module = {
    RP_MODULE_V1,
    &rp_http_ssl_module_ctx,              /* module context */
    rp_http_ssl_commands,                 /* module directives */
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


static rp_http_variable_t  rp_http_ssl_vars[] = {

    { rp_string("ssl_protocol"), NULL, rp_http_ssl_static_variable,
      (uintptr_t) rp_ssl_get_protocol, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_cipher"), NULL, rp_http_ssl_static_variable,
      (uintptr_t) rp_ssl_get_cipher_name, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_ciphers"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_ciphers, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_curves"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_curves, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_session_id"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_session_id, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_session_reused"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_session_reused, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_early_data"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_early_data,
      RP_HTTP_VAR_CHANGEABLE|RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("ssl_server_name"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_server_name, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_cert"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_certificate, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_raw_cert"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_raw_certificate,
      RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_escaped_cert"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_escaped_certificate,
      RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_s_dn"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_subject_dn, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_i_dn"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_issuer_dn, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_s_dn_legacy"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_subject_dn_legacy, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_i_dn_legacy"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_issuer_dn_legacy, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_serial"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_serial_number, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_fingerprint"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_fingerprint, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_verify"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_client_verify, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_start"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_start, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_end"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_end, RP_HTTP_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_remain"), NULL, rp_http_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_remain, RP_HTTP_VAR_CHANGEABLE, 0 },

      rp_http_null_variable
};


static rp_str_t rp_http_ssl_sess_id_ctx = rp_string("HTTP");


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
rp_http_ssl_alpn_select(rp_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int            srvlen;
    unsigned char          *srv;
#if (RP_DEBUG)
    unsigned int            i;
#endif
#if (RP_HTTP_V2)
    rp_http_connection_t  *hc;
#endif
#if (RP_HTTP_V2 || RP_DEBUG)
    rp_connection_t       *c;

    c = rp_ssl_get_connection(ssl_conn);
#endif

#if (RP_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

#if (RP_HTTP_V2)
    hc = c->data;

    if (hc->addr_conf->http2) {
        srv =
           (unsigned char *) RP_HTTP_V2_ALPN_ADVERTISE RP_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(RP_HTTP_V2_ALPN_ADVERTISE RP_HTTP_NPN_ADVERTISE) - 1;

    } else
#endif
    {
        srv = (unsigned char *) RP_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(RP_HTTP_NPN_ADVERTISE) - 1;
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef TLSEXT_TYPE_next_proto_neg

static int
rp_http_ssl_npn_advertised(rp_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg)
{
#if (RP_HTTP_V2 || RP_DEBUG)
    rp_connection_t  *c;

    c = rp_ssl_get_connection(ssl_conn);
    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "SSL NPN advertised");
#endif

#if (RP_HTTP_V2)
    {
    rp_http_connection_t  *hc;

    hc = c->data;

    if (hc->addr_conf->http2) {
        *out =
            (unsigned char *) RP_HTTP_V2_NPN_ADVERTISE RP_HTTP_NPN_ADVERTISE;
        *outlen = sizeof(RP_HTTP_V2_NPN_ADVERTISE RP_HTTP_NPN_ADVERTISE) - 1;

        return SSL_TLSEXT_ERR_OK;
    }
    }
#endif

    *out = (unsigned char *) RP_HTTP_NPN_ADVERTISE;
    *outlen = sizeof(RP_HTTP_NPN_ADVERTISE) - 1;

    return SSL_TLSEXT_ERR_OK;
}

#endif


static rp_int_t
rp_http_ssl_static_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_ssl_variable_handler_pt  handler = (rp_ssl_variable_handler_pt) data;

    size_t     len;
    rp_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return RP_OK;
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_ssl_variable(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_ssl_variable_handler_pt  handler = (rp_ssl_variable_handler_pt) data;

    rp_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != RP_OK) {
            return RP_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return RP_OK;
        }
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_ssl_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_ssl_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static void *
rp_http_ssl_create_srv_conf(rp_conf_t *cf)
{
    rp_http_ssl_srv_conf_t  *sscf;

    sscf = rp_pcalloc(cf->pool, sizeof(rp_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate_values = NULL;
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->trusted_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers = { 0, NULL };
     *     sscf->shm_zone = NULL;
     *     sscf->stapling_file = { 0, NULL };
     *     sscf->stapling_responder = { 0, NULL };
     */

    sscf->enable = RP_CONF_UNSET;
    sscf->prefer_server_ciphers = RP_CONF_UNSET;
    sscf->early_data = RP_CONF_UNSET;
    sscf->buffer_size = RP_CONF_UNSET_SIZE;
    sscf->verify = RP_CONF_UNSET_UINT;
    sscf->verify_depth = RP_CONF_UNSET_UINT;
    sscf->certificates = RP_CONF_UNSET_PTR;
    sscf->certificate_keys = RP_CONF_UNSET_PTR;
    sscf->passwords = RP_CONF_UNSET_PTR;
    sscf->builtin_session_cache = RP_CONF_UNSET;
    sscf->session_timeout = RP_CONF_UNSET;
    sscf->session_tickets = RP_CONF_UNSET;
    sscf->session_ticket_keys = RP_CONF_UNSET_PTR;
    sscf->stapling = RP_CONF_UNSET;
    sscf->stapling_verify = RP_CONF_UNSET;

    return sscf;
}


static char *
rp_http_ssl_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_ssl_srv_conf_t *prev = parent;
    rp_http_ssl_srv_conf_t *conf = child;

    rp_pool_cleanup_t  *cln;

    if (conf->enable == RP_CONF_UNSET) {
        if (prev->enable == RP_CONF_UNSET) {
            conf->enable = 0;

        } else {
            conf->enable = prev->enable;
            conf->file = prev->file;
            conf->line = prev->line;
        }
    }

    rp_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rp_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rp_conf_merge_value(conf->early_data, prev->early_data, 0);

    rp_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                          |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

    rp_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                         RP_SSL_BUFSIZE);

    rp_conf_merge_uint_value(conf->verify, prev->verify, 0);
    rp_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    rp_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    rp_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    rp_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    rp_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    rp_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    rp_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    rp_conf_merge_str_value(conf->crl, prev->crl, "");

    rp_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         RP_DEFAULT_ECDH_CURVE);

    rp_conf_merge_str_value(conf->ciphers, prev->ciphers, RP_DEFAULT_CIPHERS);

    rp_conf_merge_value(conf->stapling, prev->stapling, 0);
    rp_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    rp_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    rp_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

    conf->ssl.log = cf->log;

    if (conf->enable) {

        if (conf->certificates == NULL) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return RP_CONF_ERROR;
        }

        if (conf->certificate_keys == NULL) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return RP_CONF_ERROR;
        }

        if (conf->certificate_keys->nelts < conf->certificates->nelts) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\" and "
                          "the \"ssl\" directive in %s:%ui",
                          ((rp_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1,
                          conf->file, conf->line);
            return RP_CONF_ERROR;
        }

    } else {

        if (conf->certificates == NULL) {
            return RP_CONF_OK;
        }

        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((rp_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return RP_CONF_ERROR;
        }
    }

    if (rp_ssl_create(&conf->ssl, conf->protocols, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rp_ssl_cleanup_ctx(&conf->ssl);
        return RP_CONF_ERROR;
    }

    cln->handler = rp_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               rp_http_ssl_servername)
        == 0)
    {
        rp_log_error(RP_LOG_WARN, cf->log, 0,
            "rap was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }

#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, rp_http_ssl_alpn_select, NULL);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(conf->ssl.ctx,
                                          rp_http_ssl_npn_advertised, NULL);
#endif

    if (rp_http_ssl_compile_certificates(cf, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, rp_http_ssl_certificate, conf);

#else
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "variables in "
                      "\"ssl_certificate\" and \"ssl_certificate_key\" "
                      "directives are not supported on this platform");
        return RP_CONF_ERROR;
#endif

    } else {

        /* configure certificates */

        if (rp_ssl_certificates(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->passwords)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    if (rp_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    conf->ssl.buffer_size = conf->buffer_size;

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_verify_client");
            return RP_CONF_ERROR;
        }

        if (rp_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    if (rp_ssl_trusted_certificate(cf, &conf->ssl,
                                    &conf->trusted_certificate,
                                    conf->verify_depth)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    if (rp_ssl_crl(cf, &conf->ssl, &conf->crl) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != RP_OK) {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, RP_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (rp_ssl_session_cache(&conf->ssl, &rp_http_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    rp_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (rp_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    if (conf->stapling) {

        if (rp_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

    }

    if (rp_ssl_early_data(cf, &conf->ssl, conf->early_data) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_ssl_compile_certificates(rp_conf_t *cf,
    rp_http_ssl_srv_conf_t *conf)
{
    rp_str_t                         *cert, *key;
    rp_uint_t                         i, nelts;
    rp_http_complex_value_t          *cv;
    rp_http_compile_complex_value_t   ccv;

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (rp_http_script_variables_count(&cert[i])) {
            goto found;
        }

        if (rp_http_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return RP_OK;

found:

    conf->certificate_values = rp_array_create(cf->pool, nelts,
                                             sizeof(rp_http_complex_value_t));
    if (conf->certificate_values == NULL) {
        return RP_ERROR;
    }

    conf->certificate_key_values = rp_array_create(cf->pool, nelts,
                                             sizeof(rp_http_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return RP_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = rp_array_push(conf->certificate_values);
        if (cv == NULL) {
            return RP_ERROR;
        }

        rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rp_http_compile_complex_value(&ccv) != RP_OK) {
            return RP_ERROR;
        }

        cv = rp_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return RP_ERROR;
        }

        rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rp_http_compile_complex_value(&ccv) != RP_OK) {
            return RP_ERROR;
        }
    }

    conf->passwords = rp_ssl_preserve_passwords(cf, conf->passwords);
    if (conf->passwords == NULL) {
        return RP_ERROR;
    }

    return RP_OK;
}


static char *
rp_http_ssl_enable(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_ssl_srv_conf_t *sscf = conf;

    char  *rv;

    rv = rp_conf_set_flag_slot(cf, cmd, conf);

    if (rv != RP_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return RP_CONF_OK;
}


static char *
rp_http_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_ssl_srv_conf_t *sscf = conf;

    rp_str_t  *value;

    if (sscf->passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (sscf->passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    rp_str_t   *value, name, size;
    rp_int_t    n;
    rp_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = RP_SSL_NO_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = RP_SSL_NONE_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = RP_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && rp_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = rp_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == RP_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && rp_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = rp_parse_size(&size);

            if (n == RP_ERROR) {
                goto invalid;
            }

            if (n < (rp_int_t) (8 * rp_pagesize)) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return RP_CONF_ERROR;
            }

            sscf->shm_zone = rp_shared_memory_add(cf, &name, n,
                                                   &rp_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return RP_CONF_ERROR;
            }

            sscf->shm_zone->init = rp_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == RP_CONF_UNSET) {
        sscf->builtin_session_cache = RP_SSL_NO_BUILTIN_SCACHE;
    }

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RP_CONF_ERROR;
}


static rp_int_t
rp_http_ssl_init(rp_conf_t *cf)
{
    rp_uint_t                   a, p, s;
    rp_http_conf_addr_t        *addr;
    rp_http_conf_port_t        *port;
    rp_http_ssl_srv_conf_t     *sscf;
    rp_http_core_loc_conf_t    *clcf;
    rp_http_core_srv_conf_t   **cscfp, *cscf;
    rp_http_core_main_conf_t   *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[rp_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL || !sscf->stapling) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[rp_http_core_module.ctx_index];

        if (rp_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    if (cmcf->ports == NULL) {
        return RP_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (!addr[a].opt.ssl) {
                continue;
            }

            cscf = addr[a].default_server;
            sscf = cscf->ctx->srv_conf[rp_http_ssl_module.ctx_index];

            if (sscf->certificates == NULL) {
                rp_log_error(RP_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... ssl\" directive in %s:%ui",
                              cscf->file_name, cscf->line);
                return RP_ERROR;
            }
        }
    }

    return RP_OK;
}
