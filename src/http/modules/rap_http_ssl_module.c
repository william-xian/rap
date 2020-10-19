
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef rap_int_t (*rap_ssl_variable_handler_pt)(rap_connection_t *c,
    rap_pool_t *pool, rap_str_t *s);


#define RAP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RAP_DEFAULT_ECDH_CURVE  "auto"

#define RAP_HTTP_NPN_ADVERTISE  "\x08http/1.1"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int rap_http_ssl_alpn_select(rap_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
static int rap_http_ssl_npn_advertised(rap_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg);
#endif

static rap_int_t rap_http_ssl_static_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_ssl_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_ssl_add_variables(rap_conf_t *cf);
static void *rap_http_ssl_create_srv_conf(rap_conf_t *cf);
static char *rap_http_ssl_merge_srv_conf(rap_conf_t *cf,
    void *parent, void *child);

static rap_int_t rap_http_ssl_compile_certificates(rap_conf_t *cf,
    rap_http_ssl_srv_conf_t *conf);

static char *rap_http_ssl_enable(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

static rap_int_t rap_http_ssl_init(rap_conf_t *cf);


static rap_conf_bitmask_t  rap_http_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_http_ssl_verify[] = {
    { rap_string("off"), 0 },
    { rap_string("on"), 1 },
    { rap_string("optional"), 2 },
    { rap_string("optional_no_ca"), 3 },
    { rap_null_string, 0 }
};


static rap_conf_deprecated_t  rap_http_ssl_deprecated = {
    rap_conf_deprecated, "ssl", "listen ... ssl"
};


static rap_command_t  rap_http_ssl_commands[] = {

    { rap_string("ssl"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_http_ssl_enable,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, enable),
      &rap_http_ssl_deprecated },

    { rap_string("ssl_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, certificates),
      NULL },

    { rap_string("ssl_certificate_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, certificate_keys),
      NULL },

    { rap_string("ssl_password_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_ssl_password_file,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_dhparam"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, dhparam),
      NULL },

    { rap_string("ssl_ecdh_curve"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { rap_string("ssl_protocols"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, protocols),
      &rap_http_ssl_protocols },

    { rap_string("ssl_ciphers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, ciphers),
      NULL },

    { rap_string("ssl_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, buffer_size),
      NULL },

    { rap_string("ssl_verify_client"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, verify),
      &rap_http_ssl_verify },

    { rap_string("ssl_verify_depth"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { rap_string("ssl_client_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { rap_string("ssl_trusted_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { rap_string("ssl_prefer_server_ciphers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { rap_string("ssl_session_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE12,
      rap_http_ssl_session_cache,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_session_tickets"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, session_tickets),
      NULL },

    { rap_string("ssl_session_ticket_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, session_ticket_keys),
      NULL },

    { rap_string("ssl_session_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_sec_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { rap_string("ssl_crl"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, crl),
      NULL },

    { rap_string("ssl_stapling"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, stapling),
      NULL },

    { rap_string("ssl_stapling_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { rap_string("ssl_stapling_responder"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { rap_string("ssl_stapling_verify"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, stapling_verify),
      NULL },

    { rap_string("ssl_early_data"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_ssl_srv_conf_t, early_data),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_ssl_module_ctx = {
    rap_http_ssl_add_variables,            /* preconfiguration */
    rap_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_http_ssl_create_srv_conf,          /* create server configuration */
    rap_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_ssl_module = {
    RAP_MODULE_V1,
    &rap_http_ssl_module_ctx,              /* module context */
    rap_http_ssl_commands,                 /* module directives */
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


static rap_http_variable_t  rap_http_ssl_vars[] = {

    { rap_string("ssl_protocol"), NULL, rap_http_ssl_static_variable,
      (uintptr_t) rap_ssl_get_protocol, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_cipher"), NULL, rap_http_ssl_static_variable,
      (uintptr_t) rap_ssl_get_cipher_name, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_ciphers"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_ciphers, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_curves"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_curves, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_session_id"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_session_id, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_session_reused"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_session_reused, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_early_data"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_early_data,
      RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("ssl_server_name"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_server_name, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_cert"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_certificate, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_raw_cert"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_raw_certificate,
      RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_escaped_cert"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_escaped_certificate,
      RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_s_dn"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_subject_dn, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_i_dn"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_issuer_dn, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_s_dn_legacy"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_subject_dn_legacy, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_i_dn_legacy"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_issuer_dn_legacy, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_serial"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_serial_number, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_fingerprint"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_fingerprint, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_verify"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_client_verify, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_start"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_start, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_end"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_end, RAP_HTTP_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_remain"), NULL, rap_http_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_remain, RAP_HTTP_VAR_CHANGEABLE, 0 },

      rap_http_null_variable
};


static rap_str_t rap_http_ssl_sess_id_ctx = rap_string("HTTP");


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
rap_http_ssl_alpn_select(rap_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int            srvlen;
    unsigned char          *srv;
#if (RAP_DEBUG)
    unsigned int            i;
#endif
#if (RAP_HTTP_V2)
    rap_http_connection_t  *hc;
#endif
#if (RAP_HTTP_V2 || RAP_DEBUG)
    rap_connection_t       *c;

    c = rap_ssl_get_connection(ssl_conn);
#endif

#if (RAP_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

#if (RAP_HTTP_V2)
    hc = c->data;

    if (hc->addr_conf->http2) {
        srv =
           (unsigned char *) RAP_HTTP_V2_ALPN_ADVERTISE RAP_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(RAP_HTTP_V2_ALPN_ADVERTISE RAP_HTTP_NPN_ADVERTISE) - 1;

    } else
#endif
    {
        srv = (unsigned char *) RAP_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(RAP_HTTP_NPN_ADVERTISE) - 1;
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef TLSEXT_TYPE_next_proto_neg

static int
rap_http_ssl_npn_advertised(rap_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg)
{
#if (RAP_HTTP_V2 || RAP_DEBUG)
    rap_connection_t  *c;

    c = rap_ssl_get_connection(ssl_conn);
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "SSL NPN advertised");
#endif

#if (RAP_HTTP_V2)
    {
    rap_http_connection_t  *hc;

    hc = c->data;

    if (hc->addr_conf->http2) {
        *out =
            (unsigned char *) RAP_HTTP_V2_NPN_ADVERTISE RAP_HTTP_NPN_ADVERTISE;
        *outlen = sizeof(RAP_HTTP_V2_NPN_ADVERTISE RAP_HTTP_NPN_ADVERTISE) - 1;

        return SSL_TLSEXT_ERR_OK;
    }
    }
#endif

    *out = (unsigned char *) RAP_HTTP_NPN_ADVERTISE;
    *outlen = sizeof(RAP_HTTP_NPN_ADVERTISE) - 1;

    return SSL_TLSEXT_ERR_OK;
}

#endif


static rap_int_t
rap_http_ssl_static_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_ssl_variable_handler_pt  handler = (rap_ssl_variable_handler_pt) data;

    size_t     len;
    rap_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return RAP_OK;
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_ssl_variable(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_ssl_variable_handler_pt  handler = (rap_ssl_variable_handler_pt) data;

    rap_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != RAP_OK) {
            return RAP_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return RAP_OK;
        }
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_ssl_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_ssl_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static void *
rap_http_ssl_create_srv_conf(rap_conf_t *cf)
{
    rap_http_ssl_srv_conf_t  *sscf;

    sscf = rap_pcalloc(cf->pool, sizeof(rap_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
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

    sscf->enable = RAP_CONF_UNSET;
    sscf->prefer_server_ciphers = RAP_CONF_UNSET;
    sscf->early_data = RAP_CONF_UNSET;
    sscf->buffer_size = RAP_CONF_UNSET_SIZE;
    sscf->verify = RAP_CONF_UNSET_UINT;
    sscf->verify_depth = RAP_CONF_UNSET_UINT;
    sscf->certificates = RAP_CONF_UNSET_PTR;
    sscf->certificate_keys = RAP_CONF_UNSET_PTR;
    sscf->passwords = RAP_CONF_UNSET_PTR;
    sscf->builtin_session_cache = RAP_CONF_UNSET;
    sscf->session_timeout = RAP_CONF_UNSET;
    sscf->session_tickets = RAP_CONF_UNSET;
    sscf->session_ticket_keys = RAP_CONF_UNSET_PTR;
    sscf->stapling = RAP_CONF_UNSET;
    sscf->stapling_verify = RAP_CONF_UNSET;

    return sscf;
}


static char *
rap_http_ssl_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_ssl_srv_conf_t *prev = parent;
    rap_http_ssl_srv_conf_t *conf = child;

    rap_pool_cleanup_t  *cln;

    if (conf->enable == RAP_CONF_UNSET) {
        if (prev->enable == RAP_CONF_UNSET) {
            conf->enable = 0;

        } else {
            conf->enable = prev->enable;
            conf->file = prev->file;
            conf->line = prev->line;
        }
    }

    rap_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rap_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rap_conf_merge_value(conf->early_data, prev->early_data, 0);

    rap_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                          |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

    rap_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                         RAP_SSL_BUFSIZE);

    rap_conf_merge_uint_value(conf->verify, prev->verify, 0);
    rap_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    rap_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    rap_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    rap_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    rap_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    rap_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    rap_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    rap_conf_merge_str_value(conf->crl, prev->crl, "");

    rap_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         RAP_DEFAULT_ECDH_CURVE);

    rap_conf_merge_str_value(conf->ciphers, prev->ciphers, RAP_DEFAULT_CIPHERS);

    rap_conf_merge_value(conf->stapling, prev->stapling, 0);
    rap_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    rap_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    rap_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

    conf->ssl.log = cf->log;

    if (conf->enable) {

        if (conf->certificates == NULL) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return RAP_CONF_ERROR;
        }

        if (conf->certificate_keys == NULL) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return RAP_CONF_ERROR;
        }

        if (conf->certificate_keys->nelts < conf->certificates->nelts) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\" and "
                          "the \"ssl\" directive in %s:%ui",
                          ((rap_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1,
                          conf->file, conf->line);
            return RAP_CONF_ERROR;
        }

    } else {

        if (conf->certificates == NULL) {
            return RAP_CONF_OK;
        }

        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((rap_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return RAP_CONF_ERROR;
        }
    }

    if (rap_ssl_create(&conf->ssl, conf->protocols, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(&conf->ssl);
        return RAP_CONF_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               rap_http_ssl_servername)
        == 0)
    {
        rap_log_error(RAP_LOG_WARN, cf->log, 0,
            "rap was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }

#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, rap_http_ssl_alpn_select, NULL);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(conf->ssl.ctx,
                                          rap_http_ssl_npn_advertised, NULL);
#endif

    if (rap_http_ssl_compile_certificates(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, rap_http_ssl_certificate, conf);

#else
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "variables in "
                      "\"ssl_certificate\" and \"ssl_certificate_key\" "
                      "directives are not supported on this platform");
        return RAP_CONF_ERROR;
#endif

    } else {

        /* configure certificates */

        if (rap_ssl_certificates(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->passwords)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    conf->ssl.buffer_size = conf->buffer_size;

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_verify_client");
            return RAP_CONF_ERROR;
        }

        if (rap_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    if (rap_ssl_trusted_certificate(cf, &conf->ssl,
                                    &conf->trusted_certificate,
                                    conf->verify_depth)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_crl(cf, &conf->ssl, &conf->crl) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, RAP_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (rap_ssl_session_cache(&conf->ssl, &rap_http_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    rap_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (rap_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    if (conf->stapling) {

        if (rap_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

    }

    if (rap_ssl_early_data(cf, &conf->ssl, conf->early_data) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_ssl_compile_certificates(rap_conf_t *cf,
    rap_http_ssl_srv_conf_t *conf)
{
    rap_str_t                         *cert, *key;
    rap_uint_t                         i, nelts;
    rap_http_complex_value_t          *cv;
    rap_http_compile_complex_value_t   ccv;

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (rap_http_script_variables_count(&cert[i])) {
            goto found;
        }

        if (rap_http_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return RAP_OK;

found:

    conf->certificate_values = rap_array_create(cf->pool, nelts,
                                             sizeof(rap_http_complex_value_t));
    if (conf->certificate_values == NULL) {
        return RAP_ERROR;
    }

    conf->certificate_key_values = rap_array_create(cf->pool, nelts,
                                             sizeof(rap_http_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return RAP_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = rap_array_push(conf->certificate_values);
        if (cv == NULL) {
            return RAP_ERROR;
        }

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_ERROR;
        }

        cv = rap_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return RAP_ERROR;
        }

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    conf->passwords = rap_ssl_preserve_passwords(cf, conf->passwords);
    if (conf->passwords == NULL) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


static char *
rap_http_ssl_enable(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_ssl_srv_conf_t *sscf = conf;

    char  *rv;

    rv = rap_conf_set_flag_slot(cf, cmd, conf);

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return RAP_CONF_OK;
}


static char *
rap_http_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_ssl_srv_conf_t *sscf = conf;

    rap_str_t  *value;

    if (sscf->passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (sscf->passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    rap_str_t   *value, name, size;
    rap_int_t    n;
    rap_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = RAP_SSL_NO_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = RAP_SSL_NONE_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = RAP_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && rap_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = rap_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == RAP_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && rap_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
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

            n = rap_parse_size(&size);

            if (n == RAP_ERROR) {
                goto invalid;
            }

            if (n < (rap_int_t) (8 * rap_pagesize)) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return RAP_CONF_ERROR;
            }

            sscf->shm_zone = rap_shared_memory_add(cf, &name, n,
                                                   &rap_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return RAP_CONF_ERROR;
            }

            sscf->shm_zone->init = rap_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == RAP_CONF_UNSET) {
        sscf->builtin_session_cache = RAP_SSL_NO_BUILTIN_SCACHE;
    }

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RAP_CONF_ERROR;
}


static rap_int_t
rap_http_ssl_init(rap_conf_t *cf)
{
    rap_uint_t                   a, p, s;
    rap_http_conf_addr_t        *addr;
    rap_http_conf_port_t        *port;
    rap_http_ssl_srv_conf_t     *sscf;
    rap_http_core_loc_conf_t    *clcf;
    rap_http_core_srv_conf_t   **cscfp, *cscf;
    rap_http_core_main_conf_t   *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[rap_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL || !sscf->stapling) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[rap_http_core_module.ctx_index];

        if (rap_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    if (cmcf->ports == NULL) {
        return RAP_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (!addr[a].opt.ssl) {
                continue;
            }

            cscf = addr[a].default_server;
            sscf = cscf->ctx->srv_conf[rap_http_ssl_module.ctx_index];

            if (sscf->certificates == NULL) {
                rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... ssl\" directive in %s:%ui",
                              cscf->file_name, cscf->line);
                return RAP_ERROR;
            }
        }
    }

    return RAP_OK;
}
