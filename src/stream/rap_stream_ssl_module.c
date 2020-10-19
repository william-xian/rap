
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef rap_int_t (*rap_ssl_variable_handler_pt)(rap_connection_t *c,
    rap_pool_t *pool, rap_str_t *s);


#define RAP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RAP_DEFAULT_ECDH_CURVE  "auto"


static rap_int_t rap_stream_ssl_handler(rap_stream_session_t *s);
static rap_int_t rap_stream_ssl_init_connection(rap_ssl_t *ssl,
    rap_connection_t *c);
static void rap_stream_ssl_handshake_handler(rap_connection_t *c);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
int rap_stream_ssl_servername(rap_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#ifdef SSL_R_CERT_CB_ERROR
static int rap_stream_ssl_certificate(rap_ssl_conn_t *ssl_conn, void *arg);
#endif
static rap_int_t rap_stream_ssl_static_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_ssl_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);

static rap_int_t rap_stream_ssl_add_variables(rap_conf_t *cf);
static void *rap_stream_ssl_create_conf(rap_conf_t *cf);
static char *rap_stream_ssl_merge_conf(rap_conf_t *cf, void *parent,
    void *child);

static rap_int_t rap_stream_ssl_compile_certificates(rap_conf_t *cf,
    rap_stream_ssl_conf_t *conf);

static char *rap_stream_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_stream_ssl_init(rap_conf_t *cf);


static rap_conf_bitmask_t  rap_stream_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_stream_ssl_verify[] = {
    { rap_string("off"), 0 },
    { rap_string("on"), 1 },
    { rap_string("optional"), 2 },
    { rap_string("optional_no_ca"), 3 },
    { rap_null_string, 0 }
};


static rap_command_t  rap_stream_ssl_commands[] = {

    { rap_string("ssl_handshake_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, handshake_timeout),
      NULL },

    { rap_string("ssl_certificate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, certificates),
      NULL },

    { rap_string("ssl_certificate_key"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, certificate_keys),
      NULL },

    { rap_string("ssl_password_file"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_ssl_password_file,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_dhparam"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, dhparam),
      NULL },

    { rap_string("ssl_ecdh_curve"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, ecdh_curve),
      NULL },

    { rap_string("ssl_protocols"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, protocols),
      &rap_stream_ssl_protocols },

    { rap_string("ssl_ciphers"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, ciphers),
      NULL },

    { rap_string("ssl_verify_client"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, verify),
      &rap_stream_ssl_verify },

    { rap_string("ssl_verify_depth"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, verify_depth),
      NULL },

    { rap_string("ssl_client_certificate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, client_certificate),
      NULL },

    { rap_string("ssl_trusted_certificate"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, trusted_certificate),
      NULL },

    { rap_string("ssl_prefer_server_ciphers"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { rap_string("ssl_session_cache"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE12,
      rap_stream_ssl_session_cache,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_session_tickets"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, session_tickets),
      NULL },

    { rap_string("ssl_session_ticket_key"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, session_ticket_keys),
      NULL },

    { rap_string("ssl_session_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_sec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, session_timeout),
      NULL },

    { rap_string("ssl_crl"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_ssl_conf_t, crl),
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_ssl_module_ctx = {
    rap_stream_ssl_add_variables,          /* preconfiguration */
    rap_stream_ssl_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_stream_ssl_create_conf,            /* create server configuration */
    rap_stream_ssl_merge_conf              /* merge server configuration */
};


rap_module_t  rap_stream_ssl_module = {
    RAP_MODULE_V1,
    &rap_stream_ssl_module_ctx,            /* module context */
    rap_stream_ssl_commands,               /* module directives */
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


static rap_stream_variable_t  rap_stream_ssl_vars[] = {

    { rap_string("ssl_protocol"), NULL, rap_stream_ssl_static_variable,
      (uintptr_t) rap_ssl_get_protocol, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_cipher"), NULL, rap_stream_ssl_static_variable,
      (uintptr_t) rap_ssl_get_cipher_name, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_ciphers"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_ciphers, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_curves"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_curves, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_session_id"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_session_id, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_session_reused"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_session_reused, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_server_name"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_server_name, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_cert"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_certificate, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_raw_cert"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_raw_certificate,
      RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_escaped_cert"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_escaped_certificate,
      RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_s_dn"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_subject_dn, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_i_dn"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_issuer_dn, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_serial"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_serial_number, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_fingerprint"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_fingerprint, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_verify"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_client_verify, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_start"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_start, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_end"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_end, RAP_STREAM_VAR_CHANGEABLE, 0 },

    { rap_string("ssl_client_v_remain"), NULL, rap_stream_ssl_variable,
      (uintptr_t) rap_ssl_get_client_v_remain, RAP_STREAM_VAR_CHANGEABLE, 0 },

      rap_stream_null_variable
};


static rap_str_t rap_stream_ssl_sess_id_ctx = rap_string("STREAM");


static rap_int_t
rap_stream_ssl_handler(rap_stream_session_t *s)
{
    long                    rc;
    X509                   *cert;
    rap_int_t               rv;
    rap_connection_t       *c;
    rap_stream_ssl_conf_t  *sslcf;

    if (!s->ssl) {
        return RAP_OK;
    }

    c = s->connection;

    sslcf = rap_stream_get_module_srv_conf(s, rap_stream_ssl_module);

    if (c->ssl == NULL) {
        c->log->action = "SSL handshaking";

        rv = rap_stream_ssl_init_connection(&sslcf->ssl, c);

        if (rv != RAP_OK) {
            return rv;
        }
    }

    if (sslcf->verify) {
        rc = SSL_get_verify_result(c->ssl->connection);

        if (rc != X509_V_OK
            && (sslcf->verify != 3 || !rap_ssl_verify_error_optional(rc)))
        {
            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          "client SSL certificate verify error: (%l:%s)",
                          rc, X509_verify_cert_error_string(rc));

            rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
            return RAP_ERROR;
        }

        if (sslcf->verify == 1) {
            cert = SSL_get_peer_certificate(c->ssl->connection);

            if (cert == NULL) {
                rap_log_error(RAP_LOG_INFO, c->log, 0,
                              "client sent no required SSL certificate");

                rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
                return RAP_ERROR;
            }

            X509_free(cert);
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_ssl_init_connection(rap_ssl_t *ssl, rap_connection_t *c)
{
    rap_int_t                    rc;
    rap_stream_session_t        *s;
    rap_stream_ssl_conf_t       *sslcf;
    rap_stream_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

    if (cscf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
        return RAP_ERROR;
    }

    if (rap_ssl_create_connection(ssl, c, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    rc = rap_ssl_handshake(c);

    if (rc == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rc == RAP_AGAIN) {
        sslcf = rap_stream_get_module_srv_conf(s, rap_stream_ssl_module);

        rap_add_timer(c->read, sslcf->handshake_timeout);

        c->ssl->handler = rap_stream_ssl_handshake_handler;

        return RAP_AGAIN;
    }

    /* rc == RAP_OK */

    return RAP_OK;
}


static void
rap_stream_ssl_handshake_handler(rap_connection_t *c)
{
    rap_stream_session_t  *s;

    s = c->data;

    if (!c->ssl->handshaked) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    rap_stream_core_run_phases(s);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
rap_stream_ssl_servername(rap_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
rap_stream_ssl_certificate(rap_ssl_conn_t *ssl_conn, void *arg)
{
    rap_str_t                    cert, key;
    rap_uint_t                   i, nelts;
    rap_connection_t            *c;
    rap_stream_session_t        *s;
    rap_stream_ssl_conf_t       *sslcf;
    rap_stream_complex_value_t  *certs, *keys;

    c = rap_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    s = c->data;

    sslcf = arg;

    nelts = sslcf->certificate_values->nelts;
    certs = sslcf->certificate_values->elts;
    keys = sslcf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (rap_stream_complex_value(s, &certs[i], &cert) != RAP_OK) {
            return 0;
        }

        rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (rap_stream_complex_value(s, &keys[i], &key) != RAP_OK) {
            return 0;
        }

        rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (rap_ssl_connection_certificate(c, c->pool, &cert, &key,
                                           sslcf->passwords)
            != RAP_OK)
        {
            return 0;
        }
    }

    return 1;
}

#endif


static rap_int_t
rap_stream_ssl_static_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_ssl_variable_handler_pt  handler = (rap_ssl_variable_handler_pt) data;

    size_t     len;
    rap_str_t  str;

    if (s->connection->ssl) {

        (void) handler(s->connection, NULL, &str);

        v->data = str.data;

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
rap_stream_ssl_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_ssl_variable_handler_pt  handler = (rap_ssl_variable_handler_pt) data;

    rap_str_t  str;

    if (s->connection->ssl) {

        if (handler(s->connection, s->connection->pool, &str) != RAP_OK) {
            return RAP_ERROR;
        }

        v->len = str.len;
        v->data = str.data;

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
rap_stream_ssl_add_variables(rap_conf_t *cf)
{
    rap_stream_variable_t  *var, *v;

    for (v = rap_stream_ssl_vars; v->name.len; v++) {
        var = rap_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static void *
rap_stream_ssl_create_conf(rap_conf_t *cf)
{
    rap_stream_ssl_conf_t  *scf;

    scf = rap_pcalloc(cf->pool, sizeof(rap_stream_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     scf->listen = 0;
     *     scf->protocols = 0;
     *     scf->certificate_values = NULL;
     *     scf->dhparam = { 0, NULL };
     *     scf->ecdh_curve = { 0, NULL };
     *     scf->client_certificate = { 0, NULL };
     *     scf->trusted_certificate = { 0, NULL };
     *     scf->crl = { 0, NULL };
     *     scf->ciphers = { 0, NULL };
     *     scf->shm_zone = NULL;
     */

    scf->handshake_timeout = RAP_CONF_UNSET_MSEC;
    scf->certificates = RAP_CONF_UNSET_PTR;
    scf->certificate_keys = RAP_CONF_UNSET_PTR;
    scf->passwords = RAP_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = RAP_CONF_UNSET;
    scf->verify = RAP_CONF_UNSET_UINT;
    scf->verify_depth = RAP_CONF_UNSET_UINT;
    scf->builtin_session_cache = RAP_CONF_UNSET;
    scf->session_timeout = RAP_CONF_UNSET;
    scf->session_tickets = RAP_CONF_UNSET;
    scf->session_ticket_keys = RAP_CONF_UNSET_PTR;

    return scf;
}


static char *
rap_stream_ssl_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_stream_ssl_conf_t *prev = parent;
    rap_stream_ssl_conf_t *conf = child;

    rap_pool_cleanup_t  *cln;

    rap_conf_merge_msec_value(conf->handshake_timeout,
                         prev->handshake_timeout, 60000);

    rap_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rap_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rap_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                          |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

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


    conf->ssl.log = cf->log;

    if (!conf->listen) {
        return RAP_CONF_OK;
    }

    if (conf->certificates == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      ((rap_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_create(&conf->ssl, conf->protocols, NULL) != RAP_OK) {
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
    SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                           rap_stream_ssl_servername);
#endif

    if (rap_stream_ssl_compile_certificates(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, rap_stream_ssl_certificate, conf);

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

    if (rap_ssl_session_cache(&conf->ssl, &rap_stream_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

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

    return RAP_CONF_OK;
}


static rap_int_t
rap_stream_ssl_compile_certificates(rap_conf_t *cf,
    rap_stream_ssl_conf_t *conf)
{
    rap_str_t                           *cert, *key;
    rap_uint_t                           i, nelts;
    rap_stream_complex_value_t          *cv;
    rap_stream_compile_complex_value_t   ccv;

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (rap_stream_script_variables_count(&cert[i])) {
            goto found;
        }

        if (rap_stream_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return RAP_OK;

found:

    conf->certificate_values = rap_array_create(cf->pool, nelts,
                                           sizeof(rap_stream_complex_value_t));
    if (conf->certificate_values == NULL) {
        return RAP_ERROR;
    }

    conf->certificate_key_values = rap_array_create(cf->pool, nelts,
                                           sizeof(rap_stream_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return RAP_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = rap_array_push(conf->certificate_values);
        if (cv == NULL) {
            return RAP_ERROR;
        }

        rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_ERROR;
        }

        cv = rap_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return RAP_ERROR;
        }

        rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
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
rap_stream_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_ssl_conf_t  *scf = conf;

    rap_str_t  *value;

    if (scf->passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_stream_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_ssl_conf_t  *scf = conf;

    size_t       len;
    rap_str_t   *value, name, size;
    rap_int_t    n;
    rap_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = RAP_SSL_NO_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = RAP_SSL_NONE_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = RAP_SSL_DFLT_BUILTIN_SCACHE;
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

            scf->builtin_session_cache = n;

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

            scf->shm_zone = rap_shared_memory_add(cf, &name, n,
                                                   &rap_stream_ssl_module);
            if (scf->shm_zone == NULL) {
                return RAP_CONF_ERROR;
            }

            scf->shm_zone->init = rap_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == RAP_CONF_UNSET) {
        scf->builtin_session_cache = RAP_SSL_NO_BUILTIN_SCACHE;
    }

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RAP_CONF_ERROR;
}


static rap_int_t
rap_stream_ssl_init(rap_conf_t *cf)
{
    rap_stream_handler_pt        *h;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    h = rap_array_push(&cmcf->phases[RAP_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_stream_ssl_handler;

    return RAP_OK;
}
