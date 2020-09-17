
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef rp_int_t (*rp_ssl_variable_handler_pt)(rp_connection_t *c,
    rp_pool_t *pool, rp_str_t *s);


#define RP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RP_DEFAULT_ECDH_CURVE  "auto"


static rp_int_t rp_stream_ssl_handler(rp_stream_session_t *s);
static rp_int_t rp_stream_ssl_init_connection(rp_ssl_t *ssl,
    rp_connection_t *c);
static void rp_stream_ssl_handshake_handler(rp_connection_t *c);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
int rp_stream_ssl_servername(rp_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#ifdef SSL_R_CERT_CB_ERROR
static int rp_stream_ssl_certificate(rp_ssl_conn_t *ssl_conn, void *arg);
#endif
static rp_int_t rp_stream_ssl_static_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_ssl_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);

static rp_int_t rp_stream_ssl_add_variables(rp_conf_t *cf);
static void *rp_stream_ssl_create_conf(rp_conf_t *cf);
static char *rp_stream_ssl_merge_conf(rp_conf_t *cf, void *parent,
    void *child);

static rp_int_t rp_stream_ssl_compile_certificates(rp_conf_t *cf,
    rp_stream_ssl_conf_t *conf);

static char *rp_stream_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_stream_ssl_init(rp_conf_t *cf);


static rp_conf_bitmask_t  rp_stream_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_stream_ssl_verify[] = {
    { rp_string("off"), 0 },
    { rp_string("on"), 1 },
    { rp_string("optional"), 2 },
    { rp_string("optional_no_ca"), 3 },
    { rp_null_string, 0 }
};


static rp_command_t  rp_stream_ssl_commands[] = {

    { rp_string("ssl_handshake_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, handshake_timeout),
      NULL },

    { rp_string("ssl_certificate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, certificates),
      NULL },

    { rp_string("ssl_certificate_key"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, certificate_keys),
      NULL },

    { rp_string("ssl_password_file"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_ssl_password_file,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_dhparam"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, dhparam),
      NULL },

    { rp_string("ssl_ecdh_curve"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, ecdh_curve),
      NULL },

    { rp_string("ssl_protocols"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, protocols),
      &rp_stream_ssl_protocols },

    { rp_string("ssl_ciphers"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, ciphers),
      NULL },

    { rp_string("ssl_verify_client"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, verify),
      &rp_stream_ssl_verify },

    { rp_string("ssl_verify_depth"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, verify_depth),
      NULL },

    { rp_string("ssl_client_certificate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, client_certificate),
      NULL },

    { rp_string("ssl_trusted_certificate"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, trusted_certificate),
      NULL },

    { rp_string("ssl_prefer_server_ciphers"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { rp_string("ssl_session_cache"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE12,
      rp_stream_ssl_session_cache,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_session_tickets"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, session_tickets),
      NULL },

    { rp_string("ssl_session_ticket_key"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, session_ticket_keys),
      NULL },

    { rp_string("ssl_session_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_sec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, session_timeout),
      NULL },

    { rp_string("ssl_crl"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_ssl_conf_t, crl),
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_ssl_module_ctx = {
    rp_stream_ssl_add_variables,          /* preconfiguration */
    rp_stream_ssl_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_ssl_create_conf,            /* create server configuration */
    rp_stream_ssl_merge_conf              /* merge server configuration */
};


rp_module_t  rp_stream_ssl_module = {
    RP_MODULE_V1,
    &rp_stream_ssl_module_ctx,            /* module context */
    rp_stream_ssl_commands,               /* module directives */
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


static rp_stream_variable_t  rp_stream_ssl_vars[] = {

    { rp_string("ssl_protocol"), NULL, rp_stream_ssl_static_variable,
      (uintptr_t) rp_ssl_get_protocol, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_cipher"), NULL, rp_stream_ssl_static_variable,
      (uintptr_t) rp_ssl_get_cipher_name, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_ciphers"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_ciphers, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_curves"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_curves, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_session_id"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_session_id, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_session_reused"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_session_reused, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_server_name"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_server_name, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_cert"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_certificate, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_raw_cert"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_raw_certificate,
      RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_escaped_cert"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_escaped_certificate,
      RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_s_dn"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_subject_dn, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_i_dn"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_issuer_dn, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_serial"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_serial_number, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_fingerprint"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_fingerprint, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_verify"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_client_verify, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_start"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_start, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_end"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_end, RP_STREAM_VAR_CHANGEABLE, 0 },

    { rp_string("ssl_client_v_remain"), NULL, rp_stream_ssl_variable,
      (uintptr_t) rp_ssl_get_client_v_remain, RP_STREAM_VAR_CHANGEABLE, 0 },

      rp_stream_null_variable
};


static rp_str_t rp_stream_ssl_sess_id_ctx = rp_string("STREAM");


static rp_int_t
rp_stream_ssl_handler(rp_stream_session_t *s)
{
    long                    rc;
    X509                   *cert;
    rp_int_t               rv;
    rp_connection_t       *c;
    rp_stream_ssl_conf_t  *sslcf;

    if (!s->ssl) {
        return RP_OK;
    }

    c = s->connection;

    sslcf = rp_stream_get_module_srv_conf(s, rp_stream_ssl_module);

    if (c->ssl == NULL) {
        c->log->action = "SSL handshaking";

        rv = rp_stream_ssl_init_connection(&sslcf->ssl, c);

        if (rv != RP_OK) {
            return rv;
        }
    }

    if (sslcf->verify) {
        rc = SSL_get_verify_result(c->ssl->connection);

        if (rc != X509_V_OK
            && (sslcf->verify != 3 || !rp_ssl_verify_error_optional(rc)))
        {
            rp_log_error(RP_LOG_INFO, c->log, 0,
                          "client SSL certificate verify error: (%l:%s)",
                          rc, X509_verify_cert_error_string(rc));

            rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
            return RP_ERROR;
        }

        if (sslcf->verify == 1) {
            cert = SSL_get_peer_certificate(c->ssl->connection);

            if (cert == NULL) {
                rp_log_error(RP_LOG_INFO, c->log, 0,
                              "client sent no required SSL certificate");

                rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
                return RP_ERROR;
            }

            X509_free(cert);
        }
    }

    return RP_OK;
}


static rp_int_t
rp_stream_ssl_init_connection(rp_ssl_t *ssl, rp_connection_t *c)
{
    rp_int_t                    rc;
    rp_stream_session_t        *s;
    rp_stream_ssl_conf_t       *sslcf;
    rp_stream_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

    if (cscf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
        return RP_ERROR;
    }

    if (rp_ssl_create_connection(ssl, c, 0) != RP_OK) {
        return RP_ERROR;
    }

    rc = rp_ssl_handshake(c);

    if (rc == RP_ERROR) {
        return RP_ERROR;
    }

    if (rc == RP_AGAIN) {
        sslcf = rp_stream_get_module_srv_conf(s, rp_stream_ssl_module);

        rp_add_timer(c->read, sslcf->handshake_timeout);

        c->ssl->handler = rp_stream_ssl_handshake_handler;

        return RP_AGAIN;
    }

    /* rc == RP_OK */

    return RP_OK;
}


static void
rp_stream_ssl_handshake_handler(rp_connection_t *c)
{
    rp_stream_session_t  *s;

    s = c->data;

    if (!c->ssl->handshaked) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    rp_stream_core_run_phases(s);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
rp_stream_ssl_servername(rp_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
rp_stream_ssl_certificate(rp_ssl_conn_t *ssl_conn, void *arg)
{
    rp_str_t                    cert, key;
    rp_uint_t                   i, nelts;
    rp_connection_t            *c;
    rp_stream_session_t        *s;
    rp_stream_ssl_conf_t       *sslcf;
    rp_stream_complex_value_t  *certs, *keys;

    c = rp_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    s = c->data;

    sslcf = arg;

    nelts = sslcf->certificate_values->nelts;
    certs = sslcf->certificate_values->elts;
    keys = sslcf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (rp_stream_complex_value(s, &certs[i], &cert) != RP_OK) {
            return 0;
        }

        rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (rp_stream_complex_value(s, &keys[i], &key) != RP_OK) {
            return 0;
        }

        rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (rp_ssl_connection_certificate(c, c->pool, &cert, &key,
                                           sslcf->passwords)
            != RP_OK)
        {
            return 0;
        }
    }

    return 1;
}

#endif


static rp_int_t
rp_stream_ssl_static_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_ssl_variable_handler_pt  handler = (rp_ssl_variable_handler_pt) data;

    size_t     len;
    rp_str_t  str;

    if (s->connection->ssl) {

        (void) handler(s->connection, NULL, &str);

        v->data = str.data;

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
rp_stream_ssl_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_ssl_variable_handler_pt  handler = (rp_ssl_variable_handler_pt) data;

    rp_str_t  str;

    if (s->connection->ssl) {

        if (handler(s->connection, s->connection->pool, &str) != RP_OK) {
            return RP_ERROR;
        }

        v->len = str.len;
        v->data = str.data;

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
rp_stream_ssl_add_variables(rp_conf_t *cf)
{
    rp_stream_variable_t  *var, *v;

    for (v = rp_stream_ssl_vars; v->name.len; v++) {
        var = rp_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static void *
rp_stream_ssl_create_conf(rp_conf_t *cf)
{
    rp_stream_ssl_conf_t  *scf;

    scf = rp_pcalloc(cf->pool, sizeof(rp_stream_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
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

    scf->handshake_timeout = RP_CONF_UNSET_MSEC;
    scf->certificates = RP_CONF_UNSET_PTR;
    scf->certificate_keys = RP_CONF_UNSET_PTR;
    scf->passwords = RP_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = RP_CONF_UNSET;
    scf->verify = RP_CONF_UNSET_UINT;
    scf->verify_depth = RP_CONF_UNSET_UINT;
    scf->builtin_session_cache = RP_CONF_UNSET;
    scf->session_timeout = RP_CONF_UNSET;
    scf->session_tickets = RP_CONF_UNSET;
    scf->session_ticket_keys = RP_CONF_UNSET_PTR;

    return scf;
}


static char *
rp_stream_ssl_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_ssl_conf_t *prev = parent;
    rp_stream_ssl_conf_t *conf = child;

    rp_pool_cleanup_t  *cln;

    rp_conf_merge_msec_value(conf->handshake_timeout,
                         prev->handshake_timeout, 60000);

    rp_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rp_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rp_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                          |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

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


    conf->ssl.log = cf->log;

    if (!conf->listen) {
        return RP_CONF_OK;
    }

    if (conf->certificates == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      ((rp_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (rp_ssl_create(&conf->ssl, conf->protocols, NULL) != RP_OK) {
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
    SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                           rp_stream_ssl_servername);
#endif

    if (rp_stream_ssl_compile_certificates(cf, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, rp_stream_ssl_certificate, conf);

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

    if (rp_ssl_session_cache(&conf->ssl, &rp_stream_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

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

    return RP_CONF_OK;
}


static rp_int_t
rp_stream_ssl_compile_certificates(rp_conf_t *cf,
    rp_stream_ssl_conf_t *conf)
{
    rp_str_t                           *cert, *key;
    rp_uint_t                           i, nelts;
    rp_stream_complex_value_t          *cv;
    rp_stream_compile_complex_value_t   ccv;

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (rp_stream_script_variables_count(&cert[i])) {
            goto found;
        }

        if (rp_stream_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return RP_OK;

found:

    conf->certificate_values = rp_array_create(cf->pool, nelts,
                                           sizeof(rp_stream_complex_value_t));
    if (conf->certificate_values == NULL) {
        return RP_ERROR;
    }

    conf->certificate_key_values = rp_array_create(cf->pool, nelts,
                                           sizeof(rp_stream_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return RP_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = rp_array_push(conf->certificate_values);
        if (cv == NULL) {
            return RP_ERROR;
        }

        rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
            return RP_ERROR;
        }

        cv = rp_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return RP_ERROR;
        }

        rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
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
rp_stream_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_ssl_conf_t  *scf = conf;

    rp_str_t  *value;

    if (scf->passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_stream_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_ssl_conf_t  *scf = conf;

    size_t       len;
    rp_str_t   *value, name, size;
    rp_int_t    n;
    rp_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = RP_SSL_NO_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = RP_SSL_NONE_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = RP_SSL_DFLT_BUILTIN_SCACHE;
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

            scf->builtin_session_cache = n;

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

            scf->shm_zone = rp_shared_memory_add(cf, &name, n,
                                                   &rp_stream_ssl_module);
            if (scf->shm_zone == NULL) {
                return RP_CONF_ERROR;
            }

            scf->shm_zone->init = rp_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == RP_CONF_UNSET) {
        scf->builtin_session_cache = RP_SSL_NO_BUILTIN_SCACHE;
    }

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RP_CONF_ERROR;
}


static rp_int_t
rp_stream_ssl_init(rp_conf_t *cf)
{
    rp_stream_handler_pt        *h;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    h = rp_array_push(&cmcf->phases[RP_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_stream_ssl_handler;

    return RP_OK;
}
