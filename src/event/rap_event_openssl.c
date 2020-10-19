
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define RAP_SSL_PASSWORD_BUFFER_SIZE  4096


typedef struct {
    rap_uint_t  engine;   /* unsigned  engine:1; */
} rap_openssl_conf_t;


static X509 *rap_ssl_load_certificate(rap_pool_t *pool, char **err,
    rap_str_t *cert, STACK_OF(X509) **chain);
static EVP_PKEY *rap_ssl_load_certificate_key(rap_pool_t *pool, char **err,
    rap_str_t *key, rap_array_t *passwords);
static int rap_ssl_password_callback(char *buf, int size, int rwflag,
    void *userdata);
static int rap_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
static void rap_ssl_info_callback(const rap_ssl_conn_t *ssl_conn, int where,
    int ret);
static void rap_ssl_passwords_cleanup(void *data);
static int rap_ssl_new_client_session(rap_ssl_conn_t *ssl_conn,
    rap_ssl_session_t *sess);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static rap_int_t rap_ssl_try_early_data(rap_connection_t *c);
#endif
#if (RAP_DEBUG)
static void rap_ssl_handshake_log(rap_connection_t *c);
#endif
static void rap_ssl_handshake_handler(rap_event_t *ev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t rap_ssl_recv_early(rap_connection_t *c, u_char *buf,
    size_t size);
#endif
static rap_int_t rap_ssl_handle_recv(rap_connection_t *c, int n);
static void rap_ssl_write_handler(rap_event_t *wev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t rap_ssl_write_early(rap_connection_t *c, u_char *data,
    size_t size);
#endif
static void rap_ssl_read_handler(rap_event_t *rev);
static void rap_ssl_shutdown_handler(rap_event_t *ev);
static void rap_ssl_connection_error(rap_connection_t *c, int sslerr,
    rap_err_t err, char *text);
static void rap_ssl_clear_error(rap_log_t *log);

static rap_int_t rap_ssl_session_id_context(rap_ssl_t *ssl,
    rap_str_t *sess_ctx, rap_array_t *certificates);
static int rap_ssl_new_session(rap_ssl_conn_t *ssl_conn,
    rap_ssl_session_t *sess);
static rap_ssl_session_t *rap_ssl_get_cached_session(rap_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy);
static void rap_ssl_remove_session(SSL_CTX *ssl, rap_ssl_session_t *sess);
static void rap_ssl_expire_sessions(rap_ssl_session_cache_t *cache,
    rap_slab_pool_t *shpool, rap_uint_t n);
static void rap_ssl_session_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);

#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
static int rap_ssl_session_ticket_key_callback(rap_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc);
static void rap_ssl_session_ticket_keys_cleanup(void *data);
#endif

#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
static rap_int_t rap_ssl_check_name(rap_str_t *name, ASN1_STRING *str);
#endif

static time_t rap_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time);

static void *rap_openssl_create_conf(rap_cycle_t *cycle);
static char *rap_openssl_engine(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static void rap_openssl_exit(rap_cycle_t *cycle);


static rap_command_t  rap_openssl_commands[] = {

    { rap_string("ssl_engine"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_openssl_engine,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_openssl_module_ctx = {
    rap_string("openssl"),
    rap_openssl_create_conf,
    NULL
};


rap_module_t  rap_openssl_module = {
    RAP_MODULE_V1,
    &rap_openssl_module_ctx,               /* module context */
    rap_openssl_commands,                  /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    rap_openssl_exit,                      /* exit master */
    RAP_MODULE_V1_PADDING
};


int  rap_ssl_connection_index;
int  rap_ssl_server_conf_index;
int  rap_ssl_session_cache_index;
int  rap_ssl_session_ticket_keys_index;
int  rap_ssl_certificate_index;
int  rap_ssl_next_certificate_index;
int  rap_ssl_certificate_name_index;
int  rap_ssl_stapling_index;


rap_int_t
rap_ssl_init(rap_log_t *log)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100003L

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "OPENSSL_init_ssl() failed");
        return RAP_ERROR;
    }

    /*
     * OPENSSL_init_ssl() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

#else

    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#endif

#ifndef SSL_OP_NO_COMPRESSION
    {
    /*
     * Disable gzip compression in OpenSSL prior to 1.0.0 version,
     * this saves about 522K per connection.
     */
    int                  n;
    STACK_OF(SSL_COMP)  *ssl_comp_methods;

    ssl_comp_methods = SSL_COMP_get_compression_methods();
    n = sk_SSL_COMP_num(ssl_comp_methods);

    while (n--) {
        (void) sk_SSL_COMP_pop(ssl_comp_methods);
    }
    }
#endif

    rap_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (rap_ssl_connection_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "SSL_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (rap_ssl_server_conf_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (rap_ssl_session_cache_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_session_ticket_keys_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,
                                                                 NULL, NULL);
    if (rap_ssl_session_ticket_keys_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_certificate_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (rap_ssl_certificate_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_next_certificate_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (rap_ssl_next_certificate_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_certificate_name_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);

    if (rap_ssl_certificate_name_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    rap_ssl_stapling_index = X509_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (rap_ssl_stapling_index == -1) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return RAP_ERROR;
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_create(rap_ssl_t *ssl, rap_uint_t protocols, void *data)
{
    ssl->ctx = SSL_CTX_new(SSLv23_method());

    if (ssl->ctx == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
        return RAP_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, rap_ssl_server_conf_index, data) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return RAP_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, rap_ssl_certificate_index, NULL) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return RAP_ERROR;
    }

    ssl->buffer_size = RAP_SSL_BUFSIZE;

    /* client side options */

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

    /* server side options */

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
    /* this option allow a potential SSL 2.0 rollback (CAN-2005-2969) */
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_CTX_clear_options(ssl->ctx,
                          SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

    if (!(protocols & RAP_SSL_SSLv2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
    }
    if (!(protocols & RAP_SSL_SSLv3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv3);
    }
    if (!(protocols & RAP_SSL_TLSv1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1);
    }
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    if (!(protocols & RAP_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    if (!(protocols & RAP_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_3
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    if (!(protocols & RAP_SSL_TLSv1_3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    }
#endif

#ifdef SSL_CTX_set_min_proto_version
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_2_VERSION);
#endif

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_OP_NO_ANTI_REPLAY
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_ANTI_REPLAY);
#endif

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, rap_ssl_info_callback);

    return RAP_OK;
}


rap_int_t
rap_ssl_certificates(rap_conf_t *cf, rap_ssl_t *ssl, rap_array_t *certs,
    rap_array_t *keys, rap_array_t *passwords)
{
    rap_str_t   *cert, *key;
    rap_uint_t   i;

    cert = certs->elts;
    key = keys->elts;

    for (i = 0; i < certs->nelts; i++) {

        if (rap_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_certificate(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *cert,
    rap_str_t *key, rap_array_t *passwords)
{
    char            *err;
    X509            *x509;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;

    x509 = rap_ssl_load_certificate(cf->pool, &err, cert, &chain);
    if (x509 == NULL) {
        if (err != NULL) {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return RAP_ERROR;
    }

    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

    if (X509_set_ex_data(x509, rap_ssl_certificate_name_index, cert->data)
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

    if (X509_set_ex_data(x509, rap_ssl_next_certificate_index,
                      SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index))
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, rap_ssl_certificate_index, x509) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

    /*
     * Note that x509 is not freed here, but will be instead freed in
     * rap_ssl_cleanup_ctx().  This is because we need to preserve all
     * certificates to be able to iterate all of them through exdata
     * (rap_ssl_certificate_index, rap_ssl_next_certificate_index),
     * while OpenSSL can free a certificate if it is replaced with another
     * certificate of the same type.
     */

#ifdef SSL_CTX_set0_chain

    if (SSL_CTX_set0_chain(ssl->ctx, chain) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

#else
    {
    int  n;

    /* SSL_CTX_set0_chain() is only available in OpenSSL 1.0.2+ */

    n = sk_X509_num(chain);

    while (n--) {
        x509 = sk_X509_shift(chain);

        if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) == 0) {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_add_extra_chain_cert(\"%s\") failed",
                          cert->data);
            sk_X509_pop_free(chain, X509_free);
            return RAP_ERROR;
        }
    }

    sk_X509_free(chain);
    }
#endif

    pkey = rap_ssl_load_certificate_key(cf->pool, &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return RAP_ERROR;
    }

    if (SSL_CTX_use_PrivateKey(ssl->ctx, pkey) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey(\"%s\") failed", key->data);
        EVP_PKEY_free(pkey);
        return RAP_ERROR;
    }

    EVP_PKEY_free(pkey);

    return RAP_OK;
}


rap_int_t
rap_ssl_connection_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *cert, rap_str_t *key, rap_array_t *passwords)
{
    char            *err;
    X509            *x509;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;

    x509 = rap_ssl_load_certificate(pool, &err, cert, &chain);
    if (x509 == NULL) {
        if (err != NULL) {
            rap_ssl_error(RAP_LOG_ERR, c->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return RAP_ERROR;
    }

    if (SSL_use_certificate(c->ssl->connection, x509) == 0) {
        rap_ssl_error(RAP_LOG_ERR, c->log, 0,
                      "SSL_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

    X509_free(x509);

#ifdef SSL_set0_chain

    /*
     * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
     * but this function is only called via certificate callback,
     * which is only available in OpenSSL 1.0.2+ as well
     */

    if (SSL_set0_chain(c->ssl->connection, chain) == 0) {
        rap_ssl_error(RAP_LOG_ERR, c->log, 0,
                      "SSL_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return RAP_ERROR;
    }

#endif

    pkey = rap_ssl_load_certificate_key(pool, &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            rap_ssl_error(RAP_LOG_ERR, c->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return RAP_ERROR;
    }

    if (SSL_use_PrivateKey(c->ssl->connection, pkey) == 0) {
        rap_ssl_error(RAP_LOG_ERR, c->log, 0,
                      "SSL_use_PrivateKey(\"%s\") failed", key->data);
        EVP_PKEY_free(pkey);
        return RAP_ERROR;
    }

    EVP_PKEY_free(pkey);

    return RAP_OK;
}


static X509 *
rap_ssl_load_certificate(rap_pool_t *pool, char **err, rap_str_t *cert,
    STACK_OF(X509) **chain)
{
    BIO     *bio;
    X509    *x509, *temp;
    u_long   n;

    if (rap_strncmp(cert->data, "data:", sizeof("data:") - 1) == 0) {

        bio = BIO_new_mem_buf(cert->data + sizeof("data:") - 1,
                              cert->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
            return NULL;
        }

    } else {

        if (rap_get_full_name(pool, (rap_str_t *) &rap_cycle->conf_prefix, cert)
            != RAP_OK)
        {
            *err = NULL;
            return NULL;
        }

        bio = BIO_new_file((char *) cert->data, "r");
        if (bio == NULL) {
            *err = "BIO_new_file() failed";
            return NULL;
        }
    }

    /* certificate itself */

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        return NULL;
    }

    /* rest of the chain */

    *chain = sk_X509_new_null();
    if (*chain == NULL) {
        *err = "sk_X509_new_null() failed";
        BIO_free(bio);
        X509_free(x509);
        return NULL;
    }

    for ( ;; ) {

        temp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (temp == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(*chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(*chain, temp) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(*chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return x509;
}


static EVP_PKEY *
rap_ssl_load_certificate_key(rap_pool_t *pool, char **err,
    rap_str_t *key, rap_array_t *passwords)
{
    BIO              *bio;
    EVP_PKEY         *pkey;
    rap_str_t        *pwd;
    rap_uint_t        tries;
    pem_password_cb  *cb;

    if (rap_strncmp(key->data, "engine:", sizeof("engine:") - 1) == 0) {

#ifndef OPENSSL_NO_ENGINE

        u_char  *p, *last;
        ENGINE  *engine;

        p = key->data + sizeof("engine:") - 1;
        last = (u_char *) rap_strchr(p, ':');

        if (last == NULL) {
            *err = "invalid syntax";
            return NULL;
        }

        *last = '\0';

        engine = ENGINE_by_id((char *) p);

        if (engine == NULL) {
            *err = "ENGINE_by_id() failed";
            return NULL;
        }

        *last++ = ':';

        pkey = ENGINE_load_private_key(engine, (char *) last, 0, 0);

        if (pkey == NULL) {
            *err = "ENGINE_load_private_key() failed";
            ENGINE_free(engine);
            return NULL;
        }

        ENGINE_free(engine);

        return pkey;

#else

        *err = "loading \"engine:...\" certificate keys is not supported";
        return NULL;

#endif
    }

    if (rap_strncmp(key->data, "data:", sizeof("data:") - 1) == 0) {

        bio = BIO_new_mem_buf(key->data + sizeof("data:") - 1,
                              key->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
            return NULL;
        }

    } else {

        if (rap_get_full_name(pool, (rap_str_t *) &rap_cycle->conf_prefix, key)
            != RAP_OK)
        {
            *err = NULL;
            return NULL;
        }

        bio = BIO_new_file((char *) key->data, "r");
        if (bio == NULL) {
            *err = "BIO_new_file() failed";
            return NULL;
        }
    }

    if (passwords) {
        tries = passwords->nelts;
        pwd = passwords->elts;
        cb = rap_ssl_password_callback;

    } else {
        tries = 1;
        pwd = NULL;
        cb = NULL;
    }

    for ( ;; ) {

        pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
        if (pkey != NULL) {
            break;
        }

        if (tries-- > 1) {
            ERR_clear_error();
            (void) BIO_reset(bio);
            pwd++;
            continue;
        }

        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);

    return pkey;
}


static int
rap_ssl_password_callback(char *buf, int size, int rwflag, void *userdata)
{
    rap_str_t *pwd = userdata;

    if (rwflag) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      "rap_ssl_password_callback() is called for encryption");
        return 0;
    }

    if (pwd == NULL) {
        return 0;
    }

    if (pwd->len > (size_t) size) {
        rap_log_error(RAP_LOG_ERR, rap_cycle->log, 0,
                      "password is truncated to %d bytes", size);
    } else {
        size = pwd->len;
    }

    rap_memcpy(buf, pwd->data, size);

    return size;
}


rap_int_t
rap_ssl_ciphers(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *ciphers,
    rap_uint_t prefer_server_ciphers)
{
    if (SSL_CTX_set_cipher_list(ssl->ctx, (char *) ciphers->data) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      ciphers);
        return RAP_ERROR;
    }

    if (prefer_server_ciphers) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100001L && !defined LIBRESSL_VERSION_NUMBER)
    /* a temporary 512-bit RSA key is required for export versions of MSIE */
    SSL_CTX_set_tmp_rsa_callback(ssl->ctx, rap_ssl_rsa512_key_callback);
#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_client_certificate(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *cert,
    rap_int_t depth)
{
    STACK_OF(X509_NAME)  *list;

    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, rap_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return RAP_OK;
    }

    if (rap_conf_full_name(cf->cycle, cert, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return RAP_ERROR;
    }

    /*
     * SSL_CTX_load_verify_locations() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

    list = SSL_load_client_CA_file((char *) cert->data);

    if (list == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_load_client_CA_file(\"%s\") failed", cert->data);
        return RAP_ERROR;
    }

    SSL_CTX_set_client_CA_list(ssl->ctx, list);

    return RAP_OK;
}


rap_int_t
rap_ssl_trusted_certificate(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *cert,
    rap_int_t depth)
{
    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return RAP_OK;
    }

    if (rap_conf_full_name(cf->cycle, cert, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return RAP_ERROR;
    }

    /*
     * SSL_CTX_load_verify_locations() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

    return RAP_OK;
}


rap_int_t
rap_ssl_crl(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *crl)
{
    X509_STORE   *store;
    X509_LOOKUP  *lookup;

    if (crl->len == 0) {
        return RAP_OK;
    }

    if (rap_conf_full_name(cf->cycle, crl, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return RAP_ERROR;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

    if (lookup == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_add_lookup() failed");
        return RAP_ERROR;
    }

    if (X509_LOOKUP_load_file(lookup, (char *) crl->data, X509_FILETYPE_PEM)
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "X509_LOOKUP_load_file(\"%s\") failed", crl->data);
        return RAP_ERROR;
    }

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    return RAP_OK;
}


static int
rap_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if (RAP_DEBUG)
    char              *subject, *issuer;
    int                err, depth;
    X509              *cert;
    X509_NAME         *sname, *iname;
    rap_connection_t  *c;
    rap_ssl_conn_t    *ssl_conn;

    ssl_conn = X509_STORE_CTX_get_ex_data(x509_store,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());

    c = rap_ssl_get_connection(ssl_conn);

    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);
    subject = sname ? X509_NAME_oneline(sname, NULL, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, NULL, 0) : "(none)";

    rap_log_debug5(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "verify:%d, error:%d, depth:%d, "
                   "subject:\"%s\", issuer:\"%s\"",
                   ok, err, depth, subject, issuer);

    if (sname) {
        OPENSSL_free(subject);
    }

    if (iname) {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}


static void
rap_ssl_info_callback(const rap_ssl_conn_t *ssl_conn, int where, int ret)
{
    BIO               *rbio, *wbio;
    rap_connection_t  *c;

#ifndef SSL_OP_NO_RENEGOTIATION

    if ((where & SSL_CB_HANDSHAKE_START)
        && SSL_is_server((rap_ssl_conn_t *) ssl_conn))
    {
        c = rap_ssl_get_connection((rap_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }

#endif

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        c = rap_ssl_get_connection((rap_ssl_conn_t *) ssl_conn);

        if (!c->ssl->handshake_buffer_set) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio(ssl_conn);
            wbio = SSL_get_wbio(ssl_conn);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio, RAP_SSL_BUFSIZE);
                c->ssl->handshake_buffer_set = 1;
            }
        }
    }
}


RSA *
rap_ssl_rsa512_key_callback(rap_ssl_conn_t *ssl_conn, int is_export,
    int key_length)
{
    static RSA  *key;

    if (key_length != 512) {
        return NULL;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100003L && !defined OPENSSL_NO_DEPRECATED)

    if (key == NULL) {
        key = RSA_generate_key(512, RSA_F4, NULL, NULL);
    }

#endif

    return key;
}


rap_array_t *
rap_ssl_read_password_file(rap_conf_t *cf, rap_str_t *file)
{
    u_char              *p, *last, *end;
    size_t               len;
    ssize_t              n;
    rap_fd_t             fd;
    rap_str_t           *pwd;
    rap_array_t         *passwords;
    rap_pool_cleanup_t  *cln;
    u_char               buf[RAP_SSL_PASSWORD_BUFFER_SIZE];

    if (rap_conf_full_name(cf->cycle, file, 1) != RAP_OK) {
        return NULL;
    }

    passwords = rap_array_create(cf->temp_pool, 4, sizeof(rap_str_t));
    if (passwords == NULL) {
        return NULL;
    }

    cln = rap_pool_cleanup_add(cf->temp_pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rap_ssl_passwords_cleanup;
    cln->data = passwords;

    fd = rap_open_file(file->data, RAP_FILE_RDONLY, RAP_FILE_OPEN, 0);

    if (fd == RAP_INVALID_FILE) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                           rap_open_file_n " \"%s\" failed", file->data);
        return NULL;
    }

    len = 0;
    last = buf;

    do {
        n = rap_read_fd(fd, last, RAP_SSL_PASSWORD_BUFFER_SIZE - len);

        if (n == -1) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                               rap_read_fd_n " \"%s\" failed", file->data);
            passwords = NULL;
            goto cleanup;
        }

        end = last + n;

        if (len && n == 0) {
            *end++ = LF;
        }

        p = buf;

        for ( ;; ) {
            last = rap_strlchr(last, end, LF);

            if (last == NULL) {
                break;
            }

            len = last++ - p;

            if (len && p[len - 1] == CR) {
                len--;
            }

            if (len) {
                pwd = rap_array_push(passwords);
                if (pwd == NULL) {
                    passwords = NULL;
                    goto cleanup;
                }

                pwd->len = len;
                pwd->data = rap_pnalloc(cf->temp_pool, len);

                if (pwd->data == NULL) {
                    passwords->nelts--;
                    passwords = NULL;
                    goto cleanup;
                }

                rap_memcpy(pwd->data, p, len);
            }

            p = last;
        }

        len = end - p;

        if (len == RAP_SSL_PASSWORD_BUFFER_SIZE) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "too long line in \"%s\"", file->data);
            passwords = NULL;
            goto cleanup;
        }

        rap_memmove(buf, p, len);
        last = buf + len;

    } while (n != 0);

    if (passwords->nelts == 0) {
        pwd = rap_array_push(passwords);
        if (pwd == NULL) {
            passwords = NULL;
            goto cleanup;
        }

        rap_memzero(pwd, sizeof(rap_str_t));
    }

cleanup:

    if (rap_close_file(fd) == RAP_FILE_ERROR) {
        rap_conf_log_error(RAP_LOG_ALERT, cf, rap_errno,
                           rap_close_file_n " \"%s\" failed", file->data);
    }

    rap_explicit_memzero(buf, RAP_SSL_PASSWORD_BUFFER_SIZE);

    return passwords;
}


rap_array_t *
rap_ssl_preserve_passwords(rap_conf_t *cf, rap_array_t *passwords)
{
    rap_str_t           *opwd, *pwd;
    rap_uint_t           i;
    rap_array_t         *pwds;
    rap_pool_cleanup_t  *cln;
    static rap_array_t   empty_passwords;

    if (passwords == NULL) {

        /*
         * If there are no passwords, an empty array is used
         * to make sure OpenSSL's default password callback
         * won't block on reading from stdin.
         */

        return &empty_passwords;
    }

    /*
     * Passwords are normally allocated from the temporary pool
     * and cleared after parsing configuration.  To be used at
     * runtime they have to be copied to the configuration pool.
     */

    pwds = rap_array_create(cf->pool, passwords->nelts, sizeof(rap_str_t));
    if (pwds == NULL) {
        return NULL;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rap_ssl_passwords_cleanup;
    cln->data = pwds;

    opwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {

        pwd = rap_array_push(pwds);
        if (pwd == NULL) {
            return NULL;
        }

        pwd->len = opwd[i].len;
        pwd->data = rap_pnalloc(cf->pool, pwd->len);

        if (pwd->data == NULL) {
            pwds->nelts--;
            return NULL;
        }

        rap_memcpy(pwd->data, opwd[i].data, opwd[i].len);
    }

    return pwds;
}


static void
rap_ssl_passwords_cleanup(void *data)
{
    rap_array_t *passwords = data;

    rap_str_t   *pwd;
    rap_uint_t   i;

    pwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {
        rap_explicit_memzero(pwd[i].data, pwd[i].len);
    }
}


rap_int_t
rap_ssl_dhparam(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *file)
{
    DH   *dh;
    BIO  *bio;

    if (file->len == 0) {
        return RAP_OK;
    }

    if (rap_conf_full_name(cf->cycle, file, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return RAP_ERROR;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_DHparams(\"%s\") failed", file->data);
        BIO_free(bio);
        return RAP_ERROR;
    }

    SSL_CTX_set_tmp_dh(ssl->ctx, dh);

    DH_free(dh);
    BIO_free(bio);

    return RAP_OK;
}


rap_int_t
rap_ssl_ecdh_curve(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *name)
{
#ifndef OPENSSL_NO_ECDH

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields.  OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)

    /*
     * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
     * curve previously supported.  By default an internal list is used,
     * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
     * and X25519 in OpenSSL 1.1.0+.
     *
     * By default a curve preferred by the client will be used for
     * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
     * be used to prefer server curves instead, similar to what it
     * does for ciphers.
     */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

#if SSL_CTRL_SET_ECDH_AUTO
    /* not needed in OpenSSL 1.1.0+ */
    SSL_CTX_set_ecdh_auto(ssl->ctx, 1);
#endif

    if (rap_strcmp(name->data, "auto") == 0) {
        return RAP_OK;
    }

    if (SSL_CTX_set1_curves_list(ssl->ctx, (char *) name->data) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set1_curves_list(\"%s\") failed", name->data);
        return RAP_ERROR;
    }

#else

    int      nid;
    char    *curve;
    EC_KEY  *ecdh;

    if (rap_strcmp(name->data, "auto") == 0) {
        curve = "prime256v1";

    } else {
        curve = (char *) name->data;
    }

    nid = OBJ_sn2nid(curve);
    if (nid == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "OBJ_sn2nid(\"%s\") failed: unknown curve", curve);
        return RAP_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "EC_KEY_new_by_curve_name(\"%s\") failed", curve);
        return RAP_ERROR;
    }

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ssl->ctx, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_early_data(rap_conf_t *cf, rap_ssl_t *ssl, rap_uint_t enable)
{
    if (!enable) {
        return RAP_OK;
    }

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    SSL_CTX_set_early_data_enabled(ssl->ctx, 1);

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    SSL_CTX_set_max_early_data(ssl->ctx, RAP_SSL_BUFSIZE);

#else
    rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                  "\"ssl_early_data\" is not supported on this platform, "
                  "ignored");
#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_client_session_cache(rap_conf_t *cf, rap_ssl_t *ssl, rap_uint_t enable)
{
    if (!enable) {
        return RAP_OK;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx,
                                   SSL_SESS_CACHE_CLIENT
                                   |SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_sess_set_new_cb(ssl->ctx, rap_ssl_new_client_session);

    return RAP_OK;
}


static int
rap_ssl_new_client_session(rap_ssl_conn_t *ssl_conn, rap_ssl_session_t *sess)
{
    rap_connection_t  *c;

    c = rap_ssl_get_connection(ssl_conn);

    if (c->ssl->save_session) {
        c->ssl->session = sess;

        c->ssl->save_session(c);

        c->ssl->session = NULL;
    }

    return 0;
}


rap_int_t
rap_ssl_create_connection(rap_ssl_t *ssl, rap_connection_t *c, rap_uint_t flags)
{
    rap_ssl_connection_t  *sc;

    sc = rap_pcalloc(c->pool, sizeof(rap_ssl_connection_t));
    if (sc == NULL) {
        return RAP_ERROR;
    }

    sc->buffer = ((flags & RAP_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;

    sc->session_ctx = ssl->ctx;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(ssl->ctx)) {
        sc->try_early_data = 1;
    }
#endif

    sc->connection = SSL_new(ssl->ctx);

    if (sc->connection == NULL) {
        rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return RAP_ERROR;
    }

    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return RAP_ERROR;
    }

    if (flags & RAP_SSL_CLIENT) {
        SSL_set_connect_state(sc->connection);

    } else {
        SSL_set_accept_state(sc->connection);

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(sc->connection, SSL_OP_NO_RENEGOTIATION);
#endif
    }

    if (SSL_set_ex_data(sc->connection, rap_ssl_connection_index, c) == 0) {
        rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        return RAP_ERROR;
    }

    c->ssl = sc;

    return RAP_OK;
}


rap_ssl_session_t *
rap_ssl_get_session(rap_connection_t *c)
{
#ifdef TLS1_3_VERSION
    if (c->ssl->session) {
        SSL_SESSION_up_ref(c->ssl->session);
        return c->ssl->session;
    }
#endif

    return SSL_get1_session(c->ssl->connection);
}


rap_ssl_session_t *
rap_ssl_get0_session(rap_connection_t *c)
{
    if (c->ssl->session) {
        return c->ssl->session;
    }

    return SSL_get0_session(c->ssl->connection);
}


rap_int_t
rap_ssl_set_session(rap_connection_t *c, rap_ssl_session_t *session)
{
    if (session) {
        if (SSL_set_session(c->ssl->connection, session) == 0) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_handshake(rap_connection_t *c)
{
    int        n, sslerr;
    rap_err_t  err;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->try_early_data) {
        return rap_ssl_try_early_data(c);
    }
#endif

    rap_ssl_clear_error(c->log);

    n = SSL_do_handshake(c->ssl->connection);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == 1) {

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

#if (RAP_DEBUG)
        rap_ssl_handshake_log(c);
#endif

        c->ssl->handshaked = 1;

        c->recv = rap_ssl_recv;
        c->send = rap_ssl_write;
        c->recv_chain = rap_ssl_recv_chain;
        c->send_chain = rap_ssl_send_chain;

#ifndef SSL_OP_NO_RENEGOTIATION
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (c->ssl->connection->s3 && SSL_is_server(c->ssl->connection)) {
            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

#endif
#endif
#endif

        return RAP_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = rap_ssl_handshake_handler;
        c->write->handler = rap_ssl_handshake_handler;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = rap_ssl_handshake_handler;
        c->write->handler = rap_ssl_handshake_handler;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        rap_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return RAP_ERROR;
    }

    c->read->error = 1;

    rap_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return RAP_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static rap_int_t
rap_ssl_try_early_data(rap_connection_t *c)
{
    int        n, sslerr;
    u_char     buf;
    size_t     readbytes;
    rap_err_t  err;

    rap_ssl_clear_error(c->log);

    readbytes = 0;

    n = SSL_read_early_data(c->ssl->connection, &buf, 1, &readbytes);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_read_early_data: %d, %uz", n, readbytes);

    if (n == SSL_READ_EARLY_DATA_FINISH) {
        c->ssl->try_early_data = 0;
        return rap_ssl_handshake(c);
    }

    if (n == SSL_READ_EARLY_DATA_SUCCESS) {

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

#if (RAP_DEBUG)
        rap_ssl_handshake_log(c);
#endif

        c->ssl->try_early_data = 0;

        c->ssl->early_buf = buf;
        c->ssl->early_preread = 1;

        c->ssl->handshaked = 1;
        c->ssl->in_early = 1;

        c->recv = rap_ssl_recv;
        c->send = rap_ssl_write;
        c->recv_chain = rap_ssl_recv_chain;
        c->send_chain = rap_ssl_send_chain;

        return RAP_OK;
    }

    /* SSL_READ_EARLY_DATA_ERROR */

    sslerr = SSL_get_error(c->ssl->connection, n);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = rap_ssl_handshake_handler;
        c->write->handler = rap_ssl_handshake_handler;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = rap_ssl_handshake_handler;
        c->write->handler = rap_ssl_handshake_handler;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        rap_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return RAP_ERROR;
    }

    c->read->error = 1;

    rap_ssl_connection_error(c, sslerr, err, "SSL_read_early_data() failed");

    return RAP_ERROR;
}

#endif


#if (RAP_DEBUG)

static void
rap_ssl_handshake_log(rap_connection_t *c)
{
    char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    const
#endif
    SSL_CIPHER  *cipher;

    cipher = SSL_get_current_cipher(c->ssl->connection);

    if (cipher) {
        SSL_CIPHER_description(cipher, &buf[1], 128);

        for (s = &buf[1], d = buf; *s; s++) {
            if (*s == ' ' && *d == ' ') {
                continue;
            }

            if (*s == LF || *s == CR) {
                continue;
            }

            *++d = *s;
        }

        if (*d != ' ') {
            d++;
        }

        *d = '\0';

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL: %s, cipher: \"%s\"",
                       SSL_get_version(c->ssl->connection), &buf[1]);

        if (SSL_session_reused(c->ssl->connection)) {
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL reused session");
        }

    } else {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL no shared ciphers");
    }
}

#endif


static void
rap_ssl_handshake_handler(rap_event_t *ev)
{
    rap_connection_t  *c;

    c = ev->data;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (rap_ssl_handshake(c) == RAP_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
rap_ssl_recv_chain(rap_connection_t *c, rap_chain_t *cl, off_t limit)
{
    u_char     *last;
    ssize_t     n, bytes, size;
    rap_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = rap_ssl_recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (!c->read->ready) {
                return bytes;
            }

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == RAP_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}


ssize_t
rap_ssl_recv(rap_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return rap_ssl_recv_early(c, buf, size);
    }
#endif

    if (c->ssl->last == RAP_ERROR) {
        c->read->error = 1;
        return RAP_ERROR;
    }

    if (c->ssl->last == RAP_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    rap_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = rap_ssl_handle_recv(c, n);

        if (c->ssl->last == RAP_OK) {

            size -= n;

            if (size == 0) {
                c->read->ready = 1;

                if (c->read->available >= 0) {
                    c->read->available -= bytes;

                    /*
                     * there can be data buffered at SSL layer,
                     * so we post an event to continue reading on the next
                     * iteration of the event loop
                     */

                    if (c->read->available < 0) {
                        c->read->available = 0;
                        c->read->ready = 0;

                        if (c->read->posted) {
                            rap_delete_posted_event(c->read);
                        }

                        rap_post_event(c->read, &rap_posted_next_events);
                    }

                    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

                } else {

#if (RAP_HAVE_FIONREAD)

                    if (rap_socket_nread(c->fd, &c->read->available) == -1) {
                        c->read->error = 1;
                        rap_connection_error(c, rap_socket_errno,
                                             rap_socket_nread_n " failed");
                        return RAP_ERROR;
                    }

                    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

#endif
                }

                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            if (c->ssl->last != RAP_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case RAP_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case RAP_ERROR:
            c->read->error = 1;

            /* fall through */

        case RAP_AGAIN:
            return c->ssl->last;
        }
    }
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ssize_t
rap_ssl_recv_early(rap_connection_t *c, u_char *buf, size_t size)
{
    int        n, bytes;
    size_t     readbytes;

    if (c->ssl->last == RAP_ERROR) {
        c->read->error = 1;
        return RAP_ERROR;
    }

    if (c->ssl->last == RAP_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    rap_ssl_clear_error(c->log);

    if (c->ssl->early_preread) {

        if (size == 0) {
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;
        }

        *buf = c->ssl->early_buf;

        c->ssl->early_preread = 0;

        bytes = 1;
        size -= 1;
        buf += 1;
    }

    if (c->ssl->write_blocked) {
        return RAP_AGAIN;
    }

    /*
     * SSL_read_early_data() may return data in parts, so try to read
     * until SSL_read_early_data() would return no data
     */

    for ( ;; ) {

        readbytes = 0;

        n = SSL_read_early_data(c->ssl->connection, buf, size, &readbytes);

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read_early_data: %d, %uz", n, readbytes);

        if (n == SSL_READ_EARLY_DATA_SUCCESS) {

            c->ssl->last = rap_ssl_handle_recv(c, 1);

            bytes += readbytes;
            size -= readbytes;

            if (size == 0) {
                c->read->ready = 1;
                return bytes;
            }

            buf += readbytes;

            continue;
        }

        if (n == SSL_READ_EARLY_DATA_FINISH) {

            c->ssl->last = rap_ssl_handle_recv(c, 1);
            c->ssl->in_early = 0;

            if (bytes) {
                c->read->ready = 1;
                return bytes;
            }

            return rap_ssl_recv(c, buf, size);
        }

        /* SSL_READ_EARLY_DATA_ERROR */

        c->ssl->last = rap_ssl_handle_recv(c, 0);

        if (bytes) {
            if (c->ssl->last != RAP_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case RAP_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case RAP_ERROR:
            c->read->error = 1;

            /* fall through */

        case RAP_AGAIN:
            return c->ssl->last;
        }
    }
}

#endif


static rap_int_t
rap_ssl_handle_recv(rap_connection_t *c, int n)
{
    int        sslerr;
    rap_err_t  err;

#ifndef SSL_OP_NO_RENEGOTIATION

    if (c->ssl->renegotiation) {
        /*
         * disable renegotiation (CVE-2009-3555):
         * OpenSSL (at least up to 0.9.8l) does not handle disabled
         * renegotiation gracefully, so drop connection here
         */

        rap_log_error(RAP_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");

        while (ERR_peek_error()) {
            rap_ssl_error(RAP_LOG_DEBUG, c->log, 0,
                          "ignoring stale global SSL error");
        }

        ERR_clear_error();

        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        return RAP_ERROR;
    }

#endif

    if (n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (rap_handle_write_event(c->write, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->write, &rap_posted_events);
        }

        return RAP_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (rap_handle_write_event(c->write, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->write, &rap_posted_events);
        }

        c->read->ready = 0;
        return RAP_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read: want write");

        c->write->ready = 0;

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = rap_ssl_write_handler;
        }

        return RAP_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return RAP_DONE;
    }

    rap_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    return RAP_ERROR;
}


static void
rap_ssl_write_handler(rap_event_t *wev)
{
    rap_connection_t  *c;

    c = wev->data;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL write handler");

    c->read->handler(c->read);
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before the SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

rap_chain_t *
rap_ssl_send_chain(rap_connection_t *c, rap_chain_t *in, off_t limit)
{
    int          n;
    rap_uint_t   flush;
    ssize_t      send, size;
    rap_buf_t   *buf;

    if (!c->ssl->buffer) {

        while (in) {
            if (rap_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = rap_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == RAP_ERROR) {
                return RAP_CHAIN_ERROR;
            }

            if (n == RAP_AGAIN) {
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (RAP_MAX_INT32_VALUE - rap_pagesize)) {
        limit = RAP_MAX_INT32_VALUE - rap_pagesize;
    }

    buf = c->ssl->buf;

    if (buf == NULL) {
        buf = rap_create_temp_buf(c->pool, c->ssl->buffer_size);
        if (buf == NULL) {
            return RAP_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = rap_palloc(c->pool, c->ssl->buffer_size);
        if (buf->start == NULL) {
            return RAP_CHAIN_ERROR;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + c->ssl->buffer_size;
    }

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (rap_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %z", size);

            rap_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {
            buf->flush = 0;
            c->buffered &= ~RAP_SSL_BUFFERED;
            return in;
        }

        n = rap_ssl_write(c, buf->pos, size);

        if (n == RAP_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        if (n == RAP_AGAIN) {
            break;
        }

        buf->pos += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send == limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= RAP_SSL_BUFFERED;

    } else {
        c->buffered &= ~RAP_SSL_BUFFERED;
    }

    return in;
}


ssize_t
rap_ssl_write(rap_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    rap_err_t  err;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return rap_ssl_write_early(c, data, size);
    }
#endif

    rap_ssl_clear_error(c->log);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    n = SSL_write(c->ssl->connection, data, size);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (rap_handle_read_event(c->read, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->read, &rap_posted_events);
        }

        c->sent += n;

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (rap_handle_read_event(c->read, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->read, &rap_posted_events);
        }

        c->write->ready = 0;
        return RAP_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write: want read");

        c->read->ready = 0;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = rap_ssl_read_handler;
        }

        return RAP_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    rap_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    return RAP_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

ssize_t
rap_ssl_write_early(rap_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    size_t     written;
    rap_err_t  err;

    rap_ssl_clear_error(c->log);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    written = 0;

    n = SSL_write_early_data(c->ssl->connection, data, size, &written);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_write_early_data: %d, %uz", n, written);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (rap_handle_read_event(c->read, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->read, &rap_posted_events);
        }

        if (c->ssl->write_blocked) {
            c->ssl->write_blocked = 0;
            rap_post_event(c->read, &rap_posted_events);
        }

        c->sent += written;

        return written;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want write");

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (rap_handle_read_event(c->read, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_post_event(c->read, &rap_posted_events);
        }

        /*
         * OpenSSL 1.1.1a fails to handle SSL_read_early_data()
         * if an SSL_write_early_data() call blocked on writing,
         * see https://github.com/openssl/openssl/issues/7757
         */

        c->ssl->write_blocked = 1;

        c->write->ready = 0;
        return RAP_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want read");

        c->read->ready = 0;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = rap_ssl_read_handler;
        }

        return RAP_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    rap_ssl_connection_error(c, sslerr, err, "SSL_write_early_data() failed");

    return RAP_ERROR;
}

#endif


static void
rap_ssl_read_handler(rap_event_t *rev)
{
    rap_connection_t  *c;

    c = rev->data;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL read handler");

    c->write->handler(c->write);
}


void
rap_ssl_free_buffer(rap_connection_t *c)
{
    if (c->ssl->buf && c->ssl->buf->start) {
        if (rap_pfree(c->pool, c->ssl->buf->start) == RAP_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


rap_int_t
rap_ssl_shutdown(rap_connection_t *c)
{
    int        n, sslerr, mode;
    rap_err_t  err;

    if (SSL_in_init(c->ssl->connection)) {
        /*
         * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         * an SSL handshake, while previous versions always return 0.
         * Avoid calling SSL_shutdown() if handshake wasn't completed.
         */

        SSL_free(c->ssl->connection);
        c->ssl = NULL;

        return RAP_OK;
    }

    if (c->timedout) {
        mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;
        SSL_set_quiet_shutdown(c->ssl->connection, 1);

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }

        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }

        if (c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown) {
            SSL_set_quiet_shutdown(c->ssl->connection, 1);
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    rap_ssl_clear_error(c->log);

    n = SSL_shutdown(c->ssl->connection);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

    sslerr = 0;

    /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */

    if (n != 1 && ERR_peek_error()) {
        sslerr = SSL_get_error(c->ssl->connection, n);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);
    }

    if (n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN) {
        SSL_free(c->ssl->connection);
        c->ssl = NULL;

        return RAP_OK;
    }

    if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
        c->read->handler = rap_ssl_shutdown_handler;
        c->write->handler = rap_ssl_shutdown_handler;

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            return RAP_ERROR;
        }

        if (sslerr == SSL_ERROR_WANT_READ) {
            rap_add_timer(c->read, 30000);
        }

        return RAP_AGAIN;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? rap_errno : 0;

    rap_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

    SSL_free(c->ssl->connection);
    c->ssl = NULL;

    return RAP_ERROR;
}


static void
rap_ssl_shutdown_handler(rap_event_t *ev)
{
    rap_connection_t           *c;
    rap_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");

    if (rap_ssl_shutdown(c) == RAP_AGAIN) {
        return;
    }

    handler(c);
}


static void
rap_ssl_connection_error(rap_connection_t *c, int sslerr, rap_err_t err,
    char *text)
{
    int         n;
    rap_uint_t  level;

    level = RAP_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == RAP_ECONNRESET
#if (RAP_WIN32)
            || err == RAP_ECONNABORTED
#endif
            || err == RAP_EPIPE
            || err == RAP_ENOTCONN
            || err == RAP_ETIMEDOUT
            || err == RAP_ECONNREFUSED
            || err == RAP_ENETDOWN
            || err == RAP_ENETUNREACH
            || err == RAP_EHOSTDOWN
            || err == RAP_EHOSTUNREACH)
        {
            switch (c->log_error) {

            case RAP_ERROR_IGNORE_ECONNRESET:
            case RAP_ERROR_INFO:
                level = RAP_LOG_INFO;
                break;

            case RAP_ERROR_ERR:
                level = RAP_LOG_ERR;
                break;

            default:
                break;
            }
        }

    } else if (sslerr == SSL_ERROR_SSL) {

        n = ERR_GET_REASON(ERR_peek_error());

            /* handshake failures */
        if (n == SSL_R_BAD_CHANGE_CIPHER_SPEC                        /*  103 */
#ifdef SSL_R_NO_SUITABLE_KEY_SHARE
            || n == SSL_R_NO_SUITABLE_KEY_SHARE                      /*  101 */
#endif
#ifdef SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM
            || n == SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            /*  118 */
#endif
            || n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  /*  129 */
            || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
            || n == SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              /*  151 */
            || n == SSL_R_EXCESSIVE_MESSAGE_SIZE                     /*  152 */
            || n == SSL_R_HTTPS_PROXY_REQUEST                        /*  155 */
            || n == SSL_R_HTTP_REQUEST                               /*  156 */
            || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
#ifdef SSL_R_NO_CIPHERS_PASSED
            || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
#endif
            || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
            || n == SSL_R_NO_COMPRESSION_SPECIFIED                   /*  187 */
            || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
            || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
#ifdef SSL_R_CLIENTHELLO_TLSEXT
            || n == SSL_R_CLIENTHELLO_TLSEXT                         /*  226 */
#endif
#ifdef SSL_R_PARSE_TLSEXT
            || n == SSL_R_PARSE_TLSEXT                               /*  227 */
#endif
#ifdef SSL_R_CALLBACK_FAILED
            || n == SSL_R_CALLBACK_FAILED                            /*  234 */
#endif
            || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
            || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
            || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
            || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
#ifdef SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS
            || n == SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS             /*  253 */
#endif
            || n == SSL_R_UNSUPPORTED_PROTOCOL                       /*  258 */
#ifdef SSL_R_NO_SHARED_GROUP
            || n == SSL_R_NO_SHARED_GROUP                            /*  266 */
#endif
            || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
            || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
            || n == SSL_R_RENEGOTIATE_EXT_TOO_LONG                   /*  335 */
            || n == SSL_R_RENEGOTIATION_ENCODING_ERR                 /*  336 */
            || n == SSL_R_RENEGOTIATION_MISMATCH                     /*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
            || n == SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
            || n == SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           /*  345 */
#endif
#ifdef SSL_R_INAPPROPRIATE_FALLBACK
            || n == SSL_R_INAPPROPRIATE_FALLBACK                     /*  373 */
#endif
#ifdef SSL_R_CERT_CB_ERROR
            || n == SSL_R_CERT_CB_ERROR                              /*  377 */
#endif
#ifdef SSL_R_VERSION_TOO_LOW
            || n == SSL_R_VERSION_TOO_LOW                            /*  396 */
#endif
            || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
#ifdef SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE
            || n == SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             /* 1010 */
            || n == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 /* 1020 */
            || n == SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              /* 1021 */
            || n == SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                /* 1022 */
            || n == SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          /* 1030 */
            || n == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              /* 1040 */
            || n == SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 /* 1041 */
            || n == SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                /* 1042 */
            || n == SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        /* 1043 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            /* 1044 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            /* 1045 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            /* 1046 */
            || n == SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              /* 1047 */
            || n == SSL_R_TLSV1_ALERT_UNKNOWN_CA                     /* 1048 */
            || n == SSL_R_TLSV1_ALERT_ACCESS_DENIED                  /* 1049 */
            || n == SSL_R_TLSV1_ALERT_DECODE_ERROR                   /* 1050 */
            || n == SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  /* 1051 */
            || n == SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             /* 1060 */
            || n == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               /* 1070 */
            || n == SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          /* 1071 */
            || n == SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 /* 1080 */
            || n == SSL_R_TLSV1_ALERT_USER_CANCELLED                 /* 1090 */
            || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               /* 1100 */
#endif
            )
        {
            switch (c->log_error) {

            case RAP_ERROR_IGNORE_ECONNRESET:
            case RAP_ERROR_INFO:
                level = RAP_LOG_INFO;
                break;

            case RAP_ERROR_ERR:
                level = RAP_LOG_ERR;
                break;

            default:
                break;
            }
        }
    }

    rap_ssl_error(level, c->log, err, text);
}


static void
rap_ssl_clear_error(rap_log_t *log)
{
    while (ERR_peek_error()) {
        rap_ssl_error(RAP_LOG_ALERT, log, 0, "ignoring stale global SSL error");
    }

    ERR_clear_error();
}


void rap_cdecl
rap_ssl_error(rap_uint_t level, rap_log_t *log, rap_err_t err, char *fmt, ...)
{
    int          flags;
    u_long       n;
    va_list      args;
    u_char      *p, *last;
    u_char       errstr[RAP_MAX_CONF_ERRSTR];
    const char  *data;

    last = errstr + RAP_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = rap_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    if (ERR_peek_error()) {
        p = rap_cpystrn(p, (u_char *) " (SSL:", last - p);

        for ( ;; ) {

            n = ERR_peek_error_line_data(NULL, NULL, &data, &flags);

            if (n == 0) {
                break;
            }

            /* ERR_error_string_n() requires at least one byte */

            if (p >= last - 1) {
                goto next;
            }

            *p++ = ' ';

            ERR_error_string_n(n, (char *) p, last - p);

            while (p < last && *p) {
                p++;
            }

            if (p < last && *data && (flags & ERR_TXT_STRING)) {
                *p++ = ':';
                p = rap_cpystrn(p, (u_char *) data, last - p);
            }

        next:

            (void) ERR_get_error();
        }

        if (p < last) {
            *p++ = ')';
        }
    }

    rap_log_error(level, log, err, "%*s", p - errstr, errstr);
}


rap_int_t
rap_ssl_session_cache(rap_ssl_t *ssl, rap_str_t *sess_ctx,
    rap_array_t *certificates, ssize_t builtin_session_cache,
    rap_shm_zone_t *shm_zone, time_t timeout)
{
    long  cache_mode;

    SSL_CTX_set_timeout(ssl->ctx, (long) timeout);

    if (rap_ssl_session_id_context(ssl, sess_ctx, certificates) != RAP_OK) {
        return RAP_ERROR;
    }

    if (builtin_session_cache == RAP_SSL_NO_SCACHE) {
        SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
        return RAP_OK;
    }

    if (builtin_session_cache == RAP_SSL_NONE_SCACHE) {

        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background.  Therefore we have a special
         * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
         * where the server pretends that it supports session reuse,
         * but it does not actually store any session.
         */

        SSL_CTX_set_session_cache_mode(ssl->ctx,
                                       SSL_SESS_CACHE_SERVER
                                       |SSL_SESS_CACHE_NO_AUTO_CLEAR
                                       |SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_cache_size(ssl->ctx, 1);

        return RAP_OK;
    }

    cache_mode = SSL_SESS_CACHE_SERVER;

    if (shm_zone && builtin_session_cache == RAP_SSL_NO_BUILTIN_SCACHE) {
        cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx, cache_mode);

    if (builtin_session_cache != RAP_SSL_NO_BUILTIN_SCACHE) {

        if (builtin_session_cache != RAP_SSL_DFLT_BUILTIN_SCACHE) {
            SSL_CTX_sess_set_cache_size(ssl->ctx, builtin_session_cache);
        }
    }

    if (shm_zone) {
        SSL_CTX_sess_set_new_cb(ssl->ctx, rap_ssl_new_session);
        SSL_CTX_sess_set_get_cb(ssl->ctx, rap_ssl_get_cached_session);
        SSL_CTX_sess_set_remove_cb(ssl->ctx, rap_ssl_remove_session);

        if (SSL_CTX_set_ex_data(ssl->ctx, rap_ssl_session_cache_index, shm_zone)
            == 0)
        {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_set_ex_data() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_ssl_session_id_context(rap_ssl_t *ssl, rap_str_t *sess_ctx,
    rap_array_t *certificates)
{
    int                   n, i;
    X509                 *cert;
    X509_NAME            *name;
    rap_str_t            *certs;
    rap_uint_t            k;
    EVP_MD_CTX           *md;
    unsigned int          len;
    STACK_OF(X509_NAME)  *list;
    u_char                buf[EVP_MAX_MD_SIZE];

    /*
     * Session ID context is set based on the string provided,
     * the server certificates, and the client CA list.
     */

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return RAP_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, sess_ctx->data, sess_ctx->len) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, rap_ssl_next_certificate_index))
    {
        if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "X509_digest() failed");
            goto failed;
        }

        if (EVP_DigestUpdate(md, buf, len) == 0) {
            rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                          "EVP_DigestUpdate() failed");
            goto failed;
        }
    }

    if (SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index) == NULL) {

        /*
         * If certificates are loaded dynamically, we use certificate
         * names as specified in the configuration (with variables).
         */

        certs = certificates->elts;
        for (k = 0; k < certificates->nelts; k++) {

            if (EVP_DigestUpdate(md, certs[k].data, certs[k].len) == 0) {
                rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    list = SSL_CTX_get_client_CA_list(ssl->ctx);

    if (list != NULL) {
        n = sk_X509_NAME_num(list);

        for (i = 0; i < n; i++) {
            name = sk_X509_NAME_value(list, i);

            if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
                rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                              "X509_NAME_digest() failed");
                goto failed;
            }

            if (EVP_DigestUpdate(md, buf, len) == 0) {
                rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    if (SSL_CTX_set_session_id_context(ssl->ctx, buf, len) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_session_id_context() failed");
        return RAP_ERROR;
    }

    return RAP_OK;

failed:

    EVP_MD_CTX_destroy(md);

    return RAP_ERROR;
}


rap_int_t
rap_ssl_session_cache_init(rap_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    rap_slab_pool_t          *shpool;
    rap_ssl_session_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return RAP_OK;
    }

    shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return RAP_OK;
    }

    cache = rap_slab_alloc(shpool, sizeof(rap_ssl_session_cache_t));
    if (cache == NULL) {
        return RAP_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    rap_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    rap_ssl_session_rbtree_insert_value);

    rap_queue_init(&cache->expire_queue);

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = rap_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return RAP_ERROR;
    }

    rap_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->log_nomem = 0;

    return RAP_OK;
}


/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3/TLSv1, typically 32 bytes.
 * It seems that the typical length of the external ASN1 representation
 * of a session is 118 or 119 bytes for SSLv3/TSLv1.
 *
 * Thus on 32-bit platforms we allocate separately an rbtree node,
 * a session id, and an ASN1 representation, they take accordingly
 * 64, 32, and 128 bytes.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * and an ASN1 representation, they take accordingly 128 and 128 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
rap_ssl_new_session(rap_ssl_conn_t *ssl_conn, rap_ssl_session_t *sess)
{
    int                       len;
    u_char                   *p, *id, *cached_sess, *session_id;
    uint32_t                  hash;
    SSL_CTX                  *ssl_ctx;
    unsigned int              session_id_length;
    rap_shm_zone_t           *shm_zone;
    rap_connection_t         *c;
    rap_slab_pool_t          *shpool;
    rap_ssl_sess_id_t        *sess_id;
    rap_ssl_session_cache_t  *cache;
    u_char                    buf[RAP_SSL_MAX_SESSION_SIZE];

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > (int) RAP_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    c = rap_ssl_get_connection(ssl_conn);

    ssl_ctx = c->ssl->session_ctx;
    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, rap_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    rap_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    rap_ssl_expire_sessions(cache, shpool, 1);

    cached_sess = rap_slab_alloc_locked(shpool, len);

    if (cached_sess == NULL) {

        /* drop the oldest non-expired session and try once more */

        rap_ssl_expire_sessions(cache, shpool, 0);

        cached_sess = rap_slab_alloc_locked(shpool, len);

        if (cached_sess == NULL) {
            sess_id = NULL;
            goto failed;
        }
    }

    sess_id = rap_slab_alloc_locked(shpool, sizeof(rap_ssl_sess_id_t));

    if (sess_id == NULL) {

        /* drop the oldest non-expired session and try once more */

        rap_ssl_expire_sessions(cache, shpool, 0);

        sess_id = rap_slab_alloc_locked(shpool, sizeof(rap_ssl_sess_id_t));

        if (sess_id == NULL) {
            goto failed;
        }
    }

    session_id = (u_char *) SSL_SESSION_get_id(sess, &session_id_length);

#if (RAP_PTR_SIZE == 8)

    id = sess_id->sess_id;

#else

    id = rap_slab_alloc_locked(shpool, session_id_length);

    if (id == NULL) {

        /* drop the oldest non-expired session and try once more */

        rap_ssl_expire_sessions(cache, shpool, 0);

        id = rap_slab_alloc_locked(shpool, session_id_length);

        if (id == NULL) {
            goto failed;
        }
    }

#endif

    rap_memcpy(cached_sess, buf, len);

    rap_memcpy(id, session_id, session_id_length);

    hash = rap_crc32_short(session_id, session_id_length);

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl new session: %08XD:%ud:%d",
                   hash, session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) session_id_length;
    sess_id->id = id;
    sess_id->len = len;
    sess_id->session = cached_sess;

    sess_id->expire = rap_time() + SSL_CTX_get_timeout(ssl_ctx);

    rap_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    rap_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    rap_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (cached_sess) {
        rap_slab_free_locked(shpool, cached_sess);
    }

    if (sess_id) {
        rap_slab_free_locked(shpool, sess_id);
    }

    rap_shmtx_unlock(&shpool->mutex);

    rap_log_error(RAP_LOG_ALERT, c->log, 0,
                  "could not allocate new session%s", shpool->log_ctx);

    return 0;
}


static rap_ssl_session_t *
rap_ssl_get_cached_session(rap_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy)
{
    size_t                    slen;
    uint32_t                  hash;
    rap_int_t                 rc;
    const u_char             *p;
    rap_shm_zone_t           *shm_zone;
    rap_slab_pool_t          *shpool;
    rap_rbtree_node_t        *node, *sentinel;
    rap_ssl_session_t        *sess;
    rap_ssl_sess_id_t        *sess_id;
    rap_ssl_session_cache_t  *cache;
    u_char                    buf[RAP_SSL_MAX_SESSION_SIZE];
    rap_connection_t         *c;

    hash = rap_crc32_short((u_char *) (uintptr_t) id, (size_t) len);
    *copy = 0;

    c = rap_ssl_get_connection(ssl_conn);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl get session: %08XD:%d", hash, len);

    shm_zone = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                                   rap_ssl_session_cache_index);

    cache = shm_zone->data;

    sess = NULL;

    shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    rap_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (rap_ssl_sess_id_t *) node;

        rc = rap_memn2cmp((u_char *) (uintptr_t) id, sess_id->id,
                          (size_t) len, (size_t) node->data);

        if (rc == 0) {

            if (sess_id->expire > rap_time()) {
                slen = sess_id->len;

                rap_memcpy(buf, sess_id->session, slen);

                rap_shmtx_unlock(&shpool->mutex);

                p = buf;
                sess = d2i_SSL_SESSION(NULL, &p, slen);

                return sess;
            }

            rap_queue_remove(&sess_id->queue);

            rap_rbtree_delete(&cache->session_rbtree, node);

            rap_slab_free_locked(shpool, sess_id->session);
#if (RAP_PTR_SIZE == 4)
            rap_slab_free_locked(shpool, sess_id->id);
#endif
            rap_slab_free_locked(shpool, sess_id);

            sess = NULL;

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    rap_shmtx_unlock(&shpool->mutex);

    return sess;
}


void
rap_ssl_remove_cached_session(SSL_CTX *ssl, rap_ssl_session_t *sess)
{
    SSL_CTX_remove_session(ssl, sess);

    rap_ssl_remove_session(ssl, sess);
}


static void
rap_ssl_remove_session(SSL_CTX *ssl, rap_ssl_session_t *sess)
{
    u_char                   *id;
    uint32_t                  hash;
    rap_int_t                 rc;
    unsigned int              len;
    rap_shm_zone_t           *shm_zone;
    rap_slab_pool_t          *shpool;
    rap_rbtree_node_t        *node, *sentinel;
    rap_ssl_sess_id_t        *sess_id;
    rap_ssl_session_cache_t  *cache;

    shm_zone = SSL_CTX_get_ex_data(ssl, rap_ssl_session_cache_index);

    if (shm_zone == NULL) {
        return;
    }

    cache = shm_zone->data;

    id = (u_char *) SSL_SESSION_get_id(sess, &len);

    hash = rap_crc32_short(id, len);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, rap_cycle->log, 0,
                   "ssl remove session: %08XD:%ud", hash, len);

    shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    rap_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (rap_ssl_sess_id_t *) node;

        rc = rap_memn2cmp(id, sess_id->id, len, (size_t) node->data);

        if (rc == 0) {

            rap_queue_remove(&sess_id->queue);

            rap_rbtree_delete(&cache->session_rbtree, node);

            rap_slab_free_locked(shpool, sess_id->session);
#if (RAP_PTR_SIZE == 4)
            rap_slab_free_locked(shpool, sess_id->id);
#endif
            rap_slab_free_locked(shpool, sess_id);

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    rap_shmtx_unlock(&shpool->mutex);
}


static void
rap_ssl_expire_sessions(rap_ssl_session_cache_t *cache,
    rap_slab_pool_t *shpool, rap_uint_t n)
{
    time_t              now;
    rap_queue_t        *q;
    rap_ssl_sess_id_t  *sess_id;

    now = rap_time();

    while (n < 3) {

        if (rap_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = rap_queue_last(&cache->expire_queue);

        sess_id = rap_queue_data(q, rap_ssl_sess_id_t, queue);

        if (n++ != 0 && sess_id->expire > now) {
            return;
        }

        rap_queue_remove(q);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, rap_cycle->log, 0,
                       "expire session: %08Xi", sess_id->node.key);

        rap_rbtree_delete(&cache->session_rbtree, &sess_id->node);

        rap_slab_free_locked(shpool, sess_id->session);
#if (RAP_PTR_SIZE == 4)
        rap_slab_free_locked(shpool, sess_id->id);
#endif
        rap_slab_free_locked(shpool, sess_id);
    }
}


static void
rap_ssl_session_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t  **p;
    rap_ssl_sess_id_t   *sess_id, *sess_id_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sess_id = (rap_ssl_sess_id_t *) node;
            sess_id_temp = (rap_ssl_sess_id_t *) temp;

            p = (rap_memn2cmp(sess_id->id, sess_id_temp->id,
                              (size_t) node->data, (size_t) temp->data)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    rap_rbt_red(node);
}


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

rap_int_t
rap_ssl_session_ticket_keys(rap_conf_t *cf, rap_ssl_t *ssl, rap_array_t *paths)
{
    u_char                         buf[80];
    size_t                         size;
    ssize_t                        n;
    rap_str_t                     *path;
    rap_file_t                     file;
    rap_uint_t                     i;
    rap_array_t                   *keys;
    rap_file_info_t                fi;
    rap_pool_cleanup_t            *cln;
    rap_ssl_session_ticket_key_t  *key;

    if (paths == NULL) {
        return RAP_OK;
    }

    keys = rap_array_create(cf->pool, paths->nelts,
                            sizeof(rap_ssl_session_ticket_key_t));
    if (keys == NULL) {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_session_ticket_keys_cleanup;
    cln->data = keys;

    path = paths->elts;
    for (i = 0; i < paths->nelts; i++) {

        if (rap_conf_full_name(cf->cycle, &path[i], 1) != RAP_OK) {
            return RAP_ERROR;
        }

        rap_memzero(&file, sizeof(rap_file_t));
        file.name = path[i];
        file.log = cf->log;

        file.fd = rap_open_file(file.name.data, RAP_FILE_RDONLY,
                                RAP_FILE_OPEN, 0);

        if (file.fd == RAP_INVALID_FILE) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                               rap_open_file_n " \"%V\" failed", &file.name);
            return RAP_ERROR;
        }

        if (rap_fd_info(file.fd, &fi) == RAP_FILE_ERROR) {
            rap_conf_log_error(RAP_LOG_CRIT, cf, rap_errno,
                               rap_fd_info_n " \"%V\" failed", &file.name);
            goto failed;
        }

        size = rap_file_size(&fi);

        if (size != 48 && size != 80) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"%V\" must be 48 or 80 bytes", &file.name);
            goto failed;
        }

        n = rap_read_file(&file, buf, size, 0);

        if (n == RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_CRIT, cf, rap_errno,
                               rap_read_file_n " \"%V\" failed", &file.name);
            goto failed;
        }

        if ((size_t) n != size) {
            rap_conf_log_error(RAP_LOG_CRIT, cf, 0,
                               rap_read_file_n " \"%V\" returned only "
                               "%z bytes instead of %uz", &file.name, n, size);
            goto failed;
        }

        key = rap_array_push(keys);
        if (key == NULL) {
            goto failed;
        }

        if (size == 48) {
            key->size = 48;
            rap_memcpy(key->name, buf, 16);
            rap_memcpy(key->aes_key, buf + 16, 16);
            rap_memcpy(key->hmac_key, buf + 32, 16);

        } else {
            key->size = 80;
            rap_memcpy(key->name, buf, 16);
            rap_memcpy(key->hmac_key, buf + 16, 32);
            rap_memcpy(key->aes_key, buf + 48, 32);
        }

        if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_close_file_n " \"%V\" failed", &file.name);
        }

        rap_explicit_memzero(&buf, 80);
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, rap_ssl_session_ticket_keys_index, keys)
        == 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return RAP_ERROR;
    }

    if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx,
                                         rap_ssl_session_ticket_key_callback)
        == 0)
    {
        rap_log_error(RAP_LOG_WARN, cf->log, 0,
                      "rap was built with Session Tickets support, however, "
                      "now it is linked dynamically to an OpenSSL library "
                      "which has no tlsext support, therefore Session Tickets "
                      "are not available");
    }

    return RAP_OK;

failed:

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                      rap_close_file_n " \"%V\" failed", &file.name);
    }

    rap_explicit_memzero(&buf, 80);

    return RAP_ERROR;
}


static int
rap_ssl_session_ticket_key_callback(rap_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc)
{
    size_t                         size;
    SSL_CTX                       *ssl_ctx;
    rap_uint_t                     i;
    rap_array_t                   *keys;
    rap_connection_t              *c;
    rap_ssl_session_ticket_key_t  *key;
    const EVP_MD                  *digest;
    const EVP_CIPHER              *cipher;
#if (RAP_DEBUG)
    u_char                         buf[32];
#endif

    c = rap_ssl_get_connection(ssl_conn);
    ssl_ctx = c->ssl->session_ctx;

#ifdef OPENSSL_NO_SHA256
    digest = EVP_sha1();
#else
    digest = EVP_sha256();
#endif

    keys = SSL_CTX_get_ex_data(ssl_ctx, rap_ssl_session_ticket_keys_index);
    if (keys == NULL) {
        return -1;
    }

    key = keys->elts;

    if (enc == 1) {
        /* encrypt session ticket */

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl session ticket encrypt, key: \"%*s\" (%s session)",
                       rap_hex_dump(buf, key[0].name, 16) - buf, buf,
                       SSL_session_reused(ssl_conn) ? "reused" : "new");

        if (key[0].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "RAND_bytes() failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key[0].aes_key, iv) != 1) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0,
                          "EVP_EncryptInit_ex() failed");
            return -1;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL) != 1) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL);
#endif

        rap_memcpy(name, key[0].name, 16);

        return 1;

    } else {
        /* decrypt session ticket */

        for (i = 0; i < keys->nelts; i++) {
            if (rap_memcmp(name, key[i].name, 16) == 0) {
                goto found;
            }
        }

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl session ticket decrypt, key: \"%*s\" not found",
                       rap_hex_dump(buf, name, 16) - buf, buf);

        return 0;

    found:

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl session ticket decrypt, key: \"%*s\"%s",
                       rap_hex_dump(buf, key[i].name, 16) - buf, buf,
                       (i == 0) ? " (default)" : "");

        if (key[i].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL) != 1) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL);
#endif

        if (EVP_DecryptInit_ex(ectx, cipher, NULL, key[i].aes_key, iv) != 1) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0,
                          "EVP_DecryptInit_ex() failed");
            return -1;
        }

        return (i == 0) ? 1 : 2 /* renew */;
    }
}


static void
rap_ssl_session_ticket_keys_cleanup(void *data)
{
    rap_array_t  *keys = data;

    rap_explicit_memzero(keys->elts,
                         keys->nelts * sizeof(rap_ssl_session_ticket_key_t));
}

#else

rap_int_t
rap_ssl_session_ticket_keys(rap_conf_t *cf, rap_ssl_t *ssl, rap_array_t *paths)
{
    if (paths) {
        rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                      "\"ssl_session_ticket_key\" ignored, not supported");
    }

    return RAP_OK;
}

#endif


void
rap_ssl_cleanup_ctx(void *data)
{
    rap_ssl_t  *ssl = data;

    X509  *cert, *next;

    cert = SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index);

    while (cert) {
        next = X509_get_ex_data(cert, rap_ssl_next_certificate_index);
        X509_free(cert);
        cert = next;
    }

    SSL_CTX_free(ssl->ctx);
}


rap_int_t
rap_ssl_check_host(rap_connection_t *c, rap_str_t *name)
{
    X509   *cert;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_ERROR;
    }

#ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT

    /* X509_check_host() is only available in OpenSSL 1.0.2+ */

    if (name->len == 0) {
        goto failed;
    }

    if (X509_check_host(cert, (char *) name->data, name->len, 0, NULL) != 1) {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "X509_check_host(): no match");
        goto failed;
    }

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "X509_check_host(): match");

    goto found;

#else
    {
    int                      n, i;
    X509_NAME               *sname;
    ASN1_STRING             *str;
    X509_NAME_ENTRY         *entry;
    GENERAL_NAME            *altname;
    STACK_OF(GENERAL_NAME)  *altnames;

    /*
     * As per RFC6125 and RFC2818, we check subjectAltName extension,
     * and if it's not present - commonName in Subject is checked.
     */

    altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    if (altnames) {
        n = sk_GENERAL_NAME_num(altnames);

        for (i = 0; i < n; i++) {
            altname = sk_GENERAL_NAME_value(altnames, i);

            if (altname->type != GEN_DNS) {
                continue;
            }

            str = altname->d.dNSName;

            rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL subjectAltName: \"%*s\"",
                           ASN1_STRING_length(str), ASN1_STRING_data(str));

            if (rap_ssl_check_name(name, str) == RAP_OK) {
                rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "SSL subjectAltName: match");
                GENERAL_NAMES_free(altnames);
                goto found;
            }
        }

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL subjectAltName: no match");

        GENERAL_NAMES_free(altnames);
        goto failed;
    }

    /*
     * If there is no subjectAltName extension, check commonName
     * in Subject.  While RFC2818 requires to only check "most specific"
     * CN, both Apache and OpenSSL check all CNs, and so do we.
     */

    sname = X509_get_subject_name(cert);

    if (sname == NULL) {
        goto failed;
    }

    i = -1;
    for ( ;; ) {
        i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);

        if (i < 0) {
            break;
        }

        entry = X509_NAME_get_entry(sname, i);
        str = X509_NAME_ENTRY_get_data(entry);

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL commonName: \"%*s\"",
                       ASN1_STRING_length(str), ASN1_STRING_data(str));

        if (rap_ssl_check_name(name, str) == RAP_OK) {
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL commonName: match");
            goto found;
        }
    }

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL commonName: no match");
    }
#endif

failed:

    X509_free(cert);
    return RAP_ERROR;

found:

    X509_free(cert);
    return RAP_OK;
}


#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT

static rap_int_t
rap_ssl_check_name(rap_str_t *name, ASN1_STRING *pattern)
{
    u_char  *s, *p, *end;
    size_t   slen, plen;

    s = name->data;
    slen = name->len;

    p = ASN1_STRING_data(pattern);
    plen = ASN1_STRING_length(pattern);

    if (slen == plen && rap_strncasecmp(s, p, plen) == 0) {
        return RAP_OK;
    }

    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        plen -= 1;
        p += 1;

        end = s + slen;
        s = rap_strlchr(s, end, '.');

        if (s == NULL) {
            return RAP_ERROR;
        }

        slen = end - s;

        if (plen == slen && rap_strncasecmp(s, p, plen) == 0) {
            return RAP_OK;
        }
    }

    return RAP_ERROR;
}

#endif


rap_int_t
rap_ssl_get_protocol(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    s->data = (u_char *) SSL_get_version(c->ssl->connection);
    return RAP_OK;
}


rap_int_t
rap_ssl_get_cipher_name(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    s->data = (u_char *) SSL_get_cipher_name(c->ssl->connection);
    return RAP_OK;
}


rap_int_t
rap_ssl_get_ciphers(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
#ifdef SSL_CTRL_GET_RAW_CIPHERLIST

    int                n, i, bytes;
    size_t             len;
    u_char            *ciphers, *p;
    const SSL_CIPHER  *cipher;

    bytes = SSL_get0_raw_cipherlist(c->ssl->connection, NULL);
    n = SSL_get0_raw_cipherlist(c->ssl->connection, &ciphers);

    if (n <= 0) {
        s->len = 0;
        return RAP_OK;
    }

    len = 0;
    n /= bytes;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            len += rap_strlen(SSL_CIPHER_get_name(cipher));

        } else {
            len += sizeof("0x") - 1 + bytes * (sizeof("00") - 1);
        }

        len += sizeof(":") - 1;
    }

    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            p = rap_sprintf(p, "%s", SSL_CIPHER_get_name(cipher));

        } else {
            p = rap_sprintf(p, "0x");
            p = rap_hex_dump(p, ciphers + i * bytes, bytes);
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    u_char  buf[4096];

    if (SSL_get_shared_ciphers(c->ssl->connection, (char *) buf, 4096)
        == NULL)
    {
        s->len = 0;
        return RAP_OK;
    }

    s->len = rap_strlen(buf);
    s->data = rap_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->data, buf, s->len);

#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_get_curves(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
#ifdef SSL_CTRL_GET_CURVES

    int         *curves, n, i, nid;
    u_char      *p;
    size_t       len;

    n = SSL_get1_curves(c->ssl->connection, NULL);

    if (n <= 0) {
        s->len = 0;
        return RAP_OK;
    }

    curves = rap_palloc(pool, n * sizeof(int));

    n = SSL_get1_curves(c->ssl->connection, curves);
    len = 0;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            len += sizeof("0x0000") - 1;

        } else {
            len += rap_strlen(OBJ_nid2sn(nid));
        }

        len += sizeof(":") - 1;
    }

    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            p = rap_sprintf(p, "0x%04xd", nid & 0xffff);

        } else {
            p = rap_sprintf(p, "%s", OBJ_nid2sn(nid));
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    s->len = 0;

#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_get_session_id(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    u_char        *buf;
    SSL_SESSION   *sess;
    unsigned int   len;

    sess = SSL_get0_session(c->ssl->connection);
    if (sess == NULL) {
        s->len = 0;
        return RAP_OK;
    }

    buf = (u_char *) SSL_SESSION_get_id(sess, &len);

    s->len = 2 * len;
    s->data = rap_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    rap_hex_dump(s->data, buf, len);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_session_reused(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    if (SSL_session_reused(c->ssl->connection)) {
        rap_str_set(s, "r");

    } else {
        rap_str_set(s, ".");
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_get_early_data(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    s->len = 0;

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    if (SSL_in_early_data(c->ssl->connection)) {
        rap_str_set(s, "1");
    }

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    if (!SSL_is_init_finished(c->ssl->connection)) {
        rap_str_set(s, "1");
    }

#endif

    return RAP_OK;
}


rap_int_t
rap_ssl_get_server_name(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    size_t       len;
    const char  *name;

    name = SSL_get_servername(c->ssl->connection, TLSEXT_NAMETYPE_host_name);

    if (name) {
        len = rap_strlen(name);

        s->len = len;
        s->data = rap_pnalloc(pool, len);
        if (s->data == NULL) {
            return RAP_ERROR;
        }

        rap_memcpy(s->data, name, len);

        return RAP_OK;
    }

#endif

    s->len = 0;
    return RAP_OK;
}


rap_int_t
rap_ssl_get_raw_certificate(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    size_t   len;
    BIO     *bio;
    X509    *cert;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return RAP_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
        goto failed;
    }

    len = BIO_pending(bio);
    s->len = len;

    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, len);

    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return RAP_ERROR;
}


rap_int_t
rap_ssl_get_certificate(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    u_char      *p;
    size_t       len;
    rap_uint_t   i;
    rap_str_t    cert;

    if (rap_ssl_get_raw_certificate(c, pool, &cert) != RAP_OK) {
        return RAP_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return RAP_OK;
    }

    len = cert.len - 1;

    for (i = 0; i < cert.len - 1; i++) {
        if (cert.data[i] == LF) {
            len++;
        }
    }

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    p = s->data;

    for (i = 0; i < cert.len - 1; i++) {
        *p++ = cert.data[i];
        if (cert.data[i] == LF) {
            *p++ = '\t';
        }
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_get_escaped_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s)
{
    rap_str_t  cert;
    uintptr_t  n;

    if (rap_ssl_get_raw_certificate(c, pool, &cert) != RAP_OK) {
        return RAP_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return RAP_OK;
    }

    n = rap_escape_uri(NULL, cert.data, cert.len, RAP_ESCAPE_URI_COMPONENT);

    s->len = cert.len + n * 2;
    s->data = rap_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    rap_escape_uri(s->data, cert.data, cert.len, RAP_ESCAPE_URI_COMPONENT);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_subject_dn(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = rap_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return RAP_ERROR;
}


rap_int_t
rap_ssl_get_issuer_dn(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = rap_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return RAP_ERROR;
}


rap_int_t
rap_ssl_get_subject_dn_legacy(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return RAP_ERROR;
    }

    rap_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_issuer_dn_legacy(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return RAP_ERROR;
    }

    rap_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_serial_number(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    size_t   len;
    X509    *cert;
    BIO     *bio;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
    len = BIO_pending(bio);

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return RAP_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_fingerprint(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    X509          *cert;
    unsigned int   len;
    u_char         buf[EVP_MAX_MD_SIZE];

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    if (!X509_digest(cert, EVP_sha1(), buf, &len)) {
        X509_free(cert);
        return RAP_ERROR;
    }

    s->len = 2 * len;
    s->data = rap_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    rap_hex_dump(s->data, buf, len);

    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_client_verify(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    X509        *cert;
    long         rc;
    const char  *str;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        rap_str_set(s, "NONE");
        return RAP_OK;
    }

    X509_free(cert);

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc == X509_V_OK) {
        rap_str_set(s, "SUCCESS");
        return RAP_OK;
    }

    str = X509_verify_cert_error_string(rc);

    s->data = rap_pnalloc(pool, sizeof("FAILED:") - 1 + rap_strlen(str));
    if (s->data == NULL) {
        return RAP_ERROR;
    }

    s->len = rap_sprintf(s->data, "FAILED:%s", str) - s->data;

    return RAP_OK;
}


rap_int_t
rap_ssl_get_client_v_start(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notBefore(cert));
#else
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return RAP_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_client_v_end(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notAfter(cert));
#else
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = rap_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return RAP_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return RAP_OK;
}


rap_int_t
rap_ssl_get_client_v_remain(rap_connection_t *c, rap_pool_t *pool, rap_str_t *s)
{
    X509    *cert;
    time_t   now, end;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return RAP_OK;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    end = rap_ssl_parse_time(X509_get0_notAfter(cert));
#else
    end = rap_ssl_parse_time(X509_get_notAfter(cert));
#endif

    if (end == (time_t) RAP_ERROR) {
        X509_free(cert);
        return RAP_OK;
    }

    now = rap_time();

    if (end < now + 86400) {
        rap_str_set(s, "0");
        X509_free(cert);
        return RAP_OK;
    }

    s->data = rap_pnalloc(pool, RAP_TIME_T_LEN);
    if (s->data == NULL) {
        X509_free(cert);
        return RAP_ERROR;
    }

    s->len = rap_sprintf(s->data, "%T", (end - now) / 86400) - s->data;

    X509_free(cert);

    return RAP_OK;
}


static time_t
rap_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_TIME
     * into time_t.  To do this, we use ASN1_TIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return RAP_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_TIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = rap_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void *
rap_openssl_create_conf(rap_cycle_t *cycle)
{
    rap_openssl_conf_t  *oscf;

    oscf = rap_pcalloc(cycle->pool, sizeof(rap_openssl_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     oscf->engine = 0;
     */

    return oscf;
}


static char *
rap_openssl_engine(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#ifndef OPENSSL_NO_ENGINE

    rap_openssl_conf_t *oscf = conf;

    ENGINE     *engine;
    rap_str_t  *value;

    if (oscf->engine) {
        return "is duplicate";
    }

    oscf->engine = 1;

    value = cf->args->elts;

    engine = ENGINE_by_id((char *) value[1].data);

    if (engine == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, cf->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, cf->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &value[1]);

        ENGINE_free(engine);

        return RAP_CONF_ERROR;
    }

    ENGINE_free(engine);

    return RAP_CONF_OK;

#else

    return "is not supported";

#endif
}


static void
rap_openssl_exit(rap_cycle_t *cycle)
{
#if OPENSSL_VERSION_NUMBER < 0x10100003L

    EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif

#endif
}
