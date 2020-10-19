
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_OPENSSL_H_INCLUDED_
#define _RAP_EVENT_OPENSSL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define RAP_SSL_NAME     "OpenSSL"


#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
#define OPENSSL_VERSION_NUMBER  0x1010000fL
#else
#define OPENSSL_VERSION_NUMBER  0x1000107fL
#endif
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)

#define rap_ssl_version()       OpenSSL_version(OPENSSL_VERSION)

#else

#define rap_ssl_version()       SSLeay_version(SSLEAY_VERSION)

#endif


#define rap_ssl_session_t       SSL_SESSION
#define rap_ssl_conn_t          SSL


#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
#define SSL_is_server(s)        (s)->server
#endif


struct rap_ssl_s {
    SSL_CTX                    *ctx;
    rap_log_t                  *log;
    size_t                      buffer_size;
};


struct rap_ssl_connection_s {
    rap_ssl_conn_t             *connection;
    SSL_CTX                    *session_ctx;

    rap_int_t                   last;
    rap_buf_t                  *buf;
    size_t                      buffer_size;

    rap_connection_handler_pt   handler;

    rap_ssl_session_t          *session;
    rap_connection_handler_pt   save_session;

    rap_event_handler_pt        saved_read_handler;
    rap_event_handler_pt        saved_write_handler;

    u_char                      early_buf;

    unsigned                    handshaked:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    handshake_buffer_set:1;
    unsigned                    try_early_data:1;
    unsigned                    in_early:1;
    unsigned                    early_preread:1;
    unsigned                    write_blocked:1;
};


#define RAP_SSL_NO_SCACHE            -2
#define RAP_SSL_NONE_SCACHE          -3
#define RAP_SSL_NO_BUILTIN_SCACHE    -4
#define RAP_SSL_DFLT_BUILTIN_SCACHE  -5


#define RAP_SSL_MAX_SESSION_SIZE  4096

typedef struct rap_ssl_sess_id_s  rap_ssl_sess_id_t;

struct rap_ssl_sess_id_s {
    rap_rbtree_node_t           node;
    u_char                     *id;
    size_t                      len;
    u_char                     *session;
    rap_queue_t                 queue;
    time_t                      expire;
#if (RAP_PTR_SIZE == 8)
    void                       *stub;
    u_char                      sess_id[32];
#endif
};


typedef struct {
    rap_rbtree_t                session_rbtree;
    rap_rbtree_node_t           sentinel;
    rap_queue_t                 expire_queue;
} rap_ssl_session_cache_t;


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

typedef struct {
    size_t                      size;
    u_char                      name[16];
    u_char                      hmac_key[32];
    u_char                      aes_key[32];
} rap_ssl_session_ticket_key_t;

#endif


#define RAP_SSL_SSLv2    0x0002
#define RAP_SSL_SSLv3    0x0004
#define RAP_SSL_TLSv1    0x0008
#define RAP_SSL_TLSv1_1  0x0010
#define RAP_SSL_TLSv1_2  0x0020
#define RAP_SSL_TLSv1_3  0x0040


#define RAP_SSL_BUFFER   1
#define RAP_SSL_CLIENT   2

#define RAP_SSL_BUFSIZE  16384


rap_int_t rap_ssl_init(rap_log_t *log);
rap_int_t rap_ssl_create(rap_ssl_t *ssl, rap_uint_t protocols, void *data);

rap_int_t rap_ssl_certificates(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_array_t *certs, rap_array_t *keys, rap_array_t *passwords);
rap_int_t rap_ssl_certificate(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_str_t *cert, rap_str_t *key, rap_array_t *passwords);
rap_int_t rap_ssl_connection_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *cert, rap_str_t *key, rap_array_t *passwords);

rap_int_t rap_ssl_ciphers(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *ciphers,
    rap_uint_t prefer_server_ciphers);
rap_int_t rap_ssl_client_certificate(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_str_t *cert, rap_int_t depth);
rap_int_t rap_ssl_trusted_certificate(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_str_t *cert, rap_int_t depth);
rap_int_t rap_ssl_crl(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *crl);
rap_int_t rap_ssl_stapling(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_str_t *file, rap_str_t *responder, rap_uint_t verify);
rap_int_t rap_ssl_stapling_resolver(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_resolver_t *resolver, rap_msec_t resolver_timeout);
RSA *rap_ssl_rsa512_key_callback(rap_ssl_conn_t *ssl_conn, int is_export,
    int key_length);
rap_array_t *rap_ssl_read_password_file(rap_conf_t *cf, rap_str_t *file);
rap_array_t *rap_ssl_preserve_passwords(rap_conf_t *cf,
    rap_array_t *passwords);
rap_int_t rap_ssl_dhparam(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *file);
rap_int_t rap_ssl_ecdh_curve(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *name);
rap_int_t rap_ssl_early_data(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_uint_t enable);
rap_int_t rap_ssl_client_session_cache(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_uint_t enable);
rap_int_t rap_ssl_session_cache(rap_ssl_t *ssl, rap_str_t *sess_ctx,
    rap_array_t *certificates, ssize_t builtin_session_cache,
    rap_shm_zone_t *shm_zone, time_t timeout);
rap_int_t rap_ssl_session_ticket_keys(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_array_t *paths);
rap_int_t rap_ssl_session_cache_init(rap_shm_zone_t *shm_zone, void *data);
rap_int_t rap_ssl_create_connection(rap_ssl_t *ssl, rap_connection_t *c,
    rap_uint_t flags);

void rap_ssl_remove_cached_session(SSL_CTX *ssl, rap_ssl_session_t *sess);
rap_int_t rap_ssl_set_session(rap_connection_t *c, rap_ssl_session_t *session);
rap_ssl_session_t *rap_ssl_get_session(rap_connection_t *c);
rap_ssl_session_t *rap_ssl_get0_session(rap_connection_t *c);
#define rap_ssl_free_session        SSL_SESSION_free
#define rap_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, rap_ssl_connection_index)
#define rap_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, rap_ssl_server_conf_index)

#define rap_ssl_verify_error_optional(n)                                      \
    (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
     || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
     || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
     || n == X509_V_ERR_CERT_UNTRUSTED                                        \
     || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)

rap_int_t rap_ssl_check_host(rap_connection_t *c, rap_str_t *name);


rap_int_t rap_ssl_get_protocol(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_cipher_name(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_ciphers(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_curves(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_session_id(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_session_reused(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_early_data(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_server_name(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_raw_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_escaped_certificate(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_subject_dn(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_issuer_dn(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_subject_dn_legacy(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_issuer_dn_legacy(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_serial_number(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_fingerprint(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_client_verify(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_client_v_start(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_client_v_end(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);
rap_int_t rap_ssl_get_client_v_remain(rap_connection_t *c, rap_pool_t *pool,
    rap_str_t *s);


rap_int_t rap_ssl_handshake(rap_connection_t *c);
ssize_t rap_ssl_recv(rap_connection_t *c, u_char *buf, size_t size);
ssize_t rap_ssl_write(rap_connection_t *c, u_char *data, size_t size);
ssize_t rap_ssl_recv_chain(rap_connection_t *c, rap_chain_t *cl, off_t limit);
rap_chain_t *rap_ssl_send_chain(rap_connection_t *c, rap_chain_t *in,
    off_t limit);
void rap_ssl_free_buffer(rap_connection_t *c);
rap_int_t rap_ssl_shutdown(rap_connection_t *c);
void rap_cdecl rap_ssl_error(rap_uint_t level, rap_log_t *log, rap_err_t err,
    char *fmt, ...);
void rap_ssl_cleanup_ctx(void *data);


extern int  rap_ssl_connection_index;
extern int  rap_ssl_server_conf_index;
extern int  rap_ssl_session_cache_index;
extern int  rap_ssl_session_ticket_keys_index;
extern int  rap_ssl_certificate_index;
extern int  rap_ssl_next_certificate_index;
extern int  rap_ssl_certificate_name_index;
extern int  rap_ssl_stapling_index;


#endif /* _RAP_EVENT_OPENSSL_H_INCLUDED_ */
