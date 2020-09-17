
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_OPENSSL_H_INCLUDED_
#define _RP_EVENT_OPENSSL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>

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

#define RP_SSL_NAME     "OpenSSL"


#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
#define OPENSSL_VERSION_NUMBER  0x1010000fL
#else
#define OPENSSL_VERSION_NUMBER  0x1000107fL
#endif
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)

#define rp_ssl_version()       OpenSSL_version(OPENSSL_VERSION)

#else

#define rp_ssl_version()       SSLeay_version(SSLEAY_VERSION)

#endif


#define rp_ssl_session_t       SSL_SESSION
#define rp_ssl_conn_t          SSL


#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
#define SSL_is_server(s)        (s)->server
#endif


struct rp_ssl_s {
    SSL_CTX                    *ctx;
    rp_log_t                  *log;
    size_t                      buffer_size;
};


struct rp_ssl_connection_s {
    rp_ssl_conn_t             *connection;
    SSL_CTX                    *session_ctx;

    rp_int_t                   last;
    rp_buf_t                  *buf;
    size_t                      buffer_size;

    rp_connection_handler_pt   handler;

    rp_ssl_session_t          *session;
    rp_connection_handler_pt   save_session;

    rp_event_handler_pt        saved_read_handler;
    rp_event_handler_pt        saved_write_handler;

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


#define RP_SSL_NO_SCACHE            -2
#define RP_SSL_NONE_SCACHE          -3
#define RP_SSL_NO_BUILTIN_SCACHE    -4
#define RP_SSL_DFLT_BUILTIN_SCACHE  -5


#define RP_SSL_MAX_SESSION_SIZE  4096

typedef struct rp_ssl_sess_id_s  rp_ssl_sess_id_t;

struct rp_ssl_sess_id_s {
    rp_rbtree_node_t           node;
    u_char                     *id;
    size_t                      len;
    u_char                     *session;
    rp_queue_t                 queue;
    time_t                      expire;
#if (RP_PTR_SIZE == 8)
    void                       *stub;
    u_char                      sess_id[32];
#endif
};


typedef struct {
    rp_rbtree_t                session_rbtree;
    rp_rbtree_node_t           sentinel;
    rp_queue_t                 expire_queue;
} rp_ssl_session_cache_t;


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

typedef struct {
    size_t                      size;
    u_char                      name[16];
    u_char                      hmac_key[32];
    u_char                      aes_key[32];
} rp_ssl_session_ticket_key_t;

#endif


#define RP_SSL_SSLv2    0x0002
#define RP_SSL_SSLv3    0x0004
#define RP_SSL_TLSv1    0x0008
#define RP_SSL_TLSv1_1  0x0010
#define RP_SSL_TLSv1_2  0x0020
#define RP_SSL_TLSv1_3  0x0040


#define RP_SSL_BUFFER   1
#define RP_SSL_CLIENT   2

#define RP_SSL_BUFSIZE  16384


rp_int_t rp_ssl_init(rp_log_t *log);
rp_int_t rp_ssl_create(rp_ssl_t *ssl, rp_uint_t protocols, void *data);

rp_int_t rp_ssl_certificates(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_array_t *certs, rp_array_t *keys, rp_array_t *passwords);
rp_int_t rp_ssl_certificate(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_str_t *cert, rp_str_t *key, rp_array_t *passwords);
rp_int_t rp_ssl_connection_certificate(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *cert, rp_str_t *key, rp_array_t *passwords);

rp_int_t rp_ssl_ciphers(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *ciphers,
    rp_uint_t prefer_server_ciphers);
rp_int_t rp_ssl_client_certificate(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_str_t *cert, rp_int_t depth);
rp_int_t rp_ssl_trusted_certificate(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_str_t *cert, rp_int_t depth);
rp_int_t rp_ssl_crl(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *crl);
rp_int_t rp_ssl_stapling(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_str_t *file, rp_str_t *responder, rp_uint_t verify);
rp_int_t rp_ssl_stapling_resolver(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_resolver_t *resolver, rp_msec_t resolver_timeout);
RSA *rp_ssl_rsa512_key_callback(rp_ssl_conn_t *ssl_conn, int is_export,
    int key_length);
rp_array_t *rp_ssl_read_password_file(rp_conf_t *cf, rp_str_t *file);
rp_array_t *rp_ssl_preserve_passwords(rp_conf_t *cf,
    rp_array_t *passwords);
rp_int_t rp_ssl_dhparam(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *file);
rp_int_t rp_ssl_ecdh_curve(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *name);
rp_int_t rp_ssl_early_data(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_uint_t enable);
rp_int_t rp_ssl_client_session_cache(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_uint_t enable);
rp_int_t rp_ssl_session_cache(rp_ssl_t *ssl, rp_str_t *sess_ctx,
    rp_array_t *certificates, ssize_t builtin_session_cache,
    rp_shm_zone_t *shm_zone, time_t timeout);
rp_int_t rp_ssl_session_ticket_keys(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_array_t *paths);
rp_int_t rp_ssl_session_cache_init(rp_shm_zone_t *shm_zone, void *data);
rp_int_t rp_ssl_create_connection(rp_ssl_t *ssl, rp_connection_t *c,
    rp_uint_t flags);

void rp_ssl_remove_cached_session(SSL_CTX *ssl, rp_ssl_session_t *sess);
rp_int_t rp_ssl_set_session(rp_connection_t *c, rp_ssl_session_t *session);
rp_ssl_session_t *rp_ssl_get_session(rp_connection_t *c);
rp_ssl_session_t *rp_ssl_get0_session(rp_connection_t *c);
#define rp_ssl_free_session        SSL_SESSION_free
#define rp_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, rp_ssl_connection_index)
#define rp_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, rp_ssl_server_conf_index)

#define rp_ssl_verify_error_optional(n)                                      \
    (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
     || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
     || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
     || n == X509_V_ERR_CERT_UNTRUSTED                                        \
     || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)

rp_int_t rp_ssl_check_host(rp_connection_t *c, rp_str_t *name);


rp_int_t rp_ssl_get_protocol(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_cipher_name(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_ciphers(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_curves(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_session_id(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_session_reused(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_early_data(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_server_name(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_raw_certificate(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_certificate(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_escaped_certificate(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_subject_dn(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_issuer_dn(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_subject_dn_legacy(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_issuer_dn_legacy(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_serial_number(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_fingerprint(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_client_verify(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_client_v_start(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_client_v_end(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);
rp_int_t rp_ssl_get_client_v_remain(rp_connection_t *c, rp_pool_t *pool,
    rp_str_t *s);


rp_int_t rp_ssl_handshake(rp_connection_t *c);
ssize_t rp_ssl_recv(rp_connection_t *c, u_char *buf, size_t size);
ssize_t rp_ssl_write(rp_connection_t *c, u_char *data, size_t size);
ssize_t rp_ssl_recv_chain(rp_connection_t *c, rp_chain_t *cl, off_t limit);
rp_chain_t *rp_ssl_send_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);
void rp_ssl_free_buffer(rp_connection_t *c);
rp_int_t rp_ssl_shutdown(rp_connection_t *c);
void rp_cdecl rp_ssl_error(rp_uint_t level, rp_log_t *log, rp_err_t err,
    char *fmt, ...);
void rp_ssl_cleanup_ctx(void *data);


extern int  rp_ssl_connection_index;
extern int  rp_ssl_server_conf_index;
extern int  rp_ssl_session_cache_index;
extern int  rp_ssl_session_ticket_keys_index;
extern int  rp_ssl_certificate_index;
extern int  rp_ssl_next_certificate_index;
extern int  rp_ssl_certificate_name_index;
extern int  rp_ssl_stapling_index;


#endif /* _RP_EVENT_OPENSSL_H_INCLUDED_ */
