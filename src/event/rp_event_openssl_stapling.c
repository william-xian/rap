
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_event_connect.h>


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)


typedef struct {
    rp_str_t                    staple;
    rp_msec_t                   timeout;

    rp_resolver_t              *resolver;
    rp_msec_t                   resolver_timeout;

    rp_addr_t                  *addrs;
    rp_str_t                    host;
    rp_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;

    u_char                      *name;

    time_t                       valid;
    time_t                       refresh;

    unsigned                     verify:1;
    unsigned                     loading:1;
} rp_ssl_stapling_t;


typedef struct rp_ssl_ocsp_ctx_s  rp_ssl_ocsp_ctx_t;

struct rp_ssl_ocsp_ctx_s {
    X509                        *cert;
    X509                        *issuer;

    u_char                      *name;

    rp_uint_t                   naddrs;

    rp_addr_t                  *addrs;
    rp_str_t                    host;
    rp_str_t                    uri;
    in_port_t                    port;

    rp_resolver_t              *resolver;
    rp_msec_t                   resolver_timeout;

    rp_msec_t                   timeout;

    void                       (*handler)(rp_ssl_ocsp_ctx_t *ctx);
    void                        *data;

    rp_buf_t                   *request;
    rp_buf_t                   *response;
    rp_peer_connection_t        peer;

    rp_int_t                  (*process)(rp_ssl_ocsp_ctx_t *ctx);

    rp_uint_t                   state;

    rp_uint_t                   code;
    rp_uint_t                   count;

    rp_uint_t                   done;

    u_char                      *header_name_start;
    u_char                      *header_name_end;
    u_char                      *header_start;
    u_char                      *header_end;

    rp_pool_t                  *pool;
    rp_log_t                   *log;
};


static rp_int_t rp_ssl_stapling_certificate(rp_conf_t *cf, rp_ssl_t *ssl,
    X509 *cert, rp_str_t *file, rp_str_t *responder, rp_uint_t verify);
static rp_int_t rp_ssl_stapling_file(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple, rp_str_t *file);
static rp_int_t rp_ssl_stapling_issuer(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple);
static rp_int_t rp_ssl_stapling_responder(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple, rp_str_t *responder);

static int rp_ssl_certificate_status_callback(rp_ssl_conn_t *ssl_conn,
    void *data);
static void rp_ssl_stapling_update(rp_ssl_stapling_t *staple);
static void rp_ssl_stapling_ocsp_handler(rp_ssl_ocsp_ctx_t *ctx);

static time_t rp_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time);

static void rp_ssl_stapling_cleanup(void *data);

static rp_ssl_ocsp_ctx_t *rp_ssl_ocsp_start(void);
static void rp_ssl_ocsp_done(rp_ssl_ocsp_ctx_t *ctx);
static void rp_ssl_ocsp_request(rp_ssl_ocsp_ctx_t *ctx);
static void rp_ssl_ocsp_resolve_handler(rp_resolver_ctx_t *resolve);
static void rp_ssl_ocsp_connect(rp_ssl_ocsp_ctx_t *ctx);
static void rp_ssl_ocsp_write_handler(rp_event_t *wev);
static void rp_ssl_ocsp_read_handler(rp_event_t *rev);
static void rp_ssl_ocsp_dummy_handler(rp_event_t *ev);

static rp_int_t rp_ssl_ocsp_create_request(rp_ssl_ocsp_ctx_t *ctx);
static rp_int_t rp_ssl_ocsp_process_status_line(rp_ssl_ocsp_ctx_t *ctx);
static rp_int_t rp_ssl_ocsp_parse_status_line(rp_ssl_ocsp_ctx_t *ctx);
static rp_int_t rp_ssl_ocsp_process_headers(rp_ssl_ocsp_ctx_t *ctx);
static rp_int_t rp_ssl_ocsp_parse_header_line(rp_ssl_ocsp_ctx_t *ctx);
static rp_int_t rp_ssl_ocsp_process_body(rp_ssl_ocsp_ctx_t *ctx);

static u_char *rp_ssl_ocsp_log_error(rp_log_t *log, u_char *buf, size_t len);


rp_int_t
rp_ssl_stapling(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *file,
    rp_str_t *responder, rp_uint_t verify)
{
    X509  *cert;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, rp_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, rp_ssl_next_certificate_index))
    {
        if (rp_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    SSL_CTX_set_tlsext_status_cb(ssl->ctx, rp_ssl_certificate_status_callback);

    return RP_OK;
}


static rp_int_t
rp_ssl_stapling_certificate(rp_conf_t *cf, rp_ssl_t *ssl, X509 *cert,
    rp_str_t *file, rp_str_t *responder, rp_uint_t verify)
{
    rp_int_t            rc;
    rp_pool_cleanup_t  *cln;
    rp_ssl_stapling_t  *staple;

    staple = rp_pcalloc(cf->pool, sizeof(rp_ssl_stapling_t));
    if (staple == NULL) {
        return RP_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RP_ERROR;
    }

    cln->handler = rp_ssl_stapling_cleanup;
    cln->data = staple;

    if (X509_set_ex_data(cert, rp_ssl_stapling_index, staple) == 0) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        return RP_ERROR;
    }

    staple->ssl_ctx = ssl->ctx;
    staple->timeout = 60000;
    staple->verify = verify;
    staple->cert = cert;
    staple->name = X509_get_ex_data(staple->cert,
                                    rp_ssl_certificate_name_index);

    if (file->len) {
        /* use OCSP response from the file */

        if (rp_ssl_stapling_file(cf, ssl, staple, file) != RP_OK) {
            return RP_ERROR;
        }

        return RP_OK;
    }

    rc = rp_ssl_stapling_issuer(cf, ssl, staple);

    if (rc == RP_DECLINED) {
        return RP_OK;
    }

    if (rc != RP_OK) {
        return RP_ERROR;
    }

    rc = rp_ssl_stapling_responder(cf, ssl, staple, responder);

    if (rc == RP_DECLINED) {
        return RP_OK;
    }

    if (rc != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}


static rp_int_t
rp_ssl_stapling_file(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple, rp_str_t *file)
{
    BIO            *bio;
    int             len;
    u_char         *p, *buf;
    OCSP_RESPONSE  *response;

    if (rp_conf_full_name(cf->cycle, file, 1) != RP_OK) {
        return RP_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "rb");
    if (bio == NULL) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return RP_ERROR;
    }

    response = d2i_OCSP_RESPONSE_bio(bio, NULL);
    if (response == NULL) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "d2i_OCSP_RESPONSE_bio(\"%s\") failed", file->data);
        BIO_free(bio);
        return RP_ERROR;
    }

    len = i2d_OCSP_RESPONSE(response, NULL);
    if (len <= 0) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        goto failed;
    }

    buf = rp_alloc(len, ssl->log);
    if (buf == NULL) {
        goto failed;
    }

    p = buf;
    len = i2d_OCSP_RESPONSE(response, &p);
    if (len <= 0) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        rp_free(buf);
        goto failed;
    }

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    staple->staple.data = buf;
    staple->staple.len = len;
    staple->valid = RP_MAX_TIME_T_VALUE;

    return RP_OK;

failed:

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    return RP_ERROR;
}


static rp_int_t
rp_ssl_stapling_issuer(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple)
{
    int              i, n, rc;
    X509            *cert, *issuer;
    X509_STORE      *store;
    X509_STORE_CTX  *store_ctx;
    STACK_OF(X509)  *chain;

    cert = staple->cert;

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(ssl->ctx, cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(ssl->ctx, &chain);
#else
    chain = ssl->ctx->extra_certs;
#endif

    n = sk_X509_num(chain);

    rp_log_debug1(RP_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: %d extra certs", n);

    for (i = 0; i < n; i++) {
        issuer = sk_X509_value(chain, i);
        if (X509_check_issued(issuer, cert) == X509_V_OK) {
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
            X509_up_ref(issuer);
#else
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#endif

            rp_log_debug1(RP_LOG_DEBUG_EVENT, ssl->log, 0,
                           "SSL get issuer: found %p in extra certs", issuer);

            staple->issuer = issuer;

            return RP_OK;
        }
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);
    if (store == NULL) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return RP_ERROR;
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_new() failed");
        return RP_ERROR;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(store_ctx);
        return RP_ERROR;
    }

    rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);

    if (rc == -1) {
        rp_ssl_error(RP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_get1_issuer() failed");
        X509_STORE_CTX_free(store_ctx);
        return RP_ERROR;
    }

    if (rc == 0) {
        rp_log_error(RP_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "issuer certificate not found for certificate \"%s\"",
                      staple->name);
        X509_STORE_CTX_free(store_ctx);
        return RP_DECLINED;
    }

    X509_STORE_CTX_free(store_ctx);

    rp_log_debug1(RP_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: found %p in cert store", issuer);

    staple->issuer = issuer;

    return RP_OK;
}


static rp_int_t
rp_ssl_stapling_responder(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_ssl_stapling_t *staple, rp_str_t *responder)
{
    char                      *s;
    rp_str_t                  rsp;
    rp_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (responder->len == 0) {

        /* extract OCSP responder URL from certificate */

        aia = X509_get1_ocsp(staple->cert);
        if (aia == NULL) {
            rp_log_error(RP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            return RP_DECLINED;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        s = sk_OPENSSL_STRING_value(aia, 0);
#else
        s = sk_value(aia, 0);
#endif
        if (s == NULL) {
            rp_log_error(RP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            X509_email_free(aia);
            return RP_DECLINED;
        }

        responder = &rsp;

        responder->len = rp_strlen(s);
        responder->data = rp_palloc(cf->pool, responder->len);
        if (responder->data == NULL) {
            X509_email_free(aia);
            return RP_ERROR;
        }

        rp_memcpy(responder->data, s, responder->len);
        X509_email_free(aia);
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = *responder;
    u.default_port = 80;
    u.uri_part = 1;

    if (u.url.len > 7
        && rp_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        rp_log_error(RP_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in the certificate \"%s\"",
                      &u.url, staple->name);
        return RP_DECLINED;
    }

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_log_error(RP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "%s in OCSP responder \"%V\" "
                          "in the certificate \"%s\"",
                          u.err, &u.url, staple->name);
            return RP_DECLINED;
        }

        return RP_ERROR;
    }

    staple->addrs = u.addrs;
    staple->host = u.host;
    staple->uri = u.uri;
    staple->port = u.port;

    if (staple->uri.len == 0) {
        rp_str_set(&staple->uri, "/");
    }

    return RP_OK;
}


rp_int_t
rp_ssl_stapling_resolver(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_resolver_t *resolver, rp_msec_t resolver_timeout)
{
    X509                *cert;
    rp_ssl_stapling_t  *staple;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, rp_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, rp_ssl_next_certificate_index))
    {
        staple = X509_get_ex_data(cert, rp_ssl_stapling_index);
        staple->resolver = resolver;
        staple->resolver_timeout = resolver_timeout;
    }

    return RP_OK;
}


static int
rp_ssl_certificate_status_callback(rp_ssl_conn_t *ssl_conn, void *data)
{
    int                  rc;
    X509                *cert;
    u_char              *p;
    rp_connection_t    *c;
    rp_ssl_stapling_t  *staple;

    c = rp_ssl_get_connection(ssl_conn);

    rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL certificate status callback");

    rc = SSL_TLSEXT_ERR_NOACK;

    cert = SSL_get_certificate(ssl_conn);

    if (cert == NULL) {
        return rc;
    }

    staple = X509_get_ex_data(cert, rp_ssl_stapling_index);

    if (staple == NULL) {
        return rc;
    }

    if (staple->staple.len
        && staple->valid >= rp_time())
    {
        /* we have to copy ocsp response as OpenSSL will free it by itself */

        p = OPENSSL_malloc(staple->staple.len);
        if (p == NULL) {
            rp_ssl_error(RP_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
            return SSL_TLSEXT_ERR_NOACK;
        }

        rp_memcpy(p, staple->staple.data, staple->staple.len);

        SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->staple.len);

        rc = SSL_TLSEXT_ERR_OK;
    }

    rp_ssl_stapling_update(staple);

    return rc;
}


static void
rp_ssl_stapling_update(rp_ssl_stapling_t *staple)
{
    rp_ssl_ocsp_ctx_t  *ctx;

    if (staple->host.len == 0
        || staple->loading || staple->refresh >= rp_time())
    {
        return;
    }

    staple->loading = 1;

    ctx = rp_ssl_ocsp_start();
    if (ctx == NULL) {
        return;
    }

    ctx->cert = staple->cert;
    ctx->issuer = staple->issuer;
    ctx->name = staple->name;

    ctx->addrs = staple->addrs;
    ctx->host = staple->host;
    ctx->uri = staple->uri;
    ctx->port = staple->port;
    ctx->timeout = staple->timeout;

    ctx->resolver = staple->resolver;
    ctx->resolver_timeout = staple->resolver_timeout;

    ctx->handler = rp_ssl_stapling_ocsp_handler;
    ctx->data = staple;

    rp_ssl_ocsp_request(ctx);

    return;
}


static void
rp_ssl_stapling_ocsp_handler(rp_ssl_ocsp_ctx_t *ctx)
{
    int                    n;
    size_t                 len;
    time_t                 now, valid;
    rp_str_t              response;
    X509_STORE            *store;
    const u_char          *p;
    STACK_OF(X509)        *chain;
    OCSP_CERTID           *id;
    OCSP_RESPONSE         *ocsp;
    OCSP_BASICRESP        *basic;
    rp_ssl_stapling_t    *staple;
    ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;

    staple = ctx->data;
    now = rp_time();
    ocsp = NULL;
    basic = NULL;
    id = NULL;

    if (ctx->code != 200) {
        goto error;
    }

    /* check the response */

    len = ctx->response->last - ctx->response->pos;
    p = ctx->response->pos;

    ocsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (ocsp == NULL) {
        rp_ssl_error(RP_LOG_ERR, ctx->log, 0,
                      "d2i_OCSP_RESPONSE() failed");
        goto error;
    }

    n = OCSP_response_status(ocsp);

    if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        rp_log_error(RP_LOG_ERR, ctx->log, 0,
                      "OCSP response not successful (%d: %s)",
                      n, OCSP_response_status_str(n));
        goto error;
    }

    basic = OCSP_response_get1_basic(ocsp);
    if (basic == NULL) {
        rp_ssl_error(RP_LOG_ERR, ctx->log, 0,
                      "OCSP_response_get1_basic() failed");
        goto error;
    }

    store = SSL_CTX_get_cert_store(staple->ssl_ctx);
    if (store == NULL) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        goto error;
    }

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(staple->ssl_ctx, ctx->cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(staple->ssl_ctx, &chain);
#else
    chain = staple->ssl_ctx->extra_certs;
#endif

    if (OCSP_basic_verify(basic, chain, store,
                          staple->verify ? OCSP_TRUSTOTHER : OCSP_NOVERIFY)
        != 1)
    {
        rp_ssl_error(RP_LOG_ERR, ctx->log, 0,
                      "OCSP_basic_verify() failed");
        goto error;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto error;
    }

    if (OCSP_resp_find_status(basic, id, &n, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        rp_log_error(RP_LOG_ERR, ctx->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }

    if (n != V_OCSP_CERTSTATUS_GOOD) {
        rp_log_error(RP_LOG_ERR, ctx->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(n));
        goto error;
    }

    if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
        rp_ssl_error(RP_LOG_ERR, ctx->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        valid = rp_ssl_stapling_time(nextupdate);
        if (valid == (time_t) RP_ERROR) {
            rp_log_error(RP_LOG_ERR, ctx->log, 0,
                          "invalid nextUpdate time in certificate status");
            goto error;
        }

    } else {
        valid = RP_MAX_TIME_T_VALUE;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(ocsp);

    id = NULL;
    basic = NULL;
    ocsp = NULL;

    /* copy the response to memory not in ctx->pool */

    response.len = len;
    response.data = rp_alloc(response.len, ctx->log);

    if (response.data == NULL) {
        goto error;
    }

    rp_memcpy(response.data, ctx->response->pos, response.len);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp response, %s, %uz",
                   OCSP_cert_status_str(n), response.len);

    if (staple->staple.data) {
        rp_free(staple->staple.data);
    }

    staple->staple = response;
    staple->valid = valid;

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple->loading = 0;
    staple->refresh = rp_max(rp_min(valid - 300, now + 3600), now + 300);

    rp_ssl_ocsp_done(ctx);
    return;

error:

    staple->loading = 0;
    staple->refresh = now + 300;

    if (id) {
        OCSP_CERTID_free(id);
    }

    if (basic) {
        OCSP_BASICRESP_free(basic);
    }

    if (ocsp) {
        OCSP_RESPONSE_free(ocsp);
    }

    rp_ssl_ocsp_done(ctx);
}


static time_t
rp_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_GENERALIZEDTIME
     * into time_t.  To do this, we use ASN1_GENERALIZEDTIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return RP_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_GENERALIZEDTIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = rp_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void
rp_ssl_stapling_cleanup(void *data)
{
    rp_ssl_stapling_t  *staple = data;

    if (staple->issuer) {
        X509_free(staple->issuer);
    }

    if (staple->staple.data) {
        rp_free(staple->staple.data);
    }
}


static rp_ssl_ocsp_ctx_t *
rp_ssl_ocsp_start(void)
{
    rp_log_t           *log;
    rp_pool_t          *pool;
    rp_ssl_ocsp_ctx_t  *ctx;

    pool = rp_create_pool(2048, rp_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    ctx = rp_pcalloc(pool, sizeof(rp_ssl_ocsp_ctx_t));
    if (ctx == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    log = rp_palloc(pool, sizeof(rp_log_t));
    if (log == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    ctx->pool = pool;

    *log = *ctx->pool->log;

    ctx->pool->log = log;
    ctx->log = log;

    log->handler = rp_ssl_ocsp_log_error;
    log->data = ctx;
    log->action = "requesting certificate status";

    return ctx;
}


static void
rp_ssl_ocsp_done(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp done");

    if (ctx->peer.connection) {
        rp_close_connection(ctx->peer.connection);
    }

    rp_destroy_pool(ctx->pool);
}


static void
rp_ssl_ocsp_error(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp error");

    ctx->code = 0;
    ctx->handler(ctx);
}


static void
rp_ssl_ocsp_request(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_resolver_ctx_t  *resolve, temp;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request");

    if (rp_ssl_ocsp_create_request(ctx) != RP_OK) {
        rp_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->resolver) {
        /* resolve OCSP responder hostname */

        temp.name = ctx->host;

        resolve = rp_resolve_start(ctx->resolver, &temp);
        if (resolve == NULL) {
            rp_ssl_ocsp_error(ctx);
            return;
        }

        if (resolve == RP_NO_RESOLVER) {
            rp_log_error(RP_LOG_WARN, ctx->log, 0,
                          "no resolver defined to resolve %V", &ctx->host);
            goto connect;
        }

        resolve->name = ctx->host;
        resolve->handler = rp_ssl_ocsp_resolve_handler;
        resolve->data = ctx;
        resolve->timeout = ctx->resolver_timeout;

        if (rp_resolve_name(resolve) != RP_OK) {
            rp_ssl_ocsp_error(ctx);
            return;
        }

        return;
    }

connect:

    rp_ssl_ocsp_connect(ctx);
}


static void
rp_ssl_ocsp_resolve_handler(rp_resolver_ctx_t *resolve)
{
    rp_ssl_ocsp_ctx_t *ctx = resolve->data;

    u_char           *p;
    size_t            len;
    socklen_t         socklen;
    rp_uint_t        i;
    struct sockaddr  *sockaddr;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp resolve handler");

    if (resolve->state) {
        rp_log_error(RP_LOG_ERR, ctx->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &resolve->name, resolve->state,
                      rp_resolver_strerror(resolve->state));
        goto failed;
    }

#if (RP_DEBUG)
    {
    u_char     text[RP_SOCKADDR_STRLEN];
    rp_str_t  addr;

    addr.data = text;

    for (i = 0; i < resolve->naddrs; i++) {
        addr.len = rp_sock_ntop(resolve->addrs[i].sockaddr,
                                 resolve->addrs[i].socklen,
                                 text, RP_SOCKADDR_STRLEN, 0);

        rp_log_debug1(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                       "name was resolved to %V", &addr);

    }
    }
#endif

    ctx->naddrs = resolve->naddrs;
    ctx->addrs = rp_pcalloc(ctx->pool, ctx->naddrs * sizeof(rp_addr_t));

    if (ctx->addrs == NULL) {
        goto failed;
    }

    for (i = 0; i < resolve->naddrs; i++) {

        socklen = resolve->addrs[i].socklen;

        sockaddr = rp_palloc(ctx->pool, socklen);
        if (sockaddr == NULL) {
            goto failed;
        }

        rp_memcpy(sockaddr, resolve->addrs[i].sockaddr, socklen);
        rp_inet_set_port(sockaddr, ctx->port);

        ctx->addrs[i].sockaddr = sockaddr;
        ctx->addrs[i].socklen = socklen;

        p = rp_pnalloc(ctx->pool, RP_SOCKADDR_STRLEN);
        if (p == NULL) {
            goto failed;
        }

        len = rp_sock_ntop(sockaddr, socklen, p, RP_SOCKADDR_STRLEN, 1);

        ctx->addrs[i].name.len = len;
        ctx->addrs[i].name.data = p;
    }

    rp_resolve_name_done(resolve);

    rp_ssl_ocsp_connect(ctx);
    return;

failed:

    rp_resolve_name_done(resolve);
    rp_ssl_ocsp_error(ctx);
}


static void
rp_ssl_ocsp_connect(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_int_t  rc;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect");

    /* TODO: use all ip addresses */

    ctx->peer.sockaddr = ctx->addrs[0].sockaddr;
    ctx->peer.socklen = ctx->addrs[0].socklen;
    ctx->peer.name = &ctx->addrs[0].name;
    ctx->peer.get = rp_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = RP_ERROR_ERR;

    rc = rp_event_connect_peer(&ctx->peer);

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect peer done");

    if (rc == RP_ERROR || rc == RP_BUSY || rc == RP_DECLINED) {
        rp_ssl_ocsp_error(ctx);
        return;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;

    ctx->peer.connection->read->handler = rp_ssl_ocsp_read_handler;
    ctx->peer.connection->write->handler = rp_ssl_ocsp_write_handler;

    ctx->process = rp_ssl_ocsp_process_status_line;

    rp_add_timer(ctx->peer.connection->read, ctx->timeout);
    rp_add_timer(ctx->peer.connection->write, ctx->timeout);

    if (rc == RP_OK) {
        rp_ssl_ocsp_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
rp_ssl_ocsp_write_handler(rp_event_t *wev)
{
    ssize_t              n, size;
    rp_connection_t    *c;
    rp_ssl_ocsp_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, wev->log, 0,
                   "ssl ocsp write handler");

    if (wev->timedout) {
        rp_log_error(RP_LOG_ERR, wev->log, RP_ETIMEDOUT,
                      "OCSP responder timed out");
        rp_ssl_ocsp_error(ctx);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = rp_send(c, ctx->request->pos, size);

    if (n == RP_ERROR) {
        rp_ssl_ocsp_error(ctx);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = rp_ssl_ocsp_dummy_handler;

            if (wev->timer_set) {
                rp_del_timer(wev);
            }

            if (rp_handle_write_event(wev, 0) != RP_OK) {
                rp_ssl_ocsp_error(ctx);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        rp_add_timer(wev, ctx->timeout);
    }
}


static void
rp_ssl_ocsp_read_handler(rp_event_t *rev)
{
    ssize_t              n, size;
    rp_int_t            rc;
    rp_connection_t    *c;
    rp_ssl_ocsp_ctx_t  *ctx;

    c = rev->data;
    ctx = c->data;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, rev->log, 0,
                   "ssl ocsp read handler");

    if (rev->timedout) {
        rp_log_error(RP_LOG_ERR, rev->log, RP_ETIMEDOUT,
                      "OCSP responder timed out");
        rp_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = rp_create_temp_buf(ctx->pool, 16384);
        if (ctx->response == NULL) {
            rp_ssl_ocsp_error(ctx);
            return;
        }
    }

    for ( ;; ) {

        size = ctx->response->end - ctx->response->last;

        n = rp_recv(c, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;

            rc = ctx->process(ctx);

            if (rc == RP_ERROR) {
                rp_ssl_ocsp_error(ctx);
                return;
            }

            continue;
        }

        if (n == RP_AGAIN) {

            if (rp_handle_read_event(rev, 0) != RP_OK) {
                rp_ssl_ocsp_error(ctx);
            }

            return;
        }

        break;
    }

    ctx->done = 1;

    rc = ctx->process(ctx);

    if (rc == RP_DONE) {
        /* ctx->handler() was called */
        return;
    }

    rp_log_error(RP_LOG_ERR, ctx->log, 0,
                  "OCSP responder prematurely closed connection");

    rp_ssl_ocsp_error(ctx);
}


static void
rp_ssl_ocsp_dummy_handler(rp_event_t *ev)
{
    rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "ssl ocsp dummy handler");
}


static rp_int_t
rp_ssl_ocsp_create_request(rp_ssl_ocsp_ctx_t *ctx)
{
    int            len;
    u_char        *p;
    uintptr_t      escape;
    rp_str_t      binary, base64;
    rp_buf_t     *b;
    OCSP_CERTID   *id;
    OCSP_REQUEST  *ocsp;

    ocsp = OCSP_REQUEST_new();
    if (ocsp == NULL) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "OCSP_REQUEST_new() failed");
        return RP_ERROR;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto failed;
    }

    if (OCSP_request_add0_id(ocsp, id) == NULL) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "OCSP_request_add0_id() failed");
        OCSP_CERTID_free(id);
        goto failed;
    }

    len = i2d_OCSP_REQUEST(ocsp, NULL);
    if (len <= 0) {
        rp_ssl_error(RP_LOG_CRIT, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    binary.len = len;
    binary.data = rp_palloc(ctx->pool, len);
    if (binary.data == NULL) {
        goto failed;
    }

    p = binary.data;
    len = i2d_OCSP_REQUEST(ocsp, &p);
    if (len <= 0) {
        rp_ssl_error(RP_LOG_EMERG, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    base64.len = rp_base64_encoded_length(binary.len);
    base64.data = rp_palloc(ctx->pool, base64.len);
    if (base64.data == NULL) {
        goto failed;
    }

    rp_encode_base64(&base64, &binary);

    escape = rp_escape_uri(NULL, base64.data, base64.len,
                            RP_ESCAPE_URI_COMPONENT);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request length %z, escape %d",
                   base64.len, (int) escape);

    len = sizeof("GET ") - 1 + ctx->uri.len + sizeof("/") - 1
          + base64.len + 2 * escape + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ctx->host.len + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = rp_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        goto failed;
    }

    p = b->last;

    p = rp_cpymem(p, "GET ", sizeof("GET ") - 1);
    p = rp_cpymem(p, ctx->uri.data, ctx->uri.len);

    if (ctx->uri.data[ctx->uri.len - 1] != '/') {
        *p++ = '/';
    }

    if (escape == 0) {
        p = rp_cpymem(p, base64.data, base64.len);

    } else {
        p = (u_char *) rp_escape_uri(p, base64.data, base64.len,
                                      RP_ESCAPE_URI_COMPONENT);
    }

    p = rp_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = rp_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = rp_cpymem(p, ctx->host.data, ctx->host.len);
    *p++ = CR; *p++ = LF;

    /* add "\r\n" at the header end */
    *p++ = CR; *p++ = LF;

    b->last = p;
    ctx->request = b;

    OCSP_REQUEST_free(ocsp);

    return RP_OK;

failed:

    OCSP_REQUEST_free(ocsp);

    return RP_ERROR;
}


static rp_int_t
rp_ssl_ocsp_process_status_line(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_int_t  rc;

    rc = rp_ssl_ocsp_parse_status_line(ctx);

    if (rc == RP_OK) {
        rp_log_debug3(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp status %ui \"%*s\"",
                       ctx->code,
                       ctx->header_end - ctx->header_start,
                       ctx->header_start);

        ctx->process = rp_ssl_ocsp_process_headers;
        return ctx->process(ctx);
    }

    if (rc == RP_AGAIN) {
        return RP_AGAIN;
    }

    /* rc == RP_ERROR */

    rp_log_error(RP_LOG_ERR, ctx->log, 0,
                  "OCSP responder sent invalid response");

    return RP_ERROR;
}


static rp_int_t
rp_ssl_ocsp_parse_status_line(rp_ssl_ocsp_ctx_t *ctx)
{
    u_char      ch;
    u_char     *p;
    rp_buf_t  *b;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process status line");

    state = ctx->state;
    b = ctx->response;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return RP_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return RP_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return RP_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return RP_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return RP_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return RP_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return RP_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return RP_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return RP_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return RP_ERROR;
            }

            ctx->code = ctx->code * 10 + (ch - '0');

            if (++ctx->count == 3) {
                state = sw_space_after_status;
                ctx->header_start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            default:
                return RP_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                ctx->header_end = p - 1;
                goto done;
            default:
                return RP_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return RP_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return RP_OK;
}


static rp_int_t
rp_ssl_ocsp_process_headers(rp_ssl_ocsp_ctx_t *ctx)
{
    size_t     len;
    rp_int_t  rc;

    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process headers");

    for ( ;; ) {
        rc = rp_ssl_ocsp_parse_header_line(ctx);

        if (rc == RP_OK) {

            rp_log_debug4(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp header \"%*s: %*s\"",
                           ctx->header_name_end - ctx->header_name_start,
                           ctx->header_name_start,
                           ctx->header_end - ctx->header_start,
                           ctx->header_start);

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Content-Type") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Content-Type",
                                   sizeof("Content-Type") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len != sizeof("application/ocsp-response") - 1
                    || rp_strncasecmp(ctx->header_start,
                                       (u_char *) "application/ocsp-response",
                                       sizeof("application/ocsp-response") - 1)
                       != 0)
                {
                    rp_log_error(RP_LOG_ERR, ctx->log, 0,
                                  "OCSP responder sent invalid "
                                  "\"Content-Type\" header: \"%*s\"",
                                  ctx->header_end - ctx->header_start,
                                  ctx->header_start);
                    return RP_ERROR;
                }

                continue;
            }

            /* TODO: honor Content-Length */

            continue;
        }

        if (rc == RP_DONE) {
            break;
        }

        if (rc == RP_AGAIN) {
            return RP_AGAIN;
        }

        /* rc == RP_ERROR */

        rp_log_error(RP_LOG_ERR, ctx->log, 0,
                      "OCSP responder sent invalid response");

        return RP_ERROR;
    }

    ctx->process = rp_ssl_ocsp_process_body;
    return ctx->process(ctx);
}


static rp_int_t
rp_ssl_ocsp_parse_header_line(rp_ssl_ocsp_ctx_t *ctx)
{
    u_char  c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

#if 0
        rp_log_debug3(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                       "s:%d in:'%02Xd:%c'", state, ch, ch);
#endif

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return RP_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return RP_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return RP_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return RP_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return RP_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RP_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RP_DONE;
}


static rp_int_t
rp_ssl_ocsp_process_body(rp_ssl_ocsp_ctx_t *ctx)
{
    rp_log_debug0(RP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process body");

    if (ctx->done) {
        ctx->handler(ctx);
        return RP_DONE;
    }

    return RP_AGAIN;
}


static u_char *
rp_ssl_ocsp_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rp_ssl_ocsp_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = rp_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    if (ctx) {
        p = rp_snprintf(buf, len, ", responder: %V", &ctx->host);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->peer.name) {
        p = rp_snprintf(buf, len, ", peer: %V", ctx->peer.name);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->name) {
        p = rp_snprintf(buf, len, ", certificate: \"%s\"", ctx->name);
        len -= p - buf;
        buf = p;
    }

    return p;
}


#else


rp_int_t
rp_ssl_stapling(rp_conf_t *cf, rp_ssl_t *ssl, rp_str_t *file,
    rp_str_t *responder, rp_uint_t verify)
{
    rp_log_error(RP_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return RP_OK;
}


rp_int_t
rp_ssl_stapling_resolver(rp_conf_t *cf, rp_ssl_t *ssl,
    rp_resolver_t *resolver, rp_msec_t resolver_timeout)
{
    return RP_OK;
}


#endif
