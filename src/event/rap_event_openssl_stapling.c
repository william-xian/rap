
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_connect.h>


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)


typedef struct {
    rap_str_t                    staple;
    rap_msec_t                   timeout;

    rap_resolver_t              *resolver;
    rap_msec_t                   resolver_timeout;

    rap_addr_t                  *addrs;
    rap_str_t                    host;
    rap_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;

    u_char                      *name;

    time_t                       valid;
    time_t                       refresh;

    unsigned                     verify:1;
    unsigned                     loading:1;
} rap_ssl_stapling_t;


typedef struct rap_ssl_ocsp_ctx_s  rap_ssl_ocsp_ctx_t;

struct rap_ssl_ocsp_ctx_s {
    X509                        *cert;
    X509                        *issuer;

    u_char                      *name;

    rap_uint_t                   naddrs;

    rap_addr_t                  *addrs;
    rap_str_t                    host;
    rap_str_t                    uri;
    in_port_t                    port;

    rap_resolver_t              *resolver;
    rap_msec_t                   resolver_timeout;

    rap_msec_t                   timeout;

    void                       (*handler)(rap_ssl_ocsp_ctx_t *ctx);
    void                        *data;

    rap_buf_t                   *request;
    rap_buf_t                   *response;
    rap_peer_connection_t        peer;

    rap_int_t                  (*process)(rap_ssl_ocsp_ctx_t *ctx);

    rap_uint_t                   state;

    rap_uint_t                   code;
    rap_uint_t                   count;

    rap_uint_t                   done;

    u_char                      *header_name_start;
    u_char                      *header_name_end;
    u_char                      *header_start;
    u_char                      *header_end;

    rap_pool_t                  *pool;
    rap_log_t                   *log;
};


static rap_int_t rap_ssl_stapling_certificate(rap_conf_t *cf, rap_ssl_t *ssl,
    X509 *cert, rap_str_t *file, rap_str_t *responder, rap_uint_t verify);
static rap_int_t rap_ssl_stapling_file(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple, rap_str_t *file);
static rap_int_t rap_ssl_stapling_issuer(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple);
static rap_int_t rap_ssl_stapling_responder(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple, rap_str_t *responder);

static int rap_ssl_certificate_status_callback(rap_ssl_conn_t *ssl_conn,
    void *data);
static void rap_ssl_stapling_update(rap_ssl_stapling_t *staple);
static void rap_ssl_stapling_ocsp_handler(rap_ssl_ocsp_ctx_t *ctx);

static time_t rap_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time);

static void rap_ssl_stapling_cleanup(void *data);

static rap_ssl_ocsp_ctx_t *rap_ssl_ocsp_start(void);
static void rap_ssl_ocsp_done(rap_ssl_ocsp_ctx_t *ctx);
static void rap_ssl_ocsp_request(rap_ssl_ocsp_ctx_t *ctx);
static void rap_ssl_ocsp_resolve_handler(rap_resolver_ctx_t *resolve);
static void rap_ssl_ocsp_connect(rap_ssl_ocsp_ctx_t *ctx);
static void rap_ssl_ocsp_write_handler(rap_event_t *wev);
static void rap_ssl_ocsp_read_handler(rap_event_t *rev);
static void rap_ssl_ocsp_dummy_handler(rap_event_t *ev);

static rap_int_t rap_ssl_ocsp_create_request(rap_ssl_ocsp_ctx_t *ctx);
static rap_int_t rap_ssl_ocsp_process_status_line(rap_ssl_ocsp_ctx_t *ctx);
static rap_int_t rap_ssl_ocsp_parse_status_line(rap_ssl_ocsp_ctx_t *ctx);
static rap_int_t rap_ssl_ocsp_process_headers(rap_ssl_ocsp_ctx_t *ctx);
static rap_int_t rap_ssl_ocsp_parse_header_line(rap_ssl_ocsp_ctx_t *ctx);
static rap_int_t rap_ssl_ocsp_process_body(rap_ssl_ocsp_ctx_t *ctx);

static u_char *rap_ssl_ocsp_log_error(rap_log_t *log, u_char *buf, size_t len);


rap_int_t
rap_ssl_stapling(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *file,
    rap_str_t *responder, rap_uint_t verify)
{
    X509  *cert;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, rap_ssl_next_certificate_index))
    {
        if (rap_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    SSL_CTX_set_tlsext_status_cb(ssl->ctx, rap_ssl_certificate_status_callback);

    return RAP_OK;
}


static rap_int_t
rap_ssl_stapling_certificate(rap_conf_t *cf, rap_ssl_t *ssl, X509 *cert,
    rap_str_t *file, rap_str_t *responder, rap_uint_t verify)
{
    rap_int_t            rc;
    rap_pool_cleanup_t  *cln;
    rap_ssl_stapling_t  *staple;

    staple = rap_pcalloc(cf->pool, sizeof(rap_ssl_stapling_t));
    if (staple == NULL) {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_stapling_cleanup;
    cln->data = staple;

    if (X509_set_ex_data(cert, rap_ssl_stapling_index, staple) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        return RAP_ERROR;
    }

    staple->ssl_ctx = ssl->ctx;
    staple->timeout = 60000;
    staple->verify = verify;
    staple->cert = cert;
    staple->name = X509_get_ex_data(staple->cert,
                                    rap_ssl_certificate_name_index);

    if (file->len) {
        /* use OCSP response from the file */

        if (rap_ssl_stapling_file(cf, ssl, staple, file) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_OK;
    }

    rc = rap_ssl_stapling_issuer(cf, ssl, staple);

    if (rc == RAP_DECLINED) {
        return RAP_OK;
    }

    if (rc != RAP_OK) {
        return RAP_ERROR;
    }

    rc = rap_ssl_stapling_responder(cf, ssl, staple, responder);

    if (rc == RAP_DECLINED) {
        return RAP_OK;
    }

    if (rc != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


static rap_int_t
rap_ssl_stapling_file(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple, rap_str_t *file)
{
    BIO            *bio;
    int             len;
    u_char         *p, *buf;
    OCSP_RESPONSE  *response;

    if (rap_conf_full_name(cf->cycle, file, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "rb");
    if (bio == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return RAP_ERROR;
    }

    response = d2i_OCSP_RESPONSE_bio(bio, NULL);
    if (response == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "d2i_OCSP_RESPONSE_bio(\"%s\") failed", file->data);
        BIO_free(bio);
        return RAP_ERROR;
    }

    len = i2d_OCSP_RESPONSE(response, NULL);
    if (len <= 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        goto failed;
    }

    buf = rap_alloc(len, ssl->log);
    if (buf == NULL) {
        goto failed;
    }

    p = buf;
    len = i2d_OCSP_RESPONSE(response, &p);
    if (len <= 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        rap_free(buf);
        goto failed;
    }

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    staple->staple.data = buf;
    staple->staple.len = len;
    staple->valid = RAP_MAX_TIME_T_VALUE;

    return RAP_OK;

failed:

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    return RAP_ERROR;
}


static rap_int_t
rap_ssl_stapling_issuer(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple)
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

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: %d extra certs", n);

    for (i = 0; i < n; i++) {
        issuer = sk_X509_value(chain, i);
        if (X509_check_issued(issuer, cert) == X509_V_OK) {
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
            X509_up_ref(issuer);
#else
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#endif

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, ssl->log, 0,
                           "SSL get issuer: found %p in extra certs", issuer);

            staple->issuer = issuer;

            return RAP_OK;
        }
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);
    if (store == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return RAP_ERROR;
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_new() failed");
        return RAP_ERROR;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(store_ctx);
        return RAP_ERROR;
    }

    rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);

    if (rc == -1) {
        rap_ssl_error(RAP_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_get1_issuer() failed");
        X509_STORE_CTX_free(store_ctx);
        return RAP_ERROR;
    }

    if (rc == 0) {
        rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "issuer certificate not found for certificate \"%s\"",
                      staple->name);
        X509_STORE_CTX_free(store_ctx);
        return RAP_DECLINED;
    }

    X509_STORE_CTX_free(store_ctx);

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: found %p in cert store", issuer);

    staple->issuer = issuer;

    return RAP_OK;
}


static rap_int_t
rap_ssl_stapling_responder(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_ssl_stapling_t *staple, rap_str_t *responder)
{
    char                      *s;
    rap_str_t                  rsp;
    rap_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (responder->len == 0) {

        /* extract OCSP responder URL from certificate */

        aia = X509_get1_ocsp(staple->cert);
        if (aia == NULL) {
            rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            return RAP_DECLINED;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        s = sk_OPENSSL_STRING_value(aia, 0);
#else
        s = sk_value(aia, 0);
#endif
        if (s == NULL) {
            rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            X509_email_free(aia);
            return RAP_DECLINED;
        }

        responder = &rsp;

        responder->len = rap_strlen(s);
        responder->data = rap_palloc(cf->pool, responder->len);
        if (responder->data == NULL) {
            X509_email_free(aia);
            return RAP_ERROR;
        }

        rap_memcpy(responder->data, s, responder->len);
        X509_email_free(aia);
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = *responder;
    u.default_port = 80;
    u.uri_part = 1;

    if (u.url.len > 7
        && rap_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in the certificate \"%s\"",
                      &u.url, staple->name);
        return RAP_DECLINED;
    }

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "%s in OCSP responder \"%V\" "
                          "in the certificate \"%s\"",
                          u.err, &u.url, staple->name);
            return RAP_DECLINED;
        }

        return RAP_ERROR;
    }

    staple->addrs = u.addrs;
    staple->host = u.host;
    staple->uri = u.uri;
    staple->port = u.port;

    if (staple->uri.len == 0) {
        rap_str_set(&staple->uri, "/");
    }

    return RAP_OK;
}


rap_int_t
rap_ssl_stapling_resolver(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_resolver_t *resolver, rap_msec_t resolver_timeout)
{
    X509                *cert;
    rap_ssl_stapling_t  *staple;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, rap_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, rap_ssl_next_certificate_index))
    {
        staple = X509_get_ex_data(cert, rap_ssl_stapling_index);
        staple->resolver = resolver;
        staple->resolver_timeout = resolver_timeout;
    }

    return RAP_OK;
}


static int
rap_ssl_certificate_status_callback(rap_ssl_conn_t *ssl_conn, void *data)
{
    int                  rc;
    X509                *cert;
    u_char              *p;
    rap_connection_t    *c;
    rap_ssl_stapling_t  *staple;

    c = rap_ssl_get_connection(ssl_conn);

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL certificate status callback");

    rc = SSL_TLSEXT_ERR_NOACK;

    cert = SSL_get_certificate(ssl_conn);

    if (cert == NULL) {
        return rc;
    }

    staple = X509_get_ex_data(cert, rap_ssl_stapling_index);

    if (staple == NULL) {
        return rc;
    }

    if (staple->staple.len
        && staple->valid >= rap_time())
    {
        /* we have to copy ocsp response as OpenSSL will free it by itself */

        p = OPENSSL_malloc(staple->staple.len);
        if (p == NULL) {
            rap_ssl_error(RAP_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
            return SSL_TLSEXT_ERR_NOACK;
        }

        rap_memcpy(p, staple->staple.data, staple->staple.len);

        SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->staple.len);

        rc = SSL_TLSEXT_ERR_OK;
    }

    rap_ssl_stapling_update(staple);

    return rc;
}


static void
rap_ssl_stapling_update(rap_ssl_stapling_t *staple)
{
    rap_ssl_ocsp_ctx_t  *ctx;

    if (staple->host.len == 0
        || staple->loading || staple->refresh >= rap_time())
    {
        return;
    }

    staple->loading = 1;

    ctx = rap_ssl_ocsp_start();
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

    ctx->handler = rap_ssl_stapling_ocsp_handler;
    ctx->data = staple;

    rap_ssl_ocsp_request(ctx);

    return;
}


static void
rap_ssl_stapling_ocsp_handler(rap_ssl_ocsp_ctx_t *ctx)
{
    int                    n;
    size_t                 len;
    time_t                 now, valid;
    rap_str_t              response;
    X509_STORE            *store;
    const u_char          *p;
    STACK_OF(X509)        *chain;
    OCSP_CERTID           *id;
    OCSP_RESPONSE         *ocsp;
    OCSP_BASICRESP        *basic;
    rap_ssl_stapling_t    *staple;
    ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;

    staple = ctx->data;
    now = rap_time();
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
        rap_ssl_error(RAP_LOG_ERR, ctx->log, 0,
                      "d2i_OCSP_RESPONSE() failed");
        goto error;
    }

    n = OCSP_response_status(ocsp);

    if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                      "OCSP response not successful (%d: %s)",
                      n, OCSP_response_status_str(n));
        goto error;
    }

    basic = OCSP_response_get1_basic(ocsp);
    if (basic == NULL) {
        rap_ssl_error(RAP_LOG_ERR, ctx->log, 0,
                      "OCSP_response_get1_basic() failed");
        goto error;
    }

    store = SSL_CTX_get_cert_store(staple->ssl_ctx);
    if (store == NULL) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
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
        rap_ssl_error(RAP_LOG_ERR, ctx->log, 0,
                      "OCSP_basic_verify() failed");
        goto error;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto error;
    }

    if (OCSP_resp_find_status(basic, id, &n, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }

    if (n != V_OCSP_CERTSTATUS_GOOD) {
        rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(n));
        goto error;
    }

    if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
        rap_ssl_error(RAP_LOG_ERR, ctx->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        valid = rap_ssl_stapling_time(nextupdate);
        if (valid == (time_t) RAP_ERROR) {
            rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                          "invalid nextUpdate time in certificate status");
            goto error;
        }

    } else {
        valid = RAP_MAX_TIME_T_VALUE;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(ocsp);

    id = NULL;
    basic = NULL;
    ocsp = NULL;

    /* copy the response to memory not in ctx->pool */

    response.len = len;
    response.data = rap_alloc(response.len, ctx->log);

    if (response.data == NULL) {
        goto error;
    }

    rap_memcpy(response.data, ctx->response->pos, response.len);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp response, %s, %uz",
                   OCSP_cert_status_str(n), response.len);

    if (staple->staple.data) {
        rap_free(staple->staple.data);
    }

    staple->staple = response;
    staple->valid = valid;

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple->loading = 0;
    staple->refresh = rap_max(rap_min(valid - 300, now + 3600), now + 300);

    rap_ssl_ocsp_done(ctx);
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

    rap_ssl_ocsp_done(ctx);
}


static time_t
rap_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
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
        return RAP_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_GENERALIZEDTIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = rap_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void
rap_ssl_stapling_cleanup(void *data)
{
    rap_ssl_stapling_t  *staple = data;

    if (staple->issuer) {
        X509_free(staple->issuer);
    }

    if (staple->staple.data) {
        rap_free(staple->staple.data);
    }
}


static rap_ssl_ocsp_ctx_t *
rap_ssl_ocsp_start(void)
{
    rap_log_t           *log;
    rap_pool_t          *pool;
    rap_ssl_ocsp_ctx_t  *ctx;

    pool = rap_create_pool(2048, rap_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    ctx = rap_pcalloc(pool, sizeof(rap_ssl_ocsp_ctx_t));
    if (ctx == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    log = rap_palloc(pool, sizeof(rap_log_t));
    if (log == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    ctx->pool = pool;

    *log = *ctx->pool->log;

    ctx->pool->log = log;
    ctx->log = log;

    log->handler = rap_ssl_ocsp_log_error;
    log->data = ctx;
    log->action = "requesting certificate status";

    return ctx;
}


static void
rap_ssl_ocsp_done(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp done");

    if (ctx->peer.connection) {
        rap_close_connection(ctx->peer.connection);
    }

    rap_destroy_pool(ctx->pool);
}


static void
rap_ssl_ocsp_error(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp error");

    ctx->code = 0;
    ctx->handler(ctx);
}


static void
rap_ssl_ocsp_request(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_resolver_ctx_t  *resolve, temp;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request");

    if (rap_ssl_ocsp_create_request(ctx) != RAP_OK) {
        rap_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->resolver) {
        /* resolve OCSP responder hostname */

        temp.name = ctx->host;

        resolve = rap_resolve_start(ctx->resolver, &temp);
        if (resolve == NULL) {
            rap_ssl_ocsp_error(ctx);
            return;
        }

        if (resolve == RAP_NO_RESOLVER) {
            rap_log_error(RAP_LOG_WARN, ctx->log, 0,
                          "no resolver defined to resolve %V", &ctx->host);
            goto connect;
        }

        resolve->name = ctx->host;
        resolve->handler = rap_ssl_ocsp_resolve_handler;
        resolve->data = ctx;
        resolve->timeout = ctx->resolver_timeout;

        if (rap_resolve_name(resolve) != RAP_OK) {
            rap_ssl_ocsp_error(ctx);
            return;
        }

        return;
    }

connect:

    rap_ssl_ocsp_connect(ctx);
}


static void
rap_ssl_ocsp_resolve_handler(rap_resolver_ctx_t *resolve)
{
    rap_ssl_ocsp_ctx_t *ctx = resolve->data;

    u_char           *p;
    size_t            len;
    socklen_t         socklen;
    rap_uint_t        i;
    struct sockaddr  *sockaddr;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp resolve handler");

    if (resolve->state) {
        rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &resolve->name, resolve->state,
                      rap_resolver_strerror(resolve->state));
        goto failed;
    }

#if (RAP_DEBUG)
    {
    u_char     text[RAP_SOCKADDR_STRLEN];
    rap_str_t  addr;

    addr.data = text;

    for (i = 0; i < resolve->naddrs; i++) {
        addr.len = rap_sock_ntop(resolve->addrs[i].sockaddr,
                                 resolve->addrs[i].socklen,
                                 text, RAP_SOCKADDR_STRLEN, 0);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                       "name was resolved to %V", &addr);

    }
    }
#endif

    ctx->naddrs = resolve->naddrs;
    ctx->addrs = rap_pcalloc(ctx->pool, ctx->naddrs * sizeof(rap_addr_t));

    if (ctx->addrs == NULL) {
        goto failed;
    }

    for (i = 0; i < resolve->naddrs; i++) {

        socklen = resolve->addrs[i].socklen;

        sockaddr = rap_palloc(ctx->pool, socklen);
        if (sockaddr == NULL) {
            goto failed;
        }

        rap_memcpy(sockaddr, resolve->addrs[i].sockaddr, socklen);
        rap_inet_set_port(sockaddr, ctx->port);

        ctx->addrs[i].sockaddr = sockaddr;
        ctx->addrs[i].socklen = socklen;

        p = rap_pnalloc(ctx->pool, RAP_SOCKADDR_STRLEN);
        if (p == NULL) {
            goto failed;
        }

        len = rap_sock_ntop(sockaddr, socklen, p, RAP_SOCKADDR_STRLEN, 1);

        ctx->addrs[i].name.len = len;
        ctx->addrs[i].name.data = p;
    }

    rap_resolve_name_done(resolve);

    rap_ssl_ocsp_connect(ctx);
    return;

failed:

    rap_resolve_name_done(resolve);
    rap_ssl_ocsp_error(ctx);
}


static void
rap_ssl_ocsp_connect(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_int_t  rc;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect");

    /* TODO: use all ip addresses */

    ctx->peer.sockaddr = ctx->addrs[0].sockaddr;
    ctx->peer.socklen = ctx->addrs[0].socklen;
    ctx->peer.name = &ctx->addrs[0].name;
    ctx->peer.get = rap_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = RAP_ERROR_ERR;

    rc = rap_event_connect_peer(&ctx->peer);

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect peer done");

    if (rc == RAP_ERROR || rc == RAP_BUSY || rc == RAP_DECLINED) {
        rap_ssl_ocsp_error(ctx);
        return;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;

    ctx->peer.connection->read->handler = rap_ssl_ocsp_read_handler;
    ctx->peer.connection->write->handler = rap_ssl_ocsp_write_handler;

    ctx->process = rap_ssl_ocsp_process_status_line;

    rap_add_timer(ctx->peer.connection->read, ctx->timeout);
    rap_add_timer(ctx->peer.connection->write, ctx->timeout);

    if (rc == RAP_OK) {
        rap_ssl_ocsp_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
rap_ssl_ocsp_write_handler(rap_event_t *wev)
{
    ssize_t              n, size;
    rap_connection_t    *c;
    rap_ssl_ocsp_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, wev->log, 0,
                   "ssl ocsp write handler");

    if (wev->timedout) {
        rap_log_error(RAP_LOG_ERR, wev->log, RAP_ETIMEDOUT,
                      "OCSP responder timed out");
        rap_ssl_ocsp_error(ctx);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = rap_send(c, ctx->request->pos, size);

    if (n == RAP_ERROR) {
        rap_ssl_ocsp_error(ctx);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = rap_ssl_ocsp_dummy_handler;

            if (wev->timer_set) {
                rap_del_timer(wev);
            }

            if (rap_handle_write_event(wev, 0) != RAP_OK) {
                rap_ssl_ocsp_error(ctx);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        rap_add_timer(wev, ctx->timeout);
    }
}


static void
rap_ssl_ocsp_read_handler(rap_event_t *rev)
{
    ssize_t              n, size;
    rap_int_t            rc;
    rap_connection_t    *c;
    rap_ssl_ocsp_ctx_t  *ctx;

    c = rev->data;
    ctx = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, rev->log, 0,
                   "ssl ocsp read handler");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_ERR, rev->log, RAP_ETIMEDOUT,
                      "OCSP responder timed out");
        rap_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = rap_create_temp_buf(ctx->pool, 16384);
        if (ctx->response == NULL) {
            rap_ssl_ocsp_error(ctx);
            return;
        }
    }

    for ( ;; ) {

        size = ctx->response->end - ctx->response->last;

        n = rap_recv(c, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;

            rc = ctx->process(ctx);

            if (rc == RAP_ERROR) {
                rap_ssl_ocsp_error(ctx);
                return;
            }

            continue;
        }

        if (n == RAP_AGAIN) {

            if (rap_handle_read_event(rev, 0) != RAP_OK) {
                rap_ssl_ocsp_error(ctx);
            }

            return;
        }

        break;
    }

    ctx->done = 1;

    rc = ctx->process(ctx);

    if (rc == RAP_DONE) {
        /* ctx->handler() was called */
        return;
    }

    rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                  "OCSP responder prematurely closed connection");

    rap_ssl_ocsp_error(ctx);
}


static void
rap_ssl_ocsp_dummy_handler(rap_event_t *ev)
{
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "ssl ocsp dummy handler");
}


static rap_int_t
rap_ssl_ocsp_create_request(rap_ssl_ocsp_ctx_t *ctx)
{
    int            len;
    u_char        *p;
    uintptr_t      escape;
    rap_str_t      binary, base64;
    rap_buf_t     *b;
    OCSP_CERTID   *id;
    OCSP_REQUEST  *ocsp;

    ocsp = OCSP_REQUEST_new();
    if (ocsp == NULL) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
                      "OCSP_REQUEST_new() failed");
        return RAP_ERROR;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto failed;
    }

    if (OCSP_request_add0_id(ocsp, id) == NULL) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
                      "OCSP_request_add0_id() failed");
        OCSP_CERTID_free(id);
        goto failed;
    }

    len = i2d_OCSP_REQUEST(ocsp, NULL);
    if (len <= 0) {
        rap_ssl_error(RAP_LOG_CRIT, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    binary.len = len;
    binary.data = rap_palloc(ctx->pool, len);
    if (binary.data == NULL) {
        goto failed;
    }

    p = binary.data;
    len = i2d_OCSP_REQUEST(ocsp, &p);
    if (len <= 0) {
        rap_ssl_error(RAP_LOG_EMERG, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    base64.len = rap_base64_encoded_length(binary.len);
    base64.data = rap_palloc(ctx->pool, base64.len);
    if (base64.data == NULL) {
        goto failed;
    }

    rap_encode_base64(&base64, &binary);

    escape = rap_escape_uri(NULL, base64.data, base64.len,
                            RAP_ESCAPE_URI_COMPONENT);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request length %z, escape %d",
                   base64.len, (int) escape);

    len = sizeof("GET ") - 1 + ctx->uri.len + sizeof("/") - 1
          + base64.len + 2 * escape + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ctx->host.len + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = rap_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        goto failed;
    }

    p = b->last;

    p = rap_cpymem(p, "GET ", sizeof("GET ") - 1);
    p = rap_cpymem(p, ctx->uri.data, ctx->uri.len);

    if (ctx->uri.data[ctx->uri.len - 1] != '/') {
        *p++ = '/';
    }

    if (escape == 0) {
        p = rap_cpymem(p, base64.data, base64.len);

    } else {
        p = (u_char *) rap_escape_uri(p, base64.data, base64.len,
                                      RAP_ESCAPE_URI_COMPONENT);
    }

    p = rap_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = rap_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = rap_cpymem(p, ctx->host.data, ctx->host.len);
    *p++ = CR; *p++ = LF;

    /* add "\r\n" at the header end */
    *p++ = CR; *p++ = LF;

    b->last = p;
    ctx->request = b;

    OCSP_REQUEST_free(ocsp);

    return RAP_OK;

failed:

    OCSP_REQUEST_free(ocsp);

    return RAP_ERROR;
}


static rap_int_t
rap_ssl_ocsp_process_status_line(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_int_t  rc;

    rc = rap_ssl_ocsp_parse_status_line(ctx);

    if (rc == RAP_OK) {
        rap_log_debug3(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp status %ui \"%*s\"",
                       ctx->code,
                       ctx->header_end - ctx->header_start,
                       ctx->header_start);

        ctx->process = rap_ssl_ocsp_process_headers;
        return ctx->process(ctx);
    }

    if (rc == RAP_AGAIN) {
        return RAP_AGAIN;
    }

    /* rc == RAP_ERROR */

    rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                  "OCSP responder sent invalid response");

    return RAP_ERROR;
}


static rap_int_t
rap_ssl_ocsp_parse_status_line(rap_ssl_ocsp_ctx_t *ctx)
{
    u_char      ch;
    u_char     *p;
    rap_buf_t  *b;
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

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
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
                return RAP_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return RAP_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return RAP_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return RAP_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return RAP_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return RAP_ERROR;
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
                return RAP_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return RAP_ERROR;
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
                return RAP_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return RAP_ERROR;
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
                return RAP_ERROR;
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
                return RAP_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return RAP_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return RAP_OK;
}


static rap_int_t
rap_ssl_ocsp_process_headers(rap_ssl_ocsp_ctx_t *ctx)
{
    size_t     len;
    rap_int_t  rc;

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process headers");

    for ( ;; ) {
        rc = rap_ssl_ocsp_parse_header_line(ctx);

        if (rc == RAP_OK) {

            rap_log_debug4(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp header \"%*s: %*s\"",
                           ctx->header_name_end - ctx->header_name_start,
                           ctx->header_name_start,
                           ctx->header_end - ctx->header_start,
                           ctx->header_start);

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Content-Type") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Content-Type",
                                   sizeof("Content-Type") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len != sizeof("application/ocsp-response") - 1
                    || rap_strncasecmp(ctx->header_start,
                                       (u_char *) "application/ocsp-response",
                                       sizeof("application/ocsp-response") - 1)
                       != 0)
                {
                    rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                                  "OCSP responder sent invalid "
                                  "\"Content-Type\" header: \"%*s\"",
                                  ctx->header_end - ctx->header_start,
                                  ctx->header_start);
                    return RAP_ERROR;
                }

                continue;
            }

            /* TODO: honor Content-Length */

            continue;
        }

        if (rc == RAP_DONE) {
            break;
        }

        if (rc == RAP_AGAIN) {
            return RAP_AGAIN;
        }

        /* rc == RAP_ERROR */

        rap_log_error(RAP_LOG_ERR, ctx->log, 0,
                      "OCSP responder sent invalid response");

        return RAP_ERROR;
    }

    ctx->process = rap_ssl_ocsp_process_body;
    return ctx->process(ctx);
}


static rap_int_t
rap_ssl_ocsp_parse_header_line(rap_ssl_ocsp_ctx_t *ctx)
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
        rap_log_debug3(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
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

                return RAP_ERROR;
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

            return RAP_ERROR;

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
                return RAP_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return RAP_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return RAP_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RAP_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RAP_DONE;
}


static rap_int_t
rap_ssl_ocsp_process_body(rap_ssl_ocsp_ctx_t *ctx)
{
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process body");

    if (ctx->done) {
        ctx->handler(ctx);
        return RAP_DONE;
    }

    return RAP_AGAIN;
}


static u_char *
rap_ssl_ocsp_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rap_ssl_ocsp_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = rap_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    if (ctx) {
        p = rap_snprintf(buf, len, ", responder: %V", &ctx->host);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->peer.name) {
        p = rap_snprintf(buf, len, ", peer: %V", ctx->peer.name);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->name) {
        p = rap_snprintf(buf, len, ", certificate: \"%s\"", ctx->name);
        len -= p - buf;
        buf = p;
    }

    return p;
}


#else


rap_int_t
rap_ssl_stapling(rap_conf_t *cf, rap_ssl_t *ssl, rap_str_t *file,
    rap_str_t *responder, rap_uint_t verify)
{
    rap_log_error(RAP_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return RAP_OK;
}


rap_int_t
rap_ssl_stapling_resolver(rap_conf_t *cf, rap_ssl_t *ssl,
    rap_resolver_t *resolver, rap_msec_t resolver_timeout)
{
    return RAP_OK;
}


#endif
