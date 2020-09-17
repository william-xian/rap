
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>

#if (RP_HAVE_EXSLT)
#include <libexslt/exslt.h>
#endif


#ifndef RP_HTTP_XSLT_REUSE_DTD
#define RP_HTTP_XSLT_REUSE_DTD  1
#endif


typedef struct {
    u_char                    *name;
    void                      *data;
} rp_http_xslt_file_t;


typedef struct {
    rp_array_t                dtd_files;    /* rp_http_xslt_file_t */
    rp_array_t                sheet_files;  /* rp_http_xslt_file_t */
} rp_http_xslt_filter_main_conf_t;


typedef struct {
    u_char                    *name;
    rp_http_complex_value_t   value;
    rp_uint_t                 quote;        /* unsigned  quote:1; */
} rp_http_xslt_param_t;


typedef struct {
    xsltStylesheetPtr          stylesheet;
    rp_array_t                params;       /* rp_http_xslt_param_t */
} rp_http_xslt_sheet_t;


typedef struct {
    xmlDtdPtr                  dtd;
    rp_array_t                sheets;       /* rp_http_xslt_sheet_t */
    rp_hash_t                 types;
    rp_array_t               *types_keys;
    rp_array_t               *params;       /* rp_http_xslt_param_t */
    rp_flag_t                 last_modified;
} rp_http_xslt_filter_loc_conf_t;


typedef struct {
    xmlDocPtr                  doc;
    xmlParserCtxtPtr           ctxt;
    xsltTransformContextPtr    transform;
    rp_http_request_t        *request;
    rp_array_t                params;

    rp_uint_t                 done;         /* unsigned  done:1; */
} rp_http_xslt_filter_ctx_t;


static rp_int_t rp_http_xslt_send(rp_http_request_t *r,
    rp_http_xslt_filter_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_xslt_add_chunk(rp_http_request_t *r,
    rp_http_xslt_filter_ctx_t *ctx, rp_buf_t *b);


static void rp_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId);
static void rp_cdecl rp_http_xslt_sax_error(void *data, const char *msg, ...);


static rp_buf_t *rp_http_xslt_apply_stylesheet(rp_http_request_t *r,
    rp_http_xslt_filter_ctx_t *ctx);
static rp_int_t rp_http_xslt_params(rp_http_request_t *r,
    rp_http_xslt_filter_ctx_t *ctx, rp_array_t *params, rp_uint_t final);
static u_char *rp_http_xslt_content_type(xsltStylesheetPtr s);
static u_char *rp_http_xslt_encoding(xsltStylesheetPtr s);
static void rp_http_xslt_cleanup(void *data);

static char *rp_http_xslt_entities(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_xslt_stylesheet(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_xslt_param(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static void rp_http_xslt_cleanup_dtd(void *data);
static void rp_http_xslt_cleanup_stylesheet(void *data);
static void *rp_http_xslt_filter_create_main_conf(rp_conf_t *cf);
static void *rp_http_xslt_filter_create_conf(rp_conf_t *cf);
static char *rp_http_xslt_filter_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_xslt_filter_preconfiguration(rp_conf_t *cf);
static rp_int_t rp_http_xslt_filter_init(rp_conf_t *cf);
static void rp_http_xslt_filter_exit(rp_cycle_t *cycle);


static rp_str_t  rp_http_xslt_default_types[] = {
    rp_string("text/xml"),
    rp_null_string
};


static rp_command_t  rp_http_xslt_filter_commands[] = {

    { rp_string("xml_entities"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_xslt_entities,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("xslt_stylesheet"),
      RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_xslt_stylesheet,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("xslt_param"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_http_xslt_param,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("xslt_string_param"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_http_xslt_param,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) 1 },

    { rp_string("xslt_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_xslt_filter_loc_conf_t, types_keys),
      &rp_http_xslt_default_types[0] },

    { rp_string("xslt_last_modified"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_xslt_filter_loc_conf_t, last_modified),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_xslt_filter_module_ctx = {
    rp_http_xslt_filter_preconfiguration, /* preconfiguration */
    rp_http_xslt_filter_init,             /* postconfiguration */

    rp_http_xslt_filter_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_xslt_filter_create_conf,      /* create location configuration */
    rp_http_xslt_filter_merge_conf        /* merge location configuration */
};


rp_module_t  rp_http_xslt_filter_module = {
    RP_MODULE_V1,
    &rp_http_xslt_filter_module_ctx,      /* module context */
    rp_http_xslt_filter_commands,         /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rp_http_xslt_filter_exit,             /* exit process */
    rp_http_xslt_filter_exit,             /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_xslt_header_filter(rp_http_request_t *r)
{
    rp_http_xslt_filter_ctx_t       *ctx;
    rp_http_xslt_filter_loc_conf_t  *conf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter header");

    if (r->headers_out.status == RP_HTTP_NOT_MODIFIED) {
        return rp_http_next_header_filter(r);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_xslt_filter_module);

    if (conf->sheets.nelts == 0
        || rp_http_test_content_type(r, &conf->types) == NULL)
    {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_xslt_filter_module);

    if (ctx) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_xslt_filter_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_xslt_filter_module);

    r->main_filter_need_in_memory = 1;

    return RP_OK;
}


static rp_int_t
rp_http_xslt_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    int                          wellFormed;
    rp_chain_t                 *cl;
    rp_http_xslt_filter_ctx_t  *ctx;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter body");

    if (in == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_xslt_filter_module);

    if (ctx == NULL || ctx->done) {
        return rp_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {

        if (rp_http_xslt_add_chunk(r, ctx, cl->buf) != RP_OK) {

            if (ctx->ctxt->myDoc) {

#if (RP_HTTP_XSLT_REUSE_DTD)
                ctx->ctxt->myDoc->extSubset = NULL;
#endif
                xmlFreeDoc(ctx->ctxt->myDoc);
            }

            xmlFreeParserCtxt(ctx->ctxt);

            return rp_http_xslt_send(r, ctx, NULL);
        }

        if (cl->buf->last_buf || cl->buf->last_in_chain) {

            ctx->doc = ctx->ctxt->myDoc;

#if (RP_HTTP_XSLT_REUSE_DTD)
            ctx->doc->extSubset = NULL;
#endif

            wellFormed = ctx->ctxt->wellFormed;

            xmlFreeParserCtxt(ctx->ctxt);

            if (wellFormed) {
                return rp_http_xslt_send(r, ctx,
                                       rp_http_xslt_apply_stylesheet(r, ctx));
            }

            xmlFreeDoc(ctx->doc);

            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "not well formed XML document");

            return rp_http_xslt_send(r, ctx, NULL);
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_xslt_send(rp_http_request_t *r, rp_http_xslt_filter_ctx_t *ctx,
    rp_buf_t *b)
{
    rp_int_t                         rc;
    rp_chain_t                       out;
    rp_pool_cleanup_t               *cln;
    rp_http_xslt_filter_loc_conf_t  *conf;

    ctx->done = 1;

    if (b == NULL) {
        return rp_http_filter_finalize_request(r, &rp_http_xslt_filter_module,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
    }

    cln = rp_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        rp_free(b->pos);
        return rp_http_filter_finalize_request(r, &rp_http_xslt_filter_module,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        conf = rp_http_get_module_loc_conf(r, rp_http_xslt_filter_module);

        if (!conf->last_modified) {
            rp_http_clear_last_modified(r);
            rp_http_clear_etag(r);

        } else {
            rp_http_weak_etag(r);
        }
    }

    rc = rp_http_next_header_filter(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        rp_free(b->pos);
        return rc;
    }

    cln->handler = rp_http_xslt_cleanup;
    cln->data = b->pos;

    out.buf = b;
    out.next = NULL;

    return rp_http_next_body_filter(r, &out);
}


static rp_int_t
rp_http_xslt_add_chunk(rp_http_request_t *r, rp_http_xslt_filter_ctx_t *ctx,
    rp_buf_t *b)
{
    int               err;
    xmlParserCtxtPtr  ctxt;

    if (ctx->ctxt == NULL) {

        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
        if (ctxt == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "xmlCreatePushParserCtxt() failed");
            return RP_ERROR;
        }
        xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD
                                               |XML_PARSE_NOWARNING);

        ctxt->sax->externalSubset = rp_http_xslt_sax_external_subset;
        ctxt->sax->setDocumentLocator = NULL;
        ctxt->sax->error = rp_http_xslt_sax_error;
        ctxt->sax->fatalError = rp_http_xslt_sax_error;
        ctxt->sax->_private = ctx;

        ctx->ctxt = ctxt;
        ctx->request = r;
    }

    err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
                        (b->last_buf) || (b->last_in_chain));

    if (err == 0) {
        b->pos = b->last;
        return RP_OK;
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "xmlParseChunk() failed, error:%d", err);

    return RP_ERROR;
}


static void
rp_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = data;

    xmlDocPtr                         doc;
    xmlDtdPtr                         dtd;
    rp_http_request_t               *r;
    rp_http_xslt_filter_ctx_t       *ctx;
    rp_http_xslt_filter_loc_conf_t  *conf;

    ctx = ctxt->sax->_private;
    r = ctx->request;

    conf = rp_http_get_module_loc_conf(r, rp_http_xslt_filter_module);

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
                   name ? name : (xmlChar *) "",
                   externalId ? externalId : (xmlChar *) "",
                   systemId ? systemId : (xmlChar *) "");

    doc = ctxt->myDoc;

#if (RP_HTTP_XSLT_REUSE_DTD)

    dtd = conf->dtd;

#else

    dtd = xmlCopyDtd(conf->dtd);
    if (dtd == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "xmlCopyDtd() failed");
        return;
    }

    if (doc->children == NULL) {
        xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);

    } else {
        xmlAddPrevSibling(doc->children, (xmlNodePtr) dtd);
    }

#endif

    doc->extSubset = dtd;
}


static void rp_cdecl
rp_http_xslt_sax_error(void *data, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = data;

    size_t                       n;
    va_list                      args;
    rp_http_xslt_filter_ctx_t  *ctx;
    u_char                       buf[RP_MAX_ERROR_STR];

    ctx = ctxt->sax->_private;

    buf[0] = '\0';

    va_start(args, msg);
    n = (size_t) vsnprintf((char *) buf, RP_MAX_ERROR_STR, msg, args);
    va_end(args);

    while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    rp_log_error(RP_LOG_ERR, ctx->request->connection->log, 0,
                  "libxml2 error: \"%*s\"", n + 1, buf);
}


static rp_buf_t *
rp_http_xslt_apply_stylesheet(rp_http_request_t *r,
    rp_http_xslt_filter_ctx_t *ctx)
{
    int                               len, rc, doc_type;
    u_char                           *type, *encoding;
    rp_buf_t                        *b;
    rp_uint_t                        i;
    xmlChar                          *buf;
    xmlDocPtr                         doc, res;
    rp_http_xslt_sheet_t            *sheet;
    rp_http_xslt_filter_loc_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_xslt_filter_module);
    sheet = conf->sheets.elts;
    doc = ctx->doc;

    /* preallocate array for 4 params */

    if (rp_array_init(&ctx->params, r->pool, 4 * 2 + 1, sizeof(char *))
        != RP_OK)
    {
        xmlFreeDoc(doc);
        return NULL;
    }

    for (i = 0; i < conf->sheets.nelts; i++) {

        ctx->transform = xsltNewTransformContext(sheet[i].stylesheet, doc);
        if (ctx->transform == NULL) {
            xmlFreeDoc(doc);
            return NULL;
        }

        if (conf->params
            && rp_http_xslt_params(r, ctx, conf->params, 0) != RP_OK)
        {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        if (rp_http_xslt_params(r, ctx, &sheet[i].params, 1) != RP_OK) {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        res = xsltApplyStylesheetUser(sheet[i].stylesheet, doc,
                                      ctx->params.elts, NULL, NULL,
                                      ctx->transform);

        xsltFreeTransformContext(ctx->transform);
        xmlFreeDoc(doc);

        if (res == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;

        /* reset array elements */
        ctx->params.nelts = 0;
    }

    /* there must be at least one stylesheet */

    if (r == r->main) {
        type = rp_http_xslt_content_type(sheet[i - 1].stylesheet);

    } else {
        type = NULL;
    }

    encoding = rp_http_xslt_encoding(sheet[i - 1].stylesheet);
    doc_type = doc->type;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter type: %d t:%s e:%s",
                   doc_type, type ? type : (u_char *) "(null)",
                   encoding ? encoding : (u_char *) "(null)");

    rc = xsltSaveResultToString(&buf, &len, doc, sheet[i - 1].stylesheet);

    xmlFreeDoc(doc);

    if (rc != 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() failed");
        return NULL;
    }

    if (len == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() returned zero-length result");
        return NULL;
    }

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        rp_free(buf);
        return NULL;
    }

    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;

    if (encoding) {
        r->headers_out.charset.len = rp_strlen(encoding);
        r->headers_out.charset.data = encoding;
    }

    if (r != r->main) {
        return b;
    }

    b->last_buf = 1;

    if (type) {
        len = rp_strlen(type);

        r->headers_out.content_type_len = len;
        r->headers_out.content_type.len = len;
        r->headers_out.content_type.data = type;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        rp_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return b;
}


static rp_int_t
rp_http_xslt_params(rp_http_request_t *r, rp_http_xslt_filter_ctx_t *ctx,
    rp_array_t *params, rp_uint_t final)
{
    u_char                 *p, *value, *dst, *src, **s;
    size_t                  len;
    rp_uint_t              i;
    rp_str_t               string;
    rp_http_xslt_param_t  *param;

    param = params->elts;

    for (i = 0; i < params->nelts; i++) {

        if (rp_http_complex_value(r, &param[i].value, &string) != RP_OK) {
            return RP_ERROR;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xslt filter param: \"%s\"", string.data);

        if (param[i].name) {

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", param[i].name);

            if (param[i].quote) {
                if (xsltQuoteOneUserParam(ctx->transform, param[i].name,
                                          string.data)
                    != 0)
                {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                "xsltQuoteOneUserParam(\"%s\", \"%s\") failed",
                                param[i].name, string.data);
                    return RP_ERROR;
                }

                continue;
            }

            s = rp_array_push(&ctx->params);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = param[i].name;

            s = rp_array_push(&ctx->params);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = string.data;

            continue;
        }

        /*
         * parse param1=value1:param2=value2 syntax as used by parameters
         * specified in xslt_stylesheet directives
         */

        if (param[i].value.lengths) {
            p = string.data;

        } else {
            p = rp_pnalloc(r->pool, string.len + 1);
            if (p == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(p, string.data, string.len + 1);
        }

        while (p && *p) {

            value = p;
            p = (u_char *) rp_strchr(p, '=');
            if (p == NULL) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                "invalid libxslt parameter \"%s\"", value);
                return RP_ERROR;
            }
            *p++ = '\0';

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", value);

            s = rp_array_push(&ctx->params);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = value;

            value = p;
            p = (u_char *) rp_strchr(p, ':');

            if (p) {
                len = p - value;
                *p++ = '\0';

            } else {
                len = rp_strlen(value);
            }

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param value: \"%s\"", value);

            dst = value;
            src = value;

            rp_unescape_uri(&dst, &src, len, 0);

            *dst = '\0';

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param unescaped: \"%s\"", value);

            s = rp_array_push(&ctx->params);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = value;
        }
    }

    if (final) {
        s = rp_array_push(&ctx->params);
        if (s == NULL) {
            return RP_ERROR;
        }

        *s = NULL;
    }

    return RP_OK;
}


static u_char *
rp_http_xslt_content_type(xsltStylesheetPtr s)
{
    u_char  *type;

    if (s->mediaType) {
        return s->mediaType;
    }

    for (s = s->imports; s; s = s->next) {

        type = rp_http_xslt_content_type(s);

        if (type) {
            return type;
        }
    }

    return NULL;
}


static u_char *
rp_http_xslt_encoding(xsltStylesheetPtr s)
{
    u_char  *encoding;

    if (s->encoding) {
        return s->encoding;
    }

    for (s = s->imports; s; s = s->next) {

        encoding = rp_http_xslt_encoding(s);

        if (encoding) {
            return encoding;
        }
    }

    return NULL;
}


static void
rp_http_xslt_cleanup(void *data)
{
    rp_free(data);
}


static char *
rp_http_xslt_entities(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_xslt_filter_loc_conf_t *xlcf = conf;

    rp_str_t                         *value;
    rp_uint_t                         i;
    rp_pool_cleanup_t                *cln;
    rp_http_xslt_file_t              *file;
    rp_http_xslt_filter_main_conf_t  *xmcf;

    if (xlcf->dtd) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = rp_http_conf_get_module_main_conf(cf, rp_http_xslt_filter_module);

    file = xmcf->dtd_files.elts;
    for (i = 0; i < xmcf->dtd_files.nelts; i++) {
        if (rp_strcmp(file[i].name, value[1].data) == 0) {
            xlcf->dtd = file[i].data;
            return RP_CONF_OK;
        }
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RP_CONF_ERROR;
    }

    xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);

    if (xlcf->dtd == NULL) {
        rp_conf_log_error(RP_LOG_ERR, cf, 0, "xmlParseDTD() failed");
        return RP_CONF_ERROR;
    }

    cln->handler = rp_http_xslt_cleanup_dtd;
    cln->data = xlcf->dtd;

    file = rp_array_push(&xmcf->dtd_files);
    if (file == NULL) {
        return RP_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = xlcf->dtd;

    return RP_CONF_OK;
}



static char *
rp_http_xslt_stylesheet(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_xslt_filter_loc_conf_t *xlcf = conf;

    rp_str_t                         *value;
    rp_uint_t                         i, n;
    rp_pool_cleanup_t                *cln;
    rp_http_xslt_file_t              *file;
    rp_http_xslt_sheet_t             *sheet;
    rp_http_xslt_param_t             *param;
    rp_http_compile_complex_value_t   ccv;
    rp_http_xslt_filter_main_conf_t  *xmcf;

    value = cf->args->elts;

    if (xlcf->sheets.elts == NULL) {
        if (rp_array_init(&xlcf->sheets, cf->pool, 1,
                           sizeof(rp_http_xslt_sheet_t))
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    sheet = rp_array_push(&xlcf->sheets);
    if (sheet == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(sheet, sizeof(rp_http_xslt_sheet_t));

    if (rp_conf_full_name(cf->cycle, &value[1], 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    xmcf = rp_http_conf_get_module_main_conf(cf, rp_http_xslt_filter_module);

    file = xmcf->sheet_files.elts;
    for (i = 0; i < xmcf->sheet_files.nelts; i++) {
        if (rp_strcmp(file[i].name, value[1].data) == 0) {
            sheet->stylesheet = file[i].data;
            goto found;
        }
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RP_CONF_ERROR;
    }

    sheet->stylesheet = xsltParseStylesheetFile(value[1].data);
    if (sheet->stylesheet == NULL) {
        rp_conf_log_error(RP_LOG_ERR, cf, 0,
                           "xsltParseStylesheetFile(\"%s\") failed",
                           value[1].data);
        return RP_CONF_ERROR;
    }

    cln->handler = rp_http_xslt_cleanup_stylesheet;
    cln->data = sheet->stylesheet;

    file = rp_array_push(&xmcf->sheet_files);
    if (file == NULL) {
        return RP_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = sheet->stylesheet;

found:

    n = cf->args->nelts;

    if (n == 2) {
        return RP_CONF_OK;
    }

    if (rp_array_init(&sheet->params, cf->pool, n - 2,
                       sizeof(rp_http_xslt_param_t))
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    for (i = 2; i < n; i++) {

        param = rp_array_push(&sheet->params);
        if (param == NULL) {
            return RP_CONF_ERROR;
        }

        rp_memzero(param, sizeof(rp_http_xslt_param_t));
        rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &param->value;
        ccv.zero = 1;

        if (rp_http_compile_complex_value(&ccv) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_http_xslt_param(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_xslt_filter_loc_conf_t  *xlcf = conf;

    rp_http_xslt_param_t            *param;
    rp_http_compile_complex_value_t  ccv;
    rp_str_t                        *value;

    value = cf->args->elts;

    if (xlcf->params == NULL) {
        xlcf->params = rp_array_create(cf->pool, 2,
                                        sizeof(rp_http_xslt_param_t));
        if (xlcf->params == NULL) {
            return RP_CONF_ERROR;
        }
    }

    param = rp_array_push(xlcf->params);
    if (param == NULL) {
        return RP_CONF_ERROR;
    }

    param->name = value[1].data;
    param->quote = (cmd->post == NULL) ? 0 : 1;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &param->value;
    ccv.zero = 1;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static void
rp_http_xslt_cleanup_dtd(void *data)
{
    xmlFreeDtd(data);
}


static void
rp_http_xslt_cleanup_stylesheet(void *data)
{
    xsltFreeStylesheet(data);
}


static void *
rp_http_xslt_filter_create_main_conf(rp_conf_t *cf)
{
    rp_http_xslt_filter_main_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_xslt_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (rp_array_init(&conf->dtd_files, cf->pool, 1,
                       sizeof(rp_http_xslt_file_t))
        != RP_OK)
    {
        return NULL;
    }

    if (rp_array_init(&conf->sheet_files, cf->pool, 1,
                       sizeof(rp_http_xslt_file_t))
        != RP_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
rp_http_xslt_filter_create_conf(rp_conf_t *cf)
{
    rp_http_xslt_filter_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_xslt_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->dtd = NULL;
     *     conf->sheets = { NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->params = NULL;
     */

    conf->last_modified = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_xslt_filter_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_xslt_filter_loc_conf_t *prev = parent;
    rp_http_xslt_filter_loc_conf_t *conf = child;

    if (conf->dtd == NULL) {
        conf->dtd = prev->dtd;
    }

    if (conf->sheets.nelts == 0) {
        conf->sheets = prev->sheets;
    }

    if (conf->params == NULL) {
        conf->params = prev->params;
    }

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_xslt_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_xslt_filter_preconfiguration(rp_conf_t *cf)
{
    xmlInitParser();

#if (RP_HAVE_EXSLT)
    exsltRegisterAll();
#endif

    return RP_OK;
}


static rp_int_t
rp_http_xslt_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_xslt_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_xslt_body_filter;

    return RP_OK;
}


static void
rp_http_xslt_filter_exit(rp_cycle_t *cycle)
{
    xsltCleanupGlobals();
    xmlCleanupParser();
}
