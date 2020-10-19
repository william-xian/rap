
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/variables.h>
#include <libxslt/xsltutils.h>

#if (RAP_HAVE_EXSLT)
#include <libexslt/exslt.h>
#endif


#ifndef RAP_HTTP_XSLT_REUSE_DTD
#define RAP_HTTP_XSLT_REUSE_DTD  1
#endif


typedef struct {
    u_char                    *name;
    void                      *data;
} rap_http_xslt_file_t;


typedef struct {
    rap_array_t                dtd_files;    /* rap_http_xslt_file_t */
    rap_array_t                sheet_files;  /* rap_http_xslt_file_t */
} rap_http_xslt_filter_main_conf_t;


typedef struct {
    u_char                    *name;
    rap_http_complex_value_t   value;
    rap_uint_t                 quote;        /* unsigned  quote:1; */
} rap_http_xslt_param_t;


typedef struct {
    xsltStylesheetPtr          stylesheet;
    rap_array_t                params;       /* rap_http_xslt_param_t */
} rap_http_xslt_sheet_t;


typedef struct {
    xmlDtdPtr                  dtd;
    rap_array_t                sheets;       /* rap_http_xslt_sheet_t */
    rap_hash_t                 types;
    rap_array_t               *types_keys;
    rap_array_t               *params;       /* rap_http_xslt_param_t */
    rap_flag_t                 last_modified;
} rap_http_xslt_filter_loc_conf_t;


typedef struct {
    xmlDocPtr                  doc;
    xmlParserCtxtPtr           ctxt;
    xsltTransformContextPtr    transform;
    rap_http_request_t        *request;
    rap_array_t                params;

    rap_uint_t                 done;         /* unsigned  done:1; */
} rap_http_xslt_filter_ctx_t;


static rap_int_t rap_http_xslt_send(rap_http_request_t *r,
    rap_http_xslt_filter_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_xslt_add_chunk(rap_http_request_t *r,
    rap_http_xslt_filter_ctx_t *ctx, rap_buf_t *b);


static void rap_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId);
static void rap_cdecl rap_http_xslt_sax_error(void *data, const char *msg, ...);


static rap_buf_t *rap_http_xslt_apply_stylesheet(rap_http_request_t *r,
    rap_http_xslt_filter_ctx_t *ctx);
static rap_int_t rap_http_xslt_params(rap_http_request_t *r,
    rap_http_xslt_filter_ctx_t *ctx, rap_array_t *params, rap_uint_t final);
static u_char *rap_http_xslt_content_type(xsltStylesheetPtr s);
static u_char *rap_http_xslt_encoding(xsltStylesheetPtr s);
static void rap_http_xslt_cleanup(void *data);

static char *rap_http_xslt_entities(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_xslt_stylesheet(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_xslt_param(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static void rap_http_xslt_cleanup_dtd(void *data);
static void rap_http_xslt_cleanup_stylesheet(void *data);
static void *rap_http_xslt_filter_create_main_conf(rap_conf_t *cf);
static void *rap_http_xslt_filter_create_conf(rap_conf_t *cf);
static char *rap_http_xslt_filter_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_xslt_filter_preconfiguration(rap_conf_t *cf);
static rap_int_t rap_http_xslt_filter_init(rap_conf_t *cf);
static void rap_http_xslt_filter_exit(rap_cycle_t *cycle);


static rap_str_t  rap_http_xslt_default_types[] = {
    rap_string("text/xml"),
    rap_null_string
};


static rap_command_t  rap_http_xslt_filter_commands[] = {

    { rap_string("xml_entities"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_xslt_entities,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("xslt_stylesheet"),
      RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_xslt_stylesheet,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("xslt_param"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_http_xslt_param,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("xslt_string_param"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_http_xslt_param,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) 1 },

    { rap_string("xslt_types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_types_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_xslt_filter_loc_conf_t, types_keys),
      &rap_http_xslt_default_types[0] },

    { rap_string("xslt_last_modified"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_xslt_filter_loc_conf_t, last_modified),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_xslt_filter_module_ctx = {
    rap_http_xslt_filter_preconfiguration, /* preconfiguration */
    rap_http_xslt_filter_init,             /* postconfiguration */

    rap_http_xslt_filter_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_xslt_filter_create_conf,      /* create location configuration */
    rap_http_xslt_filter_merge_conf        /* merge location configuration */
};


rap_module_t  rap_http_xslt_filter_module = {
    RAP_MODULE_V1,
    &rap_http_xslt_filter_module_ctx,      /* module context */
    rap_http_xslt_filter_commands,         /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rap_http_xslt_filter_exit,             /* exit process */
    rap_http_xslt_filter_exit,             /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_xslt_header_filter(rap_http_request_t *r)
{
    rap_http_xslt_filter_ctx_t       *ctx;
    rap_http_xslt_filter_loc_conf_t  *conf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter header");

    if (r->headers_out.status == RAP_HTTP_NOT_MODIFIED) {
        return rap_http_next_header_filter(r);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_xslt_filter_module);

    if (conf->sheets.nelts == 0
        || rap_http_test_content_type(r, &conf->types) == NULL)
    {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_http_get_module_ctx(r, rap_http_xslt_filter_module);

    if (ctx) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_xslt_filter_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_xslt_filter_module);

    r->main_filter_need_in_memory = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_xslt_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    int                          wellFormed;
    rap_chain_t                 *cl;
    rap_http_xslt_filter_ctx_t  *ctx;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter body");

    if (in == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    ctx = rap_http_get_module_ctx(r, rap_http_xslt_filter_module);

    if (ctx == NULL || ctx->done) {
        return rap_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {

        if (rap_http_xslt_add_chunk(r, ctx, cl->buf) != RAP_OK) {

            if (ctx->ctxt->myDoc) {

#if (RAP_HTTP_XSLT_REUSE_DTD)
                ctx->ctxt->myDoc->extSubset = NULL;
#endif
                xmlFreeDoc(ctx->ctxt->myDoc);
            }

            xmlFreeParserCtxt(ctx->ctxt);

            return rap_http_xslt_send(r, ctx, NULL);
        }

        if (cl->buf->last_buf || cl->buf->last_in_chain) {

            ctx->doc = ctx->ctxt->myDoc;

#if (RAP_HTTP_XSLT_REUSE_DTD)
            ctx->doc->extSubset = NULL;
#endif

            wellFormed = ctx->ctxt->wellFormed;

            xmlFreeParserCtxt(ctx->ctxt);

            if (wellFormed) {
                return rap_http_xslt_send(r, ctx,
                                       rap_http_xslt_apply_stylesheet(r, ctx));
            }

            xmlFreeDoc(ctx->doc);

            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "not well formed XML document");

            return rap_http_xslt_send(r, ctx, NULL);
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_xslt_send(rap_http_request_t *r, rap_http_xslt_filter_ctx_t *ctx,
    rap_buf_t *b)
{
    rap_int_t                         rc;
    rap_chain_t                       out;
    rap_pool_cleanup_t               *cln;
    rap_http_xslt_filter_loc_conf_t  *conf;

    ctx->done = 1;

    if (b == NULL) {
        return rap_http_filter_finalize_request(r, &rap_http_xslt_filter_module,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
    }

    cln = rap_pool_cleanup_add(r->pool, 0);

    if (cln == NULL) {
        rap_free(b->pos);
        return rap_http_filter_finalize_request(r, &rap_http_xslt_filter_module,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
    }

    if (r == r->main) {
        r->headers_out.content_length_n = b->last - b->pos;

        if (r->headers_out.content_length) {
            r->headers_out.content_length->hash = 0;
            r->headers_out.content_length = NULL;
        }

        conf = rap_http_get_module_loc_conf(r, rap_http_xslt_filter_module);

        if (!conf->last_modified) {
            rap_http_clear_last_modified(r);
            rap_http_clear_etag(r);

        } else {
            rap_http_weak_etag(r);
        }
    }

    rc = rap_http_next_header_filter(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        rap_free(b->pos);
        return rc;
    }

    cln->handler = rap_http_xslt_cleanup;
    cln->data = b->pos;

    out.buf = b;
    out.next = NULL;

    return rap_http_next_body_filter(r, &out);
}


static rap_int_t
rap_http_xslt_add_chunk(rap_http_request_t *r, rap_http_xslt_filter_ctx_t *ctx,
    rap_buf_t *b)
{
    int               err;
    xmlParserCtxtPtr  ctxt;

    if (ctx->ctxt == NULL) {

        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
        if (ctxt == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "xmlCreatePushParserCtxt() failed");
            return RAP_ERROR;
        }
        xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD
                                               |XML_PARSE_NOWARNING);

        ctxt->sax->externalSubset = rap_http_xslt_sax_external_subset;
        ctxt->sax->setDocumentLocator = NULL;
        ctxt->sax->error = rap_http_xslt_sax_error;
        ctxt->sax->fatalError = rap_http_xslt_sax_error;
        ctxt->sax->_private = ctx;

        ctx->ctxt = ctxt;
        ctx->request = r;
    }

    err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
                        (b->last_buf) || (b->last_in_chain));

    if (err == 0) {
        b->pos = b->last;
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "xmlParseChunk() failed, error:%d", err);

    return RAP_ERROR;
}


static void
rap_http_xslt_sax_external_subset(void *data, const xmlChar *name,
    const xmlChar *externalId, const xmlChar *systemId)
{
    xmlParserCtxtPtr ctxt = data;

    xmlDocPtr                         doc;
    xmlDtdPtr                         dtd;
    rap_http_request_t               *r;
    rap_http_xslt_filter_ctx_t       *ctx;
    rap_http_xslt_filter_loc_conf_t  *conf;

    ctx = ctxt->sax->_private;
    r = ctx->request;

    conf = rap_http_get_module_loc_conf(r, rap_http_xslt_filter_module);

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
                   name ? name : (xmlChar *) "",
                   externalId ? externalId : (xmlChar *) "",
                   systemId ? systemId : (xmlChar *) "");

    doc = ctxt->myDoc;

#if (RAP_HTTP_XSLT_REUSE_DTD)

    dtd = conf->dtd;

#else

    dtd = xmlCopyDtd(conf->dtd);
    if (dtd == NULL) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
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


static void rap_cdecl
rap_http_xslt_sax_error(void *data, const char *msg, ...)
{
    xmlParserCtxtPtr ctxt = data;

    size_t                       n;
    va_list                      args;
    rap_http_xslt_filter_ctx_t  *ctx;
    u_char                       buf[RAP_MAX_ERROR_STR];

    ctx = ctxt->sax->_private;

    buf[0] = '\0';

    va_start(args, msg);
    n = (size_t) vsnprintf((char *) buf, RAP_MAX_ERROR_STR, msg, args);
    va_end(args);

    while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    rap_log_error(RAP_LOG_ERR, ctx->request->connection->log, 0,
                  "libxml2 error: \"%*s\"", n + 1, buf);
}


static rap_buf_t *
rap_http_xslt_apply_stylesheet(rap_http_request_t *r,
    rap_http_xslt_filter_ctx_t *ctx)
{
    int                               len, rc, doc_type;
    u_char                           *type, *encoding;
    rap_buf_t                        *b;
    rap_uint_t                        i;
    xmlChar                          *buf;
    xmlDocPtr                         doc, res;
    rap_http_xslt_sheet_t            *sheet;
    rap_http_xslt_filter_loc_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_xslt_filter_module);
    sheet = conf->sheets.elts;
    doc = ctx->doc;

    /* preallocate array for 4 params */

    if (rap_array_init(&ctx->params, r->pool, 4 * 2 + 1, sizeof(char *))
        != RAP_OK)
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
            && rap_http_xslt_params(r, ctx, conf->params, 0) != RAP_OK)
        {
            xsltFreeTransformContext(ctx->transform);
            xmlFreeDoc(doc);
            return NULL;
        }

        if (rap_http_xslt_params(r, ctx, &sheet[i].params, 1) != RAP_OK) {
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
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "xsltApplyStylesheet() failed");
            return NULL;
        }

        doc = res;

        /* reset array elements */
        ctx->params.nelts = 0;
    }

    /* there must be at least one stylesheet */

    if (r == r->main) {
        type = rap_http_xslt_content_type(sheet[i - 1].stylesheet);

    } else {
        type = NULL;
    }

    encoding = rap_http_xslt_encoding(sheet[i - 1].stylesheet);
    doc_type = doc->type;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "xslt filter type: %d t:%s e:%s",
                   doc_type, type ? type : (u_char *) "(null)",
                   encoding ? encoding : (u_char *) "(null)");

    rc = xsltSaveResultToString(&buf, &len, doc, sheet[i - 1].stylesheet);

    xmlFreeDoc(doc);

    if (rc != 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() failed");
        return NULL;
    }

    if (len == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "xsltSaveResultToString() returned zero-length result");
        return NULL;
    }

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        rap_free(buf);
        return NULL;
    }

    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;

    if (encoding) {
        r->headers_out.charset.len = rap_strlen(encoding);
        r->headers_out.charset.data = encoding;
    }

    if (r != r->main) {
        return b;
    }

    b->last_buf = 1;

    if (type) {
        len = rap_strlen(type);

        r->headers_out.content_type_len = len;
        r->headers_out.content_type.len = len;
        r->headers_out.content_type.data = type;

    } else if (doc_type == XML_HTML_DOCUMENT_NODE) {

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        rap_str_set(&r->headers_out.content_type, "text/html");
    }

    r->headers_out.content_type_lowcase = NULL;

    return b;
}


static rap_int_t
rap_http_xslt_params(rap_http_request_t *r, rap_http_xslt_filter_ctx_t *ctx,
    rap_array_t *params, rap_uint_t final)
{
    u_char                 *p, *value, *dst, *src, **s;
    size_t                  len;
    rap_uint_t              i;
    rap_str_t               string;
    rap_http_xslt_param_t  *param;

    param = params->elts;

    for (i = 0; i < params->nelts; i++) {

        if (rap_http_complex_value(r, &param[i].value, &string) != RAP_OK) {
            return RAP_ERROR;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xslt filter param: \"%s\"", string.data);

        if (param[i].name) {

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", param[i].name);

            if (param[i].quote) {
                if (xsltQuoteOneUserParam(ctx->transform, param[i].name,
                                          string.data)
                    != 0)
                {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                "xsltQuoteOneUserParam(\"%s\", \"%s\") failed",
                                param[i].name, string.data);
                    return RAP_ERROR;
                }

                continue;
            }

            s = rap_array_push(&ctx->params);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = param[i].name;

            s = rap_array_push(&ctx->params);
            if (s == NULL) {
                return RAP_ERROR;
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
            p = rap_pnalloc(r->pool, string.len + 1);
            if (p == NULL) {
                return RAP_ERROR;
            }

            rap_memcpy(p, string.data, string.len + 1);
        }

        while (p && *p) {

            value = p;
            p = (u_char *) rap_strchr(p, '=');
            if (p == NULL) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                "invalid libxslt parameter \"%s\"", value);
                return RAP_ERROR;
            }
            *p++ = '\0';

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param name: \"%s\"", value);

            s = rap_array_push(&ctx->params);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = value;

            value = p;
            p = (u_char *) rap_strchr(p, ':');

            if (p) {
                len = p - value;
                *p++ = '\0';

            } else {
                len = rap_strlen(value);
            }

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param value: \"%s\"", value);

            dst = value;
            src = value;

            rap_unescape_uri(&dst, &src, len, 0);

            *dst = '\0';

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "xslt filter param unescaped: \"%s\"", value);

            s = rap_array_push(&ctx->params);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = value;
        }
    }

    if (final) {
        s = rap_array_push(&ctx->params);
        if (s == NULL) {
            return RAP_ERROR;
        }

        *s = NULL;
    }

    return RAP_OK;
}


static u_char *
rap_http_xslt_content_type(xsltStylesheetPtr s)
{
    u_char  *type;

    if (s->mediaType) {
        return s->mediaType;
    }

    for (s = s->imports; s; s = s->next) {

        type = rap_http_xslt_content_type(s);

        if (type) {
            return type;
        }
    }

    return NULL;
}


static u_char *
rap_http_xslt_encoding(xsltStylesheetPtr s)
{
    u_char  *encoding;

    if (s->encoding) {
        return s->encoding;
    }

    for (s = s->imports; s; s = s->next) {

        encoding = rap_http_xslt_encoding(s);

        if (encoding) {
            return encoding;
        }
    }

    return NULL;
}


static void
rap_http_xslt_cleanup(void *data)
{
    rap_free(data);
}


static char *
rap_http_xslt_entities(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_xslt_filter_loc_conf_t *xlcf = conf;

    rap_str_t                         *value;
    rap_uint_t                         i;
    rap_pool_cleanup_t                *cln;
    rap_http_xslt_file_t              *file;
    rap_http_xslt_filter_main_conf_t  *xmcf;

    if (xlcf->dtd) {
        return "is duplicate";
    }

    value = cf->args->elts;

    xmcf = rap_http_conf_get_module_main_conf(cf, rap_http_xslt_filter_module);

    file = xmcf->dtd_files.elts;
    for (i = 0; i < xmcf->dtd_files.nelts; i++) {
        if (rap_strcmp(file[i].name, value[1].data) == 0) {
            xlcf->dtd = file[i].data;
            return RAP_CONF_OK;
        }
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_CONF_ERROR;
    }

    xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);

    if (xlcf->dtd == NULL) {
        rap_conf_log_error(RAP_LOG_ERR, cf, 0, "xmlParseDTD() failed");
        return RAP_CONF_ERROR;
    }

    cln->handler = rap_http_xslt_cleanup_dtd;
    cln->data = xlcf->dtd;

    file = rap_array_push(&xmcf->dtd_files);
    if (file == NULL) {
        return RAP_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = xlcf->dtd;

    return RAP_CONF_OK;
}



static char *
rap_http_xslt_stylesheet(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_xslt_filter_loc_conf_t *xlcf = conf;

    rap_str_t                         *value;
    rap_uint_t                         i, n;
    rap_pool_cleanup_t                *cln;
    rap_http_xslt_file_t              *file;
    rap_http_xslt_sheet_t             *sheet;
    rap_http_xslt_param_t             *param;
    rap_http_compile_complex_value_t   ccv;
    rap_http_xslt_filter_main_conf_t  *xmcf;

    value = cf->args->elts;

    if (xlcf->sheets.elts == NULL) {
        if (rap_array_init(&xlcf->sheets, cf->pool, 1,
                           sizeof(rap_http_xslt_sheet_t))
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    sheet = rap_array_push(&xlcf->sheets);
    if (sheet == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(sheet, sizeof(rap_http_xslt_sheet_t));

    if (rap_conf_full_name(cf->cycle, &value[1], 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    xmcf = rap_http_conf_get_module_main_conf(cf, rap_http_xslt_filter_module);

    file = xmcf->sheet_files.elts;
    for (i = 0; i < xmcf->sheet_files.nelts; i++) {
        if (rap_strcmp(file[i].name, value[1].data) == 0) {
            sheet->stylesheet = file[i].data;
            goto found;
        }
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_CONF_ERROR;
    }

    sheet->stylesheet = xsltParseStylesheetFile(value[1].data);
    if (sheet->stylesheet == NULL) {
        rap_conf_log_error(RAP_LOG_ERR, cf, 0,
                           "xsltParseStylesheetFile(\"%s\") failed",
                           value[1].data);
        return RAP_CONF_ERROR;
    }

    cln->handler = rap_http_xslt_cleanup_stylesheet;
    cln->data = sheet->stylesheet;

    file = rap_array_push(&xmcf->sheet_files);
    if (file == NULL) {
        return RAP_CONF_ERROR;
    }

    file->name = value[1].data;
    file->data = sheet->stylesheet;

found:

    n = cf->args->nelts;

    if (n == 2) {
        return RAP_CONF_OK;
    }

    if (rap_array_init(&sheet->params, cf->pool, n - 2,
                       sizeof(rap_http_xslt_param_t))
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    for (i = 2; i < n; i++) {

        param = rap_array_push(&sheet->params);
        if (param == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_memzero(param, sizeof(rap_http_xslt_param_t));
        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = &param->value;
        ccv.zero = 1;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_http_xslt_param(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_xslt_filter_loc_conf_t  *xlcf = conf;

    rap_http_xslt_param_t            *param;
    rap_http_compile_complex_value_t  ccv;
    rap_str_t                        *value;

    value = cf->args->elts;

    if (xlcf->params == NULL) {
        xlcf->params = rap_array_create(cf->pool, 2,
                                        sizeof(rap_http_xslt_param_t));
        if (xlcf->params == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    param = rap_array_push(xlcf->params);
    if (param == NULL) {
        return RAP_CONF_ERROR;
    }

    param->name = value[1].data;
    param->quote = (cmd->post == NULL) ? 0 : 1;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &param->value;
    ccv.zero = 1;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static void
rap_http_xslt_cleanup_dtd(void *data)
{
    xmlFreeDtd(data);
}


static void
rap_http_xslt_cleanup_stylesheet(void *data)
{
    xsltFreeStylesheet(data);
}


static void *
rap_http_xslt_filter_create_main_conf(rap_conf_t *cf)
{
    rap_http_xslt_filter_main_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_xslt_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (rap_array_init(&conf->dtd_files, cf->pool, 1,
                       sizeof(rap_http_xslt_file_t))
        != RAP_OK)
    {
        return NULL;
    }

    if (rap_array_init(&conf->sheet_files, cf->pool, 1,
                       sizeof(rap_http_xslt_file_t))
        != RAP_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
rap_http_xslt_filter_create_conf(rap_conf_t *cf)
{
    rap_http_xslt_filter_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_xslt_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->dtd = NULL;
     *     conf->sheets = { NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->params = NULL;
     */

    conf->last_modified = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_xslt_filter_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_xslt_filter_loc_conf_t *prev = parent;
    rap_http_xslt_filter_loc_conf_t *conf = child;

    if (conf->dtd == NULL) {
        conf->dtd = prev->dtd;
    }

    if (conf->sheets.nelts == 0) {
        conf->sheets = prev->sheets;
    }

    if (conf->params == NULL) {
        conf->params = prev->params;
    }

    if (rap_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rap_http_xslt_default_types)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_xslt_filter_preconfiguration(rap_conf_t *cf)
{
    xmlInitParser();

#if (RAP_HAVE_EXSLT)
    exsltRegisterAll();
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_xslt_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_xslt_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_xslt_body_filter;

    return RAP_OK;
}


static void
rap_http_xslt_filter_exit(rap_cycle_t *cycle)
{
    xsltCleanupGlobals();
    xmlCleanupParser();
}
