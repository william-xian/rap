
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#include <gd.h>


#define RP_HTTP_IMAGE_OFF       0
#define RP_HTTP_IMAGE_TEST      1
#define RP_HTTP_IMAGE_SIZE      2
#define RP_HTTP_IMAGE_RESIZE    3
#define RP_HTTP_IMAGE_CROP      4
#define RP_HTTP_IMAGE_ROTATE    5


#define RP_HTTP_IMAGE_START     0
#define RP_HTTP_IMAGE_READ      1
#define RP_HTTP_IMAGE_PROCESS   2
#define RP_HTTP_IMAGE_PASS      3
#define RP_HTTP_IMAGE_DONE      4


#define RP_HTTP_IMAGE_NONE      0
#define RP_HTTP_IMAGE_JPEG      1
#define RP_HTTP_IMAGE_GIF       2
#define RP_HTTP_IMAGE_PNG       3
#define RP_HTTP_IMAGE_WEBP      4


#define RP_HTTP_IMAGE_BUFFERED  0x08


typedef struct {
    rp_uint_t                   filter;
    rp_uint_t                   width;
    rp_uint_t                   height;
    rp_uint_t                   angle;
    rp_uint_t                   jpeg_quality;
    rp_uint_t                   webp_quality;
    rp_uint_t                   sharpen;

    rp_flag_t                   transparency;
    rp_flag_t                   interlace;

    rp_http_complex_value_t    *wcv;
    rp_http_complex_value_t    *hcv;
    rp_http_complex_value_t    *acv;
    rp_http_complex_value_t    *jqcv;
    rp_http_complex_value_t    *wqcv;
    rp_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} rp_http_image_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;

    rp_uint_t                   width;
    rp_uint_t                   height;
    rp_uint_t                   max_width;
    rp_uint_t                   max_height;
    rp_uint_t                   angle;

    rp_uint_t                   phase;
    rp_uint_t                   type;
    rp_uint_t                   force;
} rp_http_image_filter_ctx_t;


static rp_int_t rp_http_image_send(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx, rp_chain_t *in);
static rp_uint_t rp_http_image_test(rp_http_request_t *r, rp_chain_t *in);
static rp_int_t rp_http_image_read(rp_http_request_t *r, rp_chain_t *in);
static rp_buf_t *rp_http_image_process(rp_http_request_t *r);
static rp_buf_t *rp_http_image_json(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx);
static rp_buf_t *rp_http_image_asis(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx);
static void rp_http_image_length(rp_http_request_t *r, rp_buf_t *b);
static rp_int_t rp_http_image_size(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx);

static rp_buf_t *rp_http_image_resize(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx);
static gdImagePtr rp_http_image_source(rp_http_request_t *r,
    rp_http_image_filter_ctx_t *ctx);
static gdImagePtr rp_http_image_new(rp_http_request_t *r, int w, int h,
    int colors);
static u_char *rp_http_image_out(rp_http_request_t *r, rp_uint_t type,
    gdImagePtr img, int *size);
static void rp_http_image_cleanup(void *data);
static rp_uint_t rp_http_image_filter_get_value(rp_http_request_t *r,
    rp_http_complex_value_t *cv, rp_uint_t v);
static rp_uint_t rp_http_image_filter_value(rp_str_t *value);


static void *rp_http_image_filter_create_conf(rp_conf_t *cf);
static char *rp_http_image_filter_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_image_filter(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_image_filter_jpeg_quality(rp_conf_t *cf,
    rp_command_t *cmd, void *conf);
static char *rp_http_image_filter_webp_quality(rp_conf_t *cf,
    rp_command_t *cmd, void *conf);
static char *rp_http_image_filter_sharpen(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_image_filter_init(rp_conf_t *cf);


static rp_command_t  rp_http_image_filter_commands[] = {

    { rp_string("image_filter"),
      RP_HTTP_LOC_CONF|RP_CONF_TAKE123,
      rp_http_image_filter,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("image_filter_jpeg_quality"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_image_filter_jpeg_quality,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("image_filter_webp_quality"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_image_filter_webp_quality,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("image_filter_sharpen"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_image_filter_sharpen,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("image_filter_transparency"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_image_filter_conf_t, transparency),
      NULL },

    { rp_string("image_filter_interlace"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_image_filter_conf_t, interlace),
      NULL },

    { rp_string("image_filter_buffer"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_image_filter_conf_t, buffer_size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_image_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_image_filter_create_conf,     /* create location configuration */
    rp_http_image_filter_merge_conf       /* merge location configuration */
};


rp_module_t  rp_http_image_filter_module = {
    RP_MODULE_V1,
    &rp_http_image_filter_module_ctx,     /* module context */
    rp_http_image_filter_commands,        /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_str_t  rp_http_image_types[] = {
    rp_string("image/jpeg"),
    rp_string("image/gif"),
    rp_string("image/png"),
    rp_string("image/webp")
};


static rp_int_t
rp_http_image_header_filter(rp_http_request_t *r)
{
    off_t                          len;
    rp_http_image_filter_ctx_t   *ctx;
    rp_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == RP_HTTP_NOT_MODIFIED) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_image_filter_module);

    if (ctx) {
        rp_http_set_ctx(r, NULL, rp_http_image_filter_module);
        return rp_http_next_header_filter(r);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

    if (conf->filter == RP_HTTP_IMAGE_OFF) {
        return rp_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && rp_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return RP_ERROR;
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return RP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return RP_OK;
}


static rp_int_t
rp_http_image_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                      rc;
    rp_str_t                     *ct;
    rp_chain_t                    out;
    rp_http_image_filter_ctx_t   *ctx;
    rp_http_image_filter_conf_t  *conf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_image_filter_module);

    if (ctx == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case RP_HTTP_IMAGE_START:

        ctx->type = rp_http_image_test(r, in);

        conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

        if (ctx->type == RP_HTTP_IMAGE_NONE) {

            if (conf->filter == RP_HTTP_IMAGE_SIZE) {
                out.buf = rp_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = RP_HTTP_IMAGE_DONE;

                    return rp_http_image_send(r, ctx, &out);
                }
            }

            return rp_http_filter_finalize_request(r,
                                              &rp_http_image_filter_module,
                                              RP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &rp_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == RP_HTTP_IMAGE_TEST) {
            ctx->phase = RP_HTTP_IMAGE_PASS;

            return rp_http_image_send(r, ctx, in);
        }

        ctx->phase = RP_HTTP_IMAGE_READ;

        /* fall through */

    case RP_HTTP_IMAGE_READ:

        rc = rp_http_image_read(r, in);

        if (rc == RP_AGAIN) {
            return RP_OK;
        }

        if (rc == RP_ERROR) {
            return rp_http_filter_finalize_request(r,
                                              &rp_http_image_filter_module,
                                              RP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case RP_HTTP_IMAGE_PROCESS:

        out.buf = rp_http_image_process(r);

        if (out.buf == NULL) {
            return rp_http_filter_finalize_request(r,
                                              &rp_http_image_filter_module,
                                              RP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = RP_HTTP_IMAGE_PASS;

        return rp_http_image_send(r, ctx, &out);

    case RP_HTTP_IMAGE_PASS:

        return rp_http_next_body_filter(r, in);

    default: /* RP_HTTP_IMAGE_DONE */

        rc = rp_http_next_body_filter(r, NULL);

        /* RP_ERROR resets any pending data */
        return (rc == RP_OK) ? RP_ERROR : rc;
    }
}


static rp_int_t
rp_http_image_send(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx,
    rp_chain_t *in)
{
    rp_int_t  rc;

    rc = rp_http_next_header_filter(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        return RP_ERROR;
    }

    rc = rp_http_next_body_filter(r, in);

    if (ctx->phase == RP_HTTP_IMAGE_DONE) {
        /* RP_ERROR resets any pending data */
        return (rc == RP_OK) ? RP_ERROR : rc;
    }

    return rc;
}


static rp_uint_t
rp_http_image_test(rp_http_request_t *r, rp_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return RP_HTTP_IMAGE_NONE;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return RP_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return RP_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return RP_HTTP_IMAGE_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
               && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WebP */

        return RP_HTTP_IMAGE_WEBP;
    }

    return RP_HTTP_IMAGE_NONE;
}


static rp_int_t
rp_http_image_read(rp_http_request_t *r, rp_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    rp_buf_t                    *b;
    rp_chain_t                  *cl;
    rp_http_image_filter_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = rp_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return RP_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "image filter: too big response");
            return RP_ERROR;
        }

        p = rp_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return RP_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= RP_HTTP_IMAGE_BUFFERED;

    return RP_AGAIN;
}


static rp_buf_t *
rp_http_image_process(rp_http_request_t *r)
{
    rp_int_t                      rc;
    rp_http_image_filter_ctx_t   *ctx;
    rp_http_image_filter_conf_t  *conf;

    r->connection->buffered &= ~RP_HTTP_IMAGE_BUFFERED;

    ctx = rp_http_get_module_ctx(r, rp_http_image_filter_module);

    rc = rp_http_image_size(r, ctx);

    conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

    if (conf->filter == RP_HTTP_IMAGE_SIZE) {
        return rp_http_image_json(r, rc == RP_OK ? ctx : NULL);
    }

    ctx->angle = rp_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == RP_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return rp_http_image_resize(r, ctx);
    }

    ctx->max_width = rp_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = rp_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == RP_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return rp_http_image_asis(r, ctx);
    }

    return rp_http_image_resize(r, ctx);
}


static rp_buf_t *
rp_http_image_json(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    rp_buf_t  *b;

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    rp_http_clean_header(r);

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    rp_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        rp_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * RP_SIZE_T_LEN;

    b->pos = rp_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = rp_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          rp_http_image_types[ctx->type - 1].data + 6);

    rp_http_image_length(r, b);

    return b;
}


static rp_buf_t *
rp_http_image_asis(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx)
{
    rp_buf_t  *b;

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    rp_http_image_length(r, b);

    return b;
}


static void
rp_http_image_length(rp_http_request_t *r, rp_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static rp_int_t
rp_http_image_size(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    rp_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case RP_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return RP_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case RP_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return RP_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case RP_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return RP_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case RP_HTTP_IMAGE_WEBP:

        if (ctx->length < 30) {
            return RP_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return RP_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return RP_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return RP_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return RP_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return RP_DECLINED;
        }

        break;

    default:

        return RP_DECLINED;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return RP_OK;
}


static rp_buf_t *
rp_http_image_resize(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t;
    u_char                        *out;
    rp_buf_t                     *b;
    rp_uint_t                     resize;
    gdImagePtr                     src, dst;
    rp_pool_cleanup_t            *cln;
    rp_http_image_filter_conf_t  *conf;

    src = rp_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (rp_uint_t) sx <= ctx->max_width
        && (rp_uint_t) sy <= ctx->max_height)
    {
        gdImageDestroy(src);
        return rp_http_image_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            red = gdImageRed(src, transparent);
            green = gdImageGreen(src, transparent);
            blue = gdImageBlue(src, transparent);

            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;
    red = 0;
    green = 0;
    blue = 0;

transparent:

    gdImageColorTransparent(src, -1);

    dx = sx;
    dy = sy;

    if (conf->filter == RP_HTTP_IMAGE_RESIZE) {

        if ((rp_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((rp_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == RP_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else { /* RP_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((rp_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((rp_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = rp_http_image_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = rp_http_image_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = rp_http_image_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == RP_HTTP_IMAGE_CROP) {

        src = dst;

        if ((rp_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((rp_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = rp_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "image crop: %d x %d @ %d x %d",
                           dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

    if (transparent != -1 && colors) {
        gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
    }

    sharpen = rp_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = rp_http_image_out(r, ctx->type, dst, &size);

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    rp_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = rp_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = rp_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    rp_http_image_length(r, b);
    rp_http_weak_etag(r);

    return b;
}


static gdImagePtr
rp_http_image_source(rp_http_request_t *r, rp_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case RP_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case RP_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case RP_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    case RP_HTTP_IMAGE_WEBP:
#if (RP_HAVE_GD_WEBP)
        img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromWebpPtr() failed";
#else
        failed = "rap was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (img == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
rp_http_image_new(rp_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
rp_http_image_out(rp_http_request_t *r, rp_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    rp_int_t                      q;
    rp_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case RP_HTTP_IMAGE_JPEG:
        conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

        q = rp_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, q);
        failed = "gdImageJpegPtr() failed";
        break;

    case RP_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case RP_HTTP_IMAGE_PNG:
        out = gdImagePngPtr(img, size);
        failed = "gdImagePngPtr() failed";
        break;

    case RP_HTTP_IMAGE_WEBP:
#if (RP_HAVE_GD_WEBP)
        conf = rp_http_get_module_loc_conf(r, rp_http_image_filter_module);

        q = rp_http_image_filter_get_value(r, conf->wqcv, conf->webp_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageWebpPtrEx(img, size, q);
        failed = "gdImageWebpPtrEx() failed";
#else
        failed = "rap was built without GD WebP support";
#endif
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (out == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
rp_http_image_cleanup(void *data)
{
    gdFree(data);
}


static rp_uint_t
rp_http_image_filter_get_value(rp_http_request_t *r,
    rp_http_complex_value_t *cv, rp_uint_t v)
{
    rp_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (rp_http_complex_value(r, cv, &val) != RP_OK) {
        return 0;
    }

    return rp_http_image_filter_value(&val);
}


static rp_uint_t
rp_http_image_filter_value(rp_str_t *value)
{
    rp_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (rp_uint_t) -1;
    }

    n = rp_atoi(value->data, value->len);

    if (n > 0) {
        return (rp_uint_t) n;
    }

    return 0;
}


static void *
rp_http_image_filter_create_conf(rp_conf_t *cf)
{
    rp_http_image_filter_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->wqcv = NULL;
     *     conf->shcv = NULL;
     */

    conf->filter = RP_CONF_UNSET_UINT;
    conf->jpeg_quality = RP_CONF_UNSET_UINT;
    conf->webp_quality = RP_CONF_UNSET_UINT;
    conf->sharpen = RP_CONF_UNSET_UINT;
    conf->transparency = RP_CONF_UNSET;
    conf->interlace = RP_CONF_UNSET;
    conf->buffer_size = RP_CONF_UNSET_SIZE;

    return conf;
}


static char *
rp_http_image_filter_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_image_filter_conf_t *prev = parent;
    rp_http_image_filter_conf_t *conf = child;

    if (conf->filter == RP_CONF_UNSET_UINT) {

        if (prev->filter == RP_CONF_UNSET_UINT) {
            conf->filter = RP_HTTP_IMAGE_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == RP_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        rp_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->webp_quality == RP_CONF_UNSET_UINT) {

        /* 80 is libwebp default quality */
        rp_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);

        if (conf->wqcv == NULL) {
            conf->wqcv = prev->wqcv;
        }
    }

    if (conf->sharpen == RP_CONF_UNSET_UINT) {
        rp_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    rp_conf_merge_value(conf->transparency, prev->transparency, 1);

    rp_conf_merge_value(conf->interlace, prev->interlace, 0);

    rp_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    return RP_CONF_OK;
}


static char *
rp_http_image_filter(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_image_filter_conf_t *imcf = conf;

    rp_str_t                         *value;
    rp_int_t                          n;
    rp_uint_t                         i;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (rp_strcmp(value[i].data, "off") == 0) {
            imcf->filter = RP_HTTP_IMAGE_OFF;

        } else if (rp_strcmp(value[i].data, "test") == 0) {
            imcf->filter = RP_HTTP_IMAGE_TEST;

        } else if (rp_strcmp(value[i].data, "size") == 0) {
            imcf->filter = RP_HTTP_IMAGE_SIZE;

        } else {
            goto failed;
        }

        return RP_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (rp_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != RP_HTTP_IMAGE_RESIZE
                && imcf->filter != RP_HTTP_IMAGE_CROP)
            {
                imcf->filter = RP_HTTP_IMAGE_ROTATE;
            }

            rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (rp_http_compile_complex_value(&ccv) != RP_OK) {
                return RP_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = rp_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (rp_uint_t) n;

            } else {
                imcf->acv = rp_palloc(cf->pool,
                                       sizeof(rp_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return RP_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return RP_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (rp_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = RP_HTTP_IMAGE_RESIZE;

    } else if (rp_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = RP_HTTP_IMAGE_CROP;

    } else {
        goto failed;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rp_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (rp_uint_t) n;

    } else {
        imcf->wcv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return RP_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rp_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (rp_uint_t) n;

    } else {
        imcf->hcv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return RP_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return RP_CONF_OK;

failed:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return RP_CONF_ERROR;
}


static char *
rp_http_image_filter_jpeg_quality(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    rp_http_image_filter_conf_t *imcf = conf;

    rp_str_t                         *value;
    rp_int_t                          n;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rp_http_image_filter_value(&value[1]);

        if (n <= 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        imcf->jpeg_quality = (rp_uint_t) n;

    } else {
        imcf->jqcv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return RP_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return RP_CONF_OK;
}


static char *
rp_http_image_filter_webp_quality(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    rp_http_image_filter_conf_t *imcf = conf;

    rp_str_t                         *value;
    rp_int_t                          n;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rp_http_image_filter_value(&value[1]);

        if (n <= 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        imcf->webp_quality = (rp_uint_t) n;

    } else {
        imcf->wqcv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (imcf->wqcv == NULL) {
            return RP_CONF_ERROR;
        }

        *imcf->wqcv = cv;
    }

    return RP_CONF_OK;
}


static char *
rp_http_image_filter_sharpen(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    rp_http_image_filter_conf_t *imcf = conf;

    rp_str_t                         *value;
    rp_int_t                          n;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rp_http_image_filter_value(&value[1]);

        if (n < 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        imcf->sharpen = (rp_uint_t) n;

    } else {
        imcf->shcv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return RP_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_image_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_image_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_image_body_filter;

    return RP_OK;
}
