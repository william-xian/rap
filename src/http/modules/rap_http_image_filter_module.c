
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#include <gd.h>


#define RAP_HTTP_IMAGE_OFF       0
#define RAP_HTTP_IMAGE_TEST      1
#define RAP_HTTP_IMAGE_SIZE      2
#define RAP_HTTP_IMAGE_RESIZE    3
#define RAP_HTTP_IMAGE_CROP      4
#define RAP_HTTP_IMAGE_ROTATE    5


#define RAP_HTTP_IMAGE_START     0
#define RAP_HTTP_IMAGE_READ      1
#define RAP_HTTP_IMAGE_PROCESS   2
#define RAP_HTTP_IMAGE_PASS      3
#define RAP_HTTP_IMAGE_DONE      4


#define RAP_HTTP_IMAGE_NONE      0
#define RAP_HTTP_IMAGE_JPEG      1
#define RAP_HTTP_IMAGE_GIF       2
#define RAP_HTTP_IMAGE_PNG       3
#define RAP_HTTP_IMAGE_WEBP      4


#define RAP_HTTP_IMAGE_BUFFERED  0x08


typedef struct {
    rap_uint_t                   filter;
    rap_uint_t                   width;
    rap_uint_t                   height;
    rap_uint_t                   angle;
    rap_uint_t                   jpeg_quality;
    rap_uint_t                   webp_quality;
    rap_uint_t                   sharpen;

    rap_flag_t                   transparency;
    rap_flag_t                   interlace;

    rap_http_complex_value_t    *wcv;
    rap_http_complex_value_t    *hcv;
    rap_http_complex_value_t    *acv;
    rap_http_complex_value_t    *jqcv;
    rap_http_complex_value_t    *wqcv;
    rap_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} rap_http_image_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;

    rap_uint_t                   width;
    rap_uint_t                   height;
    rap_uint_t                   max_width;
    rap_uint_t                   max_height;
    rap_uint_t                   angle;

    rap_uint_t                   phase;
    rap_uint_t                   type;
    rap_uint_t                   force;
} rap_http_image_filter_ctx_t;


static rap_int_t rap_http_image_send(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx, rap_chain_t *in);
static rap_uint_t rap_http_image_test(rap_http_request_t *r, rap_chain_t *in);
static rap_int_t rap_http_image_read(rap_http_request_t *r, rap_chain_t *in);
static rap_buf_t *rap_http_image_process(rap_http_request_t *r);
static rap_buf_t *rap_http_image_json(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx);
static rap_buf_t *rap_http_image_asis(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx);
static void rap_http_image_length(rap_http_request_t *r, rap_buf_t *b);
static rap_int_t rap_http_image_size(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx);

static rap_buf_t *rap_http_image_resize(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx);
static gdImagePtr rap_http_image_source(rap_http_request_t *r,
    rap_http_image_filter_ctx_t *ctx);
static gdImagePtr rap_http_image_new(rap_http_request_t *r, int w, int h,
    int colors);
static u_char *rap_http_image_out(rap_http_request_t *r, rap_uint_t type,
    gdImagePtr img, int *size);
static void rap_http_image_cleanup(void *data);
static rap_uint_t rap_http_image_filter_get_value(rap_http_request_t *r,
    rap_http_complex_value_t *cv, rap_uint_t v);
static rap_uint_t rap_http_image_filter_value(rap_str_t *value);


static void *rap_http_image_filter_create_conf(rap_conf_t *cf);
static char *rap_http_image_filter_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_image_filter(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_image_filter_jpeg_quality(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static char *rap_http_image_filter_webp_quality(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static char *rap_http_image_filter_sharpen(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_image_filter_init(rap_conf_t *cf);


static rap_command_t  rap_http_image_filter_commands[] = {

    { rap_string("image_filter"),
      RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_http_image_filter,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("image_filter_jpeg_quality"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_image_filter_jpeg_quality,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("image_filter_webp_quality"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_image_filter_webp_quality,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("image_filter_sharpen"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_image_filter_sharpen,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("image_filter_transparency"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_image_filter_conf_t, transparency),
      NULL },

    { rap_string("image_filter_interlace"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_image_filter_conf_t, interlace),
      NULL },

    { rap_string("image_filter_buffer"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_image_filter_conf_t, buffer_size),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_image_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_image_filter_create_conf,     /* create location configuration */
    rap_http_image_filter_merge_conf       /* merge location configuration */
};


rap_module_t  rap_http_image_filter_module = {
    RAP_MODULE_V1,
    &rap_http_image_filter_module_ctx,     /* module context */
    rap_http_image_filter_commands,        /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_str_t  rap_http_image_types[] = {
    rap_string("image/jpeg"),
    rap_string("image/gif"),
    rap_string("image/png"),
    rap_string("image/webp")
};


static rap_int_t
rap_http_image_header_filter(rap_http_request_t *r)
{
    off_t                          len;
    rap_http_image_filter_ctx_t   *ctx;
    rap_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == RAP_HTTP_NOT_MODIFIED) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_http_get_module_ctx(r, rap_http_image_filter_module);

    if (ctx) {
        rap_http_set_ctx(r, NULL, rap_http_image_filter_module);
        return rap_http_next_header_filter(r);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

    if (conf->filter == RAP_HTTP_IMAGE_OFF) {
        return rap_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && rap_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return RAP_ERROR;
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return RAP_HTTP_UNSUPPORTED_MEDIA_TYPE;
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

    return RAP_OK;
}


static rap_int_t
rap_http_image_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                      rc;
    rap_str_t                     *ct;
    rap_chain_t                    out;
    rap_http_image_filter_ctx_t   *ctx;
    rap_http_image_filter_conf_t  *conf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    ctx = rap_http_get_module_ctx(r, rap_http_image_filter_module);

    if (ctx == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case RAP_HTTP_IMAGE_START:

        ctx->type = rap_http_image_test(r, in);

        conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

        if (ctx->type == RAP_HTTP_IMAGE_NONE) {

            if (conf->filter == RAP_HTTP_IMAGE_SIZE) {
                out.buf = rap_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = RAP_HTTP_IMAGE_DONE;

                    return rap_http_image_send(r, ctx, &out);
                }
            }

            return rap_http_filter_finalize_request(r,
                                              &rap_http_image_filter_module,
                                              RAP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &rap_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == RAP_HTTP_IMAGE_TEST) {
            ctx->phase = RAP_HTTP_IMAGE_PASS;

            return rap_http_image_send(r, ctx, in);
        }

        ctx->phase = RAP_HTTP_IMAGE_READ;

        /* fall through */

    case RAP_HTTP_IMAGE_READ:

        rc = rap_http_image_read(r, in);

        if (rc == RAP_AGAIN) {
            return RAP_OK;
        }

        if (rc == RAP_ERROR) {
            return rap_http_filter_finalize_request(r,
                                              &rap_http_image_filter_module,
                                              RAP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case RAP_HTTP_IMAGE_PROCESS:

        out.buf = rap_http_image_process(r);

        if (out.buf == NULL) {
            return rap_http_filter_finalize_request(r,
                                              &rap_http_image_filter_module,
                                              RAP_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = RAP_HTTP_IMAGE_PASS;

        return rap_http_image_send(r, ctx, &out);

    case RAP_HTTP_IMAGE_PASS:

        return rap_http_next_body_filter(r, in);

    default: /* RAP_HTTP_IMAGE_DONE */

        rc = rap_http_next_body_filter(r, NULL);

        /* RAP_ERROR resets any pending data */
        return (rc == RAP_OK) ? RAP_ERROR : rc;
    }
}


static rap_int_t
rap_http_image_send(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx,
    rap_chain_t *in)
{
    rap_int_t  rc;

    rc = rap_http_next_header_filter(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return RAP_ERROR;
    }

    rc = rap_http_next_body_filter(r, in);

    if (ctx->phase == RAP_HTTP_IMAGE_DONE) {
        /* RAP_ERROR resets any pending data */
        return (rc == RAP_OK) ? RAP_ERROR : rc;
    }

    return rc;
}


static rap_uint_t
rap_http_image_test(rap_http_request_t *r, rap_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return RAP_HTTP_IMAGE_NONE;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return RAP_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return RAP_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return RAP_HTTP_IMAGE_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
               && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
    {
        /* WebP */

        return RAP_HTTP_IMAGE_WEBP;
    }

    return RAP_HTTP_IMAGE_NONE;
}


static rap_int_t
rap_http_image_read(rap_http_request_t *r, rap_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    rap_buf_t                    *b;
    rap_chain_t                  *cl;
    rap_http_image_filter_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = rap_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return RAP_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "image filter: too big response");
            return RAP_ERROR;
        }

        p = rap_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return RAP_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= RAP_HTTP_IMAGE_BUFFERED;

    return RAP_AGAIN;
}


static rap_buf_t *
rap_http_image_process(rap_http_request_t *r)
{
    rap_int_t                      rc;
    rap_http_image_filter_ctx_t   *ctx;
    rap_http_image_filter_conf_t  *conf;

    r->connection->buffered &= ~RAP_HTTP_IMAGE_BUFFERED;

    ctx = rap_http_get_module_ctx(r, rap_http_image_filter_module);

    rc = rap_http_image_size(r, ctx);

    conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

    if (conf->filter == RAP_HTTP_IMAGE_SIZE) {
        return rap_http_image_json(r, rc == RAP_OK ? ctx : NULL);
    }

    ctx->angle = rap_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == RAP_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return rap_http_image_resize(r, ctx);
    }

    ctx->max_width = rap_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = rap_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == RAP_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return rap_http_image_asis(r, ctx);
    }

    return rap_http_image_resize(r, ctx);
}


static rap_buf_t *
rap_http_image_json(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    rap_buf_t  *b;

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    rap_http_clean_header(r);

    r->headers_out.status = RAP_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    rap_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        rap_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * RAP_SIZE_T_LEN;

    b->pos = rap_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = rap_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          rap_http_image_types[ctx->type - 1].data + 6);

    rap_http_image_length(r, b);

    return b;
}


static rap_buf_t *
rap_http_image_asis(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx)
{
    rap_buf_t  *b;

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    rap_http_image_length(r, b);

    return b;
}


static void
rap_http_image_length(rap_http_request_t *r, rap_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static rap_int_t
rap_http_image_size(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    rap_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case RAP_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
            return RAP_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case RAP_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return RAP_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case RAP_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return RAP_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case RAP_HTTP_IMAGE_WEBP:

        if (ctx->length < 30) {
            return RAP_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return RAP_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return RAP_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return RAP_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return RAP_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return RAP_DECLINED;
        }

        break;

    default:

        return RAP_DECLINED;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return RAP_OK;
}


static rap_buf_t *
rap_http_image_resize(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t;
    u_char                        *out;
    rap_buf_t                     *b;
    rap_uint_t                     resize;
    gdImagePtr                     src, dst;
    rap_pool_cleanup_t            *cln;
    rap_http_image_filter_conf_t  *conf;

    src = rap_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (rap_uint_t) sx <= ctx->max_width
        && (rap_uint_t) sy <= ctx->max_height)
    {
        gdImageDestroy(src);
        return rap_http_image_asis(r, ctx);
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

    if (conf->filter == RAP_HTTP_IMAGE_RESIZE) {

        if ((rap_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((rap_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == RAP_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else { /* RAP_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((rap_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((rap_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = rap_http_image_new(r, dx, dy, palette);
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
            dst = rap_http_image_new(r, dy, dx, palette);
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
            dst = rap_http_image_new(r, dx, dy, palette);
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

    if (conf->filter == RAP_HTTP_IMAGE_CROP) {

        src = dst;

        if ((rap_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((rap_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = rap_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

    sharpen = rap_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = rap_http_image_out(r, ctx->type, dst, &size);

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    rap_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = rap_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = rap_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    rap_http_image_length(r, b);
    rap_http_weak_etag(r);

    return b;
}


static gdImagePtr
rap_http_image_source(rap_http_request_t *r, rap_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case RAP_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case RAP_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case RAP_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    case RAP_HTTP_IMAGE_WEBP:
#if (RAP_HAVE_GD_WEBP)
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
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
rap_http_image_new(rap_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
rap_http_image_out(rap_http_request_t *r, rap_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    rap_int_t                      q;
    rap_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case RAP_HTTP_IMAGE_JPEG:
        conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

        q = rap_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
        if (q <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, q);
        failed = "gdImageJpegPtr() failed";
        break;

    case RAP_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case RAP_HTTP_IMAGE_PNG:
        out = gdImagePngPtr(img, size);
        failed = "gdImagePngPtr() failed";
        break;

    case RAP_HTTP_IMAGE_WEBP:
#if (RAP_HAVE_GD_WEBP)
        conf = rap_http_get_module_loc_conf(r, rap_http_image_filter_module);

        q = rap_http_image_filter_get_value(r, conf->wqcv, conf->webp_quality);
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
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
rap_http_image_cleanup(void *data)
{
    gdFree(data);
}


static rap_uint_t
rap_http_image_filter_get_value(rap_http_request_t *r,
    rap_http_complex_value_t *cv, rap_uint_t v)
{
    rap_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (rap_http_complex_value(r, cv, &val) != RAP_OK) {
        return 0;
    }

    return rap_http_image_filter_value(&val);
}


static rap_uint_t
rap_http_image_filter_value(rap_str_t *value)
{
    rap_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (rap_uint_t) -1;
    }

    n = rap_atoi(value->data, value->len);

    if (n > 0) {
        return (rap_uint_t) n;
    }

    return 0;
}


static void *
rap_http_image_filter_create_conf(rap_conf_t *cf)
{
    rap_http_image_filter_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
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

    conf->filter = RAP_CONF_UNSET_UINT;
    conf->jpeg_quality = RAP_CONF_UNSET_UINT;
    conf->webp_quality = RAP_CONF_UNSET_UINT;
    conf->sharpen = RAP_CONF_UNSET_UINT;
    conf->transparency = RAP_CONF_UNSET;
    conf->interlace = RAP_CONF_UNSET;
    conf->buffer_size = RAP_CONF_UNSET_SIZE;

    return conf;
}


static char *
rap_http_image_filter_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_image_filter_conf_t *prev = parent;
    rap_http_image_filter_conf_t *conf = child;

    if (conf->filter == RAP_CONF_UNSET_UINT) {

        if (prev->filter == RAP_CONF_UNSET_UINT) {
            conf->filter = RAP_HTTP_IMAGE_OFF;

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

    if (conf->jpeg_quality == RAP_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        rap_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->webp_quality == RAP_CONF_UNSET_UINT) {

        /* 80 is libwebp default quality */
        rap_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);

        if (conf->wqcv == NULL) {
            conf->wqcv = prev->wqcv;
        }
    }

    if (conf->sharpen == RAP_CONF_UNSET_UINT) {
        rap_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    rap_conf_merge_value(conf->transparency, prev->transparency, 1);

    rap_conf_merge_value(conf->interlace, prev->interlace, 0);

    rap_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    return RAP_CONF_OK;
}


static char *
rap_http_image_filter(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_image_filter_conf_t *imcf = conf;

    rap_str_t                         *value;
    rap_int_t                          n;
    rap_uint_t                         i;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (rap_strcmp(value[i].data, "off") == 0) {
            imcf->filter = RAP_HTTP_IMAGE_OFF;

        } else if (rap_strcmp(value[i].data, "test") == 0) {
            imcf->filter = RAP_HTTP_IMAGE_TEST;

        } else if (rap_strcmp(value[i].data, "size") == 0) {
            imcf->filter = RAP_HTTP_IMAGE_SIZE;

        } else {
            goto failed;
        }

        return RAP_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (rap_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != RAP_HTTP_IMAGE_RESIZE
                && imcf->filter != RAP_HTTP_IMAGE_CROP)
            {
                imcf->filter = RAP_HTTP_IMAGE_ROTATE;
            }

            rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = rap_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (rap_uint_t) n;

            } else {
                imcf->acv = rap_palloc(cf->pool,
                                       sizeof(rap_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return RAP_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return RAP_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (rap_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = RAP_HTTP_IMAGE_RESIZE;

    } else if (rap_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = RAP_HTTP_IMAGE_CROP;

    } else {
        goto failed;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rap_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (rap_uint_t) n;

    } else {
        imcf->wcv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return RAP_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rap_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (rap_uint_t) n;

    } else {
        imcf->hcv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return RAP_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return RAP_CONF_OK;

failed:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return RAP_CONF_ERROR;
}


static char *
rap_http_image_filter_jpeg_quality(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    rap_http_image_filter_conf_t *imcf = conf;

    rap_str_t                         *value;
    rap_int_t                          n;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rap_http_image_filter_value(&value[1]);

        if (n <= 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        imcf->jpeg_quality = (rap_uint_t) n;

    } else {
        imcf->jqcv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return RAP_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_image_filter_webp_quality(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    rap_http_image_filter_conf_t *imcf = conf;

    rap_str_t                         *value;
    rap_int_t                          n;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rap_http_image_filter_value(&value[1]);

        if (n <= 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        imcf->webp_quality = (rap_uint_t) n;

    } else {
        imcf->wqcv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (imcf->wqcv == NULL) {
            return RAP_CONF_ERROR;
        }

        *imcf->wqcv = cv;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_image_filter_sharpen(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    rap_http_image_filter_conf_t *imcf = conf;

    rap_str_t                         *value;
    rap_int_t                          n;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = rap_http_image_filter_value(&value[1]);

        if (n < 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        imcf->sharpen = (rap_uint_t) n;

    } else {
        imcf->shcv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return RAP_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_image_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_image_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_image_body_filter;

    return RAP_OK;
}
