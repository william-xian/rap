
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#define RP_HTTP_SSI_ERROR          1

#define RP_HTTP_SSI_DATE_LEN       2048

#define RP_HTTP_SSI_ADD_PREFIX     1
#define RP_HTTP_SSI_ADD_ZERO       2


typedef struct {
    rp_flag_t    enable;
    rp_flag_t    silent_errors;
    rp_flag_t    ignore_recycled_buffers;
    rp_flag_t    last_modified;

    rp_hash_t    types;

    size_t        min_file_chunk;
    size_t        value_len;

    rp_array_t  *types_keys;
} rp_http_ssi_loc_conf_t;


typedef struct {
    rp_str_t     name;
    rp_uint_t    key;
    rp_str_t     value;
} rp_http_ssi_var_t;


typedef struct {
    rp_str_t     name;
    rp_chain_t  *bufs;
    rp_uint_t    count;
} rp_http_ssi_block_t;


typedef enum {
    ssi_start_state = 0,
    ssi_tag_state,
    ssi_comment0_state,
    ssi_comment1_state,
    ssi_sharp_state,
    ssi_precommand_state,
    ssi_command_state,
    ssi_preparam_state,
    ssi_param_state,
    ssi_preequal_state,
    ssi_prevalue_state,
    ssi_double_quoted_value_state,
    ssi_quoted_value_state,
    ssi_quoted_symbol_state,
    ssi_postparam_state,
    ssi_comment_end0_state,
    ssi_comment_end1_state,
    ssi_error_state,
    ssi_error_end0_state,
    ssi_error_end1_state
} rp_http_ssi_state_e;


static rp_int_t rp_http_ssi_output(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx);
static void rp_http_ssi_buffered(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx);
static rp_int_t rp_http_ssi_parse(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx);
static rp_str_t *rp_http_ssi_get_variable(rp_http_request_t *r,
    rp_str_t *name, rp_uint_t key);
static rp_int_t rp_http_ssi_evaluate_string(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t *text, rp_uint_t flags);
static rp_int_t rp_http_ssi_regex_match(rp_http_request_t *r,
    rp_str_t *pattern, rp_str_t *str);

static rp_int_t rp_http_ssi_include(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_stub_output(rp_http_request_t *r, void *data,
    rp_int_t rc);
static rp_int_t rp_http_ssi_set_variable(rp_http_request_t *r, void *data,
    rp_int_t rc);
static rp_int_t rp_http_ssi_echo(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_config(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_set(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_if(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_else(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_endif(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_block(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);
static rp_int_t rp_http_ssi_endblock(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **params);

static rp_int_t rp_http_ssi_date_gmt_local_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t gmt);

static rp_int_t rp_http_ssi_preconfiguration(rp_conf_t *cf);
static void *rp_http_ssi_create_main_conf(rp_conf_t *cf);
static char *rp_http_ssi_init_main_conf(rp_conf_t *cf, void *conf);
static void *rp_http_ssi_create_loc_conf(rp_conf_t *cf);
static char *rp_http_ssi_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_ssi_filter_init(rp_conf_t *cf);


static rp_command_t  rp_http_ssi_filter_commands[] = {

    { rp_string("ssi"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, enable),
      NULL },

    { rp_string("ssi_silent_errors"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, silent_errors),
      NULL },

    { rp_string("ssi_ignore_recycled_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, ignore_recycled_buffers),
      NULL },

    { rp_string("ssi_min_file_chunk"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, min_file_chunk),
      NULL },

    { rp_string("ssi_value_length"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, value_len),
      NULL },

    { rp_string("ssi_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, types_keys),
      &rp_http_html_default_types[0] },

    { rp_string("ssi_last_modified"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_ssi_loc_conf_t, last_modified),
      NULL },

      rp_null_command
};



static rp_http_module_t  rp_http_ssi_filter_module_ctx = {
    rp_http_ssi_preconfiguration,         /* preconfiguration */
    rp_http_ssi_filter_init,              /* postconfiguration */

    rp_http_ssi_create_main_conf,         /* create main configuration */
    rp_http_ssi_init_main_conf,           /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_ssi_create_loc_conf,          /* create location configuration */
    rp_http_ssi_merge_loc_conf            /* merge location configuration */
};


rp_module_t  rp_http_ssi_filter_module = {
    RP_MODULE_V1,
    &rp_http_ssi_filter_module_ctx,       /* module context */
    rp_http_ssi_filter_commands,          /* module directives */
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


static u_char rp_http_ssi_string[] = "<!--";

static rp_str_t rp_http_ssi_none = rp_string("(none)");
static rp_str_t rp_http_ssi_timefmt = rp_string("%A, %d-%b-%Y %H:%M:%S %Z");
static rp_str_t rp_http_ssi_null_string = rp_null_string;


#define  RP_HTTP_SSI_INCLUDE_VIRTUAL  0
#define  RP_HTTP_SSI_INCLUDE_FILE     1
#define  RP_HTTP_SSI_INCLUDE_WAIT     2
#define  RP_HTTP_SSI_INCLUDE_SET      3
#define  RP_HTTP_SSI_INCLUDE_STUB     4

#define  RP_HTTP_SSI_ECHO_VAR         0
#define  RP_HTTP_SSI_ECHO_DEFAULT     1
#define  RP_HTTP_SSI_ECHO_ENCODING    2

#define  RP_HTTP_SSI_CONFIG_ERRMSG    0
#define  RP_HTTP_SSI_CONFIG_TIMEFMT   1

#define  RP_HTTP_SSI_SET_VAR          0
#define  RP_HTTP_SSI_SET_VALUE        1

#define  RP_HTTP_SSI_IF_EXPR          0

#define  RP_HTTP_SSI_BLOCK_NAME       0


static rp_http_ssi_param_t  rp_http_ssi_include_params[] = {
    { rp_string("virtual"), RP_HTTP_SSI_INCLUDE_VIRTUAL, 0, 0 },
    { rp_string("file"), RP_HTTP_SSI_INCLUDE_FILE, 0, 0 },
    { rp_string("wait"), RP_HTTP_SSI_INCLUDE_WAIT, 0, 0 },
    { rp_string("set"), RP_HTTP_SSI_INCLUDE_SET, 0, 0 },
    { rp_string("stub"), RP_HTTP_SSI_INCLUDE_STUB, 0, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_echo_params[] = {
    { rp_string("var"), RP_HTTP_SSI_ECHO_VAR, 1, 0 },
    { rp_string("default"), RP_HTTP_SSI_ECHO_DEFAULT, 0, 0 },
    { rp_string("encoding"), RP_HTTP_SSI_ECHO_ENCODING, 0, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_config_params[] = {
    { rp_string("errmsg"), RP_HTTP_SSI_CONFIG_ERRMSG, 0, 0 },
    { rp_string("timefmt"), RP_HTTP_SSI_CONFIG_TIMEFMT, 0, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_set_params[] = {
    { rp_string("var"), RP_HTTP_SSI_SET_VAR, 1, 0 },
    { rp_string("value"), RP_HTTP_SSI_SET_VALUE, 1, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_if_params[] = {
    { rp_string("expr"), RP_HTTP_SSI_IF_EXPR, 1, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_block_params[] = {
    { rp_string("name"), RP_HTTP_SSI_BLOCK_NAME, 1, 0 },
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_param_t  rp_http_ssi_no_params[] = {
    { rp_null_string, 0, 0, 0 }
};


static rp_http_ssi_command_t  rp_http_ssi_commands[] = {
    { rp_string("include"), rp_http_ssi_include,
                       rp_http_ssi_include_params, 0, 0, 1 },
    { rp_string("echo"), rp_http_ssi_echo,
                       rp_http_ssi_echo_params, 0, 0, 0 },
    { rp_string("config"), rp_http_ssi_config,
                       rp_http_ssi_config_params, 0, 0, 0 },
    { rp_string("set"), rp_http_ssi_set, rp_http_ssi_set_params, 0, 0, 0 },

    { rp_string("if"), rp_http_ssi_if, rp_http_ssi_if_params, 0, 0, 0 },
    { rp_string("elif"), rp_http_ssi_if, rp_http_ssi_if_params,
                       RP_HTTP_SSI_COND_IF, 0, 0 },
    { rp_string("else"), rp_http_ssi_else, rp_http_ssi_no_params,
                       RP_HTTP_SSI_COND_IF, 0, 0 },
    { rp_string("endif"), rp_http_ssi_endif, rp_http_ssi_no_params,
                       RP_HTTP_SSI_COND_ELSE, 0, 0 },

    { rp_string("block"), rp_http_ssi_block,
                       rp_http_ssi_block_params, 0, 0, 0 },
    { rp_string("endblock"), rp_http_ssi_endblock,
                       rp_http_ssi_no_params, 0, 1, 0 },

    { rp_null_string, NULL, NULL, 0, 0, 0 }
};


static rp_http_variable_t  rp_http_ssi_vars[] = {

    { rp_string("date_local"), NULL, rp_http_ssi_date_gmt_local_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("date_gmt"), NULL, rp_http_ssi_date_gmt_local_variable, 1,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

      rp_http_null_variable
};



static rp_int_t
rp_http_ssi_header_filter(rp_http_request_t *r)
{
    rp_http_ssi_ctx_t       *ctx;
    rp_http_ssi_loc_conf_t  *slcf;

    slcf = rp_http_get_module_loc_conf(r, rp_http_ssi_filter_module);

    if (!slcf->enable
        || r->headers_out.content_length_n == 0
        || rp_http_test_content_type(r, &slcf->types) == NULL)
    {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_ssi_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_ssi_filter_module);


    ctx->value_len = slcf->value_len;
    ctx->last_out = &ctx->out;

    ctx->encoding = RP_HTTP_SSI_ENTITY_ENCODING;
    ctx->output = 1;

    ctx->params.elts = ctx->params_array;
    ctx->params.size = sizeof(rp_table_elt_t);
    ctx->params.nalloc = RP_HTTP_SSI_PARAMS_N;
    ctx->params.pool = r->pool;

    ctx->timefmt = rp_http_ssi_timefmt;
    rp_str_set(&ctx->errmsg,
                "[an error occurred while processing the directive]");

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        rp_http_clear_content_length(r);
        rp_http_clear_accept_ranges(r);

        r->preserve_body = 1;

        if (!slcf->last_modified) {
            rp_http_clear_last_modified(r);
            rp_http_clear_etag(r);

        } else {
            rp_http_weak_etag(r);
        }
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_ssi_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    size_t                     len;
    rp_int_t                  rc;
    rp_buf_t                 *b;
    rp_uint_t                 i, index;
    rp_chain_t               *cl, **ll;
    rp_table_elt_t           *param;
    rp_http_ssi_ctx_t        *ctx, *mctx;
    rp_http_ssi_block_t      *bl;
    rp_http_ssi_param_t      *prm;
    rp_http_ssi_command_t    *cmd;
    rp_http_ssi_loc_conf_t   *slcf;
    rp_http_ssi_main_conf_t  *smcf;
    rp_str_t                 *params[RP_HTTP_SSI_MAX_PARAMS + 1];

    ctx = rp_http_get_module_ctx(r, rp_http_ssi_filter_module);

    if (ctx == NULL
        || (in == NULL
            && ctx->buf == NULL
            && ctx->in == NULL
            && ctx->busy == NULL))
    {
        return rp_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (rp_chain_add_copy(r->pool, &ctx->in, in) != RP_OK) {
            return RP_ERROR;
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ssi filter \"%V?%V\"", &r->uri, &r->args);

    if (ctx->wait) {

        if (r != r->connection->data) {
            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\" non-active",
                           &ctx->wait->uri, &ctx->wait->args);

            return RP_AGAIN;
        }

        if (ctx->wait->done) {
            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\" done",
                           &ctx->wait->uri, &ctx->wait->args);

            ctx->wait = NULL;

        } else {
            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ssi filter wait \"%V?%V\"",
                           &ctx->wait->uri, &ctx->wait->args);

            return rp_http_next_body_filter(r, NULL);
        }
    }

    slcf = rp_http_get_module_loc_conf(r, rp_http_ssi_filter_module);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == ssi_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %uz state: %ui", ctx->saved, ctx->state);

            rc = rp_http_ssi_parse(r, ctx);

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: %uz %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == RP_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                if (ctx->output) {

                    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "saved: %uz", ctx->saved);

                    if (ctx->saved) {

                        if (ctx->free) {
                            cl = ctx->free;
                            ctx->free = ctx->free->next;
                            b = cl->buf;
                            rp_memzero(b, sizeof(rp_buf_t));

                        } else {
                            b = rp_calloc_buf(r->pool);
                            if (b == NULL) {
                                return RP_ERROR;
                            }

                            cl = rp_alloc_chain_link(r->pool);
                            if (cl == NULL) {
                                return RP_ERROR;
                            }

                            cl->buf = b;
                        }

                        b->memory = 1;
                        b->pos = rp_http_ssi_string;
                        b->last = rp_http_ssi_string + ctx->saved;

                        *ctx->last_out = cl;
                        ctx->last_out = &cl->next;

                        ctx->saved = 0;
                    }

                    if (ctx->free) {
                        cl = ctx->free;
                        ctx->free = ctx->free->next;
                        b = cl->buf;

                    } else {
                        b = rp_alloc_buf(r->pool);
                        if (b == NULL) {
                            return RP_ERROR;
                        }

                        cl = rp_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return RP_ERROR;
                        }

                        cl->buf = b;
                    }

                    rp_memcpy(b, ctx->buf, sizeof(rp_buf_t));

                    b->pos = ctx->copy_start;
                    b->last = ctx->copy_end;
                    b->shadow = NULL;
                    b->last_buf = 0;
                    b->recycled = 0;

                    if (b->in_file) {
                        if (slcf->min_file_chunk < (size_t) (b->last - b->pos))
                        {
                            b->file_last = b->file_pos
                                                   + (b->last - ctx->buf->pos);
                            b->file_pos += b->pos - ctx->buf->pos;

                        } else {
                            b->in_file = 0;
                        }
                    }

                    cl->next = NULL;
                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                } else {
                    if (ctx->block
                        && ctx->saved + (ctx->copy_end - ctx->copy_start))
                    {
                        b = rp_create_temp_buf(r->pool,
                               ctx->saved + (ctx->copy_end - ctx->copy_start));

                        if (b == NULL) {
                            return RP_ERROR;
                        }

                        if (ctx->saved) {
                            b->last = rp_cpymem(b->pos, rp_http_ssi_string,
                                                 ctx->saved);
                        }

                        b->last = rp_cpymem(b->last, ctx->copy_start,
                                             ctx->copy_end - ctx->copy_start);

                        cl = rp_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return RP_ERROR;
                        }

                        cl->buf = b;
                        cl->next = NULL;

                        b = NULL;

                        mctx = rp_http_get_module_ctx(r->main,
                                                   rp_http_ssi_filter_module);
                        bl = mctx->blocks->elts;
                        for (ll = &bl[mctx->blocks->nelts - 1].bufs;
                             *ll;
                             ll = &(*ll)->next)
                        {
                            /* void */
                        }

                        *ll = cl;
                    }

                    ctx->saved = 0;
                }
            }

            if (ctx->state == ssi_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == RP_AGAIN) {
                continue;
            }


            b = NULL;

            if (rc == RP_OK) {

                smcf = rp_http_get_module_main_conf(r,
                                                   rp_http_ssi_filter_module);

                cmd = rp_hash_find(&smcf->hash, ctx->key, ctx->command.data,
                                    ctx->command.len);

                if (cmd == NULL) {
                    if (ctx->output) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "invalid SSI command: \"%V\"",
                                      &ctx->command);
                        goto ssi_error;
                    }

                    continue;
                }

                if (!ctx->output && !cmd->block) {

                    if (ctx->block) {

                        /* reconstruct the SSI command text */

                        len = 5 + ctx->command.len + 4;

                        param = ctx->params.elts;
                        for (i = 0; i < ctx->params.nelts; i++) {
                            len += 1 + param[i].key.len + 2
                                + param[i].value.len + 1;
                        }

                        b = rp_create_temp_buf(r->pool, len);

                        if (b == NULL) {
                            return RP_ERROR;
                        }

                        cl = rp_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return RP_ERROR;
                        }

                        cl->buf = b;
                        cl->next = NULL;

                        *b->last++ = '<';
                        *b->last++ = '!';
                        *b->last++ = '-';
                        *b->last++ = '-';
                        *b->last++ = '#';

                        b->last = rp_cpymem(b->last, ctx->command.data,
                                             ctx->command.len);

                        for (i = 0; i < ctx->params.nelts; i++) {
                            *b->last++ = ' ';
                            b->last = rp_cpymem(b->last, param[i].key.data,
                                                 param[i].key.len);
                            *b->last++ = '=';
                            *b->last++ = '"';
                            b->last = rp_cpymem(b->last, param[i].value.data,
                                                 param[i].value.len);
                            *b->last++ = '"';
                        }

                        *b->last++ = ' ';
                        *b->last++ = '-';
                        *b->last++ = '-';
                        *b->last++ = '>';

                        mctx = rp_http_get_module_ctx(r->main,
                                                   rp_http_ssi_filter_module);
                        bl = mctx->blocks->elts;
                        for (ll = &bl[mctx->blocks->nelts - 1].bufs;
                             *ll;
                             ll = &(*ll)->next)
                        {
                            /* void */
                        }

                        *ll = cl;

                        b = NULL;

                        continue;
                    }

                    if (cmd->conditional == 0) {
                        continue;
                    }
                }

                if (cmd->conditional
                    && (ctx->conditional == 0
                        || ctx->conditional > cmd->conditional))
                {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "invalid context of SSI command: \"%V\"",
                                  &ctx->command);
                    goto ssi_error;
                }

                if (ctx->params.nelts > RP_HTTP_SSI_MAX_PARAMS) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "too many SSI command parameters: \"%V\"",
                                  &ctx->command);
                    goto ssi_error;
                }

                rp_memzero(params,
                           (RP_HTTP_SSI_MAX_PARAMS + 1) * sizeof(rp_str_t *));

                param = ctx->params.elts;

                for (i = 0; i < ctx->params.nelts; i++) {

                    for (prm = cmd->params; prm->name.len; prm++) {

                        if (param[i].key.len != prm->name.len
                            || rp_strncmp(param[i].key.data, prm->name.data,
                                           prm->name.len) != 0)
                        {
                            continue;
                        }

                        if (!prm->multiple) {
                            if (params[prm->index]) {
                                rp_log_error(RP_LOG_ERR,
                                              r->connection->log, 0,
                                              "duplicate \"%V\" parameter "
                                              "in \"%V\" SSI command",
                                              &param[i].key, &ctx->command);

                                goto ssi_error;
                            }

                            params[prm->index] = &param[i].value;

                            break;
                        }

                        for (index = prm->index; params[index]; index++) {
                            /* void */
                        }

                        params[index] = &param[i].value;

                        break;
                    }

                    if (prm->name.len == 0) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "invalid parameter name: \"%V\" "
                                      "in \"%V\" SSI command",
                                      &param[i].key, &ctx->command);

                        goto ssi_error;
                    }
                }

                for (prm = cmd->params; prm->name.len; prm++) {
                    if (prm->mandatory && params[prm->index] == 0) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "mandatory \"%V\" parameter is absent "
                                      "in \"%V\" SSI command",
                                      &prm->name, &ctx->command);

                        goto ssi_error;
                    }
                }

                if (cmd->flush && ctx->out) {

                    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "ssi flush");

                    if (rp_http_ssi_output(r, ctx) == RP_ERROR) {
                        return RP_ERROR;
                    }
                }

                rc = cmd->handler(r, ctx, params);

                if (rc == RP_OK) {
                    continue;
                }

                if (rc == RP_DONE || rc == RP_AGAIN || rc == RP_ERROR) {
                    rp_http_ssi_buffered(r, ctx);
                    return rc;
                }
            }


            /* rc == RP_HTTP_SSI_ERROR */

    ssi_error:

            if (slcf->silent_errors) {
                continue;
            }

            if (ctx->free) {
                cl = ctx->free;
                ctx->free = ctx->free->next;
                b = cl->buf;
                rp_memzero(b, sizeof(rp_buf_t));

            } else {
                b = rp_calloc_buf(r->pool);
                if (b == NULL) {
                    return RP_ERROR;
                }

                cl = rp_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return RP_ERROR;
                }

                cl->buf = b;
            }

            b->memory = 1;
            b->pos = ctx->errmsg.data;
            b->last = ctx->errmsg.data + ctx->errmsg.len;

            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            continue;
        }

        if (ctx->buf->last_buf || rp_buf_in_memory(ctx->buf)) {
            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    rp_memzero(b, sizeof(rp_buf_t));

                } else {
                    b = rp_calloc_buf(r->pool);
                    if (b == NULL) {
                        return RP_ERROR;
                    }

                    cl = rp_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return RP_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            if (slcf->ignore_recycled_buffers == 0)  {
                b->recycled = ctx->buf->recycled;
            }
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return RP_OK;
    }

    return rp_http_ssi_output(r, ctx);
}


static rp_int_t
rp_http_ssi_output(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx)
{
    rp_int_t     rc;
    rp_buf_t    *b;
    rp_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ssi out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in ssi");
            rp_debug_point();
            return RP_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = rp_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (rp_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (rp_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    rp_http_ssi_buffered(r, ctx);

    return rc;
}


static void
rp_http_ssi_buffered(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx)
{
    if (ctx->in || ctx->buf) {
        r->buffered |= RP_HTTP_SSI_BUFFERED;

    } else {
        r->buffered &= ~RP_HTTP_SSI_BUFFERED;
    }
}


static rp_int_t
rp_http_ssi_parse(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx)
{
    u_char                *p, *value, *last, *copy_end, ch;
    size_t                 looked;
    rp_http_ssi_state_e   state;

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;

        if (state == ssi_start_state) {

            /* the tight loop */

            for ( ;; ) {
                if (ch == '<') {
                    copy_end = p;
                    looked = 1;
                    state = ssi_tag_state;

                    goto tag_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
            }

            ctx->state = state;
            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return RP_AGAIN;

        tag_started:

            continue;
        }

        switch (state) {

        case ssi_start_state:
            /* not reached */
            break;

        case ssi_tag_state:
            switch (ch) {
            case '!':
                looked = 2;
                state = ssi_comment0_state;
                break;

            case '<':
                copy_end = p;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment0_state:
            switch (ch) {
            case '-':
                looked = 3;
                state = ssi_comment1_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_comment1_state:
            switch (ch) {
            case '-':
                looked = 4;
                state = ssi_sharp_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_sharp_state:
            switch (ch) {
            case '#':
                if (p - ctx->pos < 4) {
                    ctx->saved = 0;
                }
                looked = 0;
                state = ssi_precommand_state;
                break;

            case '<':
                copy_end = p;
                looked = 1;
                state = ssi_tag_state;
                break;

            default:
                copy_end = p;
                looked = 0;
                state = ssi_start_state;
                break;
            }

            break;

        case ssi_precommand_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            default:
                ctx->command.len = 1;
                ctx->command.data = rp_pnalloc(r->pool,
                                                RP_HTTP_SSI_COMMAND_LEN);
                if (ctx->command.data == NULL) {
                    return RP_ERROR;
                }

                ctx->command.data[0] = ch;

                ctx->key = 0;
                ctx->key = rp_hash(ctx->key, ch);

                ctx->params.nelts = 0;

                state = ssi_command_state;
                break;
            }

            break;

        case ssi_command_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                if (ctx->command.len == RP_HTTP_SSI_COMMAND_LEN) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "the \"%V%c...\" SSI command is too long",
                                  &ctx->command, ch);

                    state = ssi_error_state;
                    break;
                }

                ctx->command.data[ctx->command.len++] = ch;
                ctx->key = rp_hash(ctx->key, ch);
            }

            break;

        case ssi_preparam_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                ctx->param = rp_array_push(&ctx->params);
                if (ctx->param == NULL) {
                    return RP_ERROR;
                }

                ctx->param->key.len = 1;
                ctx->param->key.data = rp_pnalloc(r->pool,
                                                   RP_HTTP_SSI_PARAM_LEN);
                if (ctx->param->key.data == NULL) {
                    return RP_ERROR;
                }

                ctx->param->key.data[0] = ch;

                ctx->param->value.len = 0;

                if (ctx->value_buf == NULL) {
                    ctx->param->value.data = rp_pnalloc(r->pool,
                                                         ctx->value_len + 1);
                    if (ctx->param->value.data == NULL) {
                        return RP_ERROR;
                    }

                } else {
                    ctx->param->value.data = ctx->value_buf;
                }

                state = ssi_param_state;
                break;
            }

            break;

        case ssi_param_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preequal_state;
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            case '-':
                state = ssi_error_end0_state;

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"-\" symbol after \"%V\" "
                              "parameter in \"%V\" SSI command",
                              &ctx->param->key, &ctx->command);
                break;

            default:
                if (ctx->param->key.len == RP_HTTP_SSI_PARAM_LEN) {
                    state = ssi_error_state;
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" parameter in "
                                  "\"%V\" SSI command",
                                  &ctx->param->key, ch, &ctx->command);
                    break;
                }

                ctx->param->key.data[ctx->param->key.len++] = ch;
            }

            break;

        case ssi_preequal_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '=':
                state = ssi_prevalue_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" "
                              "parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_prevalue_state:
            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                break;

            case '"':
                state = ssi_double_quoted_value_state;
                break;

            case '\'':
                state = ssi_quoted_value_state;
                break;

            default:
                if (ch == '-') {
                    state = ssi_error_end0_state;
                } else {
                    state = ssi_error_state;
                }

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol before value of "
                              "\"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->key, &ctx->command);
                break;
            }

            break;

        case ssi_double_quoted_value_state:
            switch (ch) {
            case '"':
                state = ssi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = ssi_double_quoted_value_state;
                state = ssi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" SSI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_value_state:
            switch (ch) {
            case '\'':
                state = ssi_postparam_state;
                break;

            case '\\':
                ctx->saved_state = ssi_quoted_value_state;
                state = ssi_quoted_symbol_state;

                /* fall through */

            default:
                if (ctx->param->value.len == ctx->value_len) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "too long \"%V%c...\" value of \"%V\" "
                                  "parameter in \"%V\" SSI command",
                                  &ctx->param->value, ch, &ctx->param->key,
                                  &ctx->command);
                    state = ssi_error_state;
                    break;
                }

                ctx->param->value.data[ctx->param->value.len++] = ch;
            }

            break;

        case ssi_quoted_symbol_state:
            state = ctx->saved_state;

            if (ctx->param->value.len == ctx->value_len) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "too long \"%V%c...\" value of \"%V\" "
                              "parameter in \"%V\" SSI command",
                              &ctx->param->value, ch, &ctx->param->key,
                              &ctx->command);
                state = ssi_error_state;
                break;
            }

            ctx->param->value.data[ctx->param->value.len++] = ch;

            break;

        case ssi_postparam_state:

            if (ctx->param->value.len + 1 < ctx->value_len / 2) {
                value = rp_pnalloc(r->pool, ctx->param->value.len + 1);
                if (value == NULL) {
                    return RP_ERROR;
                }

                rp_memcpy(value, ctx->param->value.data,
                           ctx->param->value.len);

                ctx->value_buf = ctx->param->value.data;
                ctx->param->value.data = value;

            } else {
                ctx->value_buf = NULL;
            }

            switch (ch) {
            case ' ':
            case CR:
            case LF:
            case '\t':
                state = ssi_preparam_state;
                break;

            case '-':
                state = ssi_comment_end0_state;
                break;

            default:
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol after \"%V\" value "
                              "of \"%V\" parameter in \"%V\" SSI command",
                              ch, &ctx->param->value, &ctx->param->key,
                              &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end0_state:
            switch (ch) {
            case '-':
                state = ssi_comment_end1_state;
                break;

            default:
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_comment_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return RP_OK;

            default:
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "unexpected \"%c\" symbol in \"%V\" SSI command",
                              ch, &ctx->command);
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_state:
            switch (ch) {
            case '-':
                state = ssi_error_end0_state;
                break;

            default:
                break;
            }

            break;

        case ssi_error_end0_state:
            switch (ch) {
            case '-':
                state = ssi_error_end1_state;
                break;

            default:
                state = ssi_error_state;
                break;
            }

            break;

        case ssi_error_end1_state:
            switch (ch) {
            case '>':
                ctx->state = ssi_start_state;
                ctx->pos = p + 1;
                ctx->looked = looked;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return RP_HTTP_SSI_ERROR;

            default:
                state = ssi_error_state;
                break;
            }

            break;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == ssi_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return RP_AGAIN;
}


static rp_str_t *
rp_http_ssi_get_variable(rp_http_request_t *r, rp_str_t *name,
    rp_uint_t key)
{
    rp_uint_t           i;
    rp_list_part_t     *part;
    rp_http_ssi_var_t  *var;
    rp_http_ssi_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r->main, rp_http_ssi_filter_module);

#if (RP_PCRE)
    {
    rp_str_t  *value;

    if (key >= '0' && key <= '9') {
        i = key - '0';

        if (i < ctx->ncaptures) {
            value = rp_palloc(r->pool, sizeof(rp_str_t));
            if (value == NULL) {
                return NULL;
            }

            i *= 2;

            value->data = ctx->captures_data + ctx->captures[i];
            value->len = ctx->captures[i + 1] - ctx->captures[i];

            return value;
        }
    }
    }
#endif

    if (ctx->variables == NULL) {
        return NULL;
    }

    part = &ctx->variables->part;
    var = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            var = part->elts;
            i = 0;
        }

        if (name->len != var[i].name.len) {
            continue;
        }

        if (key != var[i].key) {
            continue;
        }

        if (rp_strncmp(name->data, var[i].name.data, name->len) == 0) {
            return &var[i].value;
        }
    }

    return NULL;
}


static rp_int_t
rp_http_ssi_evaluate_string(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t *text, rp_uint_t flags)
{
    u_char                      ch, *p, **value, *data, *part_data;
    size_t                     *size, len, prefix, part_len;
    rp_str_t                   var, *val;
    rp_uint_t                  i, n, bracket, quoted, key;
    rp_array_t                 lengths, values;
    rp_http_variable_value_t  *vv;

    n = rp_http_script_variables_count(text);

    if (n == 0) {

        data = text->data;
        p = data;

        if ((flags & RP_HTTP_SSI_ADD_PREFIX) && text->data[0] != '/') {

            for (prefix = r->uri.len; prefix; prefix--) {
                if (r->uri.data[prefix - 1] == '/') {
                    break;
                }
            }

            if (prefix) {
                len = prefix + text->len;

                data = rp_pnalloc(r->pool, len);
                if (data == NULL) {
                    return RP_ERROR;
                }

                p = rp_copy(data, r->uri.data, prefix);
            }
        }

        quoted = 0;

        for (i = 0; i < text->len; i++) {
            ch = text->data[i];

            if (!quoted) {

                if (ch == '\\') {
                    quoted = 1;
                    continue;
                }

            } else {
                quoted = 0;

                if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
                    *p++ = '\\';
                }
            }

            *p++ = ch;
        }

        text->len = p - data;
        text->data = data;

        return RP_OK;
    }

    if (rp_array_init(&lengths, r->pool, 8, sizeof(size_t *)) != RP_OK) {
        return RP_ERROR;
    }

    if (rp_array_init(&values, r->pool, 8, sizeof(u_char *)) != RP_OK) {
        return RP_ERROR;
    }

    len = 0;
    i = 0;

    while (i < text->len) {

        if (text->data[i] == '$') {

            var.len = 0;

            if (++i == text->len) {
                goto invalid_variable;
            }

            if (text->data[i] == '{') {
                bracket = 1;

                if (++i == text->len) {
                    goto invalid_variable;
                }

                var.data = &text->data[i];

            } else {
                bracket = 0;
                var.data = &text->data[i];
            }

            for ( /* void */ ; i < text->len; i++, var.len++) {
                ch = text->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "the closing bracket in \"%V\" "
                              "variable is missing", &var);
                return RP_HTTP_SSI_ERROR;
            }

            if (var.len == 0) {
                goto invalid_variable;
            }

            key = rp_hash_strlow(var.data, var.data, var.len);

            val = rp_http_ssi_get_variable(r, &var, key);

            if (val == NULL) {
                vv = rp_http_get_variable(r, &var, key);
                if (vv == NULL) {
                    return RP_ERROR;
                }

                if (vv->not_found) {
                    continue;
                }

                part_data = vv->data;
                part_len = vv->len;

            } else {
                part_data = val->data;
                part_len = val->len;
            }

        } else {
            part_data = &text->data[i];
            quoted = 0;

            for (p = part_data; i < text->len; i++) {
                ch = text->data[i];

                if (!quoted) {

                    if (ch == '\\') {
                        quoted = 1;
                        continue;
                    }

                    if (ch == '$') {
                        break;
                    }

                } else {
                    quoted = 0;

                    if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
                        *p++ = '\\';
                    }
                }

                *p++ = ch;
            }

            part_len = p - part_data;
        }

        len += part_len;

        size = rp_array_push(&lengths);
        if (size == NULL) {
            return RP_ERROR;
        }

        *size = part_len;

        value = rp_array_push(&values);
        if (value == NULL) {
            return RP_ERROR;
        }

        *value = part_data;
    }

    prefix = 0;

    size = lengths.elts;
    value = values.elts;

    if (flags & RP_HTTP_SSI_ADD_PREFIX) {
        for (i = 0; i < values.nelts; i++) {
            if (size[i] != 0) {
                if (*value[i] != '/') {
                    for (prefix = r->uri.len; prefix; prefix--) {
                        if (r->uri.data[prefix - 1] == '/') {
                            len += prefix;
                            break;
                        }
                    }
                }

                break;
            }
        }
    }

    p = rp_pnalloc(r->pool, len + ((flags & RP_HTTP_SSI_ADD_ZERO) ? 1 : 0));
    if (p == NULL) {
        return RP_ERROR;
    }

    text->len = len;
    text->data = p;

    p = rp_copy(p, r->uri.data, prefix);

    for (i = 0; i < values.nelts; i++) {
        p = rp_copy(p, value[i], size[i]);
    }

    return RP_OK;

invalid_variable:

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "invalid variable name in \"%V\"", text);

    return RP_HTTP_SSI_ERROR;
}


static rp_int_t
rp_http_ssi_regex_match(rp_http_request_t *r, rp_str_t *pattern,
    rp_str_t *str)
{
#if (RP_PCRE)
    int                   rc, *captures;
    u_char               *p, errstr[RP_MAX_CONF_ERRSTR];
    size_t                size;
    rp_str_t            *vv, name, value;
    rp_uint_t            i, n, key;
    rp_http_ssi_ctx_t   *ctx;
    rp_http_ssi_var_t   *var;
    rp_regex_compile_t   rgc;

    rp_memzero(&rgc, sizeof(rp_regex_compile_t));

    rgc.pattern = *pattern;
    rgc.pool = r->pool;
    rgc.err.len = RP_MAX_CONF_ERRSTR;
    rgc.err.data = errstr;

    if (rp_regex_compile(&rgc) != RP_OK) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0, "%V", &rgc.err);
        return RP_HTTP_SSI_ERROR;
    }

    n = (rgc.captures + 1) * 3;

    captures = rp_palloc(r->pool, n * sizeof(int));
    if (captures == NULL) {
        return RP_ERROR;
    }

    rc = rp_regex_exec(rgc.regex, str, captures, n);

    if (rc < RP_REGEX_NO_MATCHED) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      rp_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
                      rc, str, pattern);
        return RP_HTTP_SSI_ERROR;
    }

    if (rc == RP_REGEX_NO_MATCHED) {
        return RP_DECLINED;
    }

    ctx = rp_http_get_module_ctx(r->main, rp_http_ssi_filter_module);

    ctx->ncaptures = rc;
    ctx->captures = captures;
    ctx->captures_data = str->data;

    if (rgc.named_captures > 0) {

        if (ctx->variables == NULL) {
            ctx->variables = rp_list_create(r->pool, 4,
                                             sizeof(rp_http_ssi_var_t));
            if (ctx->variables == NULL) {
                return RP_ERROR;
            }
        }

        size = rgc.name_size;
        p = rgc.names;

        for (i = 0; i < (rp_uint_t) rgc.named_captures; i++, p += size) {

            name.data = &p[2];
            name.len = rp_strlen(name.data);

            n = 2 * ((p[0] << 8) + p[1]);

            value.data = &str->data[captures[n]];
            value.len = captures[n + 1] - captures[n];

            key = rp_hash_strlow(name.data, name.data, name.len);

            vv = rp_http_ssi_get_variable(r, &name, key);

            if (vv) {
                *vv = value;
                continue;
            }

            var = rp_list_push(ctx->variables);
            if (var == NULL) {
                return RP_ERROR;
            }

            var->name = name;
            var->key = key;
            var->value = value;
        }
    }

    return RP_OK;

#else

    rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                  "the using of the regex \"%V\" in SSI requires PCRE library",
                  pattern);
    return RP_HTTP_SSI_ERROR;

#endif
}


static rp_int_t
rp_http_ssi_include(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_int_t                    rc;
    rp_str_t                   *uri, *file, *wait, *set, *stub, args;
    rp_buf_t                   *b;
    rp_uint_t                   flags, i, key;
    rp_chain_t                 *cl, *tl, **ll, *out;
    rp_http_request_t          *sr;
    rp_http_ssi_var_t          *var;
    rp_http_ssi_ctx_t          *mctx;
    rp_http_ssi_block_t        *bl;
    rp_http_post_subrequest_t  *psr;

    uri = params[RP_HTTP_SSI_INCLUDE_VIRTUAL];
    file = params[RP_HTTP_SSI_INCLUDE_FILE];
    wait = params[RP_HTTP_SSI_INCLUDE_WAIT];
    set = params[RP_HTTP_SSI_INCLUDE_SET];
    stub = params[RP_HTTP_SSI_INCLUDE_STUB];

    if (uri && file) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "inclusion may be either virtual=\"%V\" or file=\"%V\"",
                      uri, file);
        return RP_HTTP_SSI_ERROR;
    }

    if (uri == NULL && file == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "no parameter in \"include\" SSI command");
        return RP_HTTP_SSI_ERROR;
    }

    if (set && stub) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "\"set\" and \"stub\" cannot be used together "
                      "in \"include\" SSI command");
        return RP_HTTP_SSI_ERROR;
    }

    if (wait) {
        if (uri == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"wait\" cannot be used with file=\"%V\"", file);
            return RP_HTTP_SSI_ERROR;
        }

        if (wait->len == 2
            && rp_strncasecmp(wait->data, (u_char *) "no", 2) == 0)
        {
            wait = NULL;

        } else if (wait->len != 3
                   || rp_strncasecmp(wait->data, (u_char *) "yes", 3) != 0)
        {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "invalid value \"%V\" in the \"wait\" parameter",
                          wait);
            return RP_HTTP_SSI_ERROR;
        }
    }

    if (uri == NULL) {
        uri = file;
        wait = (rp_str_t *) -1;
    }

    rc = rp_http_ssi_evaluate_string(r, ctx, uri, RP_HTTP_SSI_ADD_PREFIX);

    if (rc != RP_OK) {
        return rc;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi include: \"%V\"", uri);

    rp_str_null(&args);
    flags = RP_HTTP_LOG_UNSAFE;

    if (rp_http_parse_unsafe_uri(r, uri, &args, &flags) != RP_OK) {
        return RP_HTTP_SSI_ERROR;
    }

    psr = NULL;

    mctx = rp_http_get_module_ctx(r->main, rp_http_ssi_filter_module);

    if (stub) {
        if (mctx->blocks) {
            bl = mctx->blocks->elts;
            for (i = 0; i < mctx->blocks->nelts; i++) {
                if (stub->len == bl[i].name.len
                    && rp_strncmp(stub->data, bl[i].name.data, stub->len) == 0)
                {
                    goto found;
                }
            }
        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "\"stub\"=\"%V\" for \"include\" not found", stub);
        return RP_HTTP_SSI_ERROR;

    found:

        psr = rp_palloc(r->pool, sizeof(rp_http_post_subrequest_t));
        if (psr == NULL) {
            return RP_ERROR;
        }

        psr->handler = rp_http_ssi_stub_output;

        if (bl[i].count++) {

            out = NULL;
            ll = &out;

            for (tl = bl[i].bufs; tl; tl = tl->next) {

                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;

                } else {
                    b = rp_alloc_buf(r->pool);
                    if (b == NULL) {
                        return RP_ERROR;
                    }

                    cl = rp_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return RP_ERROR;
                    }

                    cl->buf = b;
                }

                rp_memcpy(b, tl->buf, sizeof(rp_buf_t));

                b->pos = b->start;

                *ll = cl;
                cl->next = NULL;
                ll = &cl->next;
            }

            psr->data = out;

        } else {
            psr->data = bl[i].bufs;
        }
    }

    if (wait) {
        flags |= RP_HTTP_SUBREQUEST_WAITED;
    }

    if (set) {
        key = rp_hash_strlow(set->data, set->data, set->len);

        psr = rp_palloc(r->pool, sizeof(rp_http_post_subrequest_t));
        if (psr == NULL) {
            return RP_ERROR;
        }

        psr->handler = rp_http_ssi_set_variable;
        psr->data = rp_http_ssi_get_variable(r, set, key);

        if (psr->data == NULL) {

            if (mctx->variables == NULL) {
                mctx->variables = rp_list_create(r->pool, 4,
                                                  sizeof(rp_http_ssi_var_t));
                if (mctx->variables == NULL) {
                    return RP_ERROR;
                }
            }

            var = rp_list_push(mctx->variables);
            if (var == NULL) {
                return RP_ERROR;
            }

            var->name = *set;
            var->key = key;
            var->value = rp_http_ssi_null_string;
            psr->data = &var->value;
        }

        flags |= RP_HTTP_SUBREQUEST_IN_MEMORY|RP_HTTP_SUBREQUEST_WAITED;
    }

    if (rp_http_subrequest(r, uri, &args, &sr, psr, flags) != RP_OK) {
        return RP_HTTP_SSI_ERROR;
    }

    if (wait == NULL && set == NULL) {
        return RP_OK;
    }

    if (ctx->wait == NULL) {
        ctx->wait = sr;

        return RP_AGAIN;

    } else {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "can only wait for one subrequest at a time");
    }

    return RP_OK;
}


static rp_int_t
rp_http_ssi_stub_output(rp_http_request_t *r, void *data, rp_int_t rc)
{
    rp_chain_t  *out;

    if (rc == RP_ERROR || r->connection->error || r->request_output) {
        return rc;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi stub output: \"%V?%V\"", &r->uri, &r->args);

    out = data;

    if (!r->header_sent) {
        r->headers_out.content_type_len =
                                      r->parent->headers_out.content_type_len;
        r->headers_out.content_type = r->parent->headers_out.content_type;

        if (rp_http_send_header(r) == RP_ERROR) {
            return RP_ERROR;
        }
    }

    return rp_http_output_filter(r, out);
}


static rp_int_t
rp_http_ssi_set_variable(rp_http_request_t *r, void *data, rp_int_t rc)
{
    rp_str_t  *value = data;

    if (r->headers_out.status < RP_HTTP_SPECIAL_RESPONSE
        && r->out && r->out->buf)
    {
        value->len = r->out->buf->last - r->out->buf->pos;
        value->data = r->out->buf->pos;
    }

    return rc;
}


static rp_int_t
rp_http_ssi_echo(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    u_char                     *p;
    uintptr_t                   len;
    rp_buf_t                  *b;
    rp_str_t                  *var, *value, *enc, text;
    rp_uint_t                  key;
    rp_chain_t                *cl;
    rp_http_variable_value_t  *vv;

    var = params[RP_HTTP_SSI_ECHO_VAR];

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi echo \"%V\"", var);

    key = rp_hash_strlow(var->data, var->data, var->len);

    value = rp_http_ssi_get_variable(r, var, key);

    if (value == NULL) {
        vv = rp_http_get_variable(r, var, key);

        if (vv == NULL) {
            return RP_HTTP_SSI_ERROR;
        }

        if (!vv->not_found) {
            text.data = vv->data;
            text.len = vv->len;
            value = &text;
        }
    }

    if (value == NULL) {
        value = params[RP_HTTP_SSI_ECHO_DEFAULT];

        if (value == NULL) {
            value = &rp_http_ssi_none;

        } else if (value->len == 0) {
            return RP_OK;
        }

    } else {
        if (value->len == 0) {
            return RP_OK;
        }
    }

    enc = params[RP_HTTP_SSI_ECHO_ENCODING];

    if (enc) {
        if (enc->len == 4 && rp_strncmp(enc->data, "none", 4) == 0) {

            ctx->encoding = RP_HTTP_SSI_NO_ENCODING;

        } else if (enc->len == 3 && rp_strncmp(enc->data, "url", 3) == 0) {

            ctx->encoding = RP_HTTP_SSI_URL_ENCODING;

        } else if (enc->len == 6 && rp_strncmp(enc->data, "entity", 6) == 0) {

            ctx->encoding = RP_HTTP_SSI_ENTITY_ENCODING;

        } else {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "unknown encoding \"%V\" in the \"echo\" command",
                          enc);
        }
    }

    p = value->data;

    switch (ctx->encoding) {

    case RP_HTTP_SSI_URL_ENCODING:
        len = 2 * rp_escape_uri(NULL, value->data, value->len,
                                 RP_ESCAPE_HTML);

        if (len) {
            p = rp_pnalloc(r->pool, value->len + len);
            if (p == NULL) {
                return RP_HTTP_SSI_ERROR;
            }

            (void) rp_escape_uri(p, value->data, value->len, RP_ESCAPE_HTML);
        }

        len += value->len;
        break;

    case RP_HTTP_SSI_ENTITY_ENCODING:
        len = rp_escape_html(NULL, value->data, value->len);

        if (len) {
            p = rp_pnalloc(r->pool, value->len + len);
            if (p == NULL) {
                return RP_HTTP_SSI_ERROR;
            }

            (void) rp_escape_html(p, value->data, value->len);
        }

        len += value->len;
        break;

    default: /* RP_HTTP_SSI_NO_ENCODING */
        len = value->len;
        break;
    }

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_HTTP_SSI_ERROR;
    }

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_HTTP_SSI_ERROR;
    }

    b->memory = 1;
    b->pos = p;
    b->last = p + len;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return RP_OK;
}


static rp_int_t
rp_http_ssi_config(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_str_t  *value;

    value = params[RP_HTTP_SSI_CONFIG_TIMEFMT];

    if (value) {
        ctx->timefmt.len = value->len;
        ctx->timefmt.data = rp_pnalloc(r->pool, value->len + 1);
        if (ctx->timefmt.data == NULL) {
            return RP_ERROR;
        }

        rp_cpystrn(ctx->timefmt.data, value->data, value->len + 1);
    }

    value = params[RP_HTTP_SSI_CONFIG_ERRMSG];

    if (value) {
        ctx->errmsg = *value;
    }

    return RP_OK;
}


static rp_int_t
rp_http_ssi_set(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_int_t            rc;
    rp_str_t           *name, *value, *vv;
    rp_uint_t           key;
    rp_http_ssi_var_t  *var;
    rp_http_ssi_ctx_t  *mctx;

    mctx = rp_http_get_module_ctx(r->main, rp_http_ssi_filter_module);

    if (mctx->variables == NULL) {
        mctx->variables = rp_list_create(r->pool, 4,
                                          sizeof(rp_http_ssi_var_t));
        if (mctx->variables == NULL) {
            return RP_ERROR;
        }
    }

    name = params[RP_HTTP_SSI_SET_VAR];
    value = params[RP_HTTP_SSI_SET_VALUE];

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi set \"%V\" \"%V\"", name, value);

    rc = rp_http_ssi_evaluate_string(r, ctx, value, 0);

    if (rc != RP_OK) {
        return rc;
    }

    key = rp_hash_strlow(name->data, name->data, name->len);

    vv = rp_http_ssi_get_variable(r, name, key);

    if (vv) {
        *vv = *value;
        return RP_OK;
    }

    var = rp_list_push(mctx->variables);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->name = *name;
    var->key = key;
    var->value = *value;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set: \"%V\"=\"%V\"", name, value);

    return RP_OK;
}


static rp_int_t
rp_http_ssi_if(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    u_char       *p, *last;
    rp_str_t    *expr, left, right;
    rp_int_t     rc;
    rp_uint_t    negative, noregex, flags;

    if (ctx->command.len == 2) {
        if (ctx->conditional) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "the \"if\" command inside the \"if\" command");
            return RP_HTTP_SSI_ERROR;
        }
    }

    if (ctx->output_chosen) {
        ctx->output = 0;
        return RP_OK;
    }

    expr = params[RP_HTTP_SSI_IF_EXPR];

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi if expr=\"%V\"", expr);

    left.data = expr->data;
    last = expr->data + expr->len;

    for (p = left.data; p < last; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            *p |= 0x20;
            continue;
        }

        if ((*p >= 'a' && *p <= 'z')
             || (*p >= '0' && *p <= '9')
             || *p == '$' || *p == '{' || *p == '}' || *p == '_'
             || *p == '"' || *p == '\'')
        {
            continue;
        }

        break;
    }

    left.len = p - left.data;

    while (p < last && *p == ' ') {
        p++;
    }

    flags = 0;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "left: \"%V\"", &left);

    rc = rp_http_ssi_evaluate_string(r, ctx, &left, flags);

    if (rc != RP_OK) {
        return rc;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "evaluated left: \"%V\"", &left);

    if (p == last) {
        if (left.len) {
            ctx->output = 1;
            ctx->output_chosen = 1;

        } else {
            ctx->output = 0;
        }

        ctx->conditional = RP_HTTP_SSI_COND_IF;

        return RP_OK;
    }

    if (p < last && *p == '=') {
        negative = 0;
        p++;

    } else if (p + 1 < last && *p == '!' && *(p + 1) == '=') {
        negative = 1;
        p += 2;

    } else {
        goto invalid_expression;
    }

    while (p < last && *p == ' ') {
        p++;
    }

    if (p < last - 1 && *p == '/') {
        if (*(last - 1) != '/') {
            goto invalid_expression;
        }

        noregex = 0;
        flags = RP_HTTP_SSI_ADD_ZERO;
        last--;
        p++;

    } else {
        noregex = 1;
        flags = 0;

        if (p < last - 1 && p[0] == '\\' && p[1] == '/') {
            p++;
        }
    }

    right.len = last - p;
    right.data = p;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "right: \"%V\"", &right);

    rc = rp_http_ssi_evaluate_string(r, ctx, &right, flags);

    if (rc != RP_OK) {
        return rc;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "evaluated right: \"%V\"", &right);

    if (noregex) {
        if (left.len != right.len) {
            rc = -1;

        } else {
            rc = rp_strncmp(left.data, right.data, right.len);
        }

    } else {
        right.data[right.len] = '\0';

        rc = rp_http_ssi_regex_match(r, &right, &left);

        if (rc == RP_OK) {
            rc = 0;
        } else if (rc == RP_DECLINED) {
            rc = -1;
        } else {
            return rc;
        }
    }

    if ((rc == 0 && !negative) || (rc != 0 && negative)) {
        ctx->output = 1;
        ctx->output_chosen = 1;

    } else {
        ctx->output = 0;
    }

    ctx->conditional = RP_HTTP_SSI_COND_IF;

    return RP_OK;

invalid_expression:

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "invalid expression in \"%V\"", expr);

    return RP_HTTP_SSI_ERROR;
}


static rp_int_t
rp_http_ssi_else(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi else");

    if (ctx->output_chosen) {
        ctx->output = 0;
    } else {
        ctx->output = 1;
    }

    ctx->conditional = RP_HTTP_SSI_COND_ELSE;

    return RP_OK;
}


static rp_int_t
rp_http_ssi_endif(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi endif");

    ctx->output = 1;
    ctx->output_chosen = 0;
    ctx->conditional = 0;

    return RP_OK;
}


static rp_int_t
rp_http_ssi_block(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_http_ssi_ctx_t    *mctx;
    rp_http_ssi_block_t  *bl;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi block");

    mctx = rp_http_get_module_ctx(r->main, rp_http_ssi_filter_module);

    if (mctx->blocks == NULL) {
        mctx->blocks = rp_array_create(r->pool, 4,
                                        sizeof(rp_http_ssi_block_t));
        if (mctx->blocks == NULL) {
            return RP_HTTP_SSI_ERROR;
        }
    }

    bl = rp_array_push(mctx->blocks);
    if (bl == NULL) {
        return RP_HTTP_SSI_ERROR;
    }

    bl->name = *params[RP_HTTP_SSI_BLOCK_NAME];
    bl->bufs = NULL;
    bl->count = 0;

    ctx->output = 0;
    ctx->block = 1;

    return RP_OK;
}


static rp_int_t
rp_http_ssi_endblock(rp_http_request_t *r, rp_http_ssi_ctx_t *ctx,
    rp_str_t **params)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ssi endblock");

    ctx->output = 1;
    ctx->block = 0;

    return RP_OK;
}


static rp_int_t
rp_http_ssi_date_gmt_local_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t gmt)
{
    time_t               now;
    rp_http_ssi_ctx_t  *ctx;
    rp_str_t           *timefmt;
    struct tm            tm;
    char                 buf[RP_HTTP_SSI_DATE_LEN];

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    now = rp_time();

    ctx = rp_http_get_module_ctx(r, rp_http_ssi_filter_module);

    timefmt = ctx ? &ctx->timefmt : &rp_http_ssi_timefmt;

    if (timefmt->len == sizeof("%s") - 1
        && timefmt->data[0] == '%' && timefmt->data[1] == 's')
    {
        v->data = rp_pnalloc(r->pool, RP_TIME_T_LEN);
        if (v->data == NULL) {
            return RP_ERROR;
        }

        v->len = rp_sprintf(v->data, "%T", now) - v->data;

        return RP_OK;
    }

    if (gmt) {
        rp_libc_gmtime(now, &tm);
    } else {
        rp_libc_localtime(now, &tm);
    }

    v->len = strftime(buf, RP_HTTP_SSI_DATE_LEN,
                      (char *) timefmt->data, &tm);
    if (v->len == 0) {
        return RP_ERROR;
    }

    v->data = rp_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(v->data, buf, v->len);

    return RP_OK;
}


static rp_int_t
rp_http_ssi_preconfiguration(rp_conf_t *cf)
{
    rp_int_t                  rc;
    rp_http_variable_t       *var, *v;
    rp_http_ssi_command_t    *cmd;
    rp_http_ssi_main_conf_t  *smcf;

    for (v = rp_http_ssi_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    smcf = rp_http_conf_get_module_main_conf(cf, rp_http_ssi_filter_module);

    for (cmd = rp_http_ssi_commands; cmd->name.len; cmd++) {
        rc = rp_hash_add_key(&smcf->commands, &cmd->name, cmd,
                              RP_HASH_READONLY_KEY);

        if (rc == RP_OK) {
            continue;
        }

        if (rc == RP_BUSY) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"", &cmd->name);
        }

        return RP_ERROR;
    }

    return RP_OK;
}


static void *
rp_http_ssi_create_main_conf(rp_conf_t *cf)
{
    rp_http_ssi_main_conf_t  *smcf;

    smcf = rp_pcalloc(cf->pool, sizeof(rp_http_ssi_main_conf_t));
    if (smcf == NULL) {
        return NULL;
    }

    smcf->commands.pool = cf->pool;
    smcf->commands.temp_pool = cf->temp_pool;

    if (rp_hash_keys_array_init(&smcf->commands, RP_HASH_SMALL) != RP_OK) {
        return NULL;
    }

    return smcf;
}


static char *
rp_http_ssi_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_http_ssi_main_conf_t *smcf = conf;

    rp_hash_init_t  hash;

    hash.hash = &smcf->hash;
    hash.key = rp_hash_key;
    hash.max_size = 1024;
    hash.bucket_size = rp_cacheline_size;
    hash.name = "ssi_command_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rp_hash_init(&hash, smcf->commands.keys.elts,
                      smcf->commands.keys.nelts)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static void *
rp_http_ssi_create_loc_conf(rp_conf_t *cf)
{
    rp_http_ssi_loc_conf_t  *slcf;

    slcf = rp_pcalloc(cf->pool, sizeof(rp_http_ssi_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    slcf->enable = RP_CONF_UNSET;
    slcf->silent_errors = RP_CONF_UNSET;
    slcf->ignore_recycled_buffers = RP_CONF_UNSET;
    slcf->last_modified = RP_CONF_UNSET;

    slcf->min_file_chunk = RP_CONF_UNSET_SIZE;
    slcf->value_len = RP_CONF_UNSET_SIZE;

    return slcf;
}


static char *
rp_http_ssi_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_ssi_loc_conf_t *prev = parent;
    rp_http_ssi_loc_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);
    rp_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);
    rp_conf_merge_value(conf->ignore_recycled_buffers,
                         prev->ignore_recycled_buffers, 0);
    rp_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    rp_conf_merge_size_value(conf->min_file_chunk, prev->min_file_chunk, 1024);
    rp_conf_merge_size_value(conf->value_len, prev->value_len, 255);

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_html_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_ssi_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_ssi_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_ssi_body_filter;

    return RP_OK;
}
