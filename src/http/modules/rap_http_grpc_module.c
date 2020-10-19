
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t               *flushes;
    rap_array_t               *lengths;
    rap_array_t               *values;
    rap_hash_t                 hash;
} rap_http_grpc_headers_t;


typedef struct {
    rap_http_upstream_conf_t   upstream;

    rap_http_grpc_headers_t    headers;
    rap_array_t               *headers_source;

    rap_str_t                  host;
    rap_uint_t                 host_set;

    rap_array_t               *grpc_lengths;
    rap_array_t               *grpc_values;

#if (RAP_HTTP_SSL)
    rap_uint_t                 ssl;
    rap_uint_t                 ssl_protocols;
    rap_str_t                  ssl_ciphers;
    rap_uint_t                 ssl_verify_depth;
    rap_str_t                  ssl_trusted_certificate;
    rap_str_t                  ssl_crl;
    rap_str_t                  ssl_certificate;
    rap_str_t                  ssl_certificate_key;
    rap_array_t               *ssl_passwords;
#endif
} rap_http_grpc_loc_conf_t;


typedef enum {
    rap_http_grpc_st_start = 0,
    rap_http_grpc_st_length_2,
    rap_http_grpc_st_length_3,
    rap_http_grpc_st_type,
    rap_http_grpc_st_flags,
    rap_http_grpc_st_stream_id,
    rap_http_grpc_st_stream_id_2,
    rap_http_grpc_st_stream_id_3,
    rap_http_grpc_st_stream_id_4,
    rap_http_grpc_st_payload,
    rap_http_grpc_st_padding
} rap_http_grpc_state_e;


typedef struct {
    size_t                     init_window;
    size_t                     send_window;
    size_t                     recv_window;
    rap_uint_t                 last_stream_id;
} rap_http_grpc_conn_t;


typedef struct {
    rap_http_grpc_state_e      state;
    rap_uint_t                 frame_state;
    rap_uint_t                 fragment_state;

    rap_chain_t               *in;
    rap_chain_t               *out;
    rap_chain_t               *free;
    rap_chain_t               *busy;

    rap_http_grpc_conn_t      *connection;

    rap_uint_t                 id;

    rap_uint_t                 pings;
    rap_uint_t                 settings;

    ssize_t                    send_window;
    size_t                     recv_window;

    size_t                     rest;
    rap_uint_t                 stream_id;
    u_char                     type;
    u_char                     flags;
    u_char                     padding;

    rap_uint_t                 error;
    rap_uint_t                 window_update;

    rap_uint_t                 setting_id;
    rap_uint_t                 setting_value;

    u_char                     ping_data[8];

    rap_uint_t                 index;
    rap_str_t                  name;
    rap_str_t                  value;

    u_char                    *field_end;
    size_t                     field_length;
    size_t                     field_rest;
    u_char                     field_state;

    unsigned                   literal:1;
    unsigned                   field_huffman:1;

    unsigned                   header_sent:1;
    unsigned                   output_closed:1;
    unsigned                   output_blocked:1;
    unsigned                   parsing_headers:1;
    unsigned                   end_stream:1;
    unsigned                   done:1;
    unsigned                   status:1;

    rap_http_request_t        *request;

    rap_str_t                  host;
} rap_http_grpc_ctx_t;


typedef struct {
    u_char                     length_0;
    u_char                     length_1;
    u_char                     length_2;
    u_char                     type;
    u_char                     flags;
    u_char                     stream_id_0;
    u_char                     stream_id_1;
    u_char                     stream_id_2;
    u_char                     stream_id_3;
} rap_http_grpc_frame_t;


static rap_int_t rap_http_grpc_eval(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_http_grpc_loc_conf_t *glcf);
static rap_int_t rap_http_grpc_create_request(rap_http_request_t *r);
static rap_int_t rap_http_grpc_reinit_request(rap_http_request_t *r);
static rap_int_t rap_http_grpc_body_output_filter(void *data, rap_chain_t *in);
static rap_int_t rap_http_grpc_process_header(rap_http_request_t *r);
static rap_int_t rap_http_grpc_filter_init(void *data);
static rap_int_t rap_http_grpc_filter(void *data, ssize_t bytes);

static rap_int_t rap_http_grpc_parse_frame(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_header(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_fragment(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_validate_header_name(rap_http_request_t *r,
    rap_str_t *s);
static rap_int_t rap_http_grpc_validate_header_value(rap_http_request_t *r,
    rap_str_t *s);
static rap_int_t rap_http_grpc_parse_rst_stream(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_goaway(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_window_update(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_settings(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);
static rap_int_t rap_http_grpc_parse_ping(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b);

static rap_int_t rap_http_grpc_send_settings_ack(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx);
static rap_int_t rap_http_grpc_send_ping_ack(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx);
static rap_int_t rap_http_grpc_send_window_update(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx);

static rap_chain_t *rap_http_grpc_get_buf(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx);
static rap_http_grpc_ctx_t *rap_http_grpc_get_ctx(rap_http_request_t *r);
static rap_int_t rap_http_grpc_get_connection_data(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_peer_connection_t *pc);
static void rap_http_grpc_cleanup(void *data);

static void rap_http_grpc_abort_request(rap_http_request_t *r);
static void rap_http_grpc_finalize_request(rap_http_request_t *r,
    rap_int_t rc);

static rap_int_t rap_http_grpc_internal_trailers_variable(
    rap_http_request_t *r, rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_grpc_add_variables(rap_conf_t *cf);
static void *rap_http_grpc_create_loc_conf(rap_conf_t *cf);
static char *rap_http_grpc_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_grpc_init_headers(rap_conf_t *cf,
    rap_http_grpc_loc_conf_t *conf, rap_http_grpc_headers_t *headers,
    rap_keyval_t *default_headers);

static char *rap_http_grpc_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

#if (RAP_HTTP_SSL)
static char *rap_http_grpc_ssl_password_file(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static rap_int_t rap_http_grpc_set_ssl(rap_conf_t *cf,
    rap_http_grpc_loc_conf_t *glcf);
#endif


static rap_conf_bitmask_t  rap_http_grpc_next_upstream_masks[] = {
    { rap_string("error"), RAP_HTTP_UPSTREAM_FT_ERROR },
    { rap_string("timeout"), RAP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rap_string("invalid_header"), RAP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rap_string("non_idempotent"), RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rap_string("http_500"), RAP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rap_string("http_502"), RAP_HTTP_UPSTREAM_FT_HTTP_502 },
    { rap_string("http_503"), RAP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rap_string("http_504"), RAP_HTTP_UPSTREAM_FT_HTTP_504 },
    { rap_string("http_403"), RAP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rap_string("http_404"), RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rap_string("http_429"), RAP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rap_string("off"), RAP_HTTP_UPSTREAM_FT_OFF },
    { rap_null_string, 0 }
};


#if (RAP_HTTP_SSL)

static rap_conf_bitmask_t  rap_http_grpc_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};

#endif


static rap_command_t  rap_http_grpc_commands[] = {

    { rap_string("grpc_pass"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_grpc_pass,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("grpc_bind"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_bind_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.local),
      NULL },

    { rap_string("grpc_socket_keepalive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rap_string("grpc_connect_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rap_string("grpc_send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.send_timeout),
      NULL },

    { rap_string("grpc_intercept_errors"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rap_string("grpc_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.buffer_size),
      NULL },

    { rap_string("grpc_read_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.read_timeout),
      NULL },

    { rap_string("grpc_next_upstream"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.next_upstream),
      &rap_http_grpc_next_upstream_masks },

    { rap_string("grpc_next_upstream_tries"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rap_string("grpc_next_upstream_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rap_string("grpc_set_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_keyval_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, headers_source),
      NULL },

    { rap_string("grpc_pass_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.pass_headers),
      NULL },

    { rap_string("grpc_hide_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.hide_headers),
      NULL },

    { rap_string("grpc_ignore_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.ignore_headers),
      &rap_http_upstream_ignore_headers_masks },

#if (RAP_HTTP_SSL)

    { rap_string("grpc_ssl_session_reuse"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { rap_string("grpc_ssl_protocols"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_protocols),
      &rap_http_grpc_ssl_protocols },

    { rap_string("grpc_ssl_ciphers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_ciphers),
      NULL },

    { rap_string("grpc_ssl_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.ssl_name),
      NULL },

    { rap_string("grpc_ssl_server_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { rap_string("grpc_ssl_verify"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, upstream.ssl_verify),
      NULL },

    { rap_string("grpc_ssl_verify_depth"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_verify_depth),
      NULL },

    { rap_string("grpc_ssl_trusted_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { rap_string("grpc_ssl_crl"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_crl),
      NULL },

    { rap_string("grpc_ssl_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_certificate),
      NULL },

    { rap_string("grpc_ssl_certificate_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_grpc_loc_conf_t, ssl_certificate_key),
      NULL },

    { rap_string("grpc_ssl_password_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_grpc_ssl_password_file,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rap_null_command
};


static rap_http_module_t  rap_http_grpc_module_ctx = {
    rap_http_grpc_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_grpc_create_loc_conf,         /* create location configuration */
    rap_http_grpc_merge_loc_conf           /* merge location configuration */
};


rap_module_t  rap_http_grpc_module = {
    RAP_MODULE_V1,
    &rap_http_grpc_module_ctx,             /* module context */
    rap_http_grpc_commands,                /* module directives */
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


static u_char  rap_http_grpc_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


static rap_keyval_t  rap_http_grpc_headers[] = {
    { rap_string("Content-Length"), rap_string("$content_length") },
    { rap_string("TE"), rap_string("$grpc_internal_trailers") },
    { rap_string("Host"), rap_string("") },
    { rap_string("Connection"), rap_string("") },
    { rap_string("Transfer-Encoding"), rap_string("") },
    { rap_string("Keep-Alive"), rap_string("") },
    { rap_string("Expect"), rap_string("") },
    { rap_string("Upgrade"), rap_string("") },
    { rap_null_string, rap_null_string }
};


static rap_str_t  rap_http_grpc_hide_headers[] = {
    rap_string("Date"),
    rap_string("Server"),
    rap_string("X-Accel-Expires"),
    rap_string("X-Accel-Redirect"),
    rap_string("X-Accel-Limit-Rate"),
    rap_string("X-Accel-Buffering"),
    rap_string("X-Accel-Charset"),
    rap_null_string
};


static rap_http_variable_t  rap_http_grpc_vars[] = {

    { rap_string("grpc_internal_trailers"), NULL,
      rap_http_grpc_internal_trailers_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

      rap_http_null_variable
};


static rap_int_t
rap_http_grpc_handler(rap_http_request_t *r)
{
    rap_int_t                  rc;
    rap_http_upstream_t       *u;
    rap_http_grpc_ctx_t       *ctx;
    rap_http_grpc_loc_conf_t  *glcf;

    if (rap_http_upstream_create(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_grpc_ctx_t));
    if (ctx == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    rap_http_set_ctx(r, ctx, rap_http_grpc_module);

    glcf = rap_http_get_module_loc_conf(r, rap_http_grpc_module);

    u = r->upstream;

    if (glcf->grpc_lengths == NULL) {
        ctx->host = glcf->host;

#if (RAP_HTTP_SSL)
        u->ssl = (glcf->upstream.ssl != NULL);

        if (u->ssl) {
            rap_str_set(&u->schema, "grpcs://");

        } else {
            rap_str_set(&u->schema, "grpc://");
        }
#else
        rap_str_set(&u->schema, "grpc://");
#endif

    } else {
        if (rap_http_grpc_eval(r, ctx, glcf) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (rap_buf_tag_t) &rap_http_grpc_module;

    u->conf = &glcf->upstream;

    u->create_request = rap_http_grpc_create_request;
    u->reinit_request = rap_http_grpc_reinit_request;
    u->process_header = rap_http_grpc_process_header;
    u->abort_request = rap_http_grpc_abort_request;
    u->finalize_request = rap_http_grpc_finalize_request;

    u->input_filter_init = rap_http_grpc_filter_init;
    u->input_filter = rap_http_grpc_filter;
    u->input_filter_ctx = ctx;

    r->request_body_no_buffering = 1;

    rc = rap_http_read_client_request_body(r, rap_http_upstream_init);

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return RAP_DONE;
}


static rap_int_t
rap_http_grpc_eval(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_http_grpc_loc_conf_t *glcf)
{
    size_t                add;
    rap_url_t             url;
    rap_http_upstream_t  *u;

    rap_memzero(&url, sizeof(rap_url_t));

    if (rap_http_script_run(r, &url.url, glcf->grpc_lengths->elts, 0,
                            glcf->grpc_values->elts)
        == NULL)
    {
        return RAP_ERROR;
    }

    if (url.url.len > 7
        && rap_strncasecmp(url.url.data, (u_char *) "grpc://", 7) == 0)
    {
        add = 7;

    } else if (url.url.len > 8
               && rap_strncasecmp(url.url.data, (u_char *) "grpcs://", 8) == 0)
    {

#if (RAP_HTTP_SSL)
        add = 8;
        r->upstream->ssl = 1;
#else
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "grpcs protocol requires SSL support");
        return RAP_ERROR;
#endif

    } else {
        add = 0;
    }

    u = r->upstream;

    if (add) {
        u->schema.len = add;
        u->schema.data = url.url.data;

        url.url.data += add;
        url.url.len -= add;

    } else {
        rap_str_set(&u->schema, "grpc://");
    }

    url.no_resolve = 1;

    if (rap_parse_url(r->pool, &url) != RAP_OK) {
        if (url.err) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RAP_ERROR;
    }

    u->resolved = rap_pcalloc(r->pool, sizeof(rap_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RAP_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    if (url.family != AF_UNIX) {

        if (url.no_port) {
            ctx->host = url.host;

        } else {
            ctx->host.len = url.host.len + 1 + url.port_text.len;
            ctx->host.data = url.host.data;
        }

    } else {
        rap_str_set(&ctx->host, "localhost");
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_create_request(rap_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame;
    size_t                        len, tmp_len, key_len, val_len, uri_len;
    uintptr_t                     escape;
    rap_buf_t                    *b;
    rap_uint_t                    i, next;
    rap_chain_t                  *cl, *body;
    rap_list_part_t              *part;
    rap_table_elt_t              *header;
    rap_http_grpc_ctx_t          *ctx;
    rap_http_upstream_t          *u;
    rap_http_grpc_frame_t        *f;
    rap_http_script_code_pt       code;
    rap_http_grpc_loc_conf_t     *glcf;
    rap_http_script_engine_t      e, le;
    rap_http_script_len_code_pt   lcode;

    u = r->upstream;

    glcf = rap_http_get_module_loc_conf(r, rap_http_grpc_module);

    ctx = rap_http_get_module_ctx(r, rap_http_grpc_module);

    len = sizeof(rap_http_grpc_connection_start) - 1
          + sizeof(rap_http_grpc_frame_t);             /* headers frame */

    /* :method header */

    if (r->method == RAP_HTTP_GET || r->method == RAP_HTTP_POST) {
        len += 1;
        tmp_len = 0;

    } else {
        len += 1 + RAP_HTTP_V2_INT_OCTETS + r->method_name.len;
        tmp_len = r->method_name.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    if (r->valid_unparsed_uri) {
        escape = 0;
        uri_len = r->unparsed_uri.len;

    } else {
        escape = 2 * rap_escape_uri(NULL, r->uri.data, r->uri.len,
                                    RAP_ESCAPE_URI);
        uri_len = r->uri.len + escape + sizeof("?") - 1 + r->args.len;
    }

    len += 1 + RAP_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    if (!glcf->host_set) {
        len += 1 + RAP_HTTP_V2_INT_OCTETS + ctx->host.len;

        if (tmp_len < ctx->host.len) {
            tmp_len = ctx->host.len;
        }
    }

    /* other headers */

    rap_http_script_flush_no_cacheable_variables(r, glcf->headers.flushes);
    rap_memzero(&le, sizeof(rap_http_script_engine_t));

    le.ip = glcf->headers.lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rap_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += 1 + RAP_HTTP_V2_INT_OCTETS + key_len
                 + RAP_HTTP_V2_INT_OCTETS + val_len;

        if (tmp_len < key_len) {
            tmp_len = key_len;
        }

        if (tmp_len < val_len) {
            tmp_len = val_len;
        }
    }

    if (glcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (rap_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += 1 + RAP_HTTP_V2_INT_OCTETS + header[i].key.len
                     + RAP_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(rap_http_grpc_frame_t)
           * (len / RAP_HTTP_V2_DEFAULT_FRAME_SIZE);


    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    tmp = rap_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return RAP_ERROR;
    }

    key_tmp = tmp + tmp_len;
    val_tmp = tmp + 2 * tmp_len;

    /* connection preface */

    b->last = rap_copy(b->last, rap_http_grpc_connection_start,
                       sizeof(rap_http_grpc_connection_start) - 1);

    /* headers frame */

    headers_frame = b->last;

    f = (rap_http_grpc_frame_t *) b->last;
    b->last += sizeof(rap_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = RAP_HTTP_V2_HEADERS_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (r->method == RAP_HTTP_GET) {
        *b->last++ = rap_http_v2_indexed(RAP_HTTP_V2_METHOD_GET_INDEX);

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: GET\"");

    } else if (r->method == RAP_HTTP_POST) {
        *b->last++ = rap_http_v2_indexed(RAP_HTTP_V2_METHOD_POST_INDEX);

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: POST\"");

    } else {
        *b->last++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_METHOD_INDEX);
        b->last = rap_http_v2_write_value(b->last, r->method_name.data,
                                          r->method_name.len, tmp);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: %V\"", &r->method_name);
    }

#if (RAP_HTTP_SSL)
    if (u->ssl) {
        *b->last++ = rap_http_v2_indexed(RAP_HTTP_V2_SCHEME_HTTPS_INDEX);

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = rap_http_v2_indexed(RAP_HTTP_V2_SCHEME_HTTP_INDEX);

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: http\"");
    }

    if (r->valid_unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = rap_http_v2_indexed(RAP_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_PATH_INDEX);
            b->last = rap_http_v2_write_value(b->last, r->unparsed_uri.data,
                                              r->unparsed_uri.len, tmp);
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->unparsed_uri);

    } else if (escape || r->args.len > 0) {
        p = val_tmp;

        if (escape) {
            p = (u_char *) rap_escape_uri(p, r->uri.data, r->uri.len,
                                          RAP_ESCAPE_URI);

        } else {
            p = rap_copy(p, r->uri.data, r->uri.len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = rap_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_PATH_INDEX);
        b->last = rap_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %*s\"", p - val_tmp, val_tmp);

    } else {
        *b->last++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_PATH_INDEX);
        b->last = rap_http_v2_write_value(b->last, r->uri.data,
                                          r->uri.len, tmp);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->uri);
    }

    if (!glcf->host_set) {
        *b->last++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_AUTHORITY_INDEX);
        b->last = rap_http_v2_write_value(b->last, ctx->host.data,
                                          ctx->host.len, tmp);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":authority: %V\"", &ctx->host);
    }

    rap_memzero(&e, sizeof(rap_http_script_engine_t));

    e.ip = glcf->headers.values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = glcf->headers.lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rap_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        *b->last++ = 0;

        e.pos = key_tmp;

        code = *(rap_http_script_code_pt *) e.ip;
        code((rap_http_script_engine_t *) &e);

        b->last = rap_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;

        while (*(uintptr_t *) e.ip) {
            code = *(rap_http_script_code_pt *) e.ip;
            code((rap_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        b->last = rap_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (RAP_DEBUG)
        if (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP) {
            rap_strlow(key_tmp, key_tmp, key_len);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header: \"%*s: %*s\"",
                           key_len, key_tmp, val_len, val_tmp);
        }
#endif
    }

    if (glcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (rap_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = rap_http_v2_write_name(b->last, header[i].key.data,
                                             header[i].key.len, tmp);

            b->last = rap_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (RAP_DEBUG)
            if (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP) {
                rap_strlow(tmp, header[i].key.data, header[i].key.len);

                rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(rap_http_grpc_frame_t);

    if (len > RAP_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = RAP_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (rap_http_grpc_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(rap_http_grpc_frame_t) + RAP_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        rap_memmove(p + sizeof(rap_http_grpc_frame_t), p, len);
        b->last += sizeof(rap_http_grpc_frame_t);

        if (len > RAP_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = RAP_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (rap_http_grpc_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = RAP_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= RAP_HTTP_V2_END_HEADERS_FLAG;

#if (RAP_DEBUG)
    if (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = rap_min(b->last - b->pos, 256);
        m = rap_hex_dump(buf, b->pos, n) - buf;

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: %*s%s, len: %uz",
                       m, buf, b->last - b->pos > 256 ? "..." : "",
                       b->last - b->pos);
    }
#endif

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

    } else {

        body = u->request_bufs;
        u->request_bufs = cl;

        if (body == NULL) {
            f = (rap_http_grpc_frame_t *) headers_frame;
            f->flags |= RAP_HTTP_V2_END_STREAM_FLAG;
        }

        while (body) {
            b = rap_alloc_buf(r->pool);
            if (b == NULL) {
                return RAP_ERROR;
            }

            rap_memcpy(b, body->buf, sizeof(rap_buf_t));

            cl->next = rap_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return RAP_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->last_buf = 1;
    }

    u->output.output_filter = rap_http_grpc_body_output_filter;
    u->output.filter_ctx = r;

    b->flush = 1;
    cl->next = NULL;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_reinit_request(rap_http_request_t *r)
{
    rap_http_grpc_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_grpc_module);

    if (ctx == NULL) {
        return RAP_OK;
    }

    ctx->state = 0;
    ctx->header_sent = 0;
    ctx->output_closed = 0;
    ctx->output_blocked = 0;
    ctx->parsing_headers = 0;
    ctx->end_stream = 0;
    ctx->done = 0;
    ctx->status = 0;
    ctx->connection = NULL;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_body_output_filter(void *data, rap_chain_t *in)
{
    rap_http_request_t  *r = data;

    off_t                   file_pos;
    u_char                 *p, *pos, *start;
    size_t                  len, limit;
    rap_buf_t              *b;
    rap_int_t               rc;
    rap_uint_t              next, last;
    rap_chain_t            *cl, *out, **ll;
    rap_http_upstream_t    *u;
    rap_http_grpc_ctx_t    *ctx;
    rap_http_grpc_frame_t  *f;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output filter");

    ctx = rap_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    if (in) {
        if (rap_chain_add_copy(r->pool, &ctx->in, in) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers */

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output header");

        ctx->header_sent = 1;

        if (ctx->id != 1) {
            /*
             * keepalive connection: skip connection preface,
             * update stream identifiers
             */

            b = ctx->in->buf;
            b->pos += sizeof(rap_http_grpc_connection_start) - 1;

            p = b->pos;

            while (p < b->last) {
                f = (rap_http_grpc_frame_t *) p;
                p += sizeof(rap_http_grpc_frame_t);

                f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
                f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
                f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
                f->stream_id_3 = (u_char) (ctx->id & 0xff);

                p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
            }
        }

        if (ctx->in->buf->last_buf) {
            ctx->output_closed = 1;
        }

        *ll = ctx->in;
        ll = &ctx->in->next;

        ctx->in = ctx->in->next;
    }

    if (ctx->out) {
        /* queued control frames */

        *ll = ctx->out;

        for (cl = ctx->out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->out = NULL;
    }

    f = NULL;
    last = 0;

    limit = rap_max(0, ctx->send_window);

    if (limit > ctx->connection->send_window) {
        limit = ctx->connection->send_window;
    }

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#if (RAP_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->in;

    while (in && limit > 0) {

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (rap_buf_special(in->buf)) {
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {

            cl = rap_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;

            f = (rap_http_grpc_frame_t *) b->last;
            b->last += sizeof(rap_http_grpc_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = rap_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;
            start = b->start;

            rap_memcpy(b, in->buf, sizeof(rap_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and control frames
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += rap_min(RAP_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (rap_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += rap_min(RAP_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (rap_uint_t) (pos - b->pos);
            }

            b->tag = (rap_buf_tag_t) &rap_http_grpc_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = RAP_HTTP_V2_DATA_FRAME;
            f->flags = 0;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            limit -= len;
            ctx->send_window -= len;
            ctx->connection->send_window -= len;

        } while (!next && limit > 0);

        if (!next) {
            /*
             * if the buffer wasn't fully sent due to flow control limits,
             * preserve position for future use
             */

            if (in->buf->in_file) {
                in->buf->file_pos = file_pos;

            } else {
                in->buf->pos = pos;
            }

            break;
        }

    next:

        if (in->buf->last_buf) {
            last = 1;
        }

        in = in->next;
    }

    ctx->in = in;

    if (last) {

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output last");

        ctx->output_closed = 1;

        if (f) {
            f->flags |= RAP_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = rap_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;

            f = (rap_http_grpc_frame_t *) b->last;
            b->last += sizeof(rap_http_grpc_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = RAP_HTTP_V2_DATA_FRAME;
            f->flags = RAP_HTTP_V2_END_STREAM_FLAG;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            *ll = cl;
            ll = &cl->next;
        }

        cl->buf->last_buf = 1;
    }

    *ll = NULL;

#if (RAP_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        rap_log_debug7(RAP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#endif

    rc = rap_chain_writer(&r->upstream->writer, out);

    rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (rap_buf_tag_t) &rap_http_grpc_body_output_filter);

    for (cl = ctx->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == RAP_OK && ctx->in) {
        rc = RAP_AGAIN;
    }

    if (rc == RAP_AGAIN) {
        ctx->output_blocked = 1;

    } else {
        ctx->output_blocked = 0;
    }

    if (ctx->done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;

        if (ctx->in == NULL
            && ctx->out == NULL
            && ctx->output_closed
            && !ctx->output_blocked
            && ctx->state == rap_http_grpc_st_start)
        {
            u->keepalive = 1;
        }

        rap_post_event(u->peer.connection->read, &rap_posted_events);
    }

    return rc;
}


static rap_int_t
rap_http_grpc_process_header(rap_http_request_t *r)
{
    rap_str_t                      *status_line;
    rap_int_t                       rc, status;
    rap_buf_t                      *b;
    rap_table_elt_t                *h;
    rap_http_upstream_t            *u;
    rap_http_grpc_ctx_t            *ctx;
    rap_http_upstream_header_t     *hh;
    rap_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;

#if (RAP_DEBUG)
    if (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = rap_min(b->last - b->pos, 256);
        m = rap_hex_dump(buf, b->pos, n) - buf;

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc response: %*s%s, len: %uz",
                       m, buf, b->last - b->pos > 256 ? "..." : "",
                       b->last - b->pos);
    }
#endif

    ctx = rap_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    umcf = rap_http_get_module_main_conf(r, rap_http_upstream_module);

    for ( ;; ) {

        if (ctx->state < rap_http_grpc_st_payload) {

            rc = rap_http_grpc_parse_frame(r, ctx, b);

            if (rc == RAP_AGAIN) {

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */

                if (!ctx->parsing_headers) {
                    b->pos = b->start;
                    b->last = b->pos;
                }

                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->type == RAP_HTTP_V2_DATA_FRAME
                || (ctx->type == RAP_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->parsing_headers)
                || (ctx->type != RAP_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (ctx->type == RAP_HTTP_V2_RST_STREAM_FRAME) {

            rc = rap_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type == RAP_HTTP_V2_GOAWAY_FRAME) {

            rc = rap_http_grpc_parse_goaway(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = rap_http_grpc_parse_window_update(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                rap_post_event(u->peer.connection->write, &rap_posted_events);
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_SETTINGS_FRAME) {

            rc = rap_http_grpc_parse_settings(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                rap_post_event(u->peer.connection->write, &rap_posted_events);
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_PING_FRAME) {

            rc = rap_http_grpc_parse_ping(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            rap_post_event(u->peer.connection->write, &rap_posted_events);
            continue;
        }

        if (ctx->type == RAP_HTTP_V2_PUSH_PROMISE_FRAME) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type != RAP_HTTP_V2_HEADERS_FRAME
            && ctx->type != RAP_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RAP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rap_http_grpc_st_start;

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = rap_http_grpc_parse_header(r, ctx, b);

            if (rc == RAP_AGAIN) {
                break;
            }

            if (rc == RAP_OK) {

                /* a header line has been parsed successfully */

                rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%V: %V\"",
                               &ctx->name, &ctx->value);

                if (ctx->name.len && ctx->name.data[0] == ':') {

                    if (ctx->name.len != sizeof(":status") - 1
                        || rap_strncmp(ctx->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->value;

                    if (status_line->len != 3) {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = rap_atoi(status_line->data, 3);

                    if (status == RAP_ERROR) {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < RAP_HTTP_OK) {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->status = 1;

                    continue;

                } else if (!ctx->status) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = rap_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return RAP_ERROR;
                }

                h->key = ctx->name;
                h->value = ctx->value;
                h->lowcase_key = h->key.data;
                h->hash = rap_hash_key(h->key.data, h->key.len);

                hh = rap_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh && hh->handler(r, h, hh->offset) != RAP_OK) {
                    return RAP_ERROR;
                }

                continue;
            }

            if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header done");

                if (ctx->end_stream) {
                    u->headers_in.content_length_n = 0;

                    if (ctx->in == NULL
                        && ctx->out == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && b->last == b->pos)
                    {
                        u->keepalive = 1;
                    }
                }

                return RAP_OK;
            }

            /* there was error while a header line parsing */

            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == RAP_AGAIN */

        if (ctx->rest == 0) {
            ctx->state = rap_http_grpc_st_start;
            continue;
        }

        return RAP_AGAIN;
    }
}


static rap_int_t
rap_http_grpc_filter_init(void *data)
{
    rap_http_grpc_ctx_t  *ctx = data;

    rap_http_request_t   *r;
    rap_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;

    u->length = 1;

    if (ctx->end_stream) {
        u->length = 0;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_filter(void *data, ssize_t bytes)
{
    rap_http_grpc_ctx_t  *ctx = data;

    rap_int_t             rc;
    rap_buf_t            *b, *buf;
    rap_chain_t          *cl, **ll;
    rap_table_elt_t      *h;
    rap_http_request_t   *r;
    rap_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;
    b = &u->buffer;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc filter bytes:%z", bytes);

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        if (ctx->state < rap_http_grpc_st_payload) {

            rc = rap_http_grpc_parse_frame(r, ctx, b);

            if (rc == RAP_AGAIN) {

                if (ctx->done) {

                    /*
                     * We have finished parsing the response and the
                     * remaining control frames.  If there are unsent
                     * control frames, post a write event to send them.
                     */

                    if (ctx->out) {
                        rap_post_event(u->peer.connection->write,
                                       &rap_posted_events);
                        return RAP_AGAIN;
                    }

                    u->length = 0;

                    if (ctx->in == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && ctx->state == rap_http_grpc_st_start)
                    {
                        u->keepalive = 1;
                    }

                    break;
                }

                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if ((ctx->type == RAP_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->parsing_headers)
                || (ctx->type != RAP_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return RAP_ERROR;
            }

            if (ctx->type == RAP_HTTP_V2_DATA_FRAME) {

                if (ctx->stream_id != ctx->id) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent data frame "
                                  "for unknown stream %ui",
                                  ctx->stream_id);
                    return RAP_ERROR;
                }

                if (ctx->rest > ctx->recv_window) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->recv_window);
                    return RAP_ERROR;
                }

                if (ctx->rest > ctx->connection->recv_window) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->connection->recv_window);
                    return RAP_ERROR;
                }

                ctx->recv_window -= ctx->rest;
                ctx->connection->recv_window -= ctx->rest;

                if (ctx->connection->recv_window < RAP_HTTP_V2_MAX_WINDOW / 4
                    || ctx->recv_window < RAP_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (rap_http_grpc_send_window_update(r, ctx) != RAP_OK) {
                        return RAP_ERROR;
                    }

                    rap_post_event(u->peer.connection->write,
                                   &rap_posted_events);
                }
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return RAP_ERROR;
            }

            if (ctx->stream_id && ctx->done) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return RAP_ERROR;
            }

            ctx->padding = 0;
        }

        if (ctx->state == rap_http_grpc_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RAP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rap_http_grpc_st_start;

            if (ctx->flags & RAP_HTTP_V2_END_STREAM_FLAG) {
                ctx->done = 1;
            }

            continue;
        }

        /* frame payload */

        if (ctx->type == RAP_HTTP_V2_RST_STREAM_FRAME) {

            rc = rap_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return RAP_ERROR;
        }

        if (ctx->type == RAP_HTTP_V2_GOAWAY_FRAME) {

            rc = rap_http_grpc_parse_goaway(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return RAP_ERROR;
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = rap_http_grpc_parse_window_update(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (ctx->in) {
                rap_post_event(u->peer.connection->write, &rap_posted_events);
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_SETTINGS_FRAME) {

            rc = rap_http_grpc_parse_settings(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (ctx->in) {
                rap_post_event(u->peer.connection->write, &rap_posted_events);
            }

            continue;
        }

        if (ctx->type == RAP_HTTP_V2_PING_FRAME) {

            rc = rap_http_grpc_parse_ping(r, ctx, b);

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            rap_post_event(u->peer.connection->write, &rap_posted_events);
            continue;
        }

        if (ctx->type == RAP_HTTP_V2_PUSH_PROMISE_FRAME) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return RAP_ERROR;
        }

        if (ctx->type == RAP_HTTP_V2_HEADERS_FRAME
            || ctx->type == RAP_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = rap_http_grpc_parse_header(r, ctx, b);

                if (rc == RAP_AGAIN) {
                    break;
                }

                if (rc == RAP_OK) {

                    /* a header line has been parsed successfully */

                    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer: \"%V: %V\"",
                                   &ctx->name, &ctx->value);

                    if (ctx->name.len && ctx->name.data[0] == ':') {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return RAP_ERROR;
                    }

                    h = rap_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return RAP_ERROR;
                    }

                    h->key = ctx->name;
                    h->value = ctx->value;
                    h->lowcase_key = h->key.data;
                    h->hash = rap_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer done");

                    if (ctx->end_stream) {
                        ctx->done = 1;
                        break;
                    }

                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return RAP_ERROR;
                }

                /* there was error while a header line parsing */

                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return RAP_ERROR;
            }

            if (rc == RAP_HTTP_PARSE_HEADER_DONE) {
                continue;
            }

            /* rc == RAP_AGAIN */

            if (ctx->rest == 0) {
                ctx->state = rap_http_grpc_st_start;
                continue;
            }

            return RAP_AGAIN;
        }

        if (ctx->type != RAP_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RAP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rap_http_grpc_st_start;

            continue;
        }

        /*
         * data frame:
         *
         * +---------------+
         * |Pad Length? (8)|
         * +---------------+-----------------------------------------------+
         * |                            Data (*)                         ...
         * +---------------------------------------------------------------+
         * |                           Padding (*)                       ...
         * +---------------------------------------------------------------+
         */

        if (ctx->flags & RAP_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return RAP_ERROR;
            }

            if (b->pos == b->last) {
                return RAP_AGAIN;
            }

            ctx->flags &= ~RAP_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return RAP_ERROR;
            }

            continue;
        }

        if (ctx->rest == ctx->padding) {
            goto done;
        }

        if (b->pos == b->last) {
            return RAP_AGAIN;
        }

        cl = rap_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        buf = cl->buf;

        buf->flush = 1;
        buf->memory = 1;

        buf->pos = b->pos;
        buf->tag = u->output.tag;

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output buf %p", buf->pos);

        if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;
            buf->last = b->pos;

            return RAP_AGAIN;
        }

        b->pos += ctx->rest - ctx->padding;
        buf->last = b->pos;
        ctx->rest = ctx->padding;

    done:

        if (ctx->padding) {
            ctx->state = rap_http_grpc_st_padding;
            continue;
        }

        ctx->state = rap_http_grpc_st_start;

        if (ctx->flags & RAP_HTTP_V2_END_STREAM_FLAG) {
            ctx->done = 1;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_parse_frame(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char                 ch, *p;
    rap_http_grpc_state_e  state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case rap_http_grpc_st_start:
            ctx->rest = ch << 16;
            state = rap_http_grpc_st_length_2;
            break;

        case rap_http_grpc_st_length_2:
            ctx->rest |= ch << 8;
            state = rap_http_grpc_st_length_3;
            break;

        case rap_http_grpc_st_length_3:
            ctx->rest |= ch;

            if (ctx->rest > RAP_HTTP_V2_DEFAULT_FRAME_SIZE) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              ctx->rest);
                return RAP_ERROR;
            }

            state = rap_http_grpc_st_type;
            break;

        case rap_http_grpc_st_type:
            ctx->type = ch;
            state = rap_http_grpc_st_flags;
            break;

        case rap_http_grpc_st_flags:
            ctx->flags = ch;
            state = rap_http_grpc_st_stream_id;
            break;

        case rap_http_grpc_st_stream_id:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = rap_http_grpc_st_stream_id_2;
            break;

        case rap_http_grpc_st_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = rap_http_grpc_st_stream_id_3;
            break;

        case rap_http_grpc_st_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = rap_http_grpc_st_stream_id_4;
            break;

        case rap_http_grpc_st_stream_id_4:
            ctx->stream_id |= ch;

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc frame: %d, len: %uz, f:%d, i:%ui",
                           ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

            b->pos = p + 1;

            ctx->state = rap_http_grpc_st_payload;
            ctx->frame_state = 0;

            return RAP_OK;

        /* suppress warning */
        case rap_http_grpc_st_payload:
        case rap_http_grpc_st_padding:
            break;
        }
    }

    b->pos = p;
    ctx->state = state;

    return RAP_AGAIN;
}


static rap_int_t
rap_http_grpc_parse_header(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    rap_int_t  rc;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    state = ctx->frame_state;

    if (state == sw_start) {

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc parse header: start");

        if (ctx->type == RAP_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1;
            ctx->fragment_state = 0;

            min = (ctx->flags & RAP_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & RAP_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return RAP_ERROR;
            }

            if (ctx->flags & RAP_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & RAP_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & RAP_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == RAP_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->padding = 0;
        ctx->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                ctx->padding = ch;

                if (ctx->flags & RAP_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        ctx->rest -= p - b->pos;
        b->pos = p;

        ctx->frame_state = state;
        return RAP_AGAIN;

    fragment:

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return RAP_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = rap_http_grpc_parse_fragment(r, ctx, b);

        if (rc == RAP_AGAIN) {
            return RAP_AGAIN;
        }

        if (rc == RAP_ERROR) {
            return RAP_ERROR;
        }

        if (rc == RAP_OK) {
            return RAP_OK;
        }

        /* rc == RAP_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return RAP_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = rap_http_grpc_st_start;

        if (ctx->flags & RAP_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return RAP_ERROR;
            }

            ctx->parsing_headers = 0;

            return RAP_HTTP_PARSE_HEADER_DONE;
        }

        return RAP_AGAIN;
    }

    /* unreachable */

    return RAP_ERROR;
}


static rap_int_t
rap_http_grpc_parse_fragment(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      size;
    rap_uint_t  index, size_update;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    /* header block fragment */

#if 0
    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest - ctx->padding;
    }

    state = ctx->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return RAP_ERROR;
                }

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc indexed header: %ui", index);

                ctx->index = index;
                ctx->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return RAP_ERROR;
                }

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return RAP_ERROR;
                }

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc table size update: %ui", size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header never indexed: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return RAP_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return RAP_ERROR;
            }

            if (ctx->index > 61) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return RAP_ERROR;
            }

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header index: %ui", ctx->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return RAP_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return RAP_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->name.data = rap_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return RAP_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = rap_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (rap_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != RAP_OK)
                {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return RAP_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = rap_cpymem(ctx->field_end, p, size);
                ctx->name.data[ctx->name.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                rap_str_set(&ctx->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return RAP_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->value.data = rap_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return RAP_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = rap_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (rap_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != RAP_OK)
                {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return RAP_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = rap_cpymem(ctx->field_end, p, size);
                ctx->value.data[ctx->value.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    done:

        p++;
        ctx->rest -= p - b->pos;
        ctx->fragment_state = sw_start;
        b->pos = p;

        if (ctx->index) {
            ctx->name = *rap_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *rap_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (rap_http_grpc_validate_header_name(r, &ctx->name) != RAP_OK) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return RAP_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (rap_http_grpc_validate_header_value(r, &ctx->value) != RAP_OK) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return RAP_ERROR;
            }
        }

        return RAP_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return RAP_AGAIN;
    }

    return RAP_DONE;
}


static rap_int_t
rap_http_grpc_validate_header_name(rap_http_request_t *r, rap_str_t *s)
{
    u_char      ch;
    rap_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return RAP_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return RAP_ERROR;
        }

        if (ch == '\0' || ch == CR || ch == LF) {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_validate_header_value(rap_http_request_t *r, rap_str_t *s)
{
    u_char      ch;
    rap_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_parse_rst_stream(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RAP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (rap_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_start;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RAP_AGAIN;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_parse_goaway(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RAP_ERROR;
        }

        if (ctx->rest < 8) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RAP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            ctx->stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            ctx->error = (rap_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RAP_AGAIN;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc goaway: %ui, stream %ui",
                   ctx->error, ctx->stream_id);

    ctx->state = rap_http_grpc_st_start;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_parse_window_update(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RAP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            ctx->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            ctx->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            ctx->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RAP_AGAIN;
    }

    ctx->state = rap_http_grpc_st_start;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc window update: %ui", ctx->window_update);

    if (ctx->stream_id) {

        if (ctx->window_update > (size_t) RAP_HTTP_V2_MAX_WINDOW
                                 - ctx->send_window)
        {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return RAP_ERROR;
        }

        ctx->send_window += ctx->window_update;

    } else {

        if (ctx->window_update > RAP_HTTP_V2_MAX_WINDOW
                                 - ctx->connection->send_window)
        {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return RAP_ERROR;
        }

        ctx->connection->send_window += ctx->window_update;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_parse_settings(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx,
    rap_buf_t *b)
{
    u_char   ch, *p, *last;
    ssize_t  window_update;
    enum {
        sw_start = 0,
        sw_id,
        sw_id_2,
        sw_value,
        sw_value_2,
        sw_value_3,
        sw_value_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RAP_ERROR;
        }

        if (ctx->flags & RAP_HTTP_V2_ACK_FLAG) {
            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc settings ack");

            if (ctx->rest != 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              ctx->rest);
                return RAP_ERROR;
            }

            ctx->state = rap_http_grpc_st_start;

            return RAP_OK;
        }

        if (ctx->rest % 6 != 0) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RAP_ERROR;
        }

        if (ctx->free == NULL && ctx->settings++ > 1000) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many settings frames");
            return RAP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            ctx->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            ctx->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            ctx->setting_value = (rap_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            ctx->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            ctx->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            ctx->setting_value |= ch;
            state = sw_id;

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc setting: %ui %ui",
                           ctx->setting_id, ctx->setting_value);

            /*
             * The following settings are defined by the protocol:
             *
             * SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
             * SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
             * SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE
             *
             * Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed in
             * a simple client.
             */

            if (ctx->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                if (ctx->setting_value > RAP_HTTP_V2_MAX_WINDOW) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return RAP_ERROR;
                }

                window_update = ctx->setting_value
                                - ctx->connection->init_window;
                ctx->connection->init_window = ctx->setting_value;

                if (ctx->send_window > 0
                    && window_update > (ssize_t) RAP_HTTP_V2_MAX_WINDOW
                                       - ctx->send_window)
                {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return RAP_ERROR;
                }

                ctx->send_window += window_update;
            }

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RAP_AGAIN;
    }

    ctx->state = rap_http_grpc_st_start;

    return rap_http_grpc_send_settings_ack(r, ctx);
}


static rap_int_t
rap_http_grpc_parse_ping(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_data_2,
        sw_data_3,
        sw_data_4,
        sw_data_5,
        sw_data_6,
        sw_data_7,
        sw_data_8
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RAP_ERROR;
        }

        if (ctx->rest != 8) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RAP_ERROR;
        }

        if (ctx->flags & RAP_HTTP_V2_ACK_FLAG) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            return RAP_ERROR;
        }

        if (ctx->free == NULL && ctx->pings++ > 1000) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many ping frames");
            return RAP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            ctx->ping_data[state] = ch;
            state++;

        } else {
            ctx->ping_data[7] = ch;
            state = sw_start;

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc ping");
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RAP_AGAIN;
    }

    ctx->state = rap_http_grpc_st_start;

    return rap_http_grpc_send_ping_ack(r, ctx);
}


static rap_int_t
rap_http_grpc_send_settings_ack(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx)
{
    rap_chain_t            *cl, **ll;
    rap_http_grpc_frame_t  *f;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send settings ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rap_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    f = (rap_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rap_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = RAP_HTTP_V2_SETTINGS_FRAME;
    f->flags = RAP_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    *ll = cl;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_send_ping_ack(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx)
{
    rap_chain_t            *cl, **ll;
    rap_http_grpc_frame_t  *f;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send ping ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rap_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    f = (rap_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rap_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 8;
    f->type = RAP_HTTP_V2_PING_FRAME;
    f->flags = RAP_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = rap_copy(cl->buf->last, ctx->ping_data, 8);

    *ll = cl;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_send_window_update(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx)
{
    size_t                  n;
    rap_chain_t            *cl, **ll;
    rap_http_grpc_frame_t  *f;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send window update: %uz %uz",
                   ctx->connection->recv_window, ctx->recv_window);

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rap_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    f = (rap_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rap_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = RAP_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    n = RAP_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
    ctx->connection->recv_window = RAP_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    f = (rap_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rap_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = RAP_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (ctx->id & 0xff);

    n = RAP_HTTP_V2_MAX_WINDOW - ctx->recv_window;
    ctx->recv_window = RAP_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return RAP_OK;
}


static rap_chain_t *
rap_http_grpc_get_buf(rap_http_request_t *r, rap_http_grpc_ctx_t *ctx)
{
    u_char       *start;
    rap_buf_t    *b;
    rap_chain_t  *cl;

    cl = rap_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {

        /*
         * each buffer is large enough to hold two window update
         * frames in a row
         */

        start = rap_palloc(r->pool, 2 * sizeof(rap_http_grpc_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    rap_memzero(b, sizeof(rap_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(rap_http_grpc_frame_t) + 8;

    b->tag = (rap_buf_tag_t) &rap_http_grpc_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static rap_http_grpc_ctx_t *
rap_http_grpc_get_ctx(rap_http_request_t *r)
{
    rap_http_grpc_ctx_t  *ctx;
    rap_http_upstream_t  *u;

    ctx = rap_http_get_module_ctx(r, rap_http_grpc_module);

    if (ctx->connection == NULL) {
        u = r->upstream;

        if (rap_http_grpc_get_connection_data(r, ctx, &u->peer) != RAP_OK) {
            return NULL;
        }
    }

    return ctx;
}


static rap_int_t
rap_http_grpc_get_connection_data(rap_http_request_t *r,
    rap_http_grpc_ctx_t *ctx, rap_peer_connection_t *pc)
{
    rap_connection_t    *c;
    rap_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /*
         * for cached connections, connection data can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == rap_http_grpc_cleanup) {
                ctx->connection = cln->data;
                break;
            }
        }

        if (ctx->connection == NULL) {
            rap_log_error(RAP_LOG_ERR, c->log, 0,
                          "no connection data found for "
                          "keepalive http2 connection");
            return RAP_ERROR;
        }

        ctx->send_window = ctx->connection->init_window;
        ctx->recv_window = RAP_HTTP_V2_MAX_WINDOW;

        ctx->connection->last_stream_id += 2;
        ctx->id = ctx->connection->last_stream_id;

        return RAP_OK;
    }

    cln = rap_pool_cleanup_add(c->pool, sizeof(rap_http_grpc_conn_t));
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->handler = rap_http_grpc_cleanup;
    ctx->connection = cln->data;

    ctx->connection->init_window = RAP_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->send_window = RAP_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->recv_window = RAP_HTTP_V2_MAX_WINDOW;

    ctx->send_window = RAP_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = RAP_HTTP_V2_MAX_WINDOW;

    ctx->id = 1;
    ctx->connection->last_stream_id = 1;

    return RAP_OK;
}


static void
rap_http_grpc_cleanup(void *data)
{
#if 0
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "grpc cleanup");
#endif
    return;
}


static void
rap_http_grpc_abort_request(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort grpc request");
    return;
}


static void
rap_http_grpc_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize grpc request");
    return;
}


static rap_int_t
rap_http_grpc_internal_trailers_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_table_elt_t  *te;

    te = r->headers_in.te;

    if (te == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    if (rap_strlcasestrn(te->value.data, te->value.data + te->value.len,
                         (u_char *) "trailers", 8 - 1)
        == NULL)
    {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "trailers";
    v->len = sizeof("trailers") - 1;

    return RAP_OK;
}


static rap_int_t
rap_http_grpc_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_grpc_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static void *
rap_http_grpc_create_loc_conf(rap_conf_t *cf)
{
    rap_http_grpc_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_grpc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.ssl_name = NULL;
     *
     *     conf->headers_source = NULL;
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->host = { 0, NULL };
     *     conf->host_set = 0;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     */

    conf->upstream.local = RAP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RAP_CONF_UNSET;
    conf->upstream.next_upstream_tries = RAP_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RAP_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = RAP_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = RAP_CONF_UNSET_PTR;
    conf->upstream.pass_headers = RAP_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = RAP_CONF_UNSET;

#if (RAP_HTTP_SSL)
    conf->upstream.ssl_session_reuse = RAP_CONF_UNSET;
    conf->upstream.ssl_server_name = RAP_CONF_UNSET;
    conf->upstream.ssl_verify = RAP_CONF_UNSET;
    conf->ssl_verify_depth = RAP_CONF_UNSET_UINT;
    conf->ssl_passwords = RAP_CONF_UNSET_PTR;
#endif

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.pass_request_headers = 1;
    conf->upstream.pass_request_body = 1;
    conf->upstream.force_ranges = 0;
    conf->upstream.pass_trailers = 1;
    conf->upstream.preserve_output = 1;

    rap_str_set(&conf->upstream.module, "grpc");

    return conf;
}


static char *
rap_http_grpc_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_grpc_loc_conf_t *prev = parent;
    rap_http_grpc_loc_conf_t *conf = child;

    rap_int_t                  rc;
    rap_hash_init_t            hash;
    rap_http_core_loc_conf_t  *clcf;

    rap_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rap_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rap_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rap_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rap_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              RAP_CONF_BITMASK_SET);

    rap_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_UPSTREAM_FT_ERROR
                               |RAP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RAP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RAP_CONF_BITMASK_SET
                                       |RAP_HTTP_UPSTREAM_FT_OFF;
    }

    rap_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (RAP_HTTP_SSL)

    rap_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    rap_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                                  |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

    rap_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }

    rap_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    rap_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    rap_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    rap_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    rap_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rap_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");
    rap_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");
    rap_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl && rap_http_grpc_set_ssl(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#endif

    hash.max_size = 512;
    hash.bucket_size = rap_align(64, rap_cacheline_size);
    hash.name = "grpc_headers_hash";

    if (rap_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rap_http_grpc_hide_headers, &hash)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->grpc_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->host = prev->host;

        conf->grpc_lengths = prev->grpc_lengths;
        conf->grpc_values = prev->grpc_values;

#if (RAP_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->grpc_lengths))
    {
        clcf->handler = rap_http_grpc_handler;
    }

    if (conf->headers_source == NULL) {
        conf->headers = prev->headers;
        conf->headers_source = prev->headers_source;
        conf->host_set = prev->host_set;
    }

    rc = rap_http_grpc_init_headers(cf, conf, &conf->headers,
                                    rap_http_grpc_headers);
    if (rc != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
        prev->host_set = conf->host_set;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_grpc_init_headers(rap_conf_t *cf, rap_http_grpc_loc_conf_t *conf,
    rap_http_grpc_headers_t *headers, rap_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rap_uint_t                    i;
    rap_array_t                   headers_names, headers_merged;
    rap_keyval_t                 *src, *s, *h;
    rap_hash_key_t               *hk;
    rap_hash_init_t               hash;
    rap_http_script_compile_t     sc;
    rap_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return RAP_OK;
    }

    if (rap_array_init(&headers_names, cf->temp_pool, 4, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_array_init(&headers_merged, cf->temp_pool, 4, sizeof(rap_keyval_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    headers->lengths = rap_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return RAP_ERROR;
    }

    headers->values = rap_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return RAP_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

            if (src[i].key.len == 4
                && rap_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }

            s = rap_array_push(&headers_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (rap_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = rap_array_push(&headers_merged);
        if (s == NULL) {
            return RAP_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = rap_array_push(&headers_names);
        if (hk == NULL) {
            return RAP_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = rap_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = rap_array_push_n(headers->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(rap_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rap_array_push_n(headers->values, size);
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = rap_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(rap_http_script_copy_code_t);
        rap_memcpy(p, src[i].key.data, src[i].key.len);

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_ERROR;
        }

        code = rap_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = rap_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rap_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = rap_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "grpc_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rap_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rap_http_grpc_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_grpc_loc_conf_t *glcf = conf;

    size_t                      add;
    rap_str_t                  *value, *url;
    rap_url_t                   u;
    rap_uint_t                  n;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_script_compile_t   sc;

    if (glcf->upstream.upstream || glcf->grpc_lengths) {
        return "is duplicate";
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    clcf->handler = rap_http_grpc_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = rap_http_script_variables_count(url);

    if (n) {

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &glcf->grpc_lengths;
        sc.values = &glcf->grpc_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

#if (RAP_HTTP_SSL)
        glcf->ssl = 1;
#endif

        return RAP_CONF_OK;
    }

    if (rap_strncasecmp(url->data, (u_char *) "grpc://", 7) == 0) {
        add = 7;

    } else if (rap_strncasecmp(url->data, (u_char *) "grpcs://", 8) == 0) {

#if (RAP_HTTP_SSL)
        glcf->ssl = 1;

        add = 8;
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "grpcs protocol requires SSL support");
        return RAP_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    glcf->upstream.upstream = rap_http_upstream_add(cf, &u, 0);
    if (glcf->upstream.upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    if (u.family != AF_UNIX) {

        if (u.no_port) {
            glcf->host = u.host;

        } else {
            glcf->host.len = u.host.len + 1 + u.port_text.len;
            glcf->host.data = u.host.data;
        }

    } else {
        rap_str_set(&glcf->host, "localhost");
    }

    return RAP_CONF_OK;
}


#if (RAP_HTTP_SSL)

static char *
rap_http_grpc_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_grpc_loc_conf_t *glcf = conf;

    rap_str_t  *value;

    if (glcf->ssl_passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    glcf->ssl_passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (glcf->ssl_passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_grpc_set_ssl(rap_conf_t *cf, rap_http_grpc_loc_conf_t *glcf)
{
    rap_pool_cleanup_t  *cln;

    glcf->upstream.ssl = rap_pcalloc(cf->pool, sizeof(rap_ssl_t));
    if (glcf->upstream.ssl == NULL) {
        return RAP_ERROR;
    }

    glcf->upstream.ssl->log = cf->log;

    if (rap_ssl_create(glcf->upstream.ssl, glcf->ssl_protocols, NULL)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(glcf->upstream.ssl);
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = glcf->upstream.ssl;

    if (glcf->ssl_certificate.len) {

        if (glcf->ssl_certificate_key.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"grpc_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &glcf->ssl_certificate);
            return RAP_ERROR;
        }

        if (rap_ssl_certificate(cf, glcf->upstream.ssl, &glcf->ssl_certificate,
                                &glcf->ssl_certificate_key, glcf->ssl_passwords)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, glcf->upstream.ssl, &glcf->ssl_ciphers, 0)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (glcf->upstream.ssl_verify) {
        if (glcf->ssl_trusted_certificate.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
            return RAP_ERROR;
        }

        if (rap_ssl_trusted_certificate(cf, glcf->upstream.ssl,
                                        &glcf->ssl_trusted_certificate,
                                        glcf->ssl_verify_depth)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        if (rap_ssl_crl(cf, glcf->upstream.ssl, &glcf->ssl_crl) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_client_session_cache(cf, glcf->upstream.ssl,
                                     glcf->upstream.ssl_session_reuse)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (SSL_CTX_set_alpn_protos(glcf->upstream.ssl->ctx,
                                (u_char *) "\x02h2", 3)
        != 0)
    {
        rap_ssl_error(RAP_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_alpn_protos() failed");
        return RAP_ERROR;
    }

#endif

    return RAP_OK;
}

#endif
