
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t               *flushes;
    rp_array_t               *lengths;
    rp_array_t               *values;
    rp_hash_t                 hash;
} rp_http_grpc_headers_t;


typedef struct {
    rp_http_upstream_conf_t   upstream;

    rp_http_grpc_headers_t    headers;
    rp_array_t               *headers_source;

    rp_str_t                  host;
    rp_uint_t                 host_set;

    rp_array_t               *grpc_lengths;
    rp_array_t               *grpc_values;

#if (RP_HTTP_SSL)
    rp_uint_t                 ssl;
    rp_uint_t                 ssl_protocols;
    rp_str_t                  ssl_ciphers;
    rp_uint_t                 ssl_verify_depth;
    rp_str_t                  ssl_trusted_certificate;
    rp_str_t                  ssl_crl;
    rp_str_t                  ssl_certificate;
    rp_str_t                  ssl_certificate_key;
    rp_array_t               *ssl_passwords;
#endif
} rp_http_grpc_loc_conf_t;


typedef enum {
    rp_http_grpc_st_start = 0,
    rp_http_grpc_st_length_2,
    rp_http_grpc_st_length_3,
    rp_http_grpc_st_type,
    rp_http_grpc_st_flags,
    rp_http_grpc_st_stream_id,
    rp_http_grpc_st_stream_id_2,
    rp_http_grpc_st_stream_id_3,
    rp_http_grpc_st_stream_id_4,
    rp_http_grpc_st_payload,
    rp_http_grpc_st_padding
} rp_http_grpc_state_e;


typedef struct {
    size_t                     init_window;
    size_t                     send_window;
    size_t                     recv_window;
    rp_uint_t                 last_stream_id;
} rp_http_grpc_conn_t;


typedef struct {
    rp_http_grpc_state_e      state;
    rp_uint_t                 frame_state;
    rp_uint_t                 fragment_state;

    rp_chain_t               *in;
    rp_chain_t               *out;
    rp_chain_t               *free;
    rp_chain_t               *busy;

    rp_http_grpc_conn_t      *connection;

    rp_uint_t                 id;

    rp_uint_t                 pings;
    rp_uint_t                 settings;

    ssize_t                    send_window;
    size_t                     recv_window;

    size_t                     rest;
    rp_uint_t                 stream_id;
    u_char                     type;
    u_char                     flags;
    u_char                     padding;

    rp_uint_t                 error;
    rp_uint_t                 window_update;

    rp_uint_t                 setting_id;
    rp_uint_t                 setting_value;

    u_char                     ping_data[8];

    rp_uint_t                 index;
    rp_str_t                  name;
    rp_str_t                  value;

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

    rp_http_request_t        *request;

    rp_str_t                  host;
} rp_http_grpc_ctx_t;


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
} rp_http_grpc_frame_t;


static rp_int_t rp_http_grpc_eval(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_http_grpc_loc_conf_t *glcf);
static rp_int_t rp_http_grpc_create_request(rp_http_request_t *r);
static rp_int_t rp_http_grpc_reinit_request(rp_http_request_t *r);
static rp_int_t rp_http_grpc_body_output_filter(void *data, rp_chain_t *in);
static rp_int_t rp_http_grpc_process_header(rp_http_request_t *r);
static rp_int_t rp_http_grpc_filter_init(void *data);
static rp_int_t rp_http_grpc_filter(void *data, ssize_t bytes);

static rp_int_t rp_http_grpc_parse_frame(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_header(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_fragment(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_validate_header_name(rp_http_request_t *r,
    rp_str_t *s);
static rp_int_t rp_http_grpc_validate_header_value(rp_http_request_t *r,
    rp_str_t *s);
static rp_int_t rp_http_grpc_parse_rst_stream(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_goaway(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_window_update(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_settings(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);
static rp_int_t rp_http_grpc_parse_ping(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b);

static rp_int_t rp_http_grpc_send_settings_ack(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx);
static rp_int_t rp_http_grpc_send_ping_ack(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx);
static rp_int_t rp_http_grpc_send_window_update(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx);

static rp_chain_t *rp_http_grpc_get_buf(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx);
static rp_http_grpc_ctx_t *rp_http_grpc_get_ctx(rp_http_request_t *r);
static rp_int_t rp_http_grpc_get_connection_data(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_peer_connection_t *pc);
static void rp_http_grpc_cleanup(void *data);

static void rp_http_grpc_abort_request(rp_http_request_t *r);
static void rp_http_grpc_finalize_request(rp_http_request_t *r,
    rp_int_t rc);

static rp_int_t rp_http_grpc_internal_trailers_variable(
    rp_http_request_t *r, rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_grpc_add_variables(rp_conf_t *cf);
static void *rp_http_grpc_create_loc_conf(rp_conf_t *cf);
static char *rp_http_grpc_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_grpc_init_headers(rp_conf_t *cf,
    rp_http_grpc_loc_conf_t *conf, rp_http_grpc_headers_t *headers,
    rp_keyval_t *default_headers);

static char *rp_http_grpc_pass(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

#if (RP_HTTP_SSL)
static char *rp_http_grpc_ssl_password_file(rp_conf_t *cf,
    rp_command_t *cmd, void *conf);
static rp_int_t rp_http_grpc_set_ssl(rp_conf_t *cf,
    rp_http_grpc_loc_conf_t *glcf);
#endif


static rp_conf_bitmask_t  rp_http_grpc_next_upstream_masks[] = {
    { rp_string("error"), RP_HTTP_UPSTREAM_FT_ERROR },
    { rp_string("timeout"), RP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rp_string("invalid_header"), RP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rp_string("non_idempotent"), RP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rp_string("http_500"), RP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rp_string("http_502"), RP_HTTP_UPSTREAM_FT_HTTP_502 },
    { rp_string("http_503"), RP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rp_string("http_504"), RP_HTTP_UPSTREAM_FT_HTTP_504 },
    { rp_string("http_403"), RP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rp_string("http_404"), RP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rp_string("http_429"), RP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rp_string("off"), RP_HTTP_UPSTREAM_FT_OFF },
    { rp_null_string, 0 }
};


#if (RP_HTTP_SSL)

static rp_conf_bitmask_t  rp_http_grpc_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};

#endif


static rp_command_t  rp_http_grpc_commands[] = {

    { rp_string("grpc_pass"),
      RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_grpc_pass,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("grpc_bind"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_upstream_bind_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.local),
      NULL },

    { rp_string("grpc_socket_keepalive"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rp_string("grpc_connect_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rp_string("grpc_send_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.send_timeout),
      NULL },

    { rp_string("grpc_intercept_errors"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rp_string("grpc_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.buffer_size),
      NULL },

    { rp_string("grpc_read_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.read_timeout),
      NULL },

    { rp_string("grpc_next_upstream"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.next_upstream),
      &rp_http_grpc_next_upstream_masks },

    { rp_string("grpc_next_upstream_tries"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rp_string("grpc_next_upstream_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rp_string("grpc_set_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_keyval_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, headers_source),
      NULL },

    { rp_string("grpc_pass_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.pass_headers),
      NULL },

    { rp_string("grpc_hide_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.hide_headers),
      NULL },

    { rp_string("grpc_ignore_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.ignore_headers),
      &rp_http_upstream_ignore_headers_masks },

#if (RP_HTTP_SSL)

    { rp_string("grpc_ssl_session_reuse"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { rp_string("grpc_ssl_protocols"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_protocols),
      &rp_http_grpc_ssl_protocols },

    { rp_string("grpc_ssl_ciphers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_ciphers),
      NULL },

    { rp_string("grpc_ssl_name"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_set_complex_value_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.ssl_name),
      NULL },

    { rp_string("grpc_ssl_server_name"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { rp_string("grpc_ssl_verify"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, upstream.ssl_verify),
      NULL },

    { rp_string("grpc_ssl_verify_depth"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_verify_depth),
      NULL },

    { rp_string("grpc_ssl_trusted_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { rp_string("grpc_ssl_crl"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_crl),
      NULL },

    { rp_string("grpc_ssl_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_certificate),
      NULL },

    { rp_string("grpc_ssl_certificate_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_grpc_loc_conf_t, ssl_certificate_key),
      NULL },

    { rp_string("grpc_ssl_password_file"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_grpc_ssl_password_file,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rp_null_command
};


static rp_http_module_t  rp_http_grpc_module_ctx = {
    rp_http_grpc_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_grpc_create_loc_conf,         /* create location configuration */
    rp_http_grpc_merge_loc_conf           /* merge location configuration */
};


rp_module_t  rp_http_grpc_module = {
    RP_MODULE_V1,
    &rp_http_grpc_module_ctx,             /* module context */
    rp_http_grpc_commands,                /* module directives */
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


static u_char  rp_http_grpc_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


static rp_keyval_t  rp_http_grpc_headers[] = {
    { rp_string("Content-Length"), rp_string("$content_length") },
    { rp_string("TE"), rp_string("$grpc_internal_trailers") },
    { rp_string("Host"), rp_string("") },
    { rp_string("Connection"), rp_string("") },
    { rp_string("Transfer-Encoding"), rp_string("") },
    { rp_string("Keep-Alive"), rp_string("") },
    { rp_string("Expect"), rp_string("") },
    { rp_string("Upgrade"), rp_string("") },
    { rp_null_string, rp_null_string }
};


static rp_str_t  rp_http_grpc_hide_headers[] = {
    rp_string("Date"),
    rp_string("Server"),
    rp_string("X-Accel-Expires"),
    rp_string("X-Accel-Redirect"),
    rp_string("X-Accel-Limit-Rate"),
    rp_string("X-Accel-Buffering"),
    rp_string("X-Accel-Charset"),
    rp_null_string
};


static rp_http_variable_t  rp_http_grpc_vars[] = {

    { rp_string("grpc_internal_trailers"), NULL,
      rp_http_grpc_internal_trailers_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_NOHASH, 0 },

      rp_http_null_variable
};


static rp_int_t
rp_http_grpc_handler(rp_http_request_t *r)
{
    rp_int_t                  rc;
    rp_http_upstream_t       *u;
    rp_http_grpc_ctx_t       *ctx;
    rp_http_grpc_loc_conf_t  *glcf;

    if (rp_http_upstream_create(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_grpc_ctx_t));
    if (ctx == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    rp_http_set_ctx(r, ctx, rp_http_grpc_module);

    glcf = rp_http_get_module_loc_conf(r, rp_http_grpc_module);

    u = r->upstream;

    if (glcf->grpc_lengths == NULL) {
        ctx->host = glcf->host;

#if (RP_HTTP_SSL)
        u->ssl = (glcf->upstream.ssl != NULL);

        if (u->ssl) {
            rp_str_set(&u->schema, "grpcs://");

        } else {
            rp_str_set(&u->schema, "grpc://");
        }
#else
        rp_str_set(&u->schema, "grpc://");
#endif

    } else {
        if (rp_http_grpc_eval(r, ctx, glcf) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (rp_buf_tag_t) &rp_http_grpc_module;

    u->conf = &glcf->upstream;

    u->create_request = rp_http_grpc_create_request;
    u->reinit_request = rp_http_grpc_reinit_request;
    u->process_header = rp_http_grpc_process_header;
    u->abort_request = rp_http_grpc_abort_request;
    u->finalize_request = rp_http_grpc_finalize_request;

    u->input_filter_init = rp_http_grpc_filter_init;
    u->input_filter = rp_http_grpc_filter;
    u->input_filter_ctx = ctx;

    r->request_body_no_buffering = 1;

    rc = rp_http_read_client_request_body(r, rp_http_upstream_init);

    if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return RP_DONE;
}


static rp_int_t
rp_http_grpc_eval(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_http_grpc_loc_conf_t *glcf)
{
    size_t                add;
    rp_url_t             url;
    rp_http_upstream_t  *u;

    rp_memzero(&url, sizeof(rp_url_t));

    if (rp_http_script_run(r, &url.url, glcf->grpc_lengths->elts, 0,
                            glcf->grpc_values->elts)
        == NULL)
    {
        return RP_ERROR;
    }

    if (url.url.len > 7
        && rp_strncasecmp(url.url.data, (u_char *) "grpc://", 7) == 0)
    {
        add = 7;

    } else if (url.url.len > 8
               && rp_strncasecmp(url.url.data, (u_char *) "grpcs://", 8) == 0)
    {

#if (RP_HTTP_SSL)
        add = 8;
        r->upstream->ssl = 1;
#else
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "grpcs protocol requires SSL support");
        return RP_ERROR;
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
        rp_str_set(&u->schema, "grpc://");
    }

    url.no_resolve = 1;

    if (rp_parse_url(r->pool, &url) != RP_OK) {
        if (url.err) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RP_ERROR;
    }

    u->resolved = rp_pcalloc(r->pool, sizeof(rp_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RP_ERROR;
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
        rp_str_set(&ctx->host, "localhost");
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_create_request(rp_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame;
    size_t                        len, tmp_len, key_len, val_len, uri_len;
    uintptr_t                     escape;
    rp_buf_t                    *b;
    rp_uint_t                    i, next;
    rp_chain_t                  *cl, *body;
    rp_list_part_t              *part;
    rp_table_elt_t              *header;
    rp_http_grpc_ctx_t          *ctx;
    rp_http_upstream_t          *u;
    rp_http_grpc_frame_t        *f;
    rp_http_script_code_pt       code;
    rp_http_grpc_loc_conf_t     *glcf;
    rp_http_script_engine_t      e, le;
    rp_http_script_len_code_pt   lcode;

    u = r->upstream;

    glcf = rp_http_get_module_loc_conf(r, rp_http_grpc_module);

    ctx = rp_http_get_module_ctx(r, rp_http_grpc_module);

    len = sizeof(rp_http_grpc_connection_start) - 1
          + sizeof(rp_http_grpc_frame_t);             /* headers frame */

    /* :method header */

    if (r->method == RP_HTTP_GET || r->method == RP_HTTP_POST) {
        len += 1;
        tmp_len = 0;

    } else {
        len += 1 + RP_HTTP_V2_INT_OCTETS + r->method_name.len;
        tmp_len = r->method_name.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    if (r->valid_unparsed_uri) {
        escape = 0;
        uri_len = r->unparsed_uri.len;

    } else {
        escape = 2 * rp_escape_uri(NULL, r->uri.data, r->uri.len,
                                    RP_ESCAPE_URI);
        uri_len = r->uri.len + escape + sizeof("?") - 1 + r->args.len;
    }

    len += 1 + RP_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    if (!glcf->host_set) {
        len += 1 + RP_HTTP_V2_INT_OCTETS + ctx->host.len;

        if (tmp_len < ctx->host.len) {
            tmp_len = ctx->host.len;
        }
    }

    /* other headers */

    rp_http_script_flush_no_cacheable_variables(r, glcf->headers.flushes);
    rp_memzero(&le, sizeof(rp_http_script_engine_t));

    le.ip = glcf->headers.lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rp_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rp_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += 1 + RP_HTTP_V2_INT_OCTETS + key_len
                 + RP_HTTP_V2_INT_OCTETS + val_len;

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

            if (rp_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += 1 + RP_HTTP_V2_INT_OCTETS + header[i].key.len
                     + RP_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(rp_http_grpc_frame_t)
           * (len / RP_HTTP_V2_DEFAULT_FRAME_SIZE);


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

    tmp = rp_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return RP_ERROR;
    }

    key_tmp = tmp + tmp_len;
    val_tmp = tmp + 2 * tmp_len;

    /* connection preface */

    b->last = rp_copy(b->last, rp_http_grpc_connection_start,
                       sizeof(rp_http_grpc_connection_start) - 1);

    /* headers frame */

    headers_frame = b->last;

    f = (rp_http_grpc_frame_t *) b->last;
    b->last += sizeof(rp_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = RP_HTTP_V2_HEADERS_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (r->method == RP_HTTP_GET) {
        *b->last++ = rp_http_v2_indexed(RP_HTTP_V2_METHOD_GET_INDEX);

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: GET\"");

    } else if (r->method == RP_HTTP_POST) {
        *b->last++ = rp_http_v2_indexed(RP_HTTP_V2_METHOD_POST_INDEX);

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: POST\"");

    } else {
        *b->last++ = rp_http_v2_inc_indexed(RP_HTTP_V2_METHOD_INDEX);
        b->last = rp_http_v2_write_value(b->last, r->method_name.data,
                                          r->method_name.len, tmp);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: %V\"", &r->method_name);
    }

#if (RP_HTTP_SSL)
    if (u->ssl) {
        *b->last++ = rp_http_v2_indexed(RP_HTTP_V2_SCHEME_HTTPS_INDEX);

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = rp_http_v2_indexed(RP_HTTP_V2_SCHEME_HTTP_INDEX);

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: http\"");
    }

    if (r->valid_unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = rp_http_v2_indexed(RP_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = rp_http_v2_inc_indexed(RP_HTTP_V2_PATH_INDEX);
            b->last = rp_http_v2_write_value(b->last, r->unparsed_uri.data,
                                              r->unparsed_uri.len, tmp);
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->unparsed_uri);

    } else if (escape || r->args.len > 0) {
        p = val_tmp;

        if (escape) {
            p = (u_char *) rp_escape_uri(p, r->uri.data, r->uri.len,
                                          RP_ESCAPE_URI);

        } else {
            p = rp_copy(p, r->uri.data, r->uri.len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = rp_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = rp_http_v2_inc_indexed(RP_HTTP_V2_PATH_INDEX);
        b->last = rp_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %*s\"", p - val_tmp, val_tmp);

    } else {
        *b->last++ = rp_http_v2_inc_indexed(RP_HTTP_V2_PATH_INDEX);
        b->last = rp_http_v2_write_value(b->last, r->uri.data,
                                          r->uri.len, tmp);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->uri);
    }

    if (!glcf->host_set) {
        *b->last++ = rp_http_v2_inc_indexed(RP_HTTP_V2_AUTHORITY_INDEX);
        b->last = rp_http_v2_write_value(b->last, ctx->host.data,
                                          ctx->host.len, tmp);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":authority: %V\"", &ctx->host);
    }

    rp_memzero(&e, sizeof(rp_http_script_engine_t));

    e.ip = glcf->headers.values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = glcf->headers.lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rp_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rp_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(rp_http_script_code_pt *) e.ip;
                code((rp_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        *b->last++ = 0;

        e.pos = key_tmp;

        code = *(rp_http_script_code_pt *) e.ip;
        code((rp_http_script_engine_t *) &e);

        b->last = rp_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;

        while (*(uintptr_t *) e.ip) {
            code = *(rp_http_script_code_pt *) e.ip;
            code((rp_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        b->last = rp_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (RP_DEBUG)
        if (r->connection->log->log_level & RP_LOG_DEBUG_HTTP) {
            rp_strlow(key_tmp, key_tmp, key_len);

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

            if (rp_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = rp_http_v2_write_name(b->last, header[i].key.data,
                                             header[i].key.len, tmp);

            b->last = rp_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (RP_DEBUG)
            if (r->connection->log->log_level & RP_LOG_DEBUG_HTTP) {
                rp_strlow(tmp, header[i].key.data, header[i].key.len);

                rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(rp_http_grpc_frame_t);

    if (len > RP_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = RP_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (rp_http_grpc_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(rp_http_grpc_frame_t) + RP_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        rp_memmove(p + sizeof(rp_http_grpc_frame_t), p, len);
        b->last += sizeof(rp_http_grpc_frame_t);

        if (len > RP_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = RP_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (rp_http_grpc_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = RP_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= RP_HTTP_V2_END_HEADERS_FLAG;

#if (RP_DEBUG)
    if (r->connection->log->log_level & RP_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = rp_min(b->last - b->pos, 256);
        m = rp_hex_dump(buf, b->pos, n) - buf;

        rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
            f = (rp_http_grpc_frame_t *) headers_frame;
            f->flags |= RP_HTTP_V2_END_STREAM_FLAG;
        }

        while (body) {
            b = rp_alloc_buf(r->pool);
            if (b == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(b, body->buf, sizeof(rp_buf_t));

            cl->next = rp_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return RP_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        b->last_buf = 1;
    }

    u->output.output_filter = rp_http_grpc_body_output_filter;
    u->output.filter_ctx = r;

    b->flush = 1;
    cl->next = NULL;

    return RP_OK;
}


static rp_int_t
rp_http_grpc_reinit_request(rp_http_request_t *r)
{
    rp_http_grpc_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_grpc_module);

    if (ctx == NULL) {
        return RP_OK;
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

    return RP_OK;
}


static rp_int_t
rp_http_grpc_body_output_filter(void *data, rp_chain_t *in)
{
    rp_http_request_t  *r = data;

    off_t                   file_pos;
    u_char                 *p, *pos, *start;
    size_t                  len, limit;
    rp_buf_t              *b;
    rp_int_t               rc;
    rp_uint_t              next, last;
    rp_chain_t            *cl, *out, **ll;
    rp_http_upstream_t    *u;
    rp_http_grpc_ctx_t    *ctx;
    rp_http_grpc_frame_t  *f;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output filter");

    ctx = rp_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return RP_ERROR;
    }

    if (in) {
        if (rp_chain_add_copy(r->pool, &ctx->in, in) != RP_OK) {
            return RP_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers */

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output header");

        ctx->header_sent = 1;

        if (ctx->id != 1) {
            /*
             * keepalive connection: skip connection preface,
             * update stream identifiers
             */

            b = ctx->in->buf;
            b->pos += sizeof(rp_http_grpc_connection_start) - 1;

            p = b->pos;

            while (p < b->last) {
                f = (rp_http_grpc_frame_t *) p;
                p += sizeof(rp_http_grpc_frame_t);

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

    limit = rp_max(0, ctx->send_window);

    if (limit > ctx->connection->send_window) {
        limit = ctx->connection->send_window;
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#if (RP_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->in;

    while (in && limit > 0) {

        rp_log_debug7(RP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (rp_buf_special(in->buf)) {
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {

            cl = rp_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return RP_ERROR;
            }

            b = cl->buf;

            f = (rp_http_grpc_frame_t *) b->last;
            b->last += sizeof(rp_http_grpc_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = rp_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RP_ERROR;
            }

            b = cl->buf;
            start = b->start;

            rp_memcpy(b, in->buf, sizeof(rp_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and control frames
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += rp_min(RP_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (rp_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += rp_min(RP_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (rp_uint_t) (pos - b->pos);
            }

            b->tag = (rp_buf_tag_t) &rp_http_grpc_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = RP_HTTP_V2_DATA_FRAME;
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

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output last");

        ctx->output_closed = 1;

        if (f) {
            f->flags |= RP_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = rp_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return RP_ERROR;
            }

            b = cl->buf;

            f = (rp_http_grpc_frame_t *) b->last;
            b->last += sizeof(rp_http_grpc_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = RP_HTTP_V2_DATA_FRAME;
            f->flags = RP_HTTP_V2_END_STREAM_FLAG;
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

#if (RP_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        rp_log_debug7(RP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#endif

    rc = rp_chain_writer(&r->upstream->writer, out);

    rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (rp_buf_tag_t) &rp_http_grpc_body_output_filter);

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

    if (rc == RP_OK && ctx->in) {
        rc = RP_AGAIN;
    }

    if (rc == RP_AGAIN) {
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
            && ctx->state == rp_http_grpc_st_start)
        {
            u->keepalive = 1;
        }

        rp_post_event(u->peer.connection->read, &rp_posted_events);
    }

    return rc;
}


static rp_int_t
rp_http_grpc_process_header(rp_http_request_t *r)
{
    rp_str_t                      *status_line;
    rp_int_t                       rc, status;
    rp_buf_t                      *b;
    rp_table_elt_t                *h;
    rp_http_upstream_t            *u;
    rp_http_grpc_ctx_t            *ctx;
    rp_http_upstream_header_t     *hh;
    rp_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;

#if (RP_DEBUG)
    if (r->connection->log->log_level & RP_LOG_DEBUG_HTTP) {
        u_char  buf[512];
        size_t  n, m;

        n = rp_min(b->last - b->pos, 256);
        m = rp_hex_dump(buf, b->pos, n) - buf;

        rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc response: %*s%s, len: %uz",
                       m, buf, b->last - b->pos > 256 ? "..." : "",
                       b->last - b->pos);
    }
#endif

    ctx = rp_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return RP_ERROR;
    }

    umcf = rp_http_get_module_main_conf(r, rp_http_upstream_module);

    for ( ;; ) {

        if (ctx->state < rp_http_grpc_st_payload) {

            rc = rp_http_grpc_parse_frame(r, ctx, b);

            if (rc == RP_AGAIN) {

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */

                if (!ctx->parsing_headers) {
                    b->pos = b->start;
                    b->last = b->pos;
                }

                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->type == RP_HTTP_V2_DATA_FRAME
                || (ctx->type == RP_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->parsing_headers)
                || (ctx->type != RP_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (ctx->type == RP_HTTP_V2_RST_STREAM_FRAME) {

            rc = rp_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return RP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type == RP_HTTP_V2_GOAWAY_FRAME) {

            rc = rp_http_grpc_parse_goaway(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
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

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = rp_http_grpc_parse_window_update(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                rp_post_event(u->peer.connection->write, &rp_posted_events);
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_SETTINGS_FRAME) {

            rc = rp_http_grpc_parse_settings(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                rp_post_event(u->peer.connection->write, &rp_posted_events);
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_PING_FRAME) {

            rc = rp_http_grpc_parse_ping(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            rp_post_event(u->peer.connection->write, &rp_posted_events);
            continue;
        }

        if (ctx->type == RP_HTTP_V2_PUSH_PROMISE_FRAME) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return RP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type != RP_HTTP_V2_HEADERS_FRAME
            && ctx->type != RP_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rp_http_grpc_st_start;

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = rp_http_grpc_parse_header(r, ctx, b);

            if (rc == RP_AGAIN) {
                break;
            }

            if (rc == RP_OK) {

                /* a header line has been parsed successfully */

                rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%V: %V\"",
                               &ctx->name, &ctx->value);

                if (ctx->name.len && ctx->name.data[0] == ':') {

                    if (ctx->name.len != sizeof(":status") - 1
                        || rp_strncmp(ctx->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return RP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return RP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->value;

                    if (status_line->len != 3) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return RP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = rp_atoi(status_line->data, 3);

                    if (status == RP_ERROR) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return RP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < RP_HTTP_OK) {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return RP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->status = 1;

                    continue;

                } else if (!ctx->status) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return RP_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = rp_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return RP_ERROR;
                }

                h->key = ctx->name;
                h->value = ctx->value;
                h->lowcase_key = h->key.data;
                h->hash = rp_hash_key(h->key.data, h->key.len);

                hh = rp_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh && hh->handler(r, h, hh->offset) != RP_OK) {
                    return RP_ERROR;
                }

                continue;
            }

            if (rc == RP_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                return RP_OK;
            }

            /* there was error while a header line parsing */

            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return RP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == RP_AGAIN */

        if (ctx->rest == 0) {
            ctx->state = rp_http_grpc_st_start;
            continue;
        }

        return RP_AGAIN;
    }
}


static rp_int_t
rp_http_grpc_filter_init(void *data)
{
    rp_http_grpc_ctx_t  *ctx = data;

    rp_http_request_t   *r;
    rp_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;

    u->length = 1;

    if (ctx->end_stream) {
        u->length = 0;
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_filter(void *data, ssize_t bytes)
{
    rp_http_grpc_ctx_t  *ctx = data;

    rp_int_t             rc;
    rp_buf_t            *b, *buf;
    rp_chain_t          *cl, **ll;
    rp_table_elt_t      *h;
    rp_http_request_t   *r;
    rp_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;
    b = &u->buffer;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc filter bytes:%z", bytes);

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        if (ctx->state < rp_http_grpc_st_payload) {

            rc = rp_http_grpc_parse_frame(r, ctx, b);

            if (rc == RP_AGAIN) {

                if (ctx->done) {

                    /*
                     * We have finished parsing the response and the
                     * remaining control frames.  If there are unsent
                     * control frames, post a write event to send them.
                     */

                    if (ctx->out) {
                        rp_post_event(u->peer.connection->write,
                                       &rp_posted_events);
                        return RP_AGAIN;
                    }

                    u->length = 0;

                    if (ctx->in == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && ctx->state == rp_http_grpc_st_start)
                    {
                        u->keepalive = 1;
                    }

                    break;
                }

                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            if ((ctx->type == RP_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->parsing_headers)
                || (ctx->type != RP_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return RP_ERROR;
            }

            if (ctx->type == RP_HTTP_V2_DATA_FRAME) {

                if (ctx->stream_id != ctx->id) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent data frame "
                                  "for unknown stream %ui",
                                  ctx->stream_id);
                    return RP_ERROR;
                }

                if (ctx->rest > ctx->recv_window) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->recv_window);
                    return RP_ERROR;
                }

                if (ctx->rest > ctx->connection->recv_window) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->connection->recv_window);
                    return RP_ERROR;
                }

                ctx->recv_window -= ctx->rest;
                ctx->connection->recv_window -= ctx->rest;

                if (ctx->connection->recv_window < RP_HTTP_V2_MAX_WINDOW / 4
                    || ctx->recv_window < RP_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (rp_http_grpc_send_window_update(r, ctx) != RP_OK) {
                        return RP_ERROR;
                    }

                    rp_post_event(u->peer.connection->write,
                                   &rp_posted_events);
                }
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return RP_ERROR;
            }

            if (ctx->stream_id && ctx->done) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return RP_ERROR;
            }

            ctx->padding = 0;
        }

        if (ctx->state == rp_http_grpc_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rp_http_grpc_st_start;

            if (ctx->flags & RP_HTTP_V2_END_STREAM_FLAG) {
                ctx->done = 1;
            }

            continue;
        }

        /* frame payload */

        if (ctx->type == RP_HTTP_V2_RST_STREAM_FRAME) {

            rc = rp_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return RP_ERROR;
        }

        if (ctx->type == RP_HTTP_V2_GOAWAY_FRAME) {

            rc = rp_http_grpc_parse_goaway(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
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

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return RP_ERROR;
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = rp_http_grpc_parse_window_update(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            if (ctx->in) {
                rp_post_event(u->peer.connection->write, &rp_posted_events);
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_SETTINGS_FRAME) {

            rc = rp_http_grpc_parse_settings(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            if (ctx->in) {
                rp_post_event(u->peer.connection->write, &rp_posted_events);
            }

            continue;
        }

        if (ctx->type == RP_HTTP_V2_PING_FRAME) {

            rc = rp_http_grpc_parse_ping(r, ctx, b);

            if (rc == RP_AGAIN) {
                return RP_AGAIN;
            }

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            rp_post_event(u->peer.connection->write, &rp_posted_events);
            continue;
        }

        if (ctx->type == RP_HTTP_V2_PUSH_PROMISE_FRAME) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return RP_ERROR;
        }

        if (ctx->type == RP_HTTP_V2_HEADERS_FRAME
            || ctx->type == RP_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = rp_http_grpc_parse_header(r, ctx, b);

                if (rc == RP_AGAIN) {
                    break;
                }

                if (rc == RP_OK) {

                    /* a header line has been parsed successfully */

                    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer: \"%V: %V\"",
                                   &ctx->name, &ctx->value);

                    if (ctx->name.len && ctx->name.data[0] == ':') {
                        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return RP_ERROR;
                    }

                    h = rp_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return RP_ERROR;
                    }

                    h->key = ctx->name;
                    h->value = ctx->value;
                    h->lowcase_key = h->key.data;
                    h->hash = rp_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == RP_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer done");

                    if (ctx->end_stream) {
                        ctx->done = 1;
                        break;
                    }

                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return RP_ERROR;
                }

                /* there was error while a header line parsing */

                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return RP_ERROR;
            }

            if (rc == RP_HTTP_PARSE_HEADER_DONE) {
                continue;
            }

            /* rc == RP_AGAIN */

            if (ctx->rest == 0) {
                ctx->state = rp_http_grpc_st_start;
                continue;
            }

            return RP_AGAIN;
        }

        if (ctx->type != RP_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return RP_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = rp_http_grpc_st_start;

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

        if (ctx->flags & RP_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return RP_ERROR;
            }

            if (b->pos == b->last) {
                return RP_AGAIN;
            }

            ctx->flags &= ~RP_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return RP_ERROR;
            }

            continue;
        }

        if (ctx->rest == ctx->padding) {
            goto done;
        }

        if (b->pos == b->last) {
            return RP_AGAIN;
        }

        cl = rp_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return RP_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        buf = cl->buf;

        buf->flush = 1;
        buf->memory = 1;

        buf->pos = b->pos;
        buf->tag = u->output.tag;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output buf %p", buf->pos);

        if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;
            buf->last = b->pos;

            return RP_AGAIN;
        }

        b->pos += ctx->rest - ctx->padding;
        buf->last = b->pos;
        ctx->rest = ctx->padding;

    done:

        if (ctx->padding) {
            ctx->state = rp_http_grpc_st_padding;
            continue;
        }

        ctx->state = rp_http_grpc_st_start;

        if (ctx->flags & RP_HTTP_V2_END_STREAM_FLAG) {
            ctx->done = 1;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_parse_frame(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
{
    u_char                 ch, *p;
    rp_http_grpc_state_e  state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case rp_http_grpc_st_start:
            ctx->rest = ch << 16;
            state = rp_http_grpc_st_length_2;
            break;

        case rp_http_grpc_st_length_2:
            ctx->rest |= ch << 8;
            state = rp_http_grpc_st_length_3;
            break;

        case rp_http_grpc_st_length_3:
            ctx->rest |= ch;

            if (ctx->rest > RP_HTTP_V2_DEFAULT_FRAME_SIZE) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              ctx->rest);
                return RP_ERROR;
            }

            state = rp_http_grpc_st_type;
            break;

        case rp_http_grpc_st_type:
            ctx->type = ch;
            state = rp_http_grpc_st_flags;
            break;

        case rp_http_grpc_st_flags:
            ctx->flags = ch;
            state = rp_http_grpc_st_stream_id;
            break;

        case rp_http_grpc_st_stream_id:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = rp_http_grpc_st_stream_id_2;
            break;

        case rp_http_grpc_st_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = rp_http_grpc_st_stream_id_3;
            break;

        case rp_http_grpc_st_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = rp_http_grpc_st_stream_id_4;
            break;

        case rp_http_grpc_st_stream_id_4:
            ctx->stream_id |= ch;

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc frame: %d, len: %uz, f:%d, i:%ui",
                           ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

            b->pos = p + 1;

            ctx->state = rp_http_grpc_st_payload;
            ctx->frame_state = 0;

            return RP_OK;

        /* suppress warning */
        case rp_http_grpc_st_payload:
        case rp_http_grpc_st_padding:
            break;
        }
    }

    b->pos = p;
    ctx->state = state;

    return RP_AGAIN;
}


static rp_int_t
rp_http_grpc_parse_header(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    rp_int_t  rc;
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

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc parse header: start");

        if (ctx->type == RP_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1;
            ctx->fragment_state = 0;

            min = (ctx->flags & RP_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & RP_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return RP_ERROR;
            }

            if (ctx->flags & RP_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & RP_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & RP_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == RP_HTTP_V2_CONTINUATION_FRAME) {
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
            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                if (ctx->flags & RP_HTTP_V2_PRIORITY_FLAG) {
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
        return RP_AGAIN;

    fragment:

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return RP_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = rp_http_grpc_parse_fragment(r, ctx, b);

        if (rc == RP_AGAIN) {
            return RP_AGAIN;
        }

        if (rc == RP_ERROR) {
            return RP_ERROR;
        }

        if (rc == RP_OK) {
            return RP_OK;
        }

        /* rc == RP_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return RP_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = rp_http_grpc_st_start;

        if (ctx->flags & RP_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return RP_ERROR;
            }

            ctx->parsing_headers = 0;

            return RP_HTTP_PARSE_HEADER_DONE;
        }

        return RP_AGAIN;
    }

    /* unreachable */

    return RP_ERROR;
}


static rp_int_t
rp_http_grpc_parse_fragment(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      size;
    rp_uint_t  index, size_update;
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
    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return RP_ERROR;
                }

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return RP_ERROR;
                }

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return RP_ERROR;
                }

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return RP_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return RP_ERROR;
            }

            if (ctx->index > 61) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return RP_ERROR;
            }

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return RP_ERROR;
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
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return RP_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->name.data = rp_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return RP_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = rp_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (rp_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != RP_OK)
                {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return RP_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = rp_cpymem(ctx->field_end, p, size);
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
                rp_str_set(&ctx->value, "");
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
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return RP_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->value.data = rp_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return RP_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = rp_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (rp_http_v2_huff_decode(&ctx->field_state, p, size,
                                            &ctx->field_end,
                                            ctx->field_rest == 0,
                                            r->connection->log)
                    != RP_OK)
                {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return RP_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = rp_cpymem(ctx->field_end, p, size);
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
            ctx->name = *rp_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *rp_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (rp_http_grpc_validate_header_name(r, &ctx->name) != RP_OK) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return RP_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (rp_http_grpc_validate_header_value(r, &ctx->value) != RP_OK) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return RP_ERROR;
            }
        }

        return RP_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return RP_AGAIN;
    }

    return RP_DONE;
}


static rp_int_t
rp_http_grpc_validate_header_name(rp_http_request_t *r, rp_str_t *s)
{
    u_char      ch;
    rp_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return RP_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return RP_ERROR;
        }

        if (ch == '\0' || ch == CR || ch == LF) {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_validate_header_value(rp_http_request_t *r, rp_str_t *s)
{
    u_char      ch;
    rp_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_parse_rst_stream(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
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
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (rp_uint_t) ch << 24;
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

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RP_AGAIN;
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_parse_goaway(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
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
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RP_ERROR;
        }

        if (ctx->rest < 8) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
            ctx->error = (rp_uint_t) ch << 24;
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
        return RP_AGAIN;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc goaway: %ui, stream %ui",
                   ctx->error, ctx->stream_id);

    ctx->state = rp_http_grpc_st_start;

    return RP_OK;
}


static rp_int_t
rp_http_grpc_parse_window_update(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b)
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
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
        return RP_AGAIN;
    }

    ctx->state = rp_http_grpc_st_start;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc window update: %ui", ctx->window_update);

    if (ctx->stream_id) {

        if (ctx->window_update > (size_t) RP_HTTP_V2_MAX_WINDOW
                                 - ctx->send_window)
        {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return RP_ERROR;
        }

        ctx->send_window += ctx->window_update;

    } else {

        if (ctx->window_update > RP_HTTP_V2_MAX_WINDOW
                                 - ctx->connection->send_window)
        {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return RP_ERROR;
        }

        ctx->connection->send_window += ctx->window_update;
    }

    return RP_OK;
}


static rp_int_t
rp_http_grpc_parse_settings(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx,
    rp_buf_t *b)
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
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RP_ERROR;
        }

        if (ctx->flags & RP_HTTP_V2_ACK_FLAG) {
            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc settings ack");

            if (ctx->rest != 0) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              ctx->rest);
                return RP_ERROR;
            }

            ctx->state = rp_http_grpc_st_start;

            return RP_OK;
        }

        if (ctx->rest % 6 != 0) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RP_ERROR;
        }

        if (ctx->free == NULL && ctx->settings++ > 1000) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many settings frames");
            return RP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
            ctx->setting_value = (rp_uint_t) ch << 24;
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

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

                if (ctx->setting_value > RP_HTTP_V2_MAX_WINDOW) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return RP_ERROR;
                }

                window_update = ctx->setting_value
                                - ctx->connection->init_window;
                ctx->connection->init_window = ctx->setting_value;

                if (ctx->send_window > 0
                    && window_update > (ssize_t) RP_HTTP_V2_MAX_WINDOW
                                       - ctx->send_window)
                {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return RP_ERROR;
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
        return RP_AGAIN;
    }

    ctx->state = rp_http_grpc_st_start;

    return rp_http_grpc_send_settings_ack(r, ctx);
}


static rp_int_t
rp_http_grpc_parse_ping(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_buf_t *b)
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
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return RP_ERROR;
        }

        if (ctx->rest != 8) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return RP_ERROR;
        }

        if (ctx->flags & RP_HTTP_V2_ACK_FLAG) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            return RP_ERROR;
        }

        if (ctx->free == NULL && ctx->pings++ > 1000) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many ping frames");
            return RP_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            ctx->ping_data[state] = ch;
            state++;

        } else {
            ctx->ping_data[7] = ch;
            state = sw_start;

            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc ping");
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return RP_AGAIN;
    }

    ctx->state = rp_http_grpc_st_start;

    return rp_http_grpc_send_ping_ack(r, ctx);
}


static rp_int_t
rp_http_grpc_send_settings_ack(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx)
{
    rp_chain_t            *cl, **ll;
    rp_http_grpc_frame_t  *f;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send settings ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rp_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RP_ERROR;
    }

    f = (rp_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rp_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = RP_HTTP_V2_SETTINGS_FRAME;
    f->flags = RP_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    *ll = cl;

    return RP_OK;
}


static rp_int_t
rp_http_grpc_send_ping_ack(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx)
{
    rp_chain_t            *cl, **ll;
    rp_http_grpc_frame_t  *f;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send ping ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rp_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RP_ERROR;
    }

    f = (rp_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rp_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 8;
    f->type = RP_HTTP_V2_PING_FRAME;
    f->flags = RP_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = rp_copy(cl->buf->last, ctx->ping_data, 8);

    *ll = cl;

    return RP_OK;
}


static rp_int_t
rp_http_grpc_send_window_update(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx)
{
    size_t                  n;
    rp_chain_t            *cl, **ll;
    rp_http_grpc_frame_t  *f;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send window update: %uz %uz",
                   ctx->connection->recv_window, ctx->recv_window);

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rp_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return RP_ERROR;
    }

    f = (rp_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rp_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = RP_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    n = RP_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
    ctx->connection->recv_window = RP_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    f = (rp_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(rp_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = RP_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (ctx->id & 0xff);

    n = RP_HTTP_V2_MAX_WINDOW - ctx->recv_window;
    ctx->recv_window = RP_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return RP_OK;
}


static rp_chain_t *
rp_http_grpc_get_buf(rp_http_request_t *r, rp_http_grpc_ctx_t *ctx)
{
    u_char       *start;
    rp_buf_t    *b;
    rp_chain_t  *cl;

    cl = rp_chain_get_free_buf(r->pool, &ctx->free);
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

        start = rp_palloc(r->pool, 2 * sizeof(rp_http_grpc_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    rp_memzero(b, sizeof(rp_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(rp_http_grpc_frame_t) + 8;

    b->tag = (rp_buf_tag_t) &rp_http_grpc_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static rp_http_grpc_ctx_t *
rp_http_grpc_get_ctx(rp_http_request_t *r)
{
    rp_http_grpc_ctx_t  *ctx;
    rp_http_upstream_t  *u;

    ctx = rp_http_get_module_ctx(r, rp_http_grpc_module);

    if (ctx->connection == NULL) {
        u = r->upstream;

        if (rp_http_grpc_get_connection_data(r, ctx, &u->peer) != RP_OK) {
            return NULL;
        }
    }

    return ctx;
}


static rp_int_t
rp_http_grpc_get_connection_data(rp_http_request_t *r,
    rp_http_grpc_ctx_t *ctx, rp_peer_connection_t *pc)
{
    rp_connection_t    *c;
    rp_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /*
         * for cached connections, connection data can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == rp_http_grpc_cleanup) {
                ctx->connection = cln->data;
                break;
            }
        }

        if (ctx->connection == NULL) {
            rp_log_error(RP_LOG_ERR, c->log, 0,
                          "no connection data found for "
                          "keepalive http2 connection");
            return RP_ERROR;
        }

        ctx->send_window = ctx->connection->init_window;
        ctx->recv_window = RP_HTTP_V2_MAX_WINDOW;

        ctx->connection->last_stream_id += 2;
        ctx->id = ctx->connection->last_stream_id;

        return RP_OK;
    }

    cln = rp_pool_cleanup_add(c->pool, sizeof(rp_http_grpc_conn_t));
    if (cln == NULL) {
        return RP_ERROR;
    }

    cln->handler = rp_http_grpc_cleanup;
    ctx->connection = cln->data;

    ctx->connection->init_window = RP_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->send_window = RP_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->recv_window = RP_HTTP_V2_MAX_WINDOW;

    ctx->send_window = RP_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = RP_HTTP_V2_MAX_WINDOW;

    ctx->id = 1;
    ctx->connection->last_stream_id = 1;

    return RP_OK;
}


static void
rp_http_grpc_cleanup(void *data)
{
#if 0
    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "grpc cleanup");
#endif
    return;
}


static void
rp_http_grpc_abort_request(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort grpc request");
    return;
}


static void
rp_http_grpc_finalize_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize grpc request");
    return;
}


static rp_int_t
rp_http_grpc_internal_trailers_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_table_elt_t  *te;

    te = r->headers_in.te;

    if (te == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    if (rp_strlcasestrn(te->value.data, te->value.data + te->value.len,
                         (u_char *) "trailers", 8 - 1)
        == NULL)
    {
        v->not_found = 1;
        return RP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "trailers";
    v->len = sizeof("trailers") - 1;

    return RP_OK;
}


static rp_int_t
rp_http_grpc_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_grpc_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static void *
rp_http_grpc_create_loc_conf(rp_conf_t *cf)
{
    rp_http_grpc_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_grpc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
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

    conf->upstream.local = RP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RP_CONF_UNSET;
    conf->upstream.next_upstream_tries = RP_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RP_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = RP_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = RP_CONF_UNSET_PTR;
    conf->upstream.pass_headers = RP_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = RP_CONF_UNSET;

#if (RP_HTTP_SSL)
    conf->upstream.ssl_session_reuse = RP_CONF_UNSET;
    conf->upstream.ssl_server_name = RP_CONF_UNSET;
    conf->upstream.ssl_verify = RP_CONF_UNSET;
    conf->ssl_verify_depth = RP_CONF_UNSET_UINT;
    conf->ssl_passwords = RP_CONF_UNSET_PTR;
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

    rp_str_set(&conf->upstream.module, "grpc");

    return conf;
}


static char *
rp_http_grpc_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_grpc_loc_conf_t *prev = parent;
    rp_http_grpc_loc_conf_t *conf = child;

    rp_int_t                  rc;
    rp_hash_init_t            hash;
    rp_http_core_loc_conf_t  *clcf;

    rp_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rp_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rp_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rp_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rp_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rp_pagesize);

    rp_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              RP_CONF_BITMASK_SET);

    rp_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (RP_CONF_BITMASK_SET
                               |RP_HTTP_UPSTREAM_FT_ERROR
                               |RP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RP_CONF_BITMASK_SET
                                       |RP_HTTP_UPSTREAM_FT_OFF;
    }

    rp_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (RP_HTTP_SSL)

    rp_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    rp_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                                  |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

    rp_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }

    rp_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    rp_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    rp_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    rp_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    rp_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rp_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");
    rp_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");
    rp_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl && rp_http_grpc_set_ssl(cf, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

#endif

    hash.max_size = 512;
    hash.bucket_size = rp_align(64, rp_cacheline_size);
    hash.name = "grpc_headers_hash";

    if (rp_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rp_http_grpc_hide_headers, &hash)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->grpc_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->host = prev->host;

        conf->grpc_lengths = prev->grpc_lengths;
        conf->grpc_values = prev->grpc_values;

#if (RP_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->grpc_lengths))
    {
        clcf->handler = rp_http_grpc_handler;
    }

    if (conf->headers_source == NULL) {
        conf->headers = prev->headers;
        conf->headers_source = prev->headers_source;
        conf->host_set = prev->host_set;
    }

    rc = rp_http_grpc_init_headers(cf, conf, &conf->headers,
                                    rp_http_grpc_headers);
    if (rc != RP_OK) {
        return RP_CONF_ERROR;
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

    return RP_CONF_OK;
}


static rp_int_t
rp_http_grpc_init_headers(rp_conf_t *cf, rp_http_grpc_loc_conf_t *conf,
    rp_http_grpc_headers_t *headers, rp_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rp_uint_t                    i;
    rp_array_t                   headers_names, headers_merged;
    rp_keyval_t                 *src, *s, *h;
    rp_hash_key_t               *hk;
    rp_hash_init_t               hash;
    rp_http_script_compile_t     sc;
    rp_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return RP_OK;
    }

    if (rp_array_init(&headers_names, cf->temp_pool, 4, sizeof(rp_hash_key_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&headers_merged, cf->temp_pool, 4, sizeof(rp_keyval_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    headers->lengths = rp_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return RP_ERROR;
    }

    headers->values = rp_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return RP_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

            if (src[i].key.len == 4
                && rp_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }

            s = rp_array_push(&headers_merged);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (rp_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = rp_array_push(&headers_merged);
        if (s == NULL) {
            return RP_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = rp_array_push(&headers_names);
        if (hk == NULL) {
            return RP_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = rp_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = rp_array_push_n(headers->lengths,
                                sizeof(rp_http_script_copy_code_t));
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = (rp_http_script_code_pt) (void *)
                                                 rp_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(rp_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rp_array_push_n(headers->values, size);
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = rp_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(rp_http_script_copy_code_t);
        rp_memcpy(p, src[i].key.data, src[i].key.len);

        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_ERROR;
        }

        code = rp_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = rp_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rp_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RP_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = rp_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "grpc_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rp_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rp_http_grpc_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_grpc_loc_conf_t *glcf = conf;

    size_t                      add;
    rp_str_t                  *value, *url;
    rp_url_t                   u;
    rp_uint_t                  n;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_script_compile_t   sc;

    if (glcf->upstream.upstream || glcf->grpc_lengths) {
        return "is duplicate";
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);

    clcf->handler = rp_http_grpc_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = rp_http_script_variables_count(url);

    if (n) {

        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &glcf->grpc_lengths;
        sc.values = &glcf->grpc_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }

#if (RP_HTTP_SSL)
        glcf->ssl = 1;
#endif

        return RP_CONF_OK;
    }

    if (rp_strncasecmp(url->data, (u_char *) "grpc://", 7) == 0) {
        add = 7;

    } else if (rp_strncasecmp(url->data, (u_char *) "grpcs://", 8) == 0) {

#if (RP_HTTP_SSL)
        glcf->ssl = 1;

        add = 8;
#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "grpcs protocol requires SSL support");
        return RP_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    glcf->upstream.upstream = rp_http_upstream_add(cf, &u, 0);
    if (glcf->upstream.upstream == NULL) {
        return RP_CONF_ERROR;
    }

    if (u.family != AF_UNIX) {

        if (u.no_port) {
            glcf->host = u.host;

        } else {
            glcf->host.len = u.host.len + 1 + u.port_text.len;
            glcf->host.data = u.host.data;
        }

    } else {
        rp_str_set(&glcf->host, "localhost");
    }

    return RP_CONF_OK;
}


#if (RP_HTTP_SSL)

static char *
rp_http_grpc_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_grpc_loc_conf_t *glcf = conf;

    rp_str_t  *value;

    if (glcf->ssl_passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    glcf->ssl_passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (glcf->ssl_passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_grpc_set_ssl(rp_conf_t *cf, rp_http_grpc_loc_conf_t *glcf)
{
    rp_pool_cleanup_t  *cln;

    glcf->upstream.ssl = rp_pcalloc(cf->pool, sizeof(rp_ssl_t));
    if (glcf->upstream.ssl == NULL) {
        return RP_ERROR;
    }

    glcf->upstream.ssl->log = cf->log;

    if (rp_ssl_create(glcf->upstream.ssl, glcf->ssl_protocols, NULL)
        != RP_OK)
    {
        return RP_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rp_ssl_cleanup_ctx(glcf->upstream.ssl);
        return RP_ERROR;
    }

    cln->handler = rp_ssl_cleanup_ctx;
    cln->data = glcf->upstream.ssl;

    if (glcf->ssl_certificate.len) {

        if (glcf->ssl_certificate_key.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"grpc_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &glcf->ssl_certificate);
            return RP_ERROR;
        }

        if (rp_ssl_certificate(cf, glcf->upstream.ssl, &glcf->ssl_certificate,
                                &glcf->ssl_certificate_key, glcf->ssl_passwords)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    if (rp_ssl_ciphers(cf, glcf->upstream.ssl, &glcf->ssl_ciphers, 0)
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (glcf->upstream.ssl_verify) {
        if (glcf->ssl_trusted_certificate.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
            return RP_ERROR;
        }

        if (rp_ssl_trusted_certificate(cf, glcf->upstream.ssl,
                                        &glcf->ssl_trusted_certificate,
                                        glcf->ssl_verify_depth)
            != RP_OK)
        {
            return RP_ERROR;
        }

        if (rp_ssl_crl(cf, glcf->upstream.ssl, &glcf->ssl_crl) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (rp_ssl_client_session_cache(cf, glcf->upstream.ssl,
                                     glcf->upstream.ssl_session_reuse)
        != RP_OK)
    {
        return RP_ERROR;
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (SSL_CTX_set_alpn_protos(glcf->upstream.ssl->ctx,
                                (u_char *) "\x02h2", 3)
        != 0)
    {
        rp_ssl_error(RP_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_alpn_protos() failed");
        return RP_ERROR;
    }

#endif

    return RP_OK;
}

#endif
