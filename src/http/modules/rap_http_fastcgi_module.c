
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t                    caches;  /* rap_http_file_cache_t * */
} rap_http_fastcgi_main_conf_t;


typedef struct {
    rap_array_t                   *flushes;
    rap_array_t                   *lengths;
    rap_array_t                   *values;
    rap_uint_t                     number;
    rap_hash_t                     hash;
} rap_http_fastcgi_params_t;


typedef struct {
    rap_http_upstream_conf_t       upstream;

    rap_str_t                      index;

    rap_http_fastcgi_params_t      params;
#if (RAP_HTTP_CACHE)
    rap_http_fastcgi_params_t      params_cache;
#endif

    rap_array_t                   *params_source;
    rap_array_t                   *catch_stderr;

    rap_array_t                   *fastcgi_lengths;
    rap_array_t                   *fastcgi_values;

    rap_flag_t                     keep_conn;

#if (RAP_HTTP_CACHE)
    rap_http_complex_value_t       cache_key;
#endif

#if (RAP_PCRE)
    rap_regex_t                   *split_regex;
    rap_str_t                      split_name;
#endif
} rap_http_fastcgi_loc_conf_t;


typedef enum {
    rap_http_fastcgi_st_version = 0,
    rap_http_fastcgi_st_type,
    rap_http_fastcgi_st_request_id_hi,
    rap_http_fastcgi_st_request_id_lo,
    rap_http_fastcgi_st_content_length_hi,
    rap_http_fastcgi_st_content_length_lo,
    rap_http_fastcgi_st_padding_length,
    rap_http_fastcgi_st_reserved,
    rap_http_fastcgi_st_data,
    rap_http_fastcgi_st_padding
} rap_http_fastcgi_state_e;


typedef struct {
    u_char                        *start;
    u_char                        *end;
} rap_http_fastcgi_split_part_t;


typedef struct {
    rap_http_fastcgi_state_e       state;
    u_char                        *pos;
    u_char                        *last;
    rap_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    rap_chain_t                   *free;
    rap_chain_t                   *busy;

    unsigned                       fastcgi_stdout:1;
    unsigned                       large_stderr:1;
    unsigned                       header_sent:1;

    rap_array_t                   *split_parts;

    rap_str_t                      script_name;
    rap_str_t                      path_info;
} rap_http_fastcgi_ctx_t;


#define RAP_HTTP_FASTCGI_RESPONDER      1

#define RAP_HTTP_FASTCGI_KEEP_CONN      1

#define RAP_HTTP_FASTCGI_BEGIN_REQUEST  1
#define RAP_HTTP_FASTCGI_ABORT_REQUEST  2
#define RAP_HTTP_FASTCGI_END_REQUEST    3
#define RAP_HTTP_FASTCGI_PARAMS         4
#define RAP_HTTP_FASTCGI_STDIN          5
#define RAP_HTTP_FASTCGI_STDOUT         6
#define RAP_HTTP_FASTCGI_STDERR         7
#define RAP_HTTP_FASTCGI_DATA           8


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
    u_char  content_length_hi;
    u_char  content_length_lo;
    u_char  padding_length;
    u_char  reserved;
} rap_http_fastcgi_header_t;


typedef struct {
    u_char  role_hi;
    u_char  role_lo;
    u_char  flags;
    u_char  reserved[5];
} rap_http_fastcgi_begin_request_t;


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
} rap_http_fastcgi_header_small_t;


typedef struct {
    rap_http_fastcgi_header_t         h0;
    rap_http_fastcgi_begin_request_t  br;
    rap_http_fastcgi_header_small_t   h1;
} rap_http_fastcgi_request_start_t;


static rap_int_t rap_http_fastcgi_eval(rap_http_request_t *r,
    rap_http_fastcgi_loc_conf_t *flcf);
#if (RAP_HTTP_CACHE)
static rap_int_t rap_http_fastcgi_create_key(rap_http_request_t *r);
#endif
static rap_int_t rap_http_fastcgi_create_request(rap_http_request_t *r);
static rap_int_t rap_http_fastcgi_reinit_request(rap_http_request_t *r);
static rap_int_t rap_http_fastcgi_body_output_filter(void *data,
    rap_chain_t *in);
static rap_int_t rap_http_fastcgi_process_header(rap_http_request_t *r);
static rap_int_t rap_http_fastcgi_input_filter_init(void *data);
static rap_int_t rap_http_fastcgi_input_filter(rap_event_pipe_t *p,
    rap_buf_t *buf);
static rap_int_t rap_http_fastcgi_non_buffered_filter(void *data,
    ssize_t bytes);
static rap_int_t rap_http_fastcgi_process_record(rap_http_request_t *r,
    rap_http_fastcgi_ctx_t *f);
static void rap_http_fastcgi_abort_request(rap_http_request_t *r);
static void rap_http_fastcgi_finalize_request(rap_http_request_t *r,
    rap_int_t rc);

static rap_int_t rap_http_fastcgi_add_variables(rap_conf_t *cf);
static void *rap_http_fastcgi_create_main_conf(rap_conf_t *cf);
static void *rap_http_fastcgi_create_loc_conf(rap_conf_t *cf);
static char *rap_http_fastcgi_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_fastcgi_init_params(rap_conf_t *cf,
    rap_http_fastcgi_loc_conf_t *conf, rap_http_fastcgi_params_t *params,
    rap_keyval_t *default_params);

static rap_int_t rap_http_fastcgi_script_name_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_fastcgi_path_info_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_http_fastcgi_ctx_t *rap_http_fastcgi_split(rap_http_request_t *r,
    rap_http_fastcgi_loc_conf_t *flcf);

static char *rap_http_fastcgi_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_fastcgi_split_path_info(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static char *rap_http_fastcgi_store(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#if (RAP_HTTP_CACHE)
static char *rap_http_fastcgi_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_fastcgi_cache_key(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#endif

static char *rap_http_fastcgi_lowat_check(rap_conf_t *cf, void *post,
    void *data);


static rap_conf_post_t  rap_http_fastcgi_lowat_post =
    { rap_http_fastcgi_lowat_check };


static rap_conf_bitmask_t  rap_http_fastcgi_next_upstream_masks[] = {
    { rap_string("error"), RAP_HTTP_UPSTREAM_FT_ERROR },
    { rap_string("timeout"), RAP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rap_string("invalid_header"), RAP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rap_string("non_idempotent"), RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rap_string("http_500"), RAP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rap_string("http_503"), RAP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rap_string("http_403"), RAP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rap_string("http_404"), RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rap_string("http_429"), RAP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rap_string("updating"), RAP_HTTP_UPSTREAM_FT_UPDATING },
    { rap_string("off"), RAP_HTTP_UPSTREAM_FT_OFF },
    { rap_null_string, 0 }
};


rap_module_t  rap_http_fastcgi_module;


static rap_command_t  rap_http_fastcgi_commands[] = {

    { rap_string("fastcgi_pass"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_fastcgi_pass,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("fastcgi_index"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, index),
      NULL },

    { rap_string("fastcgi_split_path_info"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_fastcgi_split_path_info,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("fastcgi_store"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_fastcgi_store,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("fastcgi_store_access"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_conf_set_access_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.store_access),
      NULL },

    { rap_string("fastcgi_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.buffering),
      NULL },

    { rap_string("fastcgi_request_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { rap_string("fastcgi_ignore_client_abort"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { rap_string("fastcgi_bind"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_bind_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.local),
      NULL },

    { rap_string("fastcgi_socket_keepalive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rap_string("fastcgi_connect_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rap_string("fastcgi_send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { rap_string("fastcgi_send_lowat"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.send_lowat),
      &rap_http_fastcgi_lowat_post },

    { rap_string("fastcgi_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { rap_string("fastcgi_pass_request_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { rap_string("fastcgi_pass_request_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { rap_string("fastcgi_intercept_errors"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rap_string("fastcgi_read_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { rap_string("fastcgi_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.bufs),
      NULL },

    { rap_string("fastcgi_busy_buffers_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { rap_string("fastcgi_force_ranges"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { rap_string("fastcgi_limit_rate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (RAP_HTTP_CACHE)

    { rap_string("fastcgi_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_fastcgi_cache,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("fastcgi_cache_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_fastcgi_cache_key,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("fastcgi_cache_path"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_2MORE,
      rap_http_file_cache_set_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_fastcgi_main_conf_t, caches),
      &rap_http_fastcgi_module },

    { rap_string("fastcgi_cache_bypass"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { rap_string("fastcgi_no_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.no_cache),
      NULL },

    { rap_string("fastcgi_cache_valid"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_file_cache_valid_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { rap_string("fastcgi_cache_min_uses"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { rap_string("fastcgi_cache_max_range_offset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { rap_string("fastcgi_cache_use_stale"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_use_stale),
      &rap_http_fastcgi_next_upstream_masks },

    { rap_string("fastcgi_cache_methods"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_methods),
      &rap_http_upstream_cache_method_mask },

    { rap_string("fastcgi_cache_lock"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { rap_string("fastcgi_cache_lock_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { rap_string("fastcgi_cache_lock_age"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { rap_string("fastcgi_cache_revalidate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { rap_string("fastcgi_cache_background_update"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { rap_string("fastcgi_temp_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1234,
      rap_conf_set_path_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.temp_path),
      NULL },

    { rap_string("fastcgi_max_temp_file_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { rap_string("fastcgi_temp_file_write_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { rap_string("fastcgi_next_upstream"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.next_upstream),
      &rap_http_fastcgi_next_upstream_masks },

    { rap_string("fastcgi_next_upstream_tries"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rap_string("fastcgi_next_upstream_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rap_string("fastcgi_param"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE23,
      rap_http_upstream_param_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, params_source),
      NULL },

    { rap_string("fastcgi_pass_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { rap_string("fastcgi_hide_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { rap_string("fastcgi_ignore_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, upstream.ignore_headers),
      &rap_http_upstream_ignore_headers_masks },

    { rap_string("fastcgi_catch_stderr"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, catch_stderr),
      NULL },

    { rap_string("fastcgi_keep_conn"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_fastcgi_loc_conf_t, keep_conn),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_fastcgi_module_ctx = {
    rap_http_fastcgi_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_fastcgi_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_fastcgi_create_loc_conf,      /* create location configuration */
    rap_http_fastcgi_merge_loc_conf        /* merge location configuration */
};


rap_module_t  rap_http_fastcgi_module = {
    RAP_MODULE_V1,
    &rap_http_fastcgi_module_ctx,          /* module context */
    rap_http_fastcgi_commands,             /* module directives */
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


static rap_http_fastcgi_request_start_t  rap_http_fastcgi_request_start = {
    { 1,                                               /* version */
      RAP_HTTP_FASTCGI_BEGIN_REQUEST,                  /* type */
      0,                                               /* request_id_hi */
      1,                                               /* request_id_lo */
      0,                                               /* content_length_hi */
      sizeof(rap_http_fastcgi_begin_request_t),        /* content_length_lo */
      0,                                               /* padding_length */
      0 },                                             /* reserved */

    { 0,                                               /* role_hi */
      RAP_HTTP_FASTCGI_RESPONDER,                      /* role_lo */
      0, /* RAP_HTTP_FASTCGI_KEEP_CONN */              /* flags */
      { 0, 0, 0, 0, 0 } },                             /* reserved[5] */

    { 1,                                               /* version */
      RAP_HTTP_FASTCGI_PARAMS,                         /* type */
      0,                                               /* request_id_hi */
      1 },                                             /* request_id_lo */

};


static rap_http_variable_t  rap_http_fastcgi_vars[] = {

    { rap_string("fastcgi_script_name"), NULL,
      rap_http_fastcgi_script_name_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

    { rap_string("fastcgi_path_info"), NULL,
      rap_http_fastcgi_path_info_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

      rap_http_null_variable
};


static rap_str_t  rap_http_fastcgi_hide_headers[] = {
    rap_string("Status"),
    rap_string("X-Accel-Expires"),
    rap_string("X-Accel-Redirect"),
    rap_string("X-Accel-Limit-Rate"),
    rap_string("X-Accel-Buffering"),
    rap_string("X-Accel-Charset"),
    rap_null_string
};


#if (RAP_HTTP_CACHE)

static rap_keyval_t  rap_http_fastcgi_cache_headers[] = {
    { rap_string("HTTP_IF_MODIFIED_SINCE"),
      rap_string("$upstream_cache_last_modified") },
    { rap_string("HTTP_IF_UNMODIFIED_SINCE"), rap_string("") },
    { rap_string("HTTP_IF_NONE_MATCH"), rap_string("$upstream_cache_etag") },
    { rap_string("HTTP_IF_MATCH"), rap_string("") },
    { rap_string("HTTP_RANGE"), rap_string("") },
    { rap_string("HTTP_IF_RANGE"), rap_string("") },
    { rap_null_string, rap_null_string }
};

#endif


static rap_path_init_t  rap_http_fastcgi_temp_path = {
    rap_string(RAP_HTTP_FASTCGI_TEMP_PATH), { 1, 2, 0 }
};


static rap_int_t
rap_http_fastcgi_handler(rap_http_request_t *r)
{
    rap_int_t                      rc;
    rap_http_upstream_t           *u;
    rap_http_fastcgi_ctx_t        *f;
    rap_http_fastcgi_loc_conf_t   *flcf;
#if (RAP_HTTP_CACHE)
    rap_http_fastcgi_main_conf_t  *fmcf;
#endif

    if (rap_http_upstream_create(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    f = rap_pcalloc(r->pool, sizeof(rap_http_fastcgi_ctx_t));
    if (f == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_http_set_ctx(r, f, rap_http_fastcgi_module);

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    if (flcf->fastcgi_lengths) {
        if (rap_http_fastcgi_eval(r, flcf) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    rap_str_set(&u->schema, "fastcgi://");
    u->output.tag = (rap_buf_tag_t) &rap_http_fastcgi_module;

    u->conf = &flcf->upstream;

#if (RAP_HTTP_CACHE)
    fmcf = rap_http_get_module_main_conf(r, rap_http_fastcgi_module);

    u->caches = &fmcf->caches;
    u->create_key = rap_http_fastcgi_create_key;
#endif

    u->create_request = rap_http_fastcgi_create_request;
    u->reinit_request = rap_http_fastcgi_reinit_request;
    u->process_header = rap_http_fastcgi_process_header;
    u->abort_request = rap_http_fastcgi_abort_request;
    u->finalize_request = rap_http_fastcgi_finalize_request;
    r->state = 0;

    u->buffering = flcf->upstream.buffering;

    u->pipe = rap_pcalloc(r->pool, sizeof(rap_event_pipe_t));
    if (u->pipe == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = rap_http_fastcgi_input_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = rap_http_fastcgi_input_filter_init;
    u->input_filter = rap_http_fastcgi_non_buffered_filter;
    u->input_filter_ctx = r;

    if (!flcf->upstream.request_buffering
        && flcf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }

    rc = rap_http_read_client_request_body(r, rap_http_upstream_init);

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return RAP_DONE;
}


static rap_int_t
rap_http_fastcgi_eval(rap_http_request_t *r, rap_http_fastcgi_loc_conf_t *flcf)
{
    rap_url_t             url;
    rap_http_upstream_t  *u;

    rap_memzero(&url, sizeof(rap_url_t));

    if (rap_http_script_run(r, &url.url, flcf->fastcgi_lengths->elts, 0,
                            flcf->fastcgi_values->elts)
        == NULL)
    {
        return RAP_ERROR;
    }

    url.no_resolve = 1;

    if (rap_parse_url(r->pool, &url) != RAP_OK) {
        if (url.err) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RAP_ERROR;
    }

    u = r->upstream;

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

    return RAP_OK;
}


#if (RAP_HTTP_CACHE)

static rap_int_t
rap_http_fastcgi_create_key(rap_http_request_t *r)
{
    rap_str_t                    *key;
    rap_http_fastcgi_loc_conf_t  *flcf;

    key = rap_array_push(&r->cache->keys);
    if (key == NULL) {
        return RAP_ERROR;
    }

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    if (rap_http_complex_value(r, &flcf->cache_key, key) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_fastcgi_create_request(rap_http_request_t *r)
{
    off_t                         file_pos;
    u_char                        ch, *pos, *lowcase_key;
    size_t                        size, len, key_len, val_len, padding,
                                  allocated;
    rap_uint_t                    i, n, next, hash, skip_empty, header_params;
    rap_buf_t                    *b;
    rap_chain_t                  *cl, *body;
    rap_list_part_t              *part;
    rap_table_elt_t              *header, **ignored;
    rap_http_upstream_t          *u;
    rap_http_script_code_pt       code;
    rap_http_script_engine_t      e, le;
    rap_http_fastcgi_header_t    *h;
    rap_http_fastcgi_params_t    *params;
    rap_http_fastcgi_loc_conf_t  *flcf;
    rap_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    u = r->upstream;

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

#if (RAP_HTTP_CACHE)
    params = u->cacheable ? &flcf->params_cache : &flcf->params;
#else
    params = &flcf->params;
#endif

    if (params->lengths) {
        rap_memzero(&le, sizeof(rap_http_script_engine_t));

        rap_http_script_flush_no_cacheable_variables(r, params->flushes);
        le.flushed = 1;

        le.ip = params->lengths->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rap_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                continue;
            }

            len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
        }
    }

    if (flcf->upstream.pass_request_headers) {

        allocated = 0;
        lowcase_key = NULL;

        if (params->number) {
            n = 0;
            part = &r->headers_in.headers.part;

            while (part) {
                n += part->nelts;
                part = part->next;
            }

            ignored = rap_palloc(r->pool, n * sizeof(void *));
            if (ignored == NULL) {
                return RAP_ERROR;
            }
        }

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

            if (params->number) {
                if (allocated < header[i].key.len) {
                    allocated = header[i].key.len + 16;
                    lowcase_key = rap_pnalloc(r->pool, allocated);
                    if (lowcase_key == NULL) {
                        return RAP_ERROR;
                    }
                }

                hash = 0;

                for (n = 0; n < header[i].key.len; n++) {
                    ch = header[i].key.data[n];

                    if (ch >= 'A' && ch <= 'Z') {
                        ch |= 0x20;

                    } else if (ch == '-') {
                        ch = '_';
                    }

                    hash = rap_hash(hash, ch);
                    lowcase_key[n] = ch;
                }

                if (rap_hash_find(&params->hash, hash, lowcase_key, n)) {
                    ignored[header_params++] = &header[i];
                    continue;
                }

                n += sizeof("HTTP_") - 1;

            } else {
                n = sizeof("HTTP_") - 1 + header[i].key.len;
            }

            len += ((n > 127) ? 4 : 1) + ((header[i].value.len > 127) ? 4 : 1)
                + n + header[i].value.len;
        }
    }


    if (len > 65535) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "fastcgi request record is too big: %uz", len);
        return RAP_ERROR;
    }


    padding = 8 - len % 8;
    padding = (padding == 8) ? 0 : padding;


    size = sizeof(rap_http_fastcgi_header_t)
           + sizeof(rap_http_fastcgi_begin_request_t)

           + sizeof(rap_http_fastcgi_header_t)  /* RAP_HTTP_FASTCGI_PARAMS */
           + len + padding
           + sizeof(rap_http_fastcgi_header_t)  /* RAP_HTTP_FASTCGI_PARAMS */

           + sizeof(rap_http_fastcgi_header_t); /* RAP_HTTP_FASTCGI_STDIN */


    b = rap_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;

    rap_http_fastcgi_request_start.br.flags =
        flcf->keep_conn ? RAP_HTTP_FASTCGI_KEEP_CONN : 0;

    rap_memcpy(b->pos, &rap_http_fastcgi_request_start,
               sizeof(rap_http_fastcgi_request_start_t));

    h = (rap_http_fastcgi_header_t *)
             (b->pos + sizeof(rap_http_fastcgi_header_t)
                     + sizeof(rap_http_fastcgi_begin_request_t));

    h->content_length_hi = (u_char) ((len >> 8) & 0xff);
    h->content_length_lo = (u_char) (len & 0xff);
    h->padding_length = (u_char) padding;
    h->reserved = 0;

    b->last = b->pos + sizeof(rap_http_fastcgi_header_t)
                     + sizeof(rap_http_fastcgi_begin_request_t)
                     + sizeof(rap_http_fastcgi_header_t);


    if (params->lengths) {
        rap_memzero(&e, sizeof(rap_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rap_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                e.skip = 1;

                while (*(uintptr_t *) e.ip) {
                    code = *(rap_http_script_code_pt *) e.ip;
                    code((rap_http_script_engine_t *) &e);
                }
                e.ip += sizeof(uintptr_t);

                e.skip = 0;

                continue;
            }

            *e.pos++ = (u_char) key_len;

            if (val_len > 127) {
                *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
                *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
                *e.pos++ = (u_char) (val_len & 0xff);

            } else {
                *e.pos++ = (u_char) val_len;
            }

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }


    if (flcf->upstream.pass_request_headers) {

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

            for (n = 0; n < header_params; n++) {
                if (&header[i] == ignored[n]) {
                    goto next;
                }
            }

            key_len = sizeof("HTTP_") - 1 + header[i].key.len;
            if (key_len > 127) {
                *b->last++ = (u_char) (((key_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((key_len >> 16) & 0xff);
                *b->last++ = (u_char) ((key_len >> 8) & 0xff);
                *b->last++ = (u_char) (key_len & 0xff);

            } else {
                *b->last++ = (u_char) key_len;
            }

            val_len = header[i].value.len;
            if (val_len > 127) {
                *b->last++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((val_len >> 16) & 0xff);
                *b->last++ = (u_char) ((val_len >> 8) & 0xff);
                *b->last++ = (u_char) (val_len & 0xff);

            } else {
                *b->last++ = (u_char) val_len;
            }

            b->last = rap_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);

            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }

            b->last = rap_copy(b->last, header[i].value.data, val_len);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + val_len),
                           val_len, b->last - val_len);
        next:

            continue;
        }
    }


    if (padding) {
        rap_memzero(b->last, padding);
        b->last += padding;
    }


    h = (rap_http_fastcgi_header_t *) b->last;
    b->last += sizeof(rap_http_fastcgi_header_t);

    h->version = 1;
    h->type = RAP_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        u->output.output_filter = rap_http_fastcgi_body_output_filter;
        u->output.filter_ctx = r;

    } else if (flcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

#if (RAP_SUPPRESS_WARN)
        file_pos = 0;
        pos = NULL;
#endif

        while (body) {

            if (rap_buf_special(body->buf)) {
                body = body->next;
                continue;
            }

            if (body->buf->in_file) {
                file_pos = body->buf->file_pos;

            } else {
                pos = body->buf->pos;
            }

            next = 0;

            do {
                b = rap_alloc_buf(r->pool);
                if (b == NULL) {
                    return RAP_ERROR;
                }

                rap_memcpy(b, body->buf, sizeof(rap_buf_t));

                if (body->buf->in_file) {
                    b->file_pos = file_pos;
                    file_pos += 32 * 1024;

                    if (file_pos >= body->buf->file_last) {
                        file_pos = body->buf->file_last;
                        next = 1;
                    }

                    b->file_last = file_pos;
                    len = (rap_uint_t) (file_pos - b->file_pos);

                } else {
                    b->pos = pos;
                    b->start = pos;
                    pos += 32 * 1024;

                    if (pos >= body->buf->last) {
                        pos = body->buf->last;
                        next = 1;
                    }

                    b->last = pos;
                    len = (rap_uint_t) (pos - b->pos);
                }

                padding = 8 - len % 8;
                padding = (padding == 8) ? 0 : padding;

                h = (rap_http_fastcgi_header_t *) cl->buf->last;
                cl->buf->last += sizeof(rap_http_fastcgi_header_t);

                h->version = 1;
                h->type = RAP_HTTP_FASTCGI_STDIN;
                h->request_id_hi = 0;
                h->request_id_lo = 1;
                h->content_length_hi = (u_char) ((len >> 8) & 0xff);
                h->content_length_lo = (u_char) (len & 0xff);
                h->padding_length = (u_char) padding;
                h->reserved = 0;

                cl->next = rap_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return RAP_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

                b = rap_create_temp_buf(r->pool,
                                        sizeof(rap_http_fastcgi_header_t)
                                        + padding);
                if (b == NULL) {
                    return RAP_ERROR;
                }

                if (padding) {
                    rap_memzero(b->last, padding);
                    b->last += padding;
                }

                cl->next = rap_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return RAP_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

            } while (!next);

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    if (!r->request_body_no_buffering) {
        h = (rap_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(rap_http_fastcgi_header_t);

        h->version = 1;
        h->type = RAP_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;
    }

    cl->next = NULL;

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_reinit_request(rap_http_request_t *r)
{
    rap_http_fastcgi_ctx_t  *f;

    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    if (f == NULL) {
        return RAP_OK;
    }

    f->state = rap_http_fastcgi_st_version;
    f->fastcgi_stdout = 0;
    f->large_stderr = 0;

    if (f->split_parts) {
        f->split_parts->nelts = 0;
    }

    r->state = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_body_output_filter(void *data, rap_chain_t *in)
{
    rap_http_request_t  *r = data;

    off_t                       file_pos;
    u_char                     *pos, *start;
    size_t                      len, padding;
    rap_buf_t                  *b;
    rap_int_t                   rc;
    rap_uint_t                  next, last;
    rap_chain_t                *cl, *tl, *out, **ll;
    rap_http_fastcgi_ctx_t     *f;
    rap_http_fastcgi_header_t  *h;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fastcgi output filter");

    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!f->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "fastcgi output header");

        f->header_sent = 1;

        tl = rap_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return RAP_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    cl = rap_chain_get_free_buf(r->pool, &f->free);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    b = cl->buf;

    b->tag = (rap_buf_tag_t) &rap_http_fastcgi_body_output_filter;
    b->temporary = 1;

    if (b->start == NULL) {
        /* reserve space for maximum possible padding, 7 bytes */

        b->start = rap_palloc(r->pool,
                              sizeof(rap_http_fastcgi_header_t) + 7);
        if (b->start == NULL) {
            return RAP_ERROR;
        }

        b->pos = b->start;
        b->last = b->start;

        b->end = b->start + sizeof(rap_http_fastcgi_header_t) + 7;
    }

    *ll = cl;

    last = 0;
    padding = 0;

#if (RAP_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
#endif

    while (in) {

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (in->buf->last_buf) {
            last = 1;
        }

        if (rap_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {
            tl = rap_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return RAP_ERROR;
            }

            b = tl->buf;
            start = b->start;

            rap_memcpy(b, in->buf, sizeof(rap_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and padding
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += 32 * 1024;

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (rap_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += 32 * 1024;

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (rap_uint_t) (pos - b->pos);
            }

            b->tag = (rap_buf_tag_t) &rap_http_fastcgi_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            padding = 8 - len % 8;
            padding = (padding == 8) ? 0 : padding;

            h = (rap_http_fastcgi_header_t *) cl->buf->last;
            cl->buf->last += sizeof(rap_http_fastcgi_header_t);

            h->version = 1;
            h->type = RAP_HTTP_FASTCGI_STDIN;
            h->request_id_hi = 0;
            h->request_id_lo = 1;
            h->content_length_hi = (u_char) ((len >> 8) & 0xff);
            h->content_length_lo = (u_char) (len & 0xff);
            h->padding_length = (u_char) padding;
            h->reserved = 0;

            cl->next = tl;
            cl = tl;

            tl = rap_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return RAP_ERROR;
            }

            b = tl->buf;

            b->tag = (rap_buf_tag_t) &rap_http_fastcgi_body_output_filter;
            b->temporary = 1;

            if (b->start == NULL) {
                /* reserve space for maximum possible padding, 7 bytes */

                b->start = rap_palloc(r->pool,
                                      sizeof(rap_http_fastcgi_header_t) + 7);
                if (b->start == NULL) {
                    return RAP_ERROR;
                }

                b->pos = b->start;
                b->last = b->start;

                b->end = b->start + sizeof(rap_http_fastcgi_header_t) + 7;
            }

            if (padding) {
                rap_memzero(b->last, padding);
                b->last += padding;
            }

            cl->next = tl;
            cl = tl;

        } while (!next);

        in = in->next;
    }

    if (last) {
        h = (rap_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(rap_http_fastcgi_header_t);

        h->version = 1;
        h->type = RAP_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;

        cl->buf->last_buf = 1;

    } else if (padding == 0) {
        /* TODO: do not allocate buffers instead */
        cl->buf->temporary = 0;
        cl->buf->sync = 1;
    }

    cl->next = NULL;

out:

#if (RAP_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        rap_log_debug7(RAP_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    rc = rap_chain_writer(&r->upstream->writer, out);

    rap_chain_update_chains(r->pool, &f->free, &f->busy, &out,
                         (rap_buf_tag_t) &rap_http_fastcgi_body_output_filter);

    for (cl = f->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    return rc;
}


static rap_int_t
rap_http_fastcgi_process_header(rap_http_request_t *r)
{
    u_char                         *p, *msg, *start, *last,
                                   *part_start, *part_end;
    size_t                          size;
    rap_str_t                      *status_line, *pattern;
    rap_int_t                       rc, status;
    rap_buf_t                       buf;
    rap_uint_t                      i;
    rap_table_elt_t                *h;
    rap_http_upstream_t            *u;
    rap_http_fastcgi_ctx_t         *f;
    rap_http_upstream_header_t     *hh;
    rap_http_fastcgi_loc_conf_t    *flcf;
    rap_http_fastcgi_split_part_t  *part;
    rap_http_upstream_main_conf_t  *umcf;

    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    umcf = rap_http_get_module_main_conf(r, rap_http_upstream_module);

    u = r->upstream;

    for ( ;; ) {

        if (f->state < rap_http_fastcgi_st_data) {

            f->pos = u->buffer.pos;
            f->last = u->buffer.last;

            rc = rap_http_fastcgi_process_record(r, f);

            u->buffer.pos = f->pos;
            u->buffer.last = f->last;

            if (rc == RAP_AGAIN) {
                return RAP_AGAIN;
            }

            if (rc == RAP_ERROR) {
                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type != RAP_HTTP_FASTCGI_STDOUT
                && f->type != RAP_HTTP_FASTCGI_STDERR)
            {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI record: %ui",
                              f->type);

                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type == RAP_HTTP_FASTCGI_STDOUT && f->length == 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed FastCGI stdout");

                return RAP_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        if (f->state == rap_http_fastcgi_st_padding) {

            if (u->buffer.pos + f->padding < u->buffer.last) {
                f->state = rap_http_fastcgi_st_version;
                u->buffer.pos += f->padding;

                continue;
            }

            if (u->buffer.pos + f->padding == u->buffer.last) {
                f->state = rap_http_fastcgi_st_version;
                u->buffer.pos = u->buffer.last;

                return RAP_AGAIN;
            }

            f->padding -= u->buffer.last - u->buffer.pos;
            u->buffer.pos = u->buffer.last;

            return RAP_AGAIN;
        }


        /* f->state == rap_http_fastcgi_st_data */

        if (f->type == RAP_HTTP_FASTCGI_STDERR) {

            if (f->length) {
                msg = u->buffer.pos;

                if (u->buffer.pos + f->length <= u->buffer.last) {
                    u->buffer.pos += f->length;
                    f->length = 0;
                    f->state = rap_http_fastcgi_st_padding;

                } else {
                    f->length -= u->buffer.last - u->buffer.pos;
                    u->buffer.pos = u->buffer.last;
                }

                for (p = u->buffer.pos - 1; msg < p; p--) {
                    if (*p != LF && *p != CR && *p != '.' && *p != ' ') {
                        break;
                    }
                }

                p++;

                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"", p - msg, msg);

                flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

                if (flcf->catch_stderr) {
                    pattern = flcf->catch_stderr->elts;

                    for (i = 0; i < flcf->catch_stderr->nelts; i++) {
                        if (rap_strnstr(msg, (char *) pattern[i].data,
                                        p - msg)
                            != NULL)
                        {
                            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                        }
                    }
                }

                if (u->buffer.pos == u->buffer.last) {

                    if (!f->fastcgi_stdout) {

                        /*
                         * the special handling the large number
                         * of the PHP warnings to not allocate memory
                         */

#if (RAP_HTTP_CACHE)
                        if (r->cache) {
                            u->buffer.pos = u->buffer.start
                                                     + r->cache->header_start;
                        } else {
                            u->buffer.pos = u->buffer.start;
                        }
#else
                        u->buffer.pos = u->buffer.start;
#endif
                        u->buffer.last = u->buffer.pos;
                        f->large_stderr = 1;
                    }

                    return RAP_AGAIN;
                }

            } else {
                f->state = rap_http_fastcgi_st_padding;
            }

            continue;
        }


        /* f->type == RAP_HTTP_FASTCGI_STDOUT */

#if (RAP_HTTP_CACHE)

        if (f->large_stderr && r->cache) {
            ssize_t                     len;
            rap_http_fastcgi_header_t  *fh;

            start = u->buffer.start + r->cache->header_start;

            len = u->buffer.pos - start - 2 * sizeof(rap_http_fastcgi_header_t);

            /*
             * A tail of large stderr output before HTTP header is placed
             * in a cache file without a FastCGI record header.
             * To workaround it we put a dummy FastCGI record header at the
             * start of the stderr output or update r->cache_header_start,
             * if there is no enough place for the record header.
             */

            if (len >= 0) {
                fh = (rap_http_fastcgi_header_t *) start;
                fh->version = 1;
                fh->type = RAP_HTTP_FASTCGI_STDERR;
                fh->request_id_hi = 0;
                fh->request_id_lo = 1;
                fh->content_length_hi = (u_char) ((len >> 8) & 0xff);
                fh->content_length_lo = (u_char) (len & 0xff);
                fh->padding_length = 0;
                fh->reserved = 0;

            } else {
                r->cache->header_start += u->buffer.pos - start
                                          - sizeof(rap_http_fastcgi_header_t);
            }

            f->large_stderr = 0;
        }

#endif

        f->fastcgi_stdout = 1;

        start = u->buffer.pos;

        if (u->buffer.pos + f->length < u->buffer.last) {

            /*
             * set u->buffer.last to the end of the FastCGI record data
             * for rap_http_parse_header_line()
             */

            last = u->buffer.last;
            u->buffer.last = u->buffer.pos + f->length;

        } else {
            last = NULL;
        }

        for ( ;; ) {

            part_start = u->buffer.pos;
            part_end = u->buffer.last;

            rc = rap_http_parse_header_line(r, &u->buffer, 1);

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi parser: %i", rc);

            if (rc == RAP_AGAIN) {
                break;
            }

            if (rc == RAP_OK) {

                /* a header line has been parsed successfully */

                h = rap_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return RAP_ERROR;
                }

                if (f->split_parts && f->split_parts->nelts) {

                    part = f->split_parts->elts;
                    size = u->buffer.pos - part_start;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        size += part[i].end - part[i].start;
                    }

                    p = rap_pnalloc(r->pool, size);
                    if (p == NULL) {
                        h->hash = 0;
                        return RAP_ERROR;
                    }

                    buf.pos = p;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        p = rap_cpymem(p, part[i].start,
                                       part[i].end - part[i].start);
                    }

                    p = rap_cpymem(p, part_start, u->buffer.pos - part_start);

                    buf.last = p;

                    f->split_parts->nelts = 0;

                    rc = rap_http_parse_header_line(r, &buf, 1);

                    if (rc != RAP_OK) {
                        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                                      "invalid header after joining "
                                      "FastCGI records");
                        h->hash = 0;
                        return RAP_ERROR;
                    }

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->key.data = r->header_name_start;
                    h->key.data[h->key.len] = '\0';

                    h->value.len = r->header_end - r->header_start;
                    h->value.data = r->header_start;
                    h->value.data[h->value.len] = '\0';

                    h->lowcase_key = rap_pnalloc(r->pool, h->key.len);
                    if (h->lowcase_key == NULL) {
                        return RAP_ERROR;
                    }

                } else {

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->value.len = r->header_end - r->header_start;

                    h->key.data = rap_pnalloc(r->pool,
                                              h->key.len + 1 + h->value.len + 1
                                              + h->key.len);
                    if (h->key.data == NULL) {
                        h->hash = 0;
                        return RAP_ERROR;
                    }

                    h->value.data = h->key.data + h->key.len + 1;
                    h->lowcase_key = h->key.data + h->key.len + 1
                                     + h->value.len + 1;

                    rap_memcpy(h->key.data, r->header_name_start, h->key.len);
                    h->key.data[h->key.len] = '\0';
                    rap_memcpy(h->value.data, r->header_start, h->value.len);
                    h->value.data[h->value.len] = '\0';
                }

                h->hash = r->header_hash;

                if (h->key.len == r->lowcase_index) {
                    rap_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

                } else {
                    rap_strlow(h->lowcase_key, h->key.data, h->key.len);
                }

                hh = rap_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh && hh->handler(r, h, hh->offset) != RAP_OK) {
                    return RAP_ERROR;
                }

                rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header: \"%V: %V\"",
                               &h->key, &h->value);

                if (u->buffer.pos < u->buffer.last) {
                    continue;
                }

                /* the end of the FastCGI record */

                break;
            }

            if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header done");

                if (u->headers_in.status) {
                    status_line = &u->headers_in.status->value;

                    status = rap_atoi(status_line->data, 3);

                    if (status == RAP_ERROR) {
                        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid status \"%V\"",
                                      status_line);
                        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;
                    u->headers_in.status_line = *status_line;

                } else if (u->headers_in.location) {
                    u->headers_in.status_n = 302;
                    rap_str_set(&u->headers_in.status_line,
                                "302 Moved Temporarily");

                } else {
                    u->headers_in.status_n = 200;
                    rap_str_set(&u->headers_in.status_line, "200 OK");
                }

                if (u->state && u->state->status == 0) {
                    u->state->status = u->headers_in.status_n;
                }

                break;
            }

            /* there was error while a header line parsing */

            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (last) {
            u->buffer.last = last;
        }

        f->length -= u->buffer.pos - start;

        if (f->length == 0) {
            f->state = rap_http_fastcgi_st_padding;
        }

        if (rc == RAP_HTTP_PARSE_HEADER_DONE) {
            return RAP_OK;
        }

        if (rc == RAP_OK) {
            continue;
        }

        /* rc == RAP_AGAIN */

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "upstream split a header line in FastCGI records");

        if (f->split_parts == NULL) {
            f->split_parts = rap_array_create(r->pool, 1,
                                        sizeof(rap_http_fastcgi_split_part_t));
            if (f->split_parts == NULL) {
                return RAP_ERROR;
            }
        }

        part = rap_array_push(f->split_parts);
        if (part == NULL) {
            return RAP_ERROR;
        }

        part->start = part_start;
        part->end = part_end;

        if (u->buffer.pos < u->buffer.last) {
            continue;
        }

        return RAP_AGAIN;
    }
}


static rap_int_t
rap_http_fastcgi_input_filter_init(void *data)
{
    rap_http_request_t           *r = data;
    rap_http_fastcgi_loc_conf_t  *flcf;

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    r->upstream->pipe->length = flcf->keep_conn ?
                                (off_t) sizeof(rap_http_fastcgi_header_t) : -1;

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_input_filter(rap_event_pipe_t *p, rap_buf_t *buf)
{
    u_char                       *m, *msg;
    rap_int_t                     rc;
    rap_buf_t                    *b, **prev;
    rap_chain_t                  *cl;
    rap_http_request_t           *r;
    rap_http_fastcgi_ctx_t       *f;
    rap_http_fastcgi_loc_conf_t  *flcf;

    if (buf->pos == buf->last) {
        return RAP_OK;
    }

    r = p->input_ctx;
    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);
    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    b = NULL;
    prev = &buf->shadow;

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < rap_http_fastcgi_st_data) {

            rc = rap_http_fastcgi_process_record(r, f);

            if (rc == RAP_AGAIN) {
                break;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (f->type == RAP_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = rap_http_fastcgi_st_padding;

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                }

                rap_log_debug0(RAP_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi closed stdout");

                continue;
            }

            if (f->type == RAP_HTTP_FASTCGI_END_REQUEST) {

                rap_log_debug0(RAP_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi sent end request");

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                    break;
                }

                continue;
            }
        }


        if (f->state == rap_http_fastcgi_st_padding) {

            if (f->type == RAP_HTTP_FASTCGI_END_REQUEST) {

                if (f->pos + f->padding < f->last) {
                    p->upstream_done = 1;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    p->upstream_done = 1;
                    r->upstream->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = rap_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = rap_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == rap_http_fastcgi_st_data */

        if (f->type == RAP_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = rap_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                rap_log_error(RAP_LOG_ERR, p->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = rap_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == RAP_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = rap_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == RAP_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        cl = rap_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        b = cl->buf;

        rap_memzero(b, sizeof(rap_buf_t));

        b->pos = f->pos;
        b->start = buf->start;
        b->end = buf->end;
        b->tag = p->tag;
        b->temporary = 1;
        b->recycled = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;
        } else {
            p->in = cl;
        }
        p->last_in = &cl->next;


        /* STUB */ b->num = buf->num;

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf #%d %p", b->num, b->pos);

        if (f->pos + f->length <= f->last) {
            f->state = rap_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

            continue;
        }

        f->length -= f->last - f->pos;

        b->last = f->last;

        break;

    }

    if (flcf->keep_conn) {

        /* set p->length, minimal amount of data we want to see */

        if (f->state < rap_http_fastcgi_st_data) {
            p->length = 1;

        } else if (f->state == rap_http_fastcgi_st_padding) {
            p->length = f->padding;

        } else {
            /* rap_http_fastcgi_st_data */

            p->length = f->length;
        }
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return RAP_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (rap_event_pipe_add_free_buf(p, buf) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_non_buffered_filter(void *data, ssize_t bytes)
{
    u_char                  *m, *msg;
    rap_int_t                rc;
    rap_buf_t               *b, *buf;
    rap_chain_t             *cl, **ll;
    rap_http_request_t      *r;
    rap_http_upstream_t     *u;
    rap_http_fastcgi_ctx_t  *f;

    r = data;
    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < rap_http_fastcgi_st_data) {

            rc = rap_http_fastcgi_process_record(r, f);

            if (rc == RAP_AGAIN) {
                break;
            }

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (f->type == RAP_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = rap_http_fastcgi_st_padding;

                rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi closed stdout");

                continue;
            }
        }

        if (f->state == rap_http_fastcgi_st_padding) {

            if (f->type == RAP_HTTP_FASTCGI_END_REQUEST) {

                if (f->pos + f->padding < f->last) {
                    u->length = 0;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    u->length = 0;
                    u->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = rap_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = rap_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == rap_http_fastcgi_st_data */

        if (f->type == RAP_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = rap_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = rap_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == RAP_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = rap_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == RAP_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        cl = rap_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->flush = 1;
        b->memory = 1;

        b->pos = f->pos;
        b->tag = u->output.tag;

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi output buf %p", b->pos);

        if (f->pos + f->length <= f->last) {
            f->state = rap_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

            continue;
        }

        f->length -= f->last - f->pos;
        b->last = f->last;

        break;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_process_record(rap_http_request_t *r,
    rap_http_fastcgi_ctx_t *f)
{
    u_char                     ch, *p;
    rap_http_fastcgi_state_e   state;

    state = f->state;

    for (p = f->pos; p < f->last; p++) {

        ch = *p;

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi record byte: %02Xd", ch);

        switch (state) {

        case rap_http_fastcgi_st_version:
            if (ch != 1) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unsupported FastCGI "
                              "protocol version: %d", ch);
                return RAP_ERROR;
            }
            state = rap_http_fastcgi_st_type;
            break;

        case rap_http_fastcgi_st_type:
            switch (ch) {
            case RAP_HTTP_FASTCGI_STDOUT:
            case RAP_HTTP_FASTCGI_STDERR:
            case RAP_HTTP_FASTCGI_END_REQUEST:
                f->type = (rap_uint_t) ch;
                break;
            default:
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid FastCGI "
                              "record type: %d", ch);
                return RAP_ERROR;

            }
            state = rap_http_fastcgi_st_request_id_hi;
            break;

        /* we support the single request per connection */

        case rap_http_fastcgi_st_request_id_hi:
            if (ch != 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id high byte: %d", ch);
                return RAP_ERROR;
            }
            state = rap_http_fastcgi_st_request_id_lo;
            break;

        case rap_http_fastcgi_st_request_id_lo:
            if (ch != 1) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id low byte: %d", ch);
                return RAP_ERROR;
            }
            state = rap_http_fastcgi_st_content_length_hi;
            break;

        case rap_http_fastcgi_st_content_length_hi:
            f->length = ch << 8;
            state = rap_http_fastcgi_st_content_length_lo;
            break;

        case rap_http_fastcgi_st_content_length_lo:
            f->length |= (size_t) ch;
            state = rap_http_fastcgi_st_padding_length;
            break;

        case rap_http_fastcgi_st_padding_length:
            f->padding = (size_t) ch;
            state = rap_http_fastcgi_st_reserved;
            break;

        case rap_http_fastcgi_st_reserved:
            state = rap_http_fastcgi_st_data;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi record length: %z", f->length);

            f->pos = p + 1;
            f->state = state;

            return RAP_OK;

        /* suppress warning */
        case rap_http_fastcgi_st_data:
        case rap_http_fastcgi_st_padding:
            break;
        }
    }

    f->pos = p;
    f->state = state;

    return RAP_AGAIN;
}


static void
rap_http_fastcgi_abort_request(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http fastcgi request");

    return;
}


static void
rap_http_fastcgi_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http fastcgi request");

    return;
}


static rap_int_t
rap_http_fastcgi_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_fastcgi_vars; v->name.len; v++) {
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
rap_http_fastcgi_create_main_conf(rap_conf_t *cf)
{
    rap_http_fastcgi_main_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_fastcgi_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (RAP_HTTP_CACHE)
    if (rap_array_init(&conf->caches, cf->pool, 4,
                       sizeof(rap_http_file_cache_t *))
        != RAP_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
rap_http_fastcgi_create_loc_conf(rap_conf_t *cf)
{
    rap_http_fastcgi_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_fastcgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->index.len = { 0, NULL };
     */

    conf->upstream.store = RAP_CONF_UNSET;
    conf->upstream.store_access = RAP_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = RAP_CONF_UNSET_UINT;
    conf->upstream.buffering = RAP_CONF_UNSET;
    conf->upstream.request_buffering = RAP_CONF_UNSET;
    conf->upstream.ignore_client_abort = RAP_CONF_UNSET;
    conf->upstream.force_ranges = RAP_CONF_UNSET;

    conf->upstream.local = RAP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RAP_CONF_UNSET;

    conf->upstream.connect_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RAP_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = RAP_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = RAP_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = RAP_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = RAP_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = RAP_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = RAP_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = RAP_CONF_UNSET;
    conf->upstream.pass_request_body = RAP_CONF_UNSET;

#if (RAP_HTTP_CACHE)
    conf->upstream.cache = RAP_CONF_UNSET;
    conf->upstream.cache_min_uses = RAP_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = RAP_CONF_UNSET;
    conf->upstream.cache_bypass = RAP_CONF_UNSET_PTR;
    conf->upstream.no_cache = RAP_CONF_UNSET_PTR;
    conf->upstream.cache_valid = RAP_CONF_UNSET_PTR;
    conf->upstream.cache_lock = RAP_CONF_UNSET;
    conf->upstream.cache_lock_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = RAP_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = RAP_CONF_UNSET;
    conf->upstream.cache_background_update = RAP_CONF_UNSET;
#endif

    conf->upstream.hide_headers = RAP_CONF_UNSET_PTR;
    conf->upstream.pass_headers = RAP_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = RAP_CONF_UNSET;

    /* "fastcgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    conf->catch_stderr = RAP_CONF_UNSET_PTR;

    conf->keep_conn = RAP_CONF_UNSET;

    rap_str_set(&conf->upstream.module, "fastcgi");

    return conf;
}


static char *
rap_http_fastcgi_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_fastcgi_loc_conf_t *prev = parent;
    rap_http_fastcgi_loc_conf_t *conf = child;

    size_t                        size;
    rap_int_t                     rc;
    rap_hash_init_t               hash;
    rap_http_core_loc_conf_t     *clcf;

#if (RAP_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == RAP_CONF_UNSET) {
        rap_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    rap_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    rap_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rap_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    rap_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    rap_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    rap_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    rap_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rap_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rap_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rap_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    rap_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);


    rap_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, rap_pagesize);

    if (conf->upstream.bufs.num < 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"fastcgi_buffers\"");
        return RAP_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    rap_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return RAP_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be less than "
             "the size of all \"fastcgi_buffers\" minus one buffer");

        return RAP_CONF_ERROR;
    }


    rap_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"fastcgi_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return RAP_CONF_ERROR;
    }


    rap_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return RAP_CONF_ERROR;
    }


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

    if (rap_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &rap_http_fastcgi_temp_path)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

#if (RAP_HTTP_CACHE)

    if (conf->upstream.cache == RAP_CONF_UNSET) {
        rap_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        rap_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"fastcgi_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return RAP_CONF_ERROR;
    }

    rap_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    rap_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              RAP_MAX_OFF_T_VALUE);

    rap_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & RAP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = RAP_CONF_BITMASK_SET
                                         |RAP_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & RAP_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= RAP_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= RAP_HTTP_GET|RAP_HTTP_HEAD;

    rap_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    rap_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    rap_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "no \"fastcgi_cache_key\" for \"fastcgi_cache\"");
    }

    rap_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    rap_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    rap_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    rap_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    rap_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    rap_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

    rap_conf_merge_ptr_value(conf->catch_stderr, prev->catch_stderr, NULL);

    rap_conf_merge_value(conf->keep_conn, prev->keep_conn, 0);


    rap_conf_merge_str_value(conf->index, prev->index, "");

    hash.max_size = 512;
    hash.bucket_size = rap_align(64, rap_cacheline_size);
    hash.name = "fastcgi_hide_headers_hash";

    if (rap_http_upstream_hide_headers_hash(cf, &conf->upstream,
             &prev->upstream, rap_http_fastcgi_hide_headers, &hash)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->fastcgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->fastcgi_lengths = prev->fastcgi_lengths;
        conf->fastcgi_values = prev->fastcgi_values;
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->fastcgi_lengths))
    {
        clcf->handler = rap_http_fastcgi_handler;
    }

#if (RAP_PCRE)
    if (conf->split_regex == NULL) {
        conf->split_regex = prev->split_regex;
        conf->split_name = prev->split_name;
    }
#endif

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (RAP_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = rap_http_fastcgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#if (RAP_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = rap_http_fastcgi_init_params(cf, conf, &conf->params_cache,
                                          rap_http_fastcgi_cache_headers);
        if (rc != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->params in the "http" section
     * to inherit it to all servers
     */

    if (prev->params.hash.buckets == NULL
        && conf->params_source == prev->params_source)
    {
        prev->params = conf->params;
#if (RAP_HTTP_CACHE)
        prev->params_cache = conf->params_cache;
#endif
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_fastcgi_init_params(rap_conf_t *cf, rap_http_fastcgi_loc_conf_t *conf,
    rap_http_fastcgi_params_t *params, rap_keyval_t *default_params)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rap_uint_t                    i, nsrc;
    rap_array_t                   headers_names, params_merged;
    rap_keyval_t                 *h;
    rap_hash_key_t               *hk;
    rap_hash_init_t               hash;
    rap_http_upstream_param_t    *src, *s;
    rap_http_script_compile_t     sc;
    rap_http_script_copy_code_t  *copy;

    if (params->hash.buckets) {
        return RAP_OK;
    }

    if (conf->params_source == NULL && default_params == NULL) {
        params->hash.buckets = (void *) 1;
        return RAP_OK;
    }

    params->lengths = rap_array_create(cf->pool, 64, 1);
    if (params->lengths == NULL) {
        return RAP_ERROR;
    }

    params->values = rap_array_create(cf->pool, 512, 1);
    if (params->values == NULL) {
        return RAP_ERROR;
    }

    if (rap_array_init(&headers_names, cf->temp_pool, 4, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (conf->params_source) {
        src = conf->params_source->elts;
        nsrc = conf->params_source->nelts;

    } else {
        src = NULL;
        nsrc = 0;
    }

    if (default_params) {
        if (rap_array_init(&params_merged, cf->temp_pool, 4,
                           sizeof(rap_http_upstream_param_t))
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        for (i = 0; i < nsrc; i++) {

            s = rap_array_push(&params_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = src[i];
        }

        h = default_params;

        while (h->key.len) {

            src = params_merged.elts;
            nsrc = params_merged.nelts;

            for (i = 0; i < nsrc; i++) {
                if (rap_strcasecmp(h->key.data, src[i].key.data) == 0) {
                    goto next;
                }
            }

            s = rap_array_push(&params_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            s->key = h->key;
            s->value = h->value;
            s->skip_empty = 1;

        next:

            h++;
        }

        src = params_merged.elts;
        nsrc = params_merged.nelts;
    }

    for (i = 0; i < nsrc; i++) {

        if (src[i].key.len > sizeof("HTTP_") - 1
            && rap_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
        {
            hk = rap_array_push(&headers_names);
            if (hk == NULL) {
                return RAP_ERROR;
            }

            hk->key.len = src[i].key.len - 5;
            hk->key.data = src[i].key.data + 5;
            hk->key_hash = rap_hash_key_lc(hk->key.data, hk->key.len);
            hk->value = (void *) 1;

            if (src[i].value.len == 0) {
                continue;
            }
        }

        copy = rap_array_push_n(params->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].key.len;

        copy = rap_array_push_n(params->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(rap_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rap_array_push_n(params->values, size);
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
        sc.flushes = &params->flushes;
        sc.lengths = &params->lengths;
        sc.values = &params->values;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_ERROR;
        }

        code = rap_array_push_n(params->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = rap_array_push_n(params->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rap_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) NULL;

    params->number = headers_names.nelts;

    hash.hash = &params->hash;
    hash.key = rap_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "fastcgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rap_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static rap_int_t
rap_http_fastcgi_script_name_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    rap_http_fastcgi_ctx_t       *f;
    rap_http_fastcgi_loc_conf_t  *flcf;

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    f = rap_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return RAP_ERROR;
    }

    if (f->script_name.len == 0
        || f->script_name.data[f->script_name.len - 1] != '/')
    {
        v->len = f->script_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = f->script_name.data;

        return RAP_OK;
    }

    v->len = f->script_name.len + flcf->index.len;

    v->data = rap_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    p = rap_copy(v->data, f->script_name.data, f->script_name.len);
    rap_memcpy(p, flcf->index.data, flcf->index.len);

    return RAP_OK;
}


static rap_int_t
rap_http_fastcgi_path_info_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_fastcgi_ctx_t       *f;
    rap_http_fastcgi_loc_conf_t  *flcf;

    flcf = rap_http_get_module_loc_conf(r, rap_http_fastcgi_module);

    f = rap_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return RAP_ERROR;
    }

    v->len = f->path_info.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = f->path_info.data;

    return RAP_OK;
}


static rap_http_fastcgi_ctx_t *
rap_http_fastcgi_split(rap_http_request_t *r, rap_http_fastcgi_loc_conf_t *flcf)
{
    rap_http_fastcgi_ctx_t       *f;
#if (RAP_PCRE)
    rap_int_t                     n;
    int                           captures[(1 + 2) * 3];

    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    if (f == NULL) {
        f = rap_pcalloc(r->pool, sizeof(rap_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        rap_http_set_ctx(r, f, rap_http_fastcgi_module);
    }

    if (f->script_name.len) {
        return f;
    }

    if (flcf->split_regex == NULL) {
        f->script_name = r->uri;
        return f;
    }

    n = rap_regex_exec(flcf->split_regex, &r->uri, captures, (1 + 2) * 3);

    if (n >= 0) { /* match */
        f->script_name.len = captures[3] - captures[2];
        f->script_name.data = r->uri.data + captures[2];

        f->path_info.len = captures[5] - captures[4];
        f->path_info.data = r->uri.data + captures[4];

        return f;
    }

    if (n == RAP_REGEX_NO_MATCHED) {
        f->script_name = r->uri;
        return f;
    }

    rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                  rap_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                  n, &r->uri, &flcf->split_name);
    return NULL;

#else

    f = rap_http_get_module_ctx(r, rap_http_fastcgi_module);

    if (f == NULL) {
        f = rap_pcalloc(r->pool, sizeof(rap_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        rap_http_set_ctx(r, f, rap_http_fastcgi_module);
    }

    f->script_name = r->uri;

    return f;

#endif
}


static char *
rap_http_fastcgi_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_fastcgi_loc_conf_t *flcf = conf;

    rap_url_t                   u;
    rap_str_t                  *value, *url;
    rap_uint_t                  n;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_script_compile_t   sc;

    if (flcf->upstream.upstream || flcf->fastcgi_lengths) {
        return "is duplicate";
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    clcf->handler = rap_http_fastcgi_handler;

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
        sc.lengths = &flcf->fastcgi_lengths;
        sc.values = &flcf->fastcgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        return RAP_CONF_OK;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flcf->upstream.upstream = rap_http_upstream_add(cf, &u, 0);
    if (flcf->upstream.upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_fastcgi_split_path_info(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#if (RAP_PCRE)
    rap_http_fastcgi_loc_conf_t *flcf = conf;

    rap_str_t            *value;
    rap_regex_compile_t   rc;
    u_char                errstr[RAP_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    flcf->split_name = value[1];

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (rap_regex_compile(&rc) != RAP_OK) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%V", &rc.err);
        return RAP_CONF_ERROR;
    }

    if (rc.captures != 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "pattern \"%V\" must have 2 captures", &value[1]);
        return RAP_CONF_ERROR;
    }

    flcf->split_regex = rc.regex;

    return RAP_CONF_OK;

#else

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "\"%V\" requires PCRE library", &cmd->name);
    return RAP_CONF_ERROR;

#endif
}


static char *
rap_http_fastcgi_store(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_fastcgi_loc_conf_t *flcf = conf;

    rap_str_t                  *value;
    rap_http_script_compile_t   sc;

    if (flcf->upstream.store != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.store = 0;
        return RAP_CONF_OK;
    }

#if (RAP_HTTP_CACHE)
    if (flcf->upstream.cache > 0) {
        return "is incompatible with \"fastcgi_cache\"";
    }
#endif

    flcf->upstream.store = 1;

    if (rap_strcmp(value[1].data, "on") == 0) {
        return RAP_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &flcf->upstream.store_lengths;
    sc.values = &flcf->upstream.store_values;
    sc.variables = rap_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (rap_http_script_compile(&sc) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


#if (RAP_HTTP_CACHE)

static char *
rap_http_fastcgi_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_fastcgi_loc_conf_t *flcf = conf;

    rap_str_t                         *value;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->upstream.cache != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    if (rap_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.cache = 0;
        return RAP_CONF_OK;
    }

    if (flcf->upstream.store > 0) {
        return "is incompatible with \"fastcgi_store\"";
    }

    flcf->upstream.cache = 1;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        flcf->upstream.cache_value = rap_palloc(cf->pool,
                                             sizeof(rap_http_complex_value_t));
        if (flcf->upstream.cache_value == NULL) {
            return RAP_CONF_ERROR;
        }

        *flcf->upstream.cache_value = cv;

        return RAP_CONF_OK;
    }

    flcf->upstream.cache_zone = rap_shared_memory_add(cf, &value[1], 0,
                                                      &rap_http_fastcgi_module);
    if (flcf->upstream.cache_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_fastcgi_cache_key(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_fastcgi_loc_conf_t *flcf = conf;

    rap_str_t                         *value;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->cache_key.value.data) {
        return "is duplicate";
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &flcf->cache_key;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}

#endif


static char *
rap_http_fastcgi_lowat_check(rap_conf_t *cf, void *post, void *data)
{
#if (RAP_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= rap_freebsd_net_inet_tcp_sendspace) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"fastcgi_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           rap_freebsd_net_inet_tcp_sendspace);

        return RAP_CONF_ERROR;
    }

#elif !(RAP_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"fastcgi_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return RAP_CONF_OK;
}
