
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    u_char    *name;
    uint32_t   method;
} rap_http_method_name_t;


#define RAP_HTTP_REQUEST_BODY_FILE_OFF    0
#define RAP_HTTP_REQUEST_BODY_FILE_ON     1
#define RAP_HTTP_REQUEST_BODY_FILE_CLEAN  2


static rap_int_t rap_http_core_auth_delay(rap_http_request_t *r);
static void rap_http_core_auth_delay_handler(rap_http_request_t *r);

static rap_int_t rap_http_core_find_location(rap_http_request_t *r);
static rap_int_t rap_http_core_find_static_location(rap_http_request_t *r,
    rap_http_location_tree_node_t *node);

static rap_int_t rap_http_core_preconfiguration(rap_conf_t *cf);
static rap_int_t rap_http_core_postconfiguration(rap_conf_t *cf);
static void *rap_http_core_create_main_conf(rap_conf_t *cf);
static char *rap_http_core_init_main_conf(rap_conf_t *cf, void *conf);
static void *rap_http_core_create_srv_conf(rap_conf_t *cf);
static char *rap_http_core_merge_srv_conf(rap_conf_t *cf,
    void *parent, void *child);
static void *rap_http_core_create_loc_conf(rap_conf_t *cf);
static char *rap_http_core_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);

static char *rap_http_core_server(rap_conf_t *cf, rap_command_t *cmd,
    void *dummy);
static char *rap_http_core_location(rap_conf_t *cf, rap_command_t *cmd,
    void *dummy);
static rap_int_t rap_http_core_regex_location(rap_conf_t *cf,
    rap_http_core_loc_conf_t *clcf, rap_str_t *regex, rap_uint_t caseless);

static char *rap_http_core_types(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_type(rap_conf_t *cf, rap_command_t *dummy,
    void *conf);

static char *rap_http_core_listen(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_server_name(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_root(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_http_core_limit_except(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_set_aio(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_directio(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_error_page(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_open_file_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_error_log(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_keepalive(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_internal(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_core_resolver(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#if (RAP_HTTP_GZIP)
static rap_int_t rap_http_gzip_accept_encoding(rap_str_t *ae);
static rap_uint_t rap_http_gzip_quantity(u_char *p, u_char *last);
static char *rap_http_gzip_disable(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#endif
static rap_int_t rap_http_get_forwarded_addr_internal(rap_http_request_t *r,
    rap_addr_t *addr, u_char *xff, size_t xfflen, rap_array_t *proxies,
    int recursive);
#if (RAP_HAVE_OPENAT)
static char *rap_http_disable_symlinks(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#endif

static char *rap_http_core_lowat_check(rap_conf_t *cf, void *post, void *data);
static char *rap_http_core_pool_size(rap_conf_t *cf, void *post, void *data);

static rap_conf_post_t  rap_http_core_lowat_post =
    { rap_http_core_lowat_check };

static rap_conf_post_handler_pt  rap_http_core_pool_size_p =
    rap_http_core_pool_size;


static rap_conf_enum_t  rap_http_core_request_body_in_file[] = {
    { rap_string("off"), RAP_HTTP_REQUEST_BODY_FILE_OFF },
    { rap_string("on"), RAP_HTTP_REQUEST_BODY_FILE_ON },
    { rap_string("clean"), RAP_HTTP_REQUEST_BODY_FILE_CLEAN },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_http_core_satisfy[] = {
    { rap_string("all"), RAP_HTTP_SATISFY_ALL },
    { rap_string("any"), RAP_HTTP_SATISFY_ANY },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_http_core_lingering_close[] = {
    { rap_string("off"), RAP_HTTP_LINGERING_OFF },
    { rap_string("on"), RAP_HTTP_LINGERING_ON },
    { rap_string("always"), RAP_HTTP_LINGERING_ALWAYS },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_http_core_server_tokens[] = {
    { rap_string("off"), RAP_HTTP_SERVER_TOKENS_OFF },
    { rap_string("on"), RAP_HTTP_SERVER_TOKENS_ON },
    { rap_string("build"), RAP_HTTP_SERVER_TOKENS_BUILD },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_http_core_if_modified_since[] = {
    { rap_string("off"), RAP_HTTP_IMS_OFF },
    { rap_string("exact"), RAP_HTTP_IMS_EXACT },
    { rap_string("before"), RAP_HTTP_IMS_BEFORE },
    { rap_null_string, 0 }
};


static rap_conf_bitmask_t  rap_http_core_keepalive_disable[] = {
    { rap_string("none"), RAP_HTTP_KEEPALIVE_DISABLE_NONE },
    { rap_string("msie6"), RAP_HTTP_KEEPALIVE_DISABLE_MSIE6 },
    { rap_string("safari"), RAP_HTTP_KEEPALIVE_DISABLE_SAFARI },
    { rap_null_string, 0 }
};


static rap_path_init_t  rap_http_client_temp_path = {
    rap_string(RAP_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};


#if (RAP_HTTP_GZIP)

static rap_conf_enum_t  rap_http_gzip_http_version[] = {
    { rap_string("1.0"), RAP_HTTP_VERSION_10 },
    { rap_string("1.1"), RAP_HTTP_VERSION_11 },
    { rap_null_string, 0 }
};


static rap_conf_bitmask_t  rap_http_gzip_proxied_mask[] = {
    { rap_string("off"), RAP_HTTP_GZIP_PROXIED_OFF },
    { rap_string("expired"), RAP_HTTP_GZIP_PROXIED_EXPIRED },
    { rap_string("no-cache"), RAP_HTTP_GZIP_PROXIED_NO_CACHE },
    { rap_string("no-store"), RAP_HTTP_GZIP_PROXIED_NO_STORE },
    { rap_string("private"), RAP_HTTP_GZIP_PROXIED_PRIVATE },
    { rap_string("no_last_modified"), RAP_HTTP_GZIP_PROXIED_NO_LM },
    { rap_string("no_etag"), RAP_HTTP_GZIP_PROXIED_NO_ETAG },
    { rap_string("auth"), RAP_HTTP_GZIP_PROXIED_AUTH },
    { rap_string("any"), RAP_HTTP_GZIP_PROXIED_ANY },
    { rap_null_string, 0 }
};


static rap_str_t  rap_http_gzip_no_cache = rap_string("no-cache");
static rap_str_t  rap_http_gzip_no_store = rap_string("no-store");
static rap_str_t  rap_http_gzip_private = rap_string("private");

#endif


static rap_command_t  rap_http_core_commands[] = {

    { rap_string("variables_hash_max_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_core_main_conf_t, variables_hash_max_size),
      NULL },

    { rap_string("variables_hash_bucket_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { rap_string("server_names_hash_max_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_core_main_conf_t, server_names_hash_max_size),
      NULL },

    { rap_string("server_names_hash_bucket_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_core_main_conf_t, server_names_hash_bucket_size),
      NULL },

    { rap_string("server"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_NOARGS,
      rap_http_core_server,
      0,
      0,
      NULL },

    { rap_string("connection_pool_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, connection_pool_size),
      &rap_http_core_pool_size_p },

    { rap_string("request_pool_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, request_pool_size),
      &rap_http_core_pool_size_p },

    { rap_string("client_header_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, client_header_timeout),
      NULL },

    { rap_string("client_header_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, client_header_buffer_size),
      NULL },

    { rap_string("large_client_header_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, large_client_header_buffers),
      NULL },

    { rap_string("ignore_invalid_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, ignore_invalid_headers),
      NULL },

    { rap_string("merge_slashes"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, merge_slashes),
      NULL },

    { rap_string("underscores_in_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_core_srv_conf_t, underscores_in_headers),
      NULL },

    { rap_string("location"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE12,
      rap_http_core_location,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("listen"),
      RAP_HTTP_SRV_CONF|RAP_CONF_1MORE,
      rap_http_core_listen,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("server_name"),
      RAP_HTTP_SRV_CONF|RAP_CONF_1MORE,
      rap_http_core_server_name,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("types_hash_max_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, types_hash_max_size),
      NULL },

    { rap_string("types_hash_bucket_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, types_hash_bucket_size),
      NULL },

    { rap_string("types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF
                                          |RAP_CONF_BLOCK|RAP_CONF_NOARGS,
      rap_http_core_types,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("default_type"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, default_type),
      NULL },

    { rap_string("root"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE1,
      rap_http_core_root,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("alias"),
      RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_core_root,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("limit_except"),
      RAP_HTTP_LOC_CONF|RAP_CONF_BLOCK|RAP_CONF_1MORE,
      rap_http_core_limit_except,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("client_max_body_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_max_body_size),
      NULL },

    { rap_string("client_body_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_body_buffer_size),
      NULL },

    { rap_string("client_body_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_body_timeout),
      NULL },

    { rap_string("client_body_temp_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1234,
      rap_conf_set_path_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_body_temp_path),
      NULL },

    { rap_string("client_body_in_file_only"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_body_in_file_only),
      &rap_http_core_request_body_in_file },

    { rap_string("client_body_in_single_buffer"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, client_body_in_single_buffer),
      NULL },

    { rap_string("sendfile"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, sendfile),
      NULL },

    { rap_string("sendfile_max_chunk"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, sendfile_max_chunk),
      NULL },

    { rap_string("subrequest_output_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, subrequest_output_buffer_size),
      NULL },

    { rap_string("aio"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_core_set_aio,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("aio_write"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, aio_write),
      NULL },

    { rap_string("read_ahead"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, read_ahead),
      NULL },

    { rap_string("directio"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_core_directio,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("directio_alignment"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, directio_alignment),
      NULL },

    { rap_string("tcp_nopush"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, tcp_nopush),
      NULL },

    { rap_string("tcp_nodelay"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, tcp_nodelay),
      NULL },

    { rap_string("send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, send_timeout),
      NULL },

    { rap_string("send_lowat"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, send_lowat),
      &rap_http_core_lowat_post },

    { rap_string("postpone_output"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, postpone_output),
      NULL },

    { rap_string("limit_rate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE1,
      rap_http_set_complex_value_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, limit_rate),
      NULL },

    { rap_string("limit_rate_after"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE1,
      rap_http_set_complex_value_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, limit_rate_after),
      NULL },

    { rap_string("keepalive_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_core_keepalive,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("keepalive_requests"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, keepalive_requests),
      NULL },

    { rap_string("keepalive_disable"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, keepalive_disable),
      &rap_http_core_keepalive_disable },

    { rap_string("satisfy"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, satisfy),
      &rap_http_core_satisfy },

    { rap_string("auth_delay"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, auth_delay),
      NULL },

    { rap_string("internal"),
      RAP_HTTP_LOC_CONF|RAP_CONF_NOARGS,
      rap_http_core_internal,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("lingering_close"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, lingering_close),
      &rap_http_core_lingering_close },

    { rap_string("lingering_time"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, lingering_time),
      NULL },

    { rap_string("lingering_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, lingering_timeout),
      NULL },

    { rap_string("reset_timedout_connection"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, reset_timedout_connection),
      NULL },

    { rap_string("absolute_redirect"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, absolute_redirect),
      NULL },

    { rap_string("server_name_in_redirect"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, server_name_in_redirect),
      NULL },

    { rap_string("port_in_redirect"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, port_in_redirect),
      NULL },

    { rap_string("msie_padding"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, msie_padding),
      NULL },

    { rap_string("msie_refresh"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, msie_refresh),
      NULL },

    { rap_string("log_not_found"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, log_not_found),
      NULL },

    { rap_string("log_subrequest"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, log_subrequest),
      NULL },

    { rap_string("recursive_error_pages"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, recursive_error_pages),
      NULL },

    { rap_string("server_tokens"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, server_tokens),
      &rap_http_core_server_tokens },

    { rap_string("if_modified_since"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, if_modified_since),
      &rap_http_core_if_modified_since },

    { rap_string("max_ranges"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, max_ranges),
      NULL },

    { rap_string("chunked_transfer_encoding"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, chunked_transfer_encoding),
      NULL },

    { rap_string("etag"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, etag),
      NULL },

    { rap_string("error_page"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_2MORE,
      rap_http_core_error_page,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("post_action"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, post_action),
      NULL },

    { rap_string("error_log"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_core_error_log,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("open_file_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_core_open_file_cache,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, open_file_cache),
      NULL },

    { rap_string("open_file_cache_valid"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_sec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, open_file_cache_valid),
      NULL },

    { rap_string("open_file_cache_min_uses"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, open_file_cache_min_uses),
      NULL },

    { rap_string("open_file_cache_errors"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, open_file_cache_errors),
      NULL },

    { rap_string("open_file_cache_events"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, open_file_cache_events),
      NULL },

    { rap_string("resolver"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_core_resolver,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("resolver_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, resolver_timeout),
      NULL },

#if (RAP_HTTP_GZIP)

    { rap_string("gzip_vary"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, gzip_vary),
      NULL },

    { rap_string("gzip_http_version"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, gzip_http_version),
      &rap_http_gzip_http_version },

    { rap_string("gzip_proxied"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_core_loc_conf_t, gzip_proxied),
      &rap_http_gzip_proxied_mask },

    { rap_string("gzip_disable"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_gzip_disable,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

#if (RAP_HAVE_OPENAT)

    { rap_string("disable_symlinks"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_disable_symlinks,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rap_null_command
};


static rap_http_module_t  rap_http_core_module_ctx = {
    rap_http_core_preconfiguration,        /* preconfiguration */
    rap_http_core_postconfiguration,       /* postconfiguration */

    rap_http_core_create_main_conf,        /* create main configuration */
    rap_http_core_init_main_conf,          /* init main configuration */

    rap_http_core_create_srv_conf,         /* create server configuration */
    rap_http_core_merge_srv_conf,          /* merge server configuration */

    rap_http_core_create_loc_conf,         /* create location configuration */
    rap_http_core_merge_loc_conf           /* merge location configuration */
};


rap_module_t  rap_http_core_module = {
    RAP_MODULE_V1,
    &rap_http_core_module_ctx,             /* module context */
    rap_http_core_commands,                /* module directives */
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


rap_str_t  rap_http_core_get_method = { 3, (u_char *) "GET" };


void
rap_http_handler(rap_http_request_t *r)
{
    rap_http_core_main_conf_t  *cmcf;

    r->connection->log->action = NULL;

    if (!r->internal) {
        switch (r->headers_in.connection_type) {
        case 0:
            r->keepalive = (r->http_version > RAP_HTTP_VERSION_10);
            break;

        case RAP_HTTP_CONNECTION_CLOSE:
            r->keepalive = 0;
            break;

        case RAP_HTTP_CONNECTION_KEEP_ALIVE:
            r->keepalive = 1;
            break;
        }

        r->lingering_close = (r->headers_in.content_length_n > 0
                              || r->headers_in.chunked);
        r->phase_handler = 0;

    } else {
        cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);
        r->phase_handler = cmcf->phase_engine.server_rewrite_index;
    }

    r->valid_location = 1;
#if (RAP_HTTP_GZIP)
    r->gzip_tested = 0;
    r->gzip_ok = 0;
    r->gzip_vary = 0;
#endif

    r->write_event_handler = rap_http_core_run_phases;
    rap_http_core_run_phases(r);
}


void
rap_http_core_run_phases(rap_http_request_t *r)
{
    rap_int_t                   rc;
    rap_http_phase_handler_t   *ph;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[r->phase_handler].checker) {

        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);

        if (rc == RAP_OK) {
            return;
        }
    }
}


rap_int_t
rap_http_core_generic_phase(rap_http_request_t *r, rap_http_phase_handler_t *ph)
{
    rap_int_t  rc;

    /*
     * generic phase checker,
     * used by the post read and pre-access phases
     */

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generic phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RAP_OK) {
        r->phase_handler = ph->next;
        return RAP_AGAIN;
    }

    if (rc == RAP_DECLINED) {
        r->phase_handler++;
        return RAP_AGAIN;
    }

    if (rc == RAP_AGAIN || rc == RAP_DONE) {
        return RAP_OK;
    }

    /* rc == RAP_ERROR || rc == RAP_HTTP_...  */

    rap_http_finalize_request(r, rc);

    return RAP_OK;
}


rap_int_t
rap_http_core_rewrite_phase(rap_http_request_t *r, rap_http_phase_handler_t *ph)
{
    rap_int_t  rc;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rewrite phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RAP_DECLINED) {
        r->phase_handler++;
        return RAP_AGAIN;
    }

    if (rc == RAP_DONE) {
        return RAP_OK;
    }

    /* RAP_OK, RAP_AGAIN, RAP_ERROR, RAP_HTTP_...  */

    rap_http_finalize_request(r, rc);

    return RAP_OK;
}


rap_int_t
rap_http_core_find_config_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph)
{
    u_char                    *p;
    size_t                     len;
    rap_int_t                  rc;
    rap_http_core_loc_conf_t  *clcf;

    r->content_handler = NULL;
    r->uri_changed = 0;

    rc = rap_http_core_find_location(r);

    if (rc == RAP_ERROR) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!r->internal && clcf->internal) {
        rap_http_finalize_request(r, RAP_HTTP_NOT_FOUND);
        return RAP_OK;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "using configuration \"%s%V\"",
                   (clcf->noname ? "*" : (clcf->exact_match ? "=" : "")),
                   &clcf->name);

    rap_http_update_location_config(r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl:%O max:%O",
                   r->headers_in.content_length_n, clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && !r->discard_body
        && clcf->client_max_body_size
        && clcf->client_max_body_size < r->headers_in.content_length_n)
    {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client intended to send too large body: %O bytes",
                      r->headers_in.content_length_n);

        r->expect_tested = 1;
        (void) rap_http_discard_request_body(r);
        rap_http_finalize_request(r, RAP_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return RAP_OK;
    }

    if (rc == RAP_DONE) {
        rap_http_clear_location(r);

        r->headers_out.location = rap_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return RAP_OK;
        }

        r->headers_out.location->hash = 1;
        rap_str_set(&r->headers_out.location->key, "Location");

        if (r->args.len == 0) {
            r->headers_out.location->value = clcf->name;

        } else {
            len = clcf->name.len + 1 + r->args.len;
            p = rap_pnalloc(r->pool, len);

            if (p == NULL) {
                rap_http_clear_location(r);
                rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                return RAP_OK;
            }

            r->headers_out.location->value.len = len;
            r->headers_out.location->value.data = p;

            p = rap_cpymem(p, clcf->name.data, clcf->name.len);
            *p++ = '?';
            rap_memcpy(p, r->args.data, r->args.len);
        }

        rap_http_finalize_request(r, RAP_HTTP_MOVED_PERMANENTLY);
        return RAP_OK;
    }

    r->phase_handler++;
    return RAP_AGAIN;
}


rap_int_t
rap_http_core_post_rewrite_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph)
{
    rap_http_core_srv_conf_t  *cscf;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post rewrite phase: %ui", r->phase_handler);

    if (!r->uri_changed) {
        r->phase_handler++;
        return RAP_AGAIN;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri changes: %d", r->uri_changes);

    /*
     * gcc before 3.3 compiles the broken code for
     *     if (r->uri_changes-- == 0)
     * if the r->uri_changes is defined as
     *     unsigned  uri_changes:4
     */

    r->uri_changes--;

    if (r->uri_changes == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while processing \"%V\"", &r->uri);

        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_OK;
    }

    r->phase_handler = ph->next;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    return RAP_AGAIN;
}


rap_int_t
rap_http_core_access_phase(rap_http_request_t *r, rap_http_phase_handler_t *ph)
{
    rap_int_t                  rc;
    rap_http_core_loc_conf_t  *clcf;

    if (r != r->main) {
        r->phase_handler = ph->next;
        return RAP_AGAIN;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "access phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RAP_DECLINED) {
        r->phase_handler++;
        return RAP_AGAIN;
    }

    if (rc == RAP_AGAIN || rc == RAP_DONE) {
        return RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->satisfy == RAP_HTTP_SATISFY_ALL) {

        if (rc == RAP_OK) {
            r->phase_handler++;
            return RAP_AGAIN;
        }

    } else {
        if (rc == RAP_OK) {
            r->access_code = 0;

            if (r->headers_out.www_authenticate) {
                r->headers_out.www_authenticate->hash = 0;
            }

            r->phase_handler = ph->next;
            return RAP_AGAIN;
        }

        if (rc == RAP_HTTP_FORBIDDEN || rc == RAP_HTTP_UNAUTHORIZED) {
            if (r->access_code != RAP_HTTP_UNAUTHORIZED) {
                r->access_code = rc;
            }

            r->phase_handler++;
            return RAP_AGAIN;
        }
    }

    /* rc == RAP_ERROR || rc == RAP_HTTP_...  */

    if (rc == RAP_HTTP_UNAUTHORIZED) {
        return rap_http_core_auth_delay(r);
    }

    rap_http_finalize_request(r, rc);
    return RAP_OK;
}


rap_int_t
rap_http_core_post_access_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph)
{
    rap_int_t  access_code;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post access phase: %ui", r->phase_handler);

    access_code = r->access_code;

    if (access_code) {
        r->access_code = 0;

        if (access_code == RAP_HTTP_FORBIDDEN) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        if (access_code == RAP_HTTP_UNAUTHORIZED) {
            return rap_http_core_auth_delay(r);
        }

        rap_http_finalize_request(r, access_code);
        return RAP_OK;
    }

    r->phase_handler++;
    return RAP_AGAIN;
}


static rap_int_t
rap_http_core_auth_delay(rap_http_request_t *r)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->auth_delay == 0) {
        rap_http_finalize_request(r, RAP_HTTP_UNAUTHORIZED);
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                  "delaying unauthorized request");

    if (rap_handle_read_event(r->connection->read, 0) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = rap_http_test_reading;
    r->write_event_handler = rap_http_core_auth_delay_handler;

    r->connection->write->delayed = 1;
    rap_add_timer(r->connection->write, clcf->auth_delay);

    /*
     * trigger an additional event loop iteration
     * to ensure constant-time processing
     */

    rap_post_event(r->connection->write, &rap_posted_next_events);

    return RAP_OK;
}


static void
rap_http_core_auth_delay_handler(rap_http_request_t *r)
{
    rap_event_t  *wev;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth delay handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rap_handle_write_event(wev, 0) != RAP_OK) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    rap_http_finalize_request(r, RAP_HTTP_UNAUTHORIZED);
}


rap_int_t
rap_http_core_content_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph)
{
    size_t     root;
    rap_int_t  rc;
    rap_str_t  path;

    if (r->content_handler) {
        r->write_event_handler = rap_http_request_empty_handler;
        rap_http_finalize_request(r, r->content_handler(r));
        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "content phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc != RAP_DECLINED) {
        rap_http_finalize_request(r, rc);
        return RAP_OK;
    }

    /* rc == RAP_DECLINED */

    ph++;

    if (ph->checker) {
        r->phase_handler++;
        return RAP_AGAIN;
    }

    /* no content handler was found */

    if (r->uri.data[r->uri.len - 1] == '/') {

        if (rap_http_map_uri_to_path(r, &path, &root, 0) != NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "directory index of \"%s\" is forbidden", path.data);
        }

        rap_http_finalize_request(r, RAP_HTTP_FORBIDDEN);
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0, "no handler found");

    rap_http_finalize_request(r, RAP_HTTP_NOT_FOUND);
    return RAP_OK;
}


void
rap_http_update_location_config(rap_http_request_t *r)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->method & clcf->limit_except) {
        r->loc_conf = clcf->limit_except_loc_conf;
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    }

    if (r == r->main) {
        rap_set_connection_log(r->connection, clcf->error_log);
    }

    if ((rap_io.flags & RAP_IO_SENDFILE) && clcf->sendfile) {
        r->connection->sendfile = 1;

    } else {
        r->connection->sendfile = 0;
    }

    if (clcf->client_body_in_file_only) {
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file =
            clcf->client_body_in_file_only == RAP_HTTP_REQUEST_BODY_FILE_CLEAN;
        r->request_body_file_log_level = RAP_LOG_NOTICE;

    } else {
        r->request_body_file_log_level = RAP_LOG_WARN;
    }

    r->request_body_in_single_buf = clcf->client_body_in_single_buffer;

    if (r->keepalive) {
        if (clcf->keepalive_timeout == 0) {
            r->keepalive = 0;

        } else if (r->connection->requests >= clcf->keepalive_requests) {
            r->keepalive = 0;

        } else if (r->headers_in.msie6
                   && r->method == RAP_HTTP_POST
                   && (clcf->keepalive_disable
                       & RAP_HTTP_KEEPALIVE_DISABLE_MSIE6))
        {
            /*
             * MSIE may wait for some time if an response for
             * a POST request was sent over a keepalive connection
             */
            r->keepalive = 0;

        } else if (r->headers_in.safari
                   && (clcf->keepalive_disable
                       & RAP_HTTP_KEEPALIVE_DISABLE_SAFARI))
        {
            /*
             * Safari may send a POST request to a closed keepalive
             * connection and may stall for some time, see
             *     https://bugs.webkit.org/show_bug.cgi?id=5760
             */
            r->keepalive = 0;
        }
    }

    if (!clcf->tcp_nopush) {
        /* disable TCP_NOPUSH/TCP_CORK use */
        r->connection->tcp_nopush = RAP_TCP_NOPUSH_DISABLED;
    }

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }
}


/*
 * RAP_OK       - exact or regex match
 * RAP_DONE     - auto redirect
 * RAP_AGAIN    - inclusive match
 * RAP_ERROR    - regex error
 * RAP_DECLINED - no match
 */

static rap_int_t
rap_http_core_find_location(rap_http_request_t *r)
{
    rap_int_t                  rc;
    rap_http_core_loc_conf_t  *pclcf;
#if (RAP_PCRE)
    rap_int_t                  n;
    rap_uint_t                 noregex;
    rap_http_core_loc_conf_t  *clcf, **clcfp;

    noregex = 0;
#endif

    pclcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rc = rap_http_core_find_static_location(r, pclcf->static_locations);

    if (rc == RAP_AGAIN) {

#if (RAP_PCRE)
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        noregex = clcf->noregex;
#endif

        /* look up nested locations */

        rc = rap_http_core_find_location(r);
    }

    if (rc == RAP_OK || rc == RAP_DONE) {
        return rc;
    }

    /* rc == RAP_DECLINED or rc == RAP_AGAIN in nested location */

#if (RAP_PCRE)

    if (noregex == 0 && pclcf->regex_locations) {

        for (clcfp = pclcf->regex_locations; *clcfp; clcfp++) {

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: ~ \"%V\"", &(*clcfp)->name);

            n = rap_http_regex_exec(r, (*clcfp)->regex, &r->uri);

            if (n == RAP_OK) {
                r->loc_conf = (*clcfp)->loc_conf;

                /* look up nested locations */

                rc = rap_http_core_find_location(r);

                return (rc == RAP_ERROR) ? rc : RAP_OK;
            }

            if (n == RAP_DECLINED) {
                continue;
            }

            return RAP_ERROR;
        }
    }
#endif

    return rc;
}


/*
 * RAP_OK       - exact match
 * RAP_DONE     - auto redirect
 * RAP_AGAIN    - inclusive match
 * RAP_DECLINED - no match
 */

static rap_int_t
rap_http_core_find_static_location(rap_http_request_t *r,
    rap_http_location_tree_node_t *node)
{
    u_char     *uri;
    size_t      len, n;
    rap_int_t   rc, rv;

    len = r->uri.len;
    uri = r->uri.data;

    rv = RAP_DECLINED;

    for ( ;; ) {

        if (node == NULL) {
            return rv;
        }

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "test location: \"%*s\"",
                       (size_t) node->len, node->name);

        n = (len <= (size_t) node->len) ? len : node->len;

        rc = rap_filename_cmp(uri, node->name, n);

        if (rc != 0) {
            node = (rc < 0) ? node->left : node->right;

            continue;
        }

        if (len > (size_t) node->len) {

            if (node->inclusive) {

                r->loc_conf = node->inclusive->loc_conf;
                rv = RAP_AGAIN;

                node = node->tree;
                uri += n;
                len -= n;

                continue;
            }

            /* exact only */

            node = node->right;

            continue;
        }

        if (len == (size_t) node->len) {

            if (node->exact) {
                r->loc_conf = node->exact->loc_conf;
                return RAP_OK;

            } else {
                r->loc_conf = node->inclusive->loc_conf;
                return RAP_AGAIN;
            }
        }

        /* len < node->len */

        if (len + 1 == (size_t) node->len && node->auto_redirect) {

            r->loc_conf = (node->exact) ? node->exact->loc_conf:
                                          node->inclusive->loc_conf;
            rv = RAP_DONE;
        }

        node = node->left;
    }
}


void *
rap_http_test_content_type(rap_http_request_t *r, rap_hash_t *types_hash)
{
    u_char      c, *lowcase;
    size_t      len;
    rap_uint_t  i, hash;

    if (types_hash->size == 0) {
        return (void *) 4;
    }

    if (r->headers_out.content_type.len == 0) {
        return NULL;
    }

    len = r->headers_out.content_type_len;

    if (r->headers_out.content_type_lowcase == NULL) {

        lowcase = rap_pnalloc(r->pool, len);
        if (lowcase == NULL) {
            return NULL;
        }

        r->headers_out.content_type_lowcase = lowcase;

        hash = 0;

        for (i = 0; i < len; i++) {
            c = rap_tolower(r->headers_out.content_type.data[i]);
            hash = rap_hash(hash, c);
            lowcase[i] = c;
        }

        r->headers_out.content_type_hash = hash;
    }

    return rap_hash_find(types_hash, r->headers_out.content_type_hash,
                         r->headers_out.content_type_lowcase, len);
}


rap_int_t
rap_http_set_content_type(rap_http_request_t *r)
{
    u_char                     c, *exten;
    rap_str_t                 *type;
    rap_uint_t                 i, hash;
    rap_http_core_loc_conf_t  *clcf;

    if (r->headers_out.content_type.len) {
        return RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->exten.len) {

        hash = 0;

        for (i = 0; i < r->exten.len; i++) {
            c = r->exten.data[i];

            if (c >= 'A' && c <= 'Z') {

                exten = rap_pnalloc(r->pool, r->exten.len);
                if (exten == NULL) {
                    return RAP_ERROR;
                }

                hash = rap_hash_strlow(exten, r->exten.data, r->exten.len);

                r->exten.data = exten;

                break;
            }

            hash = rap_hash(hash, c);
        }

        type = rap_hash_find(&clcf->types_hash, hash,
                             r->exten.data, r->exten.len);

        if (type) {
            r->headers_out.content_type_len = type->len;
            r->headers_out.content_type = *type;

            return RAP_OK;
        }
    }

    r->headers_out.content_type_len = clcf->default_type.len;
    r->headers_out.content_type = clcf->default_type;

    return RAP_OK;
}


void
rap_http_set_exten(rap_http_request_t *r)
{
    rap_int_t  i;

    rap_str_null(&r->exten);

    for (i = r->uri.len - 1; i > 1; i--) {
        if (r->uri.data[i] == '.' && r->uri.data[i - 1] != '/') {

            r->exten.len = r->uri.len - i - 1;
            r->exten.data = &r->uri.data[i + 1];

            return;

        } else if (r->uri.data[i] == '/') {
            return;
        }
    }

    return;
}


rap_int_t
rap_http_set_etag(rap_http_request_t *r)
{
    rap_table_elt_t           *etag;
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!clcf->etag) {
        return RAP_OK;
    }

    etag = rap_list_push(&r->headers_out.headers);
    if (etag == NULL) {
        return RAP_ERROR;
    }

    etag->hash = 1;
    rap_str_set(&etag->key, "ETag");

    etag->value.data = rap_pnalloc(r->pool, RAP_OFF_T_LEN + RAP_TIME_T_LEN + 3);
    if (etag->value.data == NULL) {
        etag->hash = 0;
        return RAP_ERROR;
    }

    etag->value.len = rap_sprintf(etag->value.data, "\"%xT-%xO\"",
                                  r->headers_out.last_modified_time,
                                  r->headers_out.content_length_n)
                      - etag->value.data;

    r->headers_out.etag = etag;

    return RAP_OK;
}


void
rap_http_weak_etag(rap_http_request_t *r)
{
    size_t            len;
    u_char           *p;
    rap_table_elt_t  *etag;

    etag = r->headers_out.etag;

    if (etag == NULL) {
        return;
    }

    if (etag->value.len > 2
        && etag->value.data[0] == 'W'
        && etag->value.data[1] == '/')
    {
        return;
    }

    if (etag->value.len < 1 || etag->value.data[0] != '"') {
        r->headers_out.etag->hash = 0;
        r->headers_out.etag = NULL;
        return;
    }

    p = rap_pnalloc(r->pool, etag->value.len + 2);
    if (p == NULL) {
        r->headers_out.etag->hash = 0;
        r->headers_out.etag = NULL;
        return;
    }

    len = rap_sprintf(p, "W/%V", &etag->value) - p;

    etag->value.data = p;
    etag->value.len = len;
}


rap_int_t
rap_http_send_response(rap_http_request_t *r, rap_uint_t status,
    rap_str_t *ct, rap_http_complex_value_t *cv)
{
    rap_int_t     rc;
    rap_str_t     val;
    rap_buf_t    *b;
    rap_chain_t   out;

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    r->headers_out.status = status;

    if (rap_http_complex_value(r, cv, &val) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (status == RAP_HTTP_MOVED_PERMANENTLY
        || status == RAP_HTTP_MOVED_TEMPORARILY
        || status == RAP_HTTP_SEE_OTHER
        || status == RAP_HTTP_TEMPORARY_REDIRECT
        || status == RAP_HTTP_PERMANENT_REDIRECT)
    {
        rap_http_clear_location(r);

        r->headers_out.location = rap_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->hash = 1;
        rap_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = val;

        return status;
    }

    r->headers_out.content_length_n = val.len;

    if (ct) {
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;

    } else {
        if (rap_http_set_content_type(r) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (r->method == RAP_HTTP_HEAD || (r != r->main && val.len == 0)) {
        return rap_http_send_header(r);
    }

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = val.data;
    b->last = val.data + val.len;
    b->memory = val.len ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return rc;
    }

    return rap_http_output_filter(r, &out);
}


rap_int_t
rap_http_send_header(rap_http_request_t *r)
{
    if (r->post_action) {
        return RAP_OK;
    }

    if (r->header_sent) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "header already sent");
        return RAP_ERROR;
    }

    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return rap_http_top_header_filter(r);
}


rap_int_t
rap_http_output_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t          rc;
    rap_connection_t  *c;

    c = r->connection;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http output filter \"%V?%V\"", &r->uri, &r->args);

    rc = rap_http_top_body_filter(r, in);

    if (rc == RAP_ERROR) {
        /* RAP_ERROR may be returned by any filter */
        c->error = 1;
    }

    return rc;
}


u_char *
rap_http_map_uri_to_path(rap_http_request_t *r, rap_str_t *path,
    size_t *root_length, size_t reserved)
{
    u_char                    *last;
    size_t                     alias;
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    alias = clcf->alias;

    if (alias && !r->valid_location) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "\"alias\" cannot be used in location \"%V\" "
                      "where URI was rewritten", &clcf->name);
        return NULL;
    }

    if (clcf->root_lengths == NULL) {

        *root_length = clcf->root.len;

        path->len = clcf->root.len + reserved + r->uri.len - alias + 1;

        path->data = rap_pnalloc(r->pool, path->len);
        if (path->data == NULL) {
            return NULL;
        }

        last = rap_copy(path->data, clcf->root.data, clcf->root.len);

    } else {

        if (alias == RAP_MAX_SIZE_T_VALUE) {
            reserved += r->add_uri_to_alias ? r->uri.len + 1 : 1;

        } else {
            reserved += r->uri.len - alias + 1;
        }

        if (rap_http_script_run(r, path, clcf->root_lengths->elts, reserved,
                                clcf->root_values->elts)
            == NULL)
        {
            return NULL;
        }

        if (rap_get_full_name(r->pool, (rap_str_t *) &rap_cycle->prefix, path)
            != RAP_OK)
        {
            return NULL;
        }

        *root_length = path->len - reserved;
        last = path->data + *root_length;

        if (alias == RAP_MAX_SIZE_T_VALUE) {
            if (!r->add_uri_to_alias) {
                *last = '\0';
                return last;
            }

            alias = 0;
        }
    }

    last = rap_copy(last, r->uri.data + alias, r->uri.len - alias);
    *last = '\0';

    return last;
}


rap_int_t
rap_http_auth_basic_user(rap_http_request_t *r)
{
    rap_str_t   auth, encoded;
    rap_uint_t  len;

    if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return RAP_DECLINED;
    }

    if (r->headers_in.authorization == NULL) {
        r->headers_in.user.data = (u_char *) "";
        return RAP_DECLINED;
    }

    encoded = r->headers_in.authorization->value;

    if (encoded.len < sizeof("Basic ") - 1
        || rap_strncasecmp(encoded.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1)
           != 0)
    {
        r->headers_in.user.data = (u_char *) "";
        return RAP_DECLINED;
    }

    encoded.len -= sizeof("Basic ") - 1;
    encoded.data += sizeof("Basic ") - 1;

    while (encoded.len && encoded.data[0] == ' ') {
        encoded.len--;
        encoded.data++;
    }

    if (encoded.len == 0) {
        r->headers_in.user.data = (u_char *) "";
        return RAP_DECLINED;
    }

    auth.len = rap_base64_decoded_length(encoded.len);
    auth.data = rap_pnalloc(r->pool, auth.len + 1);
    if (auth.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&auth, &encoded) != RAP_OK) {
        r->headers_in.user.data = (u_char *) "";
        return RAP_DECLINED;
    }

    auth.data[auth.len] = '\0';

    for (len = 0; len < auth.len; len++) {
        if (auth.data[len] == ':') {
            break;
        }
    }

    if (len == 0 || len == auth.len) {
        r->headers_in.user.data = (u_char *) "";
        return RAP_DECLINED;
    }

    r->headers_in.user.len = len;
    r->headers_in.user.data = auth.data;
    r->headers_in.passwd.len = auth.len - len - 1;
    r->headers_in.passwd.data = &auth.data[len + 1];

    return RAP_OK;
}


#if (RAP_HTTP_GZIP)

rap_int_t
rap_http_gzip_ok(rap_http_request_t *r)
{
    time_t                     date, expires;
    rap_uint_t                 p;
    rap_array_t               *cc;
    rap_table_elt_t           *e, *d, *ae;
    rap_http_core_loc_conf_t  *clcf;

    r->gzip_tested = 1;

    if (r != r->main) {
        return RAP_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return RAP_DECLINED;
    }

    if (ae->value.len < sizeof("gzip") - 1) {
        return RAP_DECLINED;
    }

    /*
     * test first for the most common case "gzip,...":
     *   MSIE:    "gzip, deflate"
     *   Firefox: "gzip,deflate"
     *   Chrome:  "gzip,deflate,sdch"
     *   Safari:  "gzip, deflate"
     *   Opera:   "gzip, deflate"
     */

    if (rap_memcmp(ae->value.data, "gzip,", 5) != 0
        && rap_http_gzip_accept_encoding(&ae->value) != RAP_OK)
    {
        return RAP_DECLINED;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->headers_in.msie6 && clcf->gzip_disable_msie6) {
        return RAP_DECLINED;
    }

    if (r->http_version < clcf->gzip_http_version) {
        return RAP_DECLINED;
    }

    if (r->headers_in.via == NULL) {
        goto ok;
    }

    p = clcf->gzip_proxied;

    if (p & RAP_HTTP_GZIP_PROXIED_OFF) {
        return RAP_DECLINED;
    }

    if (p & RAP_HTTP_GZIP_PROXIED_ANY) {
        goto ok;
    }

    if (r->headers_in.authorization && (p & RAP_HTTP_GZIP_PROXIED_AUTH)) {
        goto ok;
    }

    e = r->headers_out.expires;

    if (e) {

        if (!(p & RAP_HTTP_GZIP_PROXIED_EXPIRED)) {
            return RAP_DECLINED;
        }

        expires = rap_parse_http_time(e->value.data, e->value.len);
        if (expires == RAP_ERROR) {
            return RAP_DECLINED;
        }

        d = r->headers_out.date;

        if (d) {
            date = rap_parse_http_time(d->value.data, d->value.len);
            if (date == RAP_ERROR) {
                return RAP_DECLINED;
            }

        } else {
            date = rap_time();
        }

        if (expires < date) {
            goto ok;
        }

        return RAP_DECLINED;
    }

    cc = &r->headers_out.cache_control;

    if (cc->elts) {

        if ((p & RAP_HTTP_GZIP_PROXIED_NO_CACHE)
            && rap_http_parse_multi_header_lines(cc, &rap_http_gzip_no_cache,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        if ((p & RAP_HTTP_GZIP_PROXIED_NO_STORE)
            && rap_http_parse_multi_header_lines(cc, &rap_http_gzip_no_store,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        if ((p & RAP_HTTP_GZIP_PROXIED_PRIVATE)
            && rap_http_parse_multi_header_lines(cc, &rap_http_gzip_private,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        return RAP_DECLINED;
    }

    if ((p & RAP_HTTP_GZIP_PROXIED_NO_LM) && r->headers_out.last_modified) {
        return RAP_DECLINED;
    }

    if ((p & RAP_HTTP_GZIP_PROXIED_NO_ETAG) && r->headers_out.etag) {
        return RAP_DECLINED;
    }

ok:

#if (RAP_PCRE)

    if (clcf->gzip_disable && r->headers_in.user_agent) {

        if (rap_regex_exec_array(clcf->gzip_disable,
                                 &r->headers_in.user_agent->value,
                                 r->connection->log)
            != RAP_DECLINED)
        {
            return RAP_DECLINED;
        }
    }

#endif

    r->gzip_ok = 1;

    return RAP_OK;
}


/*
 * gzip is enabled for the following quantities:
 *     "gzip; q=0.001" ... "gzip; q=1.000"
 * gzip is disabled for the following quantities:
 *     "gzip; q=0" ... "gzip; q=0.000", and for any invalid cases
 */

static rap_int_t
rap_http_gzip_accept_encoding(rap_str_t *ae)
{
    u_char  *p, *start, *last;

    start = ae->data;
    last = start + ae->len;

    for ( ;; ) {
        p = rap_strcasestrn(start, "gzip", 4 - 1);
        if (p == NULL) {
            return RAP_DECLINED;
        }

        if (p == start || (*(p - 1) == ',' || *(p - 1) == ' ')) {
            break;
        }

        start = p + 4;
    }

    p += 4;

    while (p < last) {
        switch (*p++) {
        case ',':
            return RAP_OK;
        case ';':
            goto quantity;
        case ' ':
            continue;
        default:
            return RAP_DECLINED;
        }
    }

    return RAP_OK;

quantity:

    while (p < last) {
        switch (*p++) {
        case 'q':
        case 'Q':
            goto equal;
        case ' ':
            continue;
        default:
            return RAP_DECLINED;
        }
    }

    return RAP_OK;

equal:

    if (p + 2 > last || *p++ != '=') {
        return RAP_DECLINED;
    }

    if (rap_http_gzip_quantity(p, last) == 0) {
        return RAP_DECLINED;
    }

    return RAP_OK;
}


static rap_uint_t
rap_http_gzip_quantity(u_char *p, u_char *last)
{
    u_char      c;
    rap_uint_t  n, q;

    c = *p++;

    if (c != '0' && c != '1') {
        return 0;
    }

    q = (c - '0') * 100;

    if (p == last) {
        return q;
    }

    c = *p++;

    if (c == ',' || c == ' ') {
        return q;
    }

    if (c != '.') {
        return 0;
    }

    n = 0;

    while (p < last) {
        c = *p++;

        if (c == ',' || c == ' ') {
            break;
        }

        if (c >= '0' && c <= '9') {
            q += c - '0';
            n++;
            continue;
        }

        return 0;
    }

    if (q > 100 || n > 3) {
        return 0;
    }

    return q;
}

#endif


rap_int_t
rap_http_subrequest(rap_http_request_t *r,
    rap_str_t *uri, rap_str_t *args, rap_http_request_t **psr,
    rap_http_post_subrequest_t *ps, rap_uint_t flags)
{
    rap_time_t                    *tp;
    rap_connection_t              *c;
    rap_http_request_t            *sr;
    rap_http_core_srv_conf_t      *cscf;
    rap_http_postponed_request_t  *pr, *p;

    if (r->subrequests == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        return RAP_ERROR;
    }

    /*
     * 1000 is reserved for other purposes.
     */
    if (r->main->count >= 65535 - 1000) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "request reference counter overflow "
                      "while processing \"%V\"", uri);
        return RAP_ERROR;
    }

    if (r->subrequest_in_memory) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "nested in-memory subrequest \"%V\"", uri);
        return RAP_ERROR;
    }

    sr = rap_pcalloc(r->pool, sizeof(rap_http_request_t));
    if (sr == NULL) {
        return RAP_ERROR;
    }

    sr->signature = RAP_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = rap_pcalloc(r->pool, sizeof(void *) * rap_http_max_module);
    if (sr->ctx == NULL) {
        return RAP_ERROR;
    }

    if (rap_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_list_init(&sr->headers_out.trailers, r->pool, 4,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in = r->headers_in;

    rap_http_clear_content_length(sr);
    rap_http_clear_accept_ranges(sr);
    rap_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (RAP_HTTP_V2)
    sr->stream = r->stream;
#endif

    sr->method = RAP_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & RAP_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & RAP_HTTP_SUBREQUEST_WAITED) != 0;
    sr->background = (flags & RAP_HTTP_SUBREQUEST_BACKGROUND) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = rap_http_core_get_method;
    sr->http_protocol = r->http_protocol;
    sr->schema = r->schema;

    rap_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = rap_http_request_empty_handler;
    sr->write_event_handler = rap_http_handler;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    if (sr->subrequest_in_memory) {
        sr->filter_need_in_memory = 1;
    }

    if (!sr->background) {
        if (c->data == r && r->postponed == NULL) {
            c->data = sr;
        }

        pr = rap_palloc(r->pool, sizeof(rap_http_postponed_request_t));
        if (pr == NULL) {
            return RAP_ERROR;
        }

        pr->request = sr;
        pr->out = NULL;
        pr->next = NULL;

        if (r->postponed) {
            for (p = r->postponed; p->next; p = p->next) { /* void */ }
            p->next = pr;

        } else {
            r->postponed = pr;
        }
    }

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = RAP_HTTP_MAX_URI_CHANGES + 1;
    sr->subrequests = r->subrequests - 1;

    tp = rap_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    if (flags & RAP_HTTP_SUBREQUEST_CLONE) {
        sr->method = r->method;
        sr->method_name = r->method_name;
        sr->loc_conf = r->loc_conf;
        sr->valid_location = r->valid_location;
        sr->valid_unparsed_uri = r->valid_unparsed_uri;
        sr->content_handler = r->content_handler;
        sr->phase_handler = r->phase_handler;
        sr->write_event_handler = rap_http_core_run_phases;

#if (RAP_PCRE)
        sr->ncaptures = r->ncaptures;
        sr->captures = r->captures;
        sr->captures_data = r->captures_data;
        sr->realloc_captures = 1;
        r->realloc_captures = 1;
#endif

        rap_http_update_location_config(sr);
    }

    return rap_http_post_request(sr, NULL);
}


rap_int_t
rap_http_internal_redirect(rap_http_request_t *r,
    rap_str_t *uri, rap_str_t *args)
{
    rap_http_core_srv_conf_t  *cscf;

    r->uri_changes--;

    if (r->uri_changes == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while internally redirecting to \"%V\"", uri);

        r->main->count++;
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_DONE;
    }

    r->uri = *uri;

    if (args) {
        r->args = *args;

    } else {
        rap_str_null(&r->args);
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%V?%V\"", uri, &r->args);

    rap_http_set_exten(r);

    /* clear the modules contexts */
    rap_memzero(r->ctx, sizeof(void *) * rap_http_max_module);

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    rap_http_update_location_config(r);

#if (RAP_HTTP_CACHE)
    r->cache = NULL;
#endif

    r->internal = 1;
    r->valid_unparsed_uri = 0;
    r->add_uri_to_alias = 0;
    r->main->count++;

    rap_http_handler(r);

    return RAP_DONE;
}


rap_int_t
rap_http_named_location(rap_http_request_t *r, rap_str_t *name)
{
    rap_http_core_srv_conf_t    *cscf;
    rap_http_core_loc_conf_t   **clcfp;
    rap_http_core_main_conf_t   *cmcf;

    r->main->count++;
    r->uri_changes--;

    if (r->uri_changes == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while redirect to named location \"%V\"", name);

        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_DONE;
    }

    if (r->uri.len == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "empty URI in redirect to named location \"%V\"", name);

        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_DONE;
    }

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

    if (cscf->named_locations) {

        for (clcfp = cscf->named_locations; *clcfp; clcfp++) {

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: \"%V\"", &(*clcfp)->name);

            if (name->len != (*clcfp)->name.len
                || rap_strncmp(name->data, (*clcfp)->name.data, name->len) != 0)
            {
                continue;
            }

            rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "using location: %V \"%V?%V\"",
                           name, &r->uri, &r->args);

            r->internal = 1;
            r->content_handler = NULL;
            r->uri_changed = 0;
            r->loc_conf = (*clcfp)->loc_conf;

            /* clear the modules contexts */
            rap_memzero(r->ctx, sizeof(void *) * rap_http_max_module);

            rap_http_update_location_config(r);

            cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

            r->phase_handler = cmcf->phase_engine.location_rewrite_index;

            r->write_event_handler = rap_http_core_run_phases;
            rap_http_core_run_phases(r);

            return RAP_DONE;
        }
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "could not find named location \"%V\"", name);

    rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);

    return RAP_DONE;
}


rap_http_cleanup_t *
rap_http_cleanup_add(rap_http_request_t *r, size_t size)
{
    rap_http_cleanup_t  *cln;

    r = r->main;

    cln = rap_palloc(r->pool, sizeof(rap_http_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = rap_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cleanup add: %p", cln);

    return cln;
}


rap_int_t
rap_http_set_disable_symlinks(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, rap_str_t *path, rap_open_file_info_t *of)
{
#if (RAP_HAVE_OPENAT)
    u_char     *p;
    rap_str_t   from;

    of->disable_symlinks = clcf->disable_symlinks;

    if (clcf->disable_symlinks_from == NULL) {
        return RAP_OK;
    }

    if (rap_http_complex_value(r, clcf->disable_symlinks_from, &from)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (from.len == 0
        || from.len > path->len
        || rap_memcmp(path->data, from.data, from.len) != 0)
    {
        return RAP_OK;
    }

    if (from.len == path->len) {
        of->disable_symlinks = RAP_DISABLE_SYMLINKS_OFF;
        return RAP_OK;
    }

    p = path->data + from.len;

    if (*p == '/') {
        of->disable_symlinks_from = from.len;
        return RAP_OK;
    }

    p--;

    if (*p == '/') {
        of->disable_symlinks_from = from.len - 1;
    }
#endif

    return RAP_OK;
}


rap_int_t
rap_http_get_forwarded_addr(rap_http_request_t *r, rap_addr_t *addr,
    rap_array_t *headers, rap_str_t *value, rap_array_t *proxies,
    int recursive)
{
    rap_int_t          rc;
    rap_uint_t         i, found;
    rap_table_elt_t  **h;

    if (headers == NULL) {
        return rap_http_get_forwarded_addr_internal(r, addr, value->data,
                                                    value->len, proxies,
                                                    recursive);
    }

    i = headers->nelts;
    h = headers->elts;

    rc = RAP_DECLINED;

    found = 0;

    while (i-- > 0) {
        rc = rap_http_get_forwarded_addr_internal(r, addr, h[i]->value.data,
                                                  h[i]->value.len, proxies,
                                                  recursive);

        if (!recursive) {
            break;
        }

        if (rc == RAP_DECLINED && found) {
            rc = RAP_DONE;
            break;
        }

        if (rc != RAP_OK) {
            break;
        }

        found = 1;
    }

    return rc;
}


static rap_int_t
rap_http_get_forwarded_addr_internal(rap_http_request_t *r, rap_addr_t *addr,
    u_char *xff, size_t xfflen, rap_array_t *proxies, int recursive)
{
    u_char      *p;
    rap_addr_t   paddr;
    rap_uint_t   found;

    found = 0;

    do {

        if (rap_cidr_match(addr->sockaddr, proxies) != RAP_OK) {
            return found ? RAP_DONE : RAP_DECLINED;
        }

        for (p = xff + xfflen - 1; p > xff; p--, xfflen--) {
            if (*p != ' ' && *p != ',') {
                break;
            }
        }

        for ( /* void */ ; p > xff; p--) {
            if (*p == ' ' || *p == ',') {
                p++;
                break;
            }
        }

        if (rap_parse_addr_port(r->pool, &paddr, p, xfflen - (p - xff))
            != RAP_OK)
        {
            return found ? RAP_DONE : RAP_DECLINED;
        }

        *addr = paddr;
        found = 1;
        xfflen = p - 1 - xff;

    } while (recursive && p > xff);

    return RAP_OK;
}


static char *
rap_http_core_server(rap_conf_t *cf, rap_command_t *cmd, void *dummy)
{
    char                        *rv;
    void                        *mconf;
    size_t                       len;
    u_char                      *p;
    rap_uint_t                   i;
    rap_conf_t                   pcf;
    rap_http_module_t           *module;
    struct sockaddr_in          *sin;
    rap_http_conf_ctx_t         *ctx, *http_ctx;
    rap_http_listen_opt_t        lsopt;
    rap_http_core_srv_conf_t    *cscf, **cscfp;
    rap_http_core_main_conf_t   *cmcf;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->srv_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->loc_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }


    /* the server configuration context */

    cscf = ctx->srv_conf[rap_http_core_module.ctx_index];
    cscf->ctx = ctx;


    cmcf = ctx->main_conf[rap_http_core_module.ctx_index];

    cscfp = rap_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RAP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_HTTP_SRV_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == RAP_CONF_OK && !cscf->listen) {
        rap_memzero(&lsopt, sizeof(rap_http_listen_opt_t));

        p = rap_pcalloc(cf->pool, sizeof(struct sockaddr_in));
        if (p == NULL) {
            return RAP_CONF_ERROR;
        }

        lsopt.sockaddr = (struct sockaddr *) p;

        sin = (struct sockaddr_in *) p;

        sin->sin_family = AF_INET;
#if (RAP_WIN32)
        sin->sin_port = htons(80);
#else
        sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
#endif
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = RAP_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (RAP_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
#if (RAP_HAVE_TCP_FASTOPEN)
        lsopt.fastopen = -1;
#endif
        lsopt.wildcard = 1;

        len = RAP_INET_ADDRSTRLEN + sizeof(":65535") - 1;

        p = rap_pnalloc(cf->pool, len);
        if (p == NULL) {
            return RAP_CONF_ERROR;
        }

        lsopt.addr_text.data = p;
        lsopt.addr_text.len = rap_sock_ntop(lsopt.sockaddr, lsopt.socklen, p,
                                            len, 1);

        if (rap_http_add_listen(cf, cscf, &lsopt) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return rv;
}


static char *
rap_http_core_location(rap_conf_t *cf, rap_command_t *cmd, void *dummy)
{
    char                      *rv;
    u_char                    *mod;
    size_t                     len;
    rap_str_t                 *value, *name;
    rap_uint_t                 i;
    rap_conf_t                 save;
    rap_http_module_t         *module;
    rap_http_conf_ctx_t       *ctx, *pctx;
    rap_http_core_loc_conf_t  *clcf, *pclcf;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[cf->cycle->modules[i]->ctx_index] == NULL) {
                return RAP_CONF_ERROR;
            }
        }
    }

    clcf = ctx->loc_conf[rap_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;

    value = cf->args->elts;

    if (cf->args->nelts == 3) {

        len = value[1].len;
        mod = value[1].data;
        name = &value[2];

        if (len == 1 && mod[0] == '=') {

            clcf->name = *name;
            clcf->exact_match = 1;

        } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {

            clcf->name = *name;
            clcf->noregex = 1;

        } else if (len == 1 && mod[0] == '~') {

            if (rap_http_core_regex_location(cf, clcf, name, 0) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

        } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {

            if (rap_http_core_regex_location(cf, clcf, name, 1) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

    } else {

        name = &value[1];

        if (name->data[0] == '=') {

            clcf->name.len = name->len - 1;
            clcf->name.data = name->data + 1;
            clcf->exact_match = 1;

        } else if (name->data[0] == '^' && name->data[1] == '~') {

            clcf->name.len = name->len - 2;
            clcf->name.data = name->data + 2;
            clcf->noregex = 1;

        } else if (name->data[0] == '~') {

            name->len--;
            name->data++;

            if (name->data[0] == '*') {

                name->len--;
                name->data++;

                if (rap_http_core_regex_location(cf, clcf, name, 1) != RAP_OK) {
                    return RAP_CONF_ERROR;
                }

            } else {
                if (rap_http_core_regex_location(cf, clcf, name, 0) != RAP_OK) {
                    return RAP_CONF_ERROR;
                }
            }

        } else {

            clcf->name = *name;

            if (name->data[0] == '@') {
                clcf->named = 1;
            }
        }
    }

    pclcf = pctx->loc_conf[rap_http_core_module.ctx_index];

    if (cf->cmd_type == RAP_HTTP_LOC_CONF) {

        /* nested location */

#if 0
        clcf->prev_location = pclcf;
#endif

        if (pclcf->exact_match) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the exact location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RAP_CONF_ERROR;
        }

        if (pclcf->named) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the named location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RAP_CONF_ERROR;
        }

        if (clcf->named) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "named location \"%V\" can be "
                               "on the server level only",
                               &clcf->name);
            return RAP_CONF_ERROR;
        }

        len = pclcf->name.len;

#if (RAP_PCRE)
        if (clcf->regex == NULL
            && rap_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
#else
        if (rap_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
#endif
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "location \"%V\" is outside location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RAP_CONF_ERROR;
        }
    }

    if (rap_http_add_location(cf, &pclcf->locations, clcf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_HTTP_LOC_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static rap_int_t
rap_http_core_regex_location(rap_conf_t *cf, rap_http_core_loc_conf_t *clcf,
    rap_str_t *regex, rap_uint_t caseless)
{
#if (RAP_PCRE)
    rap_regex_compile_t  rc;
    u_char               errstr[RAP_MAX_CONF_ERRSTR];

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (RAP_HAVE_CASELESS_FILESYSTEM)
    rc.options = RAP_REGEX_CASELESS;
#else
    rc.options = caseless ? RAP_REGEX_CASELESS : 0;
#endif

    clcf->regex = rap_http_regex_compile(cf, &rc);
    if (clcf->regex == NULL) {
        return RAP_ERROR;
    }

    clcf->name = *regex;

    return RAP_OK;

#else

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return RAP_ERROR;

#endif
}


static char *
rap_http_core_types(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    char        *rv;
    rap_conf_t   save;

    if (clcf->types == NULL) {
        clcf->types = rap_array_create(cf->pool, 64, sizeof(rap_hash_key_t));
        if (clcf->types == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = rap_http_core_type;
    cf->handler_conf = conf;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
rap_http_core_type(rap_conf_t *cf, rap_command_t *dummy, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t       *value, *content_type, *old;
    rap_uint_t       i, n, hash;
    rap_hash_key_t  *type;

    value = cf->args->elts;

    if (rap_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return RAP_CONF_ERROR;
        }

        return rap_conf_include(cf, dummy, conf);
    }

    content_type = rap_palloc(cf->pool, sizeof(rap_str_t));
    if (content_type == NULL) {
        return RAP_CONF_ERROR;
    }

    *content_type = value[0];

    for (i = 1; i < cf->args->nelts; i++) {

        hash = rap_hash_strlow(value[i].data, value[i].data, value[i].len);

        type = clcf->types->elts;
        for (n = 0; n < clcf->types->nelts; n++) {
            if (rap_strcmp(value[i].data, type[n].key.data) == 0) {
                old = type[n].value;
                type[n].value = content_type;

                rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                                   "duplicate extension \"%V\", "
                                   "content type: \"%V\", "
                                   "previous content type: \"%V\"",
                                   &value[i], content_type, old);
                goto next;
            }
        }


        type = rap_array_push(clcf->types);
        if (type == NULL) {
            return RAP_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = content_type;

    next:
        continue;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_core_preconfiguration(rap_conf_t *cf)
{
    return rap_http_variables_add_core_vars(cf);
}


static rap_int_t
rap_http_core_postconfiguration(rap_conf_t *cf)
{
    rap_http_top_request_body_filter = rap_http_request_body_save_filter;

    return RAP_OK;
}


static void *
rap_http_core_create_main_conf(rap_conf_t *cf)
{
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_pcalloc(cf->pool, sizeof(rap_http_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rap_http_core_srv_conf_t *))
        != RAP_OK)
    {
        return NULL;
    }

    cmcf->server_names_hash_max_size = RAP_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = RAP_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = RAP_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = RAP_CONF_UNSET_UINT;

    return cmcf;
}


static char *
rap_http_core_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_http_core_main_conf_t *cmcf = conf;

    rap_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
    rap_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
                             rap_cacheline_size);

    cmcf->server_names_hash_bucket_size =
            rap_align(cmcf->server_names_hash_bucket_size, rap_cacheline_size);


    rap_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    rap_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               rap_align(cmcf->variables_hash_bucket_size, rap_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return RAP_CONF_OK;
}


static void *
rap_http_core_create_srv_conf(rap_conf_t *cf)
{
    rap_http_core_srv_conf_t  *cscf;

    cscf = rap_pcalloc(cf->pool, sizeof(rap_http_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->client_large_buffers.num = 0;
     */

    if (rap_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(rap_http_server_name_t))
        != RAP_OK)
    {
        return NULL;
    }

    cscf->connection_pool_size = RAP_CONF_UNSET_SIZE;
    cscf->request_pool_size = RAP_CONF_UNSET_SIZE;
    cscf->client_header_timeout = RAP_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = RAP_CONF_UNSET_SIZE;
    cscf->ignore_invalid_headers = RAP_CONF_UNSET;
    cscf->merge_slashes = RAP_CONF_UNSET;
    cscf->underscores_in_headers = RAP_CONF_UNSET;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
rap_http_core_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_core_srv_conf_t *prev = parent;
    rap_http_core_srv_conf_t *conf = child;

    rap_str_t                name;
    rap_http_server_name_t  *sn;

    /* TODO: it does not merge, it inits only */

    rap_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 64 * sizeof(void *));
    rap_conf_merge_size_value(conf->request_pool_size,
                              prev->request_pool_size, 4096);
    rap_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);
    rap_conf_merge_size_value(conf->client_header_buffer_size,
                              prev->client_header_buffer_size, 1024);
    rap_conf_merge_bufs_value(conf->large_client_header_buffers,
                              prev->large_client_header_buffers,
                              4, 8192);

    if (conf->large_client_header_buffers.size < conf->connection_pool_size) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the \"large_client_header_buffers\" size must be "
                           "equal to or greater than \"connection_pool_size\"");
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->ignore_invalid_headers,
                              prev->ignore_invalid_headers, 1);

    rap_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);

    rap_conf_merge_value(conf->underscores_in_headers,
                              prev->underscores_in_headers, 0);

    if (conf->server_names.nelts == 0) {
        /* the array has 4 empty preallocated elements, so push cannot fail */
        sn = rap_array_push(&conf->server_names);
#if (RAP_PCRE)
        sn->regex = NULL;
#endif
        sn->server = conf;
        rap_str_set(&sn->name, "");
    }

    sn = conf->server_names.elts;
    name = sn[0].name;

#if (RAP_PCRE)
    if (sn->regex) {
        name.len++;
        name.data--;
    } else
#endif

    if (name.data[0] == '.') {
        name.len--;
        name.data++;
    }

    conf->server_name.len = name.len;
    conf->server_name.data = rap_pstrdup(cf->pool, &name);
    if (conf->server_name.data == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static void *
rap_http_core_create_loc_conf(rap_conf_t *cf)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_pcalloc(cf->pool, sizeof(rap_http_core_loc_conf_t));
    if (clcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     clcf->root = { 0, NULL };
     *     clcf->limit_except = 0;
     *     clcf->post_action = { 0, NULL };
     *     clcf->types = NULL;
     *     clcf->default_type = { 0, NULL };
     *     clcf->error_log = NULL;
     *     clcf->error_pages = NULL;
     *     clcf->client_body_path = NULL;
     *     clcf->regex = NULL;
     *     clcf->exact_match = 0;
     *     clcf->auto_redirect = 0;
     *     clcf->alias = 0;
     *     clcf->limit_rate = NULL;
     *     clcf->limit_rate_after = NULL;
     *     clcf->gzip_proxied = 0;
     *     clcf->keepalive_disable = 0;
     */

    clcf->client_max_body_size = RAP_CONF_UNSET;
    clcf->client_body_buffer_size = RAP_CONF_UNSET_SIZE;
    clcf->client_body_timeout = RAP_CONF_UNSET_MSEC;
    clcf->satisfy = RAP_CONF_UNSET_UINT;
    clcf->auth_delay = RAP_CONF_UNSET_MSEC;
    clcf->if_modified_since = RAP_CONF_UNSET_UINT;
    clcf->max_ranges = RAP_CONF_UNSET_UINT;
    clcf->client_body_in_file_only = RAP_CONF_UNSET_UINT;
    clcf->client_body_in_single_buffer = RAP_CONF_UNSET;
    clcf->internal = RAP_CONF_UNSET;
    clcf->sendfile = RAP_CONF_UNSET;
    clcf->sendfile_max_chunk = RAP_CONF_UNSET_SIZE;
    clcf->subrequest_output_buffer_size = RAP_CONF_UNSET_SIZE;
    clcf->aio = RAP_CONF_UNSET;
    clcf->aio_write = RAP_CONF_UNSET;
#if (RAP_THREADS)
    clcf->thread_pool = RAP_CONF_UNSET_PTR;
    clcf->thread_pool_value = RAP_CONF_UNSET_PTR;
#endif
    clcf->read_ahead = RAP_CONF_UNSET_SIZE;
    clcf->directio = RAP_CONF_UNSET;
    clcf->directio_alignment = RAP_CONF_UNSET;
    clcf->tcp_nopush = RAP_CONF_UNSET;
    clcf->tcp_nodelay = RAP_CONF_UNSET;
    clcf->send_timeout = RAP_CONF_UNSET_MSEC;
    clcf->send_lowat = RAP_CONF_UNSET_SIZE;
    clcf->postpone_output = RAP_CONF_UNSET_SIZE;
    clcf->keepalive_timeout = RAP_CONF_UNSET_MSEC;
    clcf->keepalive_header = RAP_CONF_UNSET;
    clcf->keepalive_requests = RAP_CONF_UNSET_UINT;
    clcf->lingering_close = RAP_CONF_UNSET_UINT;
    clcf->lingering_time = RAP_CONF_UNSET_MSEC;
    clcf->lingering_timeout = RAP_CONF_UNSET_MSEC;
    clcf->resolver_timeout = RAP_CONF_UNSET_MSEC;
    clcf->reset_timedout_connection = RAP_CONF_UNSET;
    clcf->absolute_redirect = RAP_CONF_UNSET;
    clcf->server_name_in_redirect = RAP_CONF_UNSET;
    clcf->port_in_redirect = RAP_CONF_UNSET;
    clcf->msie_padding = RAP_CONF_UNSET;
    clcf->msie_refresh = RAP_CONF_UNSET;
    clcf->log_not_found = RAP_CONF_UNSET;
    clcf->log_subrequest = RAP_CONF_UNSET;
    clcf->recursive_error_pages = RAP_CONF_UNSET;
    clcf->chunked_transfer_encoding = RAP_CONF_UNSET;
    clcf->etag = RAP_CONF_UNSET;
    clcf->server_tokens = RAP_CONF_UNSET_UINT;
    clcf->types_hash_max_size = RAP_CONF_UNSET_UINT;
    clcf->types_hash_bucket_size = RAP_CONF_UNSET_UINT;

    clcf->open_file_cache = RAP_CONF_UNSET_PTR;
    clcf->open_file_cache_valid = RAP_CONF_UNSET;
    clcf->open_file_cache_min_uses = RAP_CONF_UNSET_UINT;
    clcf->open_file_cache_errors = RAP_CONF_UNSET;
    clcf->open_file_cache_events = RAP_CONF_UNSET;

#if (RAP_HTTP_GZIP)
    clcf->gzip_vary = RAP_CONF_UNSET;
    clcf->gzip_http_version = RAP_CONF_UNSET_UINT;
#if (RAP_PCRE)
    clcf->gzip_disable = RAP_CONF_UNSET_PTR;
#endif
    clcf->gzip_disable_msie6 = 3;
#if (RAP_HTTP_DEGRADATION)
    clcf->gzip_disable_degradation = 3;
#endif
#endif

#if (RAP_HAVE_OPENAT)
    clcf->disable_symlinks = RAP_CONF_UNSET_UINT;
    clcf->disable_symlinks_from = RAP_CONF_UNSET_PTR;
#endif

    return clcf;
}


static rap_str_t  rap_http_core_text_html_type = rap_string("text/html");
static rap_str_t  rap_http_core_image_gif_type = rap_string("image/gif");
static rap_str_t  rap_http_core_image_jpeg_type = rap_string("image/jpeg");

static rap_hash_key_t  rap_http_core_default_types[] = {
    { rap_string("html"), 0, &rap_http_core_text_html_type },
    { rap_string("gif"), 0, &rap_http_core_image_gif_type },
    { rap_string("jpg"), 0, &rap_http_core_image_jpeg_type },
    { rap_null_string, 0, NULL }
};


static char *
rap_http_core_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_core_loc_conf_t *prev = parent;
    rap_http_core_loc_conf_t *conf = child;

    rap_uint_t        i;
    rap_hash_key_t   *type;
    rap_hash_init_t   types_hash;

    if (conf->root.data == NULL) {

        conf->alias = prev->alias;
        conf->root = prev->root;
        conf->root_lengths = prev->root_lengths;
        conf->root_values = prev->root_values;

        if (prev->root.data == NULL) {
            rap_str_set(&conf->root, "html");

            if (rap_conf_full_name(cf->cycle, &conf->root, 0) != RAP_OK) {
                return RAP_CONF_ERROR;
            }
        }
    }

    if (conf->post_action.data == NULL) {
        conf->post_action = prev->post_action;
    }

    rap_conf_merge_uint_value(conf->types_hash_max_size,
                              prev->types_hash_max_size, 1024);

    rap_conf_merge_uint_value(conf->types_hash_bucket_size,
                              prev->types_hash_bucket_size, 64);

    conf->types_hash_bucket_size = rap_align(conf->types_hash_bucket_size,
                                             rap_cacheline_size);

    /*
     * the special handling of the "types" directive in the "http" section
     * to inherit the http's conf->types_hash to all servers
     */

    if (prev->types && prev->types_hash.buckets == NULL) {

        types_hash.hash = &prev->types_hash;
        types_hash.key = rap_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (rap_hash_init(&types_hash, prev->types->elts, prev->types->nelts)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    if (conf->types == NULL) {
        conf->types = prev->types;
        conf->types_hash = prev->types_hash;
    }

    if (conf->types == NULL) {
        conf->types = rap_array_create(cf->pool, 3, sizeof(rap_hash_key_t));
        if (conf->types == NULL) {
            return RAP_CONF_ERROR;
        }

        for (i = 0; rap_http_core_default_types[i].key.len; i++) {
            type = rap_array_push(conf->types);
            if (type == NULL) {
                return RAP_CONF_ERROR;
            }

            type->key = rap_http_core_default_types[i].key;
            type->key_hash =
                       rap_hash_key_lc(rap_http_core_default_types[i].key.data,
                                       rap_http_core_default_types[i].key.len);
            type->value = rap_http_core_default_types[i].value;
        }
    }

    if (conf->types_hash.buckets == NULL) {

        types_hash.hash = &conf->types_hash;
        types_hash.key = rap_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (rap_hash_init(&types_hash, conf->types->elts, conf->types->nelts)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    if (conf->error_pages == NULL && prev->error_pages) {
        conf->error_pages = prev->error_pages;
    }

    rap_conf_merge_str_value(conf->default_type,
                              prev->default_type, "text/plain");

    rap_conf_merge_off_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1 * 1024 * 1024);
    rap_conf_merge_size_value(conf->client_body_buffer_size,
                              prev->client_body_buffer_size,
                              (size_t) 2 * rap_pagesize);
    rap_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 60000);

    rap_conf_merge_bitmask_value(conf->keepalive_disable,
                              prev->keepalive_disable,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_KEEPALIVE_DISABLE_MSIE6));
    rap_conf_merge_uint_value(conf->satisfy, prev->satisfy,
                              RAP_HTTP_SATISFY_ALL);
    rap_conf_merge_msec_value(conf->auth_delay, prev->auth_delay, 0);
    rap_conf_merge_uint_value(conf->if_modified_since, prev->if_modified_since,
                              RAP_HTTP_IMS_EXACT);
    rap_conf_merge_uint_value(conf->max_ranges, prev->max_ranges,
                              RAP_MAX_INT32_VALUE);
    rap_conf_merge_uint_value(conf->client_body_in_file_only,
                              prev->client_body_in_file_only,
                              RAP_HTTP_REQUEST_BODY_FILE_OFF);
    rap_conf_merge_value(conf->client_body_in_single_buffer,
                              prev->client_body_in_single_buffer, 0);
    rap_conf_merge_value(conf->internal, prev->internal, 0);
    rap_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    rap_conf_merge_size_value(conf->sendfile_max_chunk,
                              prev->sendfile_max_chunk, 0);
    rap_conf_merge_size_value(conf->subrequest_output_buffer_size,
                              prev->subrequest_output_buffer_size,
                              (size_t) rap_pagesize);
    rap_conf_merge_value(conf->aio, prev->aio, RAP_HTTP_AIO_OFF);
    rap_conf_merge_value(conf->aio_write, prev->aio_write, 0);
#if (RAP_THREADS)
    rap_conf_merge_ptr_value(conf->thread_pool, prev->thread_pool, NULL);
    rap_conf_merge_ptr_value(conf->thread_pool_value, prev->thread_pool_value,
                             NULL);
#endif
    rap_conf_merge_size_value(conf->read_ahead, prev->read_ahead, 0);
    rap_conf_merge_off_value(conf->directio, prev->directio,
                              RAP_OPEN_FILE_DIRECTIO_OFF);
    rap_conf_merge_off_value(conf->directio_alignment, prev->directio_alignment,
                              512);
    rap_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    rap_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    rap_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    rap_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
    rap_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);

    if (conf->limit_rate == NULL) {
        conf->limit_rate = prev->limit_rate;
    }

    if (conf->limit_rate_after == NULL) {
        conf->limit_rate_after = prev->limit_rate_after;
    }

    rap_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);
    rap_conf_merge_sec_value(conf->keepalive_header,
                              prev->keepalive_header, 0);
    rap_conf_merge_uint_value(conf->keepalive_requests,
                              prev->keepalive_requests, 100);
    rap_conf_merge_uint_value(conf->lingering_close,
                              prev->lingering_close, RAP_HTTP_LINGERING_ON);
    rap_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    rap_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);
    rap_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in http {} context
             * to inherit it in all servers
             */

            prev->resolver = rap_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return RAP_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (rap_conf_merge_path_value(cf, &conf->client_body_temp_path,
                              prev->client_body_temp_path,
                              &rap_http_client_temp_path)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->reset_timedout_connection,
                              prev->reset_timedout_connection, 0);
    rap_conf_merge_value(conf->absolute_redirect,
                              prev->absolute_redirect, 1);
    rap_conf_merge_value(conf->server_name_in_redirect,
                              prev->server_name_in_redirect, 0);
    rap_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 1);
    rap_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);
    rap_conf_merge_value(conf->msie_refresh, prev->msie_refresh, 0);
    rap_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);
    rap_conf_merge_value(conf->log_subrequest, prev->log_subrequest, 0);
    rap_conf_merge_value(conf->recursive_error_pages,
                              prev->recursive_error_pages, 0);
    rap_conf_merge_value(conf->chunked_transfer_encoding,
                              prev->chunked_transfer_encoding, 1);
    rap_conf_merge_value(conf->etag, prev->etag, 1);

    rap_conf_merge_uint_value(conf->server_tokens, prev->server_tokens,
                              RAP_HTTP_SERVER_TOKENS_ON);

    rap_conf_merge_ptr_value(conf->open_file_cache,
                              prev->open_file_cache, NULL);

    rap_conf_merge_sec_value(conf->open_file_cache_valid,
                              prev->open_file_cache_valid, 60);

    rap_conf_merge_uint_value(conf->open_file_cache_min_uses,
                              prev->open_file_cache_min_uses, 1);

    rap_conf_merge_sec_value(conf->open_file_cache_errors,
                              prev->open_file_cache_errors, 0);

    rap_conf_merge_sec_value(conf->open_file_cache_events,
                              prev->open_file_cache_events, 0);
#if (RAP_HTTP_GZIP)

    rap_conf_merge_value(conf->gzip_vary, prev->gzip_vary, 0);
    rap_conf_merge_uint_value(conf->gzip_http_version, prev->gzip_http_version,
                              RAP_HTTP_VERSION_11);
    rap_conf_merge_bitmask_value(conf->gzip_proxied, prev->gzip_proxied,
                              (RAP_CONF_BITMASK_SET|RAP_HTTP_GZIP_PROXIED_OFF));

#if (RAP_PCRE)
    rap_conf_merge_ptr_value(conf->gzip_disable, prev->gzip_disable, NULL);
#endif

    if (conf->gzip_disable_msie6 == 3) {
        conf->gzip_disable_msie6 =
            (prev->gzip_disable_msie6 == 3) ? 0 : prev->gzip_disable_msie6;
    }

#if (RAP_HTTP_DEGRADATION)

    if (conf->gzip_disable_degradation == 3) {
        conf->gzip_disable_degradation =
            (prev->gzip_disable_degradation == 3) ?
                 0 : prev->gzip_disable_degradation;
    }

#endif
#endif

#if (RAP_HAVE_OPENAT)
    rap_conf_merge_uint_value(conf->disable_symlinks, prev->disable_symlinks,
                              RAP_DISABLE_SYMLINKS_OFF);
    rap_conf_merge_ptr_value(conf->disable_symlinks_from,
                             prev->disable_symlinks_from, NULL);
#endif

    return RAP_CONF_OK;
}


static char *
rap_http_core_listen(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_srv_conf_t *cscf = conf;

    rap_str_t              *value, size;
    rap_url_t               u;
    rap_uint_t              n;
    rap_http_listen_opt_t   lsopt;

    cscf->listen = 1;

    value = cf->args->elts;

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 80;

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return RAP_CONF_ERROR;
    }

    rap_memzero(&lsopt, sizeof(rap_http_listen_opt_t));

    lsopt.backlog = RAP_LISTEN_BACKLOG;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (RAP_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
#if (RAP_HAVE_TCP_FASTOPEN)
    lsopt.fastopen = -1;
#endif
#if (RAP_HAVE_INET6)
    lsopt.ipv6only = 1;
#endif

    for (n = 2; n < cf->args->nelts; n++) {

        if (rap_strcmp(value[n].data, "default_server") == 0
            || rap_strcmp(value[n].data, "default") == 0)
        {
            lsopt.default_server = 1;
            continue;
        }

        if (rap_strcmp(value[n].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

#if (RAP_HAVE_SETFIB)
        if (rap_strncmp(value[n].data, "setfib=", 7) == 0) {
            lsopt.setfib = rap_atoi(value[n].data + 7, value[n].len - 7);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.setfib == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[n]);
                return RAP_CONF_ERROR;
            }

            continue;
        }
#endif

#if (RAP_HAVE_TCP_FASTOPEN)
        if (rap_strncmp(value[n].data, "fastopen=", 9) == 0) {
            lsopt.fastopen = rap_atoi(value[n].data + 9, value[n].len - 9);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.fastopen == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[n]);
                return RAP_CONF_ERROR;
            }

            continue;
        }
#endif

        if (rap_strncmp(value[n].data, "backlog=", 8) == 0) {
            lsopt.backlog = rap_atoi(value[n].data + 8, value[n].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == RAP_ERROR || lsopt.backlog == 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.rcvbuf = rap_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.sndbuf = rap_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[n].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (rap_strcmp(value[n].data, "deferred") == 0) {
#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rap_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
#if (RAP_HAVE_INET6 && defined IPV6_V6ONLY)
            if (rap_strcmp(&value[n].data[10], "n") == 0) {
                lsopt.ipv6only = 1;

            } else if (rap_strcmp(&value[n].data[10], "ff") == 0) {
                lsopt.ipv6only = 0;

            } else {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[n].data[9]);
                return RAP_CONF_ERROR;
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strcmp(value[n].data, "reuseport") == 0) {
#if (RAP_HAVE_REUSEPORT)
            lsopt.reuseport = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rap_strcmp(value[n].data, "ssl") == 0) {
#if (RAP_HTTP_SSL)
            lsopt.ssl = 1;
            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rap_http_ssl_module");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strcmp(value[n].data, "http2") == 0) {
#if (RAP_HTTP_V2)
            lsopt.http2 = 1;
            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the \"http2\" parameter requires "
                               "rap_http_v2_module");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strcmp(value[n].data, "spdy") == 0) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "invalid parameter \"spdy\": "
                               "rap_http_spdy_module was superseded "
                               "by rap_http_v2_module");
            continue;
        }

        if (rap_strncmp(value[n].data, "so_keepalive=", 13) == 0) {

            if (rap_strcmp(&value[n].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (rap_strcmp(&value[n].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (RAP_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                rap_str_t   s;

                end = value[n].data + value[n].len;
                s.data = value[n].data + 13;

                p = rap_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = rap_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) RAP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = rap_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = rap_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) RAP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = rap_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == RAP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
                    && lsopt.tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt.so_keepalive = 1;

#else

                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return RAP_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (RAP_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[n].data[13]);
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strcmp(value[n].data, "proxy_protocol") == 0) {
            lsopt.proxy_protocol = 1;
            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[n]);
        return RAP_CONF_ERROR;
    }

    for (n = 0; n < u.naddrs; n++) {
        lsopt.sockaddr = u.addrs[n].sockaddr;
        lsopt.socklen = u.addrs[n].socklen;
        lsopt.addr_text = u.addrs[n].name;
        lsopt.wildcard = rap_inet_wildcard(lsopt.sockaddr);

        if (rap_http_add_listen(cf, cscf, &lsopt) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_http_core_server_name(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    rap_str_t               *value;
    rap_uint_t               i;
    rap_http_server_name_t  *sn;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return RAP_CONF_ERROR;
        }

        if (rap_strchr(value[i].data, '/')) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }

        sn = rap_array_push(&cscf->server_names);
        if (sn == NULL) {
            return RAP_CONF_ERROR;
        }

#if (RAP_PCRE)
        sn->regex = NULL;
#endif
        sn->server = cscf;

        if (rap_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;

        } else {
            sn->name = value[i];
        }

        if (value[i].data[0] != '~') {
            rap_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

#if (RAP_PCRE)
        {
        u_char               *p;
        rap_regex_compile_t   rc;
        u_char                errstr[RAP_MAX_CONF_ERRSTR];

        if (value[i].len == 1) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "empty regex in server name \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        rap_memzero(&rc, sizeof(rap_regex_compile_t));

        rc.pattern = value[i];
        rc.err.len = RAP_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        for (p = value[i].data; p < value[i].data + value[i].len; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                rc.options = RAP_REGEX_CASELESS;
                break;
            }
        }

        sn->regex = rap_http_regex_compile(cf, &rc);
        if (sn->regex == NULL) {
            return RAP_CONF_ERROR;
        }

        sn->name = value[i];
        cscf->captures = (rc.captures > 0);
        }
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return RAP_CONF_ERROR;
#endif
    }

    return RAP_CONF_OK;
}


static char *
rap_http_core_root(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t                  *value;
    rap_int_t                   alias;
    rap_uint_t                  n;
    rap_http_script_compile_t   sc;

    alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;

    if (clcf->root.data) {

        if ((clcf->alias != 0) == alias) {
            return "is duplicate";
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" directive is duplicate, "
                           "\"%s\" directive was specified earlier",
                           &cmd->name, clcf->alias ? "alias" : "root");

        return RAP_CONF_ERROR;
    }

    if (clcf->named && alias) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the \"alias\" directive cannot be used "
                           "inside the named location");

        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    if (rap_strstr(value[1].data, "$document_root")
        || rap_strstr(value[1].data, "${document_root}"))
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the $document_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return RAP_CONF_ERROR;
    }

    if (rap_strstr(value[1].data, "$realpath_root")
        || rap_strstr(value[1].data, "${realpath_root}"))
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the $realpath_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return RAP_CONF_ERROR;
    }

    clcf->alias = alias ? clcf->name.len : 0;
    clcf->root = value[1];

    if (!alias && clcf->root.len > 0
        && clcf->root.data[clcf->root.len - 1] == '/')
    {
        clcf->root.len--;
    }

    if (clcf->root.data[0] != '$') {
        if (rap_conf_full_name(cf->cycle, &clcf->root, 0) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    n = rap_http_script_variables_count(&clcf->root);

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));
    sc.variables = n;

#if (RAP_PCRE)
    if (alias && clcf->regex) {
        clcf->alias = RAP_MAX_SIZE_T_VALUE;
        n = 1;
    }
#endif

    if (n) {
        sc.cf = cf;
        sc.source = &clcf->root;
        sc.lengths = &clcf->root_lengths;
        sc.values = &clcf->root_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static rap_http_method_name_t  rap_methods_names[] = {
    { (u_char *) "GET",       (uint32_t) ~RAP_HTTP_GET },
    { (u_char *) "HEAD",      (uint32_t) ~RAP_HTTP_HEAD },
    { (u_char *) "POST",      (uint32_t) ~RAP_HTTP_POST },
    { (u_char *) "PUT",       (uint32_t) ~RAP_HTTP_PUT },
    { (u_char *) "DELETE",    (uint32_t) ~RAP_HTTP_DELETE },
    { (u_char *) "MKCOL",     (uint32_t) ~RAP_HTTP_MKCOL },
    { (u_char *) "COPY",      (uint32_t) ~RAP_HTTP_COPY },
    { (u_char *) "MOVE",      (uint32_t) ~RAP_HTTP_MOVE },
    { (u_char *) "OPTIONS",   (uint32_t) ~RAP_HTTP_OPTIONS },
    { (u_char *) "PROPFIND",  (uint32_t) ~RAP_HTTP_PROPFIND },
    { (u_char *) "PROPPATCH", (uint32_t) ~RAP_HTTP_PROPPATCH },
    { (u_char *) "LOCK",      (uint32_t) ~RAP_HTTP_LOCK },
    { (u_char *) "UNLOCK",    (uint32_t) ~RAP_HTTP_UNLOCK },
    { (u_char *) "PATCH",     (uint32_t) ~RAP_HTTP_PATCH },
    { NULL, 0 }
};


static char *
rap_http_core_limit_except(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *pclcf = conf;

    char                      *rv;
    void                      *mconf;
    rap_str_t                 *value;
    rap_uint_t                 i;
    rap_conf_t                 save;
    rap_http_module_t         *module;
    rap_http_conf_ctx_t       *ctx, *pctx;
    rap_http_method_name_t    *name;
    rap_http_core_loc_conf_t  *clcf;

    if (pclcf->limit_except) {
        return "is duplicate";
    }

    pclcf->limit_except = 0xffffffff;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        for (name = rap_methods_names; name->name; name++) {

            if (rap_strcasecmp(value[i].data, name->name) == 0) {
                pclcf->limit_except &= name->method;
                goto next;
            }
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid method \"%V\"", &value[i]);
        return RAP_CONF_ERROR;

    next:
        continue;
    }

    if (!(pclcf->limit_except & RAP_HTTP_GET)) {
        pclcf->limit_except &= (uint32_t) ~RAP_HTTP_HEAD;
    }

    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }


    clcf = ctx->loc_conf[rap_http_core_module.ctx_index];
    pclcf->limit_except_loc_conf = ctx->loc_conf;
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;
    clcf->lmt_excpt = 1;

    if (rap_http_add_location(cf, &pclcf->locations, clcf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_HTTP_LMT_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
rap_http_core_set_aio(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t  *value;

    if (clcf->aio != RAP_CONF_UNSET) {
        return "is duplicate";
    }

#if (RAP_THREADS)
    clcf->thread_pool = NULL;
    clcf->thread_pool_value = NULL;
#endif

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        clcf->aio = RAP_HTTP_AIO_OFF;
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[1].data, "on") == 0) {
#if (RAP_HAVE_FILE_AIO)
        clcf->aio = RAP_HTTP_AIO_ON;
        return RAP_CONF_OK;
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"aio on\" "
                           "is unsupported on this platform");
        return RAP_CONF_ERROR;
#endif
    }

#if (RAP_HAVE_AIO_SENDFILE)

    if (rap_strcmp(value[1].data, "sendfile") == 0) {
        clcf->aio = RAP_HTTP_AIO_ON;

        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "the \"sendfile\" parameter of "
                           "the \"aio\" directive is deprecated");
        return RAP_CONF_OK;
    }

#endif

    if (rap_strncmp(value[1].data, "threads", 7) == 0
        && (value[1].len == 7 || value[1].data[7] == '='))
    {
#if (RAP_THREADS)
        rap_str_t                          name;
        rap_thread_pool_t                 *tp;
        rap_http_complex_value_t           cv;
        rap_http_compile_complex_value_t   ccv;

        clcf->aio = RAP_HTTP_AIO_THREADS;

        if (value[1].len >= 8) {
            name.len = value[1].len - 8;
            name.data = value[1].data + 8;

            rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &name;
            ccv.complex_value = &cv;

            if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

            if (cv.lengths != NULL) {
                clcf->thread_pool_value = rap_palloc(cf->pool,
                                    sizeof(rap_http_complex_value_t));
                if (clcf->thread_pool_value == NULL) {
                    return RAP_CONF_ERROR;
                }

                *clcf->thread_pool_value = cv;

                return RAP_CONF_OK;
            }

            tp = rap_thread_pool_add(cf, &name);

        } else {
            tp = rap_thread_pool_add(cf, NULL);
        }

        if (tp == NULL) {
            return RAP_CONF_ERROR;
        }

        clcf->thread_pool = tp;

        return RAP_CONF_OK;
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"aio threads\" "
                           "is unsupported on this platform");
        return RAP_CONF_ERROR;
#endif
    }

    return "invalid value";
}


static char *
rap_http_core_directio(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t  *value;

    if (clcf->directio != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        clcf->directio = RAP_OPEN_FILE_DIRECTIO_OFF;
        return RAP_CONF_OK;
    }

    clcf->directio = rap_parse_offset(&value[1]);
    if (clcf->directio == (off_t) RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


static char *
rap_http_core_error_page(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    u_char                            *p;
    rap_int_t                          overwrite;
    rap_str_t                         *value, uri, args;
    rap_uint_t                         i, n;
    rap_http_err_page_t               *err;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    if (clcf->error_pages == NULL) {
        clcf->error_pages = rap_array_create(cf->pool, 4,
                                             sizeof(rap_http_err_page_t));
        if (clcf->error_pages == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    i = cf->args->nelts - 2;

    if (value[i].data[0] == '=') {
        if (i == 1) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }

        if (value[i].len > 1) {
            overwrite = rap_atoi(&value[i].data[1], value[i].len - 1);

            if (overwrite == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

        } else {
            overwrite = 0;
        }

        n = 2;

    } else {
        overwrite = -1;
        n = 1;
    }

    uri = value[cf->args->nelts - 1];

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &uri;
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    rap_str_null(&args);

    if (cv.lengths == NULL && uri.len && uri.data[0] == '/') {
        p = (u_char *) rap_strchr(uri.data, '?');

        if (p) {
            cv.value.len = p - uri.data;
            cv.value.data = uri.data;
            p++;
            args.len = (uri.data + uri.len) - p;
            args.data = p;
        }
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        err = rap_array_push(clcf->error_pages);
        if (err == NULL) {
            return RAP_CONF_ERROR;
        }

        err->status = rap_atoi(value[i].data, value[i].len);

        if (err->status == RAP_ERROR || err->status == 499) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }

        if (err->status < 300 || err->status > 599) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "value \"%V\" must be between 300 and 599",
                               &value[i]);
            return RAP_CONF_ERROR;
        }

        err->overwrite = overwrite;

        if (overwrite == -1) {
            switch (err->status) {
                case RAP_HTTP_TO_HTTPS:
                case RAP_HTTPS_CERT_ERROR:
                case RAP_HTTPS_NO_CERT:
                case RAP_HTTP_REQUEST_HEADER_TOO_LARGE:
                    err->overwrite = RAP_HTTP_BAD_REQUEST;
            }
        }

        err->value = cv;
        err->args = args;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_core_open_file_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    time_t       inactive;
    rap_str_t   *value, s;
    rap_int_t    max;
    rap_uint_t   i;

    if (clcf->open_file_cache != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "max=", 4) == 0) {

            max = rap_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rap_parse_time(&s, 1);
            if (inactive == (time_t) RAP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rap_strcmp(value[i].data, "off") == 0) {

            clcf->open_file_cache = NULL;

            continue;
        }

    failed:

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid \"open_file_cache\" parameter \"%V\"",
                           &value[i]);
        return RAP_CONF_ERROR;
    }

    if (clcf->open_file_cache == NULL) {
        return RAP_CONF_OK;
    }

    if (max == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                        "\"open_file_cache\" must have the \"max\" parameter");
        return RAP_CONF_ERROR;
    }

    clcf->open_file_cache = rap_open_file_cache_init(cf->pool, max, inactive);
    if (clcf->open_file_cache) {
        return RAP_CONF_OK;
    }

    return RAP_CONF_ERROR;
}


static char *
rap_http_core_error_log(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    return rap_log_set_log(cf, &clcf->error_log);
}


static char *
rap_http_core_keepalive(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t  *value;

    if (clcf->keepalive_timeout != RAP_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->keepalive_timeout = rap_parse_time(&value[1], 0);

    if (clcf->keepalive_timeout == (rap_msec_t) RAP_ERROR) {
        return "invalid value";
    }

    if (cf->args->nelts == 2) {
        return RAP_CONF_OK;
    }

    clcf->keepalive_header = rap_parse_time(&value[2], 1);

    if (clcf->keepalive_header == (time_t) RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


static char *
rap_http_core_internal(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    if (clcf->internal != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    clcf->internal = 1;

    return RAP_CONF_OK;
}


static char *
rap_http_core_resolver(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t  *clcf = conf;

    rap_str_t  *value;

    if (clcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->resolver = rap_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (clcf->resolver == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


#if (RAP_HTTP_GZIP)

static char *
rap_http_gzip_disable(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t  *clcf = conf;

#if (RAP_PCRE)

    rap_str_t            *value;
    rap_uint_t            i;
    rap_regex_elt_t      *re;
    rap_regex_compile_t   rc;
    u_char                errstr[RAP_MAX_CONF_ERRSTR];

    if (clcf->gzip_disable == RAP_CONF_UNSET_PTR) {
        clcf->gzip_disable = rap_array_create(cf->pool, 2,
                                              sizeof(rap_regex_elt_t));
        if (clcf->gzip_disable == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pool = cf->pool;
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (RAP_HTTP_DEGRADATION)

        if (rap_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        re = rap_array_push(clcf->gzip_disable);
        if (re == NULL) {
            return RAP_CONF_ERROR;
        }

        rc.pattern = value[i];
        rc.options = RAP_REGEX_CASELESS;

        if (rap_regex_compile(&rc) != RAP_OK) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%V", &rc.err);
            return RAP_CONF_ERROR;
        }

        re->regex = rc.regex;
        re->name = value[i].data;
    }

    return RAP_CONF_OK;

#else
    rap_str_t   *value;
    rap_uint_t   i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (rap_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (RAP_HTTP_DEGRADATION)

        if (rap_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "without PCRE library \"gzip_disable\" supports "
                           "builtin \"msie6\" and \"degradation\" mask only");

        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;

#endif
}

#endif


#if (RAP_HAVE_OPENAT)

static char *
rap_http_disable_symlinks(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t *clcf = conf;

    rap_str_t                         *value;
    rap_uint_t                         i;
    rap_http_compile_complex_value_t   ccv;

    if (clcf->disable_symlinks != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strcmp(value[i].data, "off") == 0) {
            clcf->disable_symlinks = RAP_DISABLE_SYMLINKS_OFF;
            continue;
        }

        if (rap_strcmp(value[i].data, "if_not_owner") == 0) {
            clcf->disable_symlinks = RAP_DISABLE_SYMLINKS_NOTOWNER;
            continue;
        }

        if (rap_strcmp(value[i].data, "on") == 0) {
            clcf->disable_symlinks = RAP_DISABLE_SYMLINKS_ON;
            continue;
        }

        if (rap_strncmp(value[i].data, "from=", 5) == 0) {
            value[i].len -= 5;
            value[i].data += 5;

            rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = rap_palloc(cf->pool,
                                           sizeof(rap_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return RAP_CONF_ERROR;
            }

            if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

            clcf->disable_symlinks_from = ccv.complex_value;

            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (clcf->disable_symlinks == RAP_CONF_UNSET_UINT) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"off\", \"on\" "
                           "or \"if_not_owner\" parameter",
                           &cmd->name);
        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        clcf->disable_symlinks_from = NULL;
        return RAP_CONF_OK;
    }

    if (clcf->disable_symlinks_from == RAP_CONF_UNSET_PTR) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "duplicate parameters \"%V %V\"",
                           &value[1], &value[2]);
        return RAP_CONF_ERROR;
    }

    if (clcf->disable_symlinks == RAP_DISABLE_SYMLINKS_OFF) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"from=\" cannot be used with \"off\" parameter");
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}

#endif


static char *
rap_http_core_lowat_check(rap_conf_t *cf, void *post, void *data)
{
#if (RAP_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= rap_freebsd_net_inet_tcp_sendspace) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           rap_freebsd_net_inet_tcp_sendspace);

        return RAP_CONF_ERROR;
    }

#elif !(RAP_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return RAP_CONF_OK;
}


static char *
rap_http_core_pool_size(rap_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < RAP_MIN_POOL_SIZE) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           RAP_MIN_POOL_SIZE);
        return RAP_CONF_ERROR;
    }

    if (*sp % RAP_POOL_ALIGNMENT) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           RAP_POOL_ALIGNMENT);
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
