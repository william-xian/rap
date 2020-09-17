
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    u_char    *name;
    uint32_t   method;
} rp_http_method_name_t;


#define RP_HTTP_REQUEST_BODY_FILE_OFF    0
#define RP_HTTP_REQUEST_BODY_FILE_ON     1
#define RP_HTTP_REQUEST_BODY_FILE_CLEAN  2


static rp_int_t rp_http_core_auth_delay(rp_http_request_t *r);
static void rp_http_core_auth_delay_handler(rp_http_request_t *r);

static rp_int_t rp_http_core_find_location(rp_http_request_t *r);
static rp_int_t rp_http_core_find_static_location(rp_http_request_t *r,
    rp_http_location_tree_node_t *node);

static rp_int_t rp_http_core_preconfiguration(rp_conf_t *cf);
static rp_int_t rp_http_core_postconfiguration(rp_conf_t *cf);
static void *rp_http_core_create_main_conf(rp_conf_t *cf);
static char *rp_http_core_init_main_conf(rp_conf_t *cf, void *conf);
static void *rp_http_core_create_srv_conf(rp_conf_t *cf);
static char *rp_http_core_merge_srv_conf(rp_conf_t *cf,
    void *parent, void *child);
static void *rp_http_core_create_loc_conf(rp_conf_t *cf);
static char *rp_http_core_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);

static char *rp_http_core_server(rp_conf_t *cf, rp_command_t *cmd,
    void *dummy);
static char *rp_http_core_location(rp_conf_t *cf, rp_command_t *cmd,
    void *dummy);
static rp_int_t rp_http_core_regex_location(rp_conf_t *cf,
    rp_http_core_loc_conf_t *clcf, rp_str_t *regex, rp_uint_t caseless);

static char *rp_http_core_types(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_type(rp_conf_t *cf, rp_command_t *dummy,
    void *conf);

static char *rp_http_core_listen(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_server_name(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_root(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_http_core_limit_except(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_set_aio(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_directio(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_error_page(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_open_file_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_error_log(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_keepalive(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_internal(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_core_resolver(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
#if (RP_HTTP_GZIP)
static rp_int_t rp_http_gzip_accept_encoding(rp_str_t *ae);
static rp_uint_t rp_http_gzip_quantity(u_char *p, u_char *last);
static char *rp_http_gzip_disable(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
#endif
static rp_int_t rp_http_get_forwarded_addr_internal(rp_http_request_t *r,
    rp_addr_t *addr, u_char *xff, size_t xfflen, rp_array_t *proxies,
    int recursive);
#if (RP_HAVE_OPENAT)
static char *rp_http_disable_symlinks(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
#endif

static char *rp_http_core_lowat_check(rp_conf_t *cf, void *post, void *data);
static char *rp_http_core_pool_size(rp_conf_t *cf, void *post, void *data);

static rp_conf_post_t  rp_http_core_lowat_post =
    { rp_http_core_lowat_check };

static rp_conf_post_handler_pt  rp_http_core_pool_size_p =
    rp_http_core_pool_size;


static rp_conf_enum_t  rp_http_core_request_body_in_file[] = {
    { rp_string("off"), RP_HTTP_REQUEST_BODY_FILE_OFF },
    { rp_string("on"), RP_HTTP_REQUEST_BODY_FILE_ON },
    { rp_string("clean"), RP_HTTP_REQUEST_BODY_FILE_CLEAN },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_http_core_satisfy[] = {
    { rp_string("all"), RP_HTTP_SATISFY_ALL },
    { rp_string("any"), RP_HTTP_SATISFY_ANY },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_http_core_lingering_close[] = {
    { rp_string("off"), RP_HTTP_LINGERING_OFF },
    { rp_string("on"), RP_HTTP_LINGERING_ON },
    { rp_string("always"), RP_HTTP_LINGERING_ALWAYS },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_http_core_server_tokens[] = {
    { rp_string("off"), RP_HTTP_SERVER_TOKENS_OFF },
    { rp_string("on"), RP_HTTP_SERVER_TOKENS_ON },
    { rp_string("build"), RP_HTTP_SERVER_TOKENS_BUILD },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_http_core_if_modified_since[] = {
    { rp_string("off"), RP_HTTP_IMS_OFF },
    { rp_string("exact"), RP_HTTP_IMS_EXACT },
    { rp_string("before"), RP_HTTP_IMS_BEFORE },
    { rp_null_string, 0 }
};


static rp_conf_bitmask_t  rp_http_core_keepalive_disable[] = {
    { rp_string("none"), RP_HTTP_KEEPALIVE_DISABLE_NONE },
    { rp_string("msie6"), RP_HTTP_KEEPALIVE_DISABLE_MSIE6 },
    { rp_string("safari"), RP_HTTP_KEEPALIVE_DISABLE_SAFARI },
    { rp_null_string, 0 }
};


static rp_path_init_t  rp_http_client_temp_path = {
    rp_string(RP_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};


#if (RP_HTTP_GZIP)

static rp_conf_enum_t  rp_http_gzip_http_version[] = {
    { rp_string("1.0"), RP_HTTP_VERSION_10 },
    { rp_string("1.1"), RP_HTTP_VERSION_11 },
    { rp_null_string, 0 }
};


static rp_conf_bitmask_t  rp_http_gzip_proxied_mask[] = {
    { rp_string("off"), RP_HTTP_GZIP_PROXIED_OFF },
    { rp_string("expired"), RP_HTTP_GZIP_PROXIED_EXPIRED },
    { rp_string("no-cache"), RP_HTTP_GZIP_PROXIED_NO_CACHE },
    { rp_string("no-store"), RP_HTTP_GZIP_PROXIED_NO_STORE },
    { rp_string("private"), RP_HTTP_GZIP_PROXIED_PRIVATE },
    { rp_string("no_last_modified"), RP_HTTP_GZIP_PROXIED_NO_LM },
    { rp_string("no_etag"), RP_HTTP_GZIP_PROXIED_NO_ETAG },
    { rp_string("auth"), RP_HTTP_GZIP_PROXIED_AUTH },
    { rp_string("any"), RP_HTTP_GZIP_PROXIED_ANY },
    { rp_null_string, 0 }
};


static rp_str_t  rp_http_gzip_no_cache = rp_string("no-cache");
static rp_str_t  rp_http_gzip_no_store = rp_string("no-store");
static rp_str_t  rp_http_gzip_private = rp_string("private");

#endif


static rp_command_t  rp_http_core_commands[] = {

    { rp_string("variables_hash_max_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_core_main_conf_t, variables_hash_max_size),
      NULL },

    { rp_string("variables_hash_bucket_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { rp_string("server_names_hash_max_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_core_main_conf_t, server_names_hash_max_size),
      NULL },

    { rp_string("server_names_hash_bucket_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_core_main_conf_t, server_names_hash_bucket_size),
      NULL },

    { rp_string("server"),
      RP_HTTP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_http_core_server,
      0,
      0,
      NULL },

    { rp_string("connection_pool_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, connection_pool_size),
      &rp_http_core_pool_size_p },

    { rp_string("request_pool_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, request_pool_size),
      &rp_http_core_pool_size_p },

    { rp_string("client_header_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, client_header_timeout),
      NULL },

    { rp_string("client_header_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, client_header_buffer_size),
      NULL },

    { rp_string("large_client_header_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, large_client_header_buffers),
      NULL },

    { rp_string("ignore_invalid_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, ignore_invalid_headers),
      NULL },

    { rp_string("merge_slashes"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, merge_slashes),
      NULL },

    { rp_string("underscores_in_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_core_srv_conf_t, underscores_in_headers),
      NULL },

    { rp_string("location"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_BLOCK|RP_CONF_TAKE12,
      rp_http_core_location,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("listen"),
      RP_HTTP_SRV_CONF|RP_CONF_1MORE,
      rp_http_core_listen,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("server_name"),
      RP_HTTP_SRV_CONF|RP_CONF_1MORE,
      rp_http_core_server_name,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("types_hash_max_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, types_hash_max_size),
      NULL },

    { rp_string("types_hash_bucket_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, types_hash_bucket_size),
      NULL },

    { rp_string("types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF
                                          |RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_http_core_types,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("default_type"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, default_type),
      NULL },

    { rp_string("root"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE1,
      rp_http_core_root,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("alias"),
      RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_core_root,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("limit_except"),
      RP_HTTP_LOC_CONF|RP_CONF_BLOCK|RP_CONF_1MORE,
      rp_http_core_limit_except,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("client_max_body_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_off_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_max_body_size),
      NULL },

    { rp_string("client_body_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_body_buffer_size),
      NULL },

    { rp_string("client_body_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_body_timeout),
      NULL },

    { rp_string("client_body_temp_path"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1234,
      rp_conf_set_path_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_body_temp_path),
      NULL },

    { rp_string("client_body_in_file_only"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_body_in_file_only),
      &rp_http_core_request_body_in_file },

    { rp_string("client_body_in_single_buffer"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, client_body_in_single_buffer),
      NULL },

    { rp_string("sendfile"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, sendfile),
      NULL },

    { rp_string("sendfile_max_chunk"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, sendfile_max_chunk),
      NULL },

    { rp_string("subrequest_output_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, subrequest_output_buffer_size),
      NULL },

    { rp_string("aio"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_core_set_aio,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("aio_write"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, aio_write),
      NULL },

    { rp_string("read_ahead"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, read_ahead),
      NULL },

    { rp_string("directio"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_core_directio,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("directio_alignment"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_off_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, directio_alignment),
      NULL },

    { rp_string("tcp_nopush"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, tcp_nopush),
      NULL },

    { rp_string("tcp_nodelay"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, tcp_nodelay),
      NULL },

    { rp_string("send_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, send_timeout),
      NULL },

    { rp_string("send_lowat"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, send_lowat),
      &rp_http_core_lowat_post },

    { rp_string("postpone_output"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, postpone_output),
      NULL },

    { rp_string("limit_rate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE1,
      rp_http_set_complex_value_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, limit_rate),
      NULL },

    { rp_string("limit_rate_after"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE1,
      rp_http_set_complex_value_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, limit_rate_after),
      NULL },

    { rp_string("keepalive_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_core_keepalive,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("keepalive_requests"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, keepalive_requests),
      NULL },

    { rp_string("keepalive_disable"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, keepalive_disable),
      &rp_http_core_keepalive_disable },

    { rp_string("satisfy"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, satisfy),
      &rp_http_core_satisfy },

    { rp_string("auth_delay"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, auth_delay),
      NULL },

    { rp_string("internal"),
      RP_HTTP_LOC_CONF|RP_CONF_NOARGS,
      rp_http_core_internal,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("lingering_close"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, lingering_close),
      &rp_http_core_lingering_close },

    { rp_string("lingering_time"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, lingering_time),
      NULL },

    { rp_string("lingering_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, lingering_timeout),
      NULL },

    { rp_string("reset_timedout_connection"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, reset_timedout_connection),
      NULL },

    { rp_string("absolute_redirect"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, absolute_redirect),
      NULL },

    { rp_string("server_name_in_redirect"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, server_name_in_redirect),
      NULL },

    { rp_string("port_in_redirect"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, port_in_redirect),
      NULL },

    { rp_string("msie_padding"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, msie_padding),
      NULL },

    { rp_string("msie_refresh"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, msie_refresh),
      NULL },

    { rp_string("log_not_found"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, log_not_found),
      NULL },

    { rp_string("log_subrequest"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, log_subrequest),
      NULL },

    { rp_string("recursive_error_pages"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, recursive_error_pages),
      NULL },

    { rp_string("server_tokens"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, server_tokens),
      &rp_http_core_server_tokens },

    { rp_string("if_modified_since"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, if_modified_since),
      &rp_http_core_if_modified_since },

    { rp_string("max_ranges"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, max_ranges),
      NULL },

    { rp_string("chunked_transfer_encoding"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, chunked_transfer_encoding),
      NULL },

    { rp_string("etag"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, etag),
      NULL },

    { rp_string("error_page"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_2MORE,
      rp_http_core_error_page,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("post_action"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, post_action),
      NULL },

    { rp_string("error_log"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_core_error_log,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("open_file_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_core_open_file_cache,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, open_file_cache),
      NULL },

    { rp_string("open_file_cache_valid"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_sec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, open_file_cache_valid),
      NULL },

    { rp_string("open_file_cache_min_uses"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, open_file_cache_min_uses),
      NULL },

    { rp_string("open_file_cache_errors"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, open_file_cache_errors),
      NULL },

    { rp_string("open_file_cache_events"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, open_file_cache_events),
      NULL },

    { rp_string("resolver"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_core_resolver,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("resolver_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, resolver_timeout),
      NULL },

#if (RP_HTTP_GZIP)

    { rp_string("gzip_vary"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, gzip_vary),
      NULL },

    { rp_string("gzip_http_version"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, gzip_http_version),
      &rp_http_gzip_http_version },

    { rp_string("gzip_proxied"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_core_loc_conf_t, gzip_proxied),
      &rp_http_gzip_proxied_mask },

    { rp_string("gzip_disable"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_gzip_disable,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

#if (RP_HAVE_OPENAT)

    { rp_string("disable_symlinks"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_disable_symlinks,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rp_null_command
};


static rp_http_module_t  rp_http_core_module_ctx = {
    rp_http_core_preconfiguration,        /* preconfiguration */
    rp_http_core_postconfiguration,       /* postconfiguration */

    rp_http_core_create_main_conf,        /* create main configuration */
    rp_http_core_init_main_conf,          /* init main configuration */

    rp_http_core_create_srv_conf,         /* create server configuration */
    rp_http_core_merge_srv_conf,          /* merge server configuration */

    rp_http_core_create_loc_conf,         /* create location configuration */
    rp_http_core_merge_loc_conf           /* merge location configuration */
};


rp_module_t  rp_http_core_module = {
    RP_MODULE_V1,
    &rp_http_core_module_ctx,             /* module context */
    rp_http_core_commands,                /* module directives */
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


rp_str_t  rp_http_core_get_method = { 3, (u_char *) "GET" };


void
rp_http_handler(rp_http_request_t *r)
{
    rp_http_core_main_conf_t  *cmcf;

    r->connection->log->action = NULL;

    if (!r->internal) {
        switch (r->headers_in.connection_type) {
        case 0:
            r->keepalive = (r->http_version > RP_HTTP_VERSION_10);
            break;

        case RP_HTTP_CONNECTION_CLOSE:
            r->keepalive = 0;
            break;

        case RP_HTTP_CONNECTION_KEEP_ALIVE:
            r->keepalive = 1;
            break;
        }

        r->lingering_close = (r->headers_in.content_length_n > 0
                              || r->headers_in.chunked);
        r->phase_handler = 0;

    } else {
        cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);
        r->phase_handler = cmcf->phase_engine.server_rewrite_index;
    }

    r->valid_location = 1;
#if (RP_HTTP_GZIP)
    r->gzip_tested = 0;
    r->gzip_ok = 0;
    r->gzip_vary = 0;
#endif

    r->write_event_handler = rp_http_core_run_phases;
    rp_http_core_run_phases(r);
}


void
rp_http_core_run_phases(rp_http_request_t *r)
{
    rp_int_t                   rc;
    rp_http_phase_handler_t   *ph;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[r->phase_handler].checker) {

        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);

        if (rc == RP_OK) {
            return;
        }
    }
}


rp_int_t
rp_http_core_generic_phase(rp_http_request_t *r, rp_http_phase_handler_t *ph)
{
    rp_int_t  rc;

    /*
     * generic phase checker,
     * used by the post read and pre-access phases
     */

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generic phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RP_OK) {
        r->phase_handler = ph->next;
        return RP_AGAIN;
    }

    if (rc == RP_DECLINED) {
        r->phase_handler++;
        return RP_AGAIN;
    }

    if (rc == RP_AGAIN || rc == RP_DONE) {
        return RP_OK;
    }

    /* rc == RP_ERROR || rc == RP_HTTP_...  */

    rp_http_finalize_request(r, rc);

    return RP_OK;
}


rp_int_t
rp_http_core_rewrite_phase(rp_http_request_t *r, rp_http_phase_handler_t *ph)
{
    rp_int_t  rc;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rewrite phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RP_DECLINED) {
        r->phase_handler++;
        return RP_AGAIN;
    }

    if (rc == RP_DONE) {
        return RP_OK;
    }

    /* RP_OK, RP_AGAIN, RP_ERROR, RP_HTTP_...  */

    rp_http_finalize_request(r, rc);

    return RP_OK;
}


rp_int_t
rp_http_core_find_config_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph)
{
    u_char                    *p;
    size_t                     len;
    rp_int_t                  rc;
    rp_http_core_loc_conf_t  *clcf;

    r->content_handler = NULL;
    r->uri_changed = 0;

    rc = rp_http_core_find_location(r);

    if (rc == RP_ERROR) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (!r->internal && clcf->internal) {
        rp_http_finalize_request(r, RP_HTTP_NOT_FOUND);
        return RP_OK;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "using configuration \"%s%V\"",
                   (clcf->noname ? "*" : (clcf->exact_match ? "=" : "")),
                   &clcf->name);

    rp_http_update_location_config(r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl:%O max:%O",
                   r->headers_in.content_length_n, clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && !r->discard_body
        && clcf->client_max_body_size
        && clcf->client_max_body_size < r->headers_in.content_length_n)
    {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "client intended to send too large body: %O bytes",
                      r->headers_in.content_length_n);

        r->expect_tested = 1;
        (void) rp_http_discard_request_body(r);
        rp_http_finalize_request(r, RP_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return RP_OK;
    }

    if (rc == RP_DONE) {
        rp_http_clear_location(r);

        r->headers_out.location = rp_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return RP_OK;
        }

        r->headers_out.location->hash = 1;
        rp_str_set(&r->headers_out.location->key, "Location");

        if (r->args.len == 0) {
            r->headers_out.location->value = clcf->name;

        } else {
            len = clcf->name.len + 1 + r->args.len;
            p = rp_pnalloc(r->pool, len);

            if (p == NULL) {
                rp_http_clear_location(r);
                rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                return RP_OK;
            }

            r->headers_out.location->value.len = len;
            r->headers_out.location->value.data = p;

            p = rp_cpymem(p, clcf->name.data, clcf->name.len);
            *p++ = '?';
            rp_memcpy(p, r->args.data, r->args.len);
        }

        rp_http_finalize_request(r, RP_HTTP_MOVED_PERMANENTLY);
        return RP_OK;
    }

    r->phase_handler++;
    return RP_AGAIN;
}


rp_int_t
rp_http_core_post_rewrite_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph)
{
    rp_http_core_srv_conf_t  *cscf;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post rewrite phase: %ui", r->phase_handler);

    if (!r->uri_changed) {
        r->phase_handler++;
        return RP_AGAIN;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri changes: %d", r->uri_changes);

    /*
     * gcc before 3.3 compiles the broken code for
     *     if (r->uri_changes-- == 0)
     * if the r->uri_changes is defined as
     *     unsigned  uri_changes:4
     */

    r->uri_changes--;

    if (r->uri_changes == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while processing \"%V\"", &r->uri);

        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_OK;
    }

    r->phase_handler = ph->next;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    return RP_AGAIN;
}


rp_int_t
rp_http_core_access_phase(rp_http_request_t *r, rp_http_phase_handler_t *ph)
{
    rp_int_t                  rc;
    rp_http_core_loc_conf_t  *clcf;

    if (r != r->main) {
        r->phase_handler = ph->next;
        return RP_AGAIN;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "access phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == RP_DECLINED) {
        r->phase_handler++;
        return RP_AGAIN;
    }

    if (rc == RP_AGAIN || rc == RP_DONE) {
        return RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->satisfy == RP_HTTP_SATISFY_ALL) {

        if (rc == RP_OK) {
            r->phase_handler++;
            return RP_AGAIN;
        }

    } else {
        if (rc == RP_OK) {
            r->access_code = 0;

            if (r->headers_out.www_authenticate) {
                r->headers_out.www_authenticate->hash = 0;
            }

            r->phase_handler = ph->next;
            return RP_AGAIN;
        }

        if (rc == RP_HTTP_FORBIDDEN || rc == RP_HTTP_UNAUTHORIZED) {
            if (r->access_code != RP_HTTP_UNAUTHORIZED) {
                r->access_code = rc;
            }

            r->phase_handler++;
            return RP_AGAIN;
        }
    }

    /* rc == RP_ERROR || rc == RP_HTTP_...  */

    if (rc == RP_HTTP_UNAUTHORIZED) {
        return rp_http_core_auth_delay(r);
    }

    rp_http_finalize_request(r, rc);
    return RP_OK;
}


rp_int_t
rp_http_core_post_access_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph)
{
    rp_int_t  access_code;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post access phase: %ui", r->phase_handler);

    access_code = r->access_code;

    if (access_code) {
        r->access_code = 0;

        if (access_code == RP_HTTP_FORBIDDEN) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        if (access_code == RP_HTTP_UNAUTHORIZED) {
            return rp_http_core_auth_delay(r);
        }

        rp_http_finalize_request(r, access_code);
        return RP_OK;
    }

    r->phase_handler++;
    return RP_AGAIN;
}


static rp_int_t
rp_http_core_auth_delay(rp_http_request_t *r)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->auth_delay == 0) {
        rp_http_finalize_request(r, RP_HTTP_UNAUTHORIZED);
        return RP_OK;
    }

    rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                  "delaying unauthorized request");

    if (rp_handle_read_event(r->connection->read, 0) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = rp_http_test_reading;
    r->write_event_handler = rp_http_core_auth_delay_handler;

    r->connection->write->delayed = 1;
    rp_add_timer(r->connection->write, clcf->auth_delay);

    /*
     * trigger an additional event loop iteration
     * to ensure constant-time processing
     */

    rp_post_event(r->connection->write, &rp_posted_next_events);

    return RP_OK;
}


static void
rp_http_core_auth_delay_handler(rp_http_request_t *r)
{
    rp_event_t  *wev;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth delay handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rp_handle_write_event(wev, 0) != RP_OK) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    rp_http_finalize_request(r, RP_HTTP_UNAUTHORIZED);
}


rp_int_t
rp_http_core_content_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph)
{
    size_t     root;
    rp_int_t  rc;
    rp_str_t  path;

    if (r->content_handler) {
        r->write_event_handler = rp_http_request_empty_handler;
        rp_http_finalize_request(r, r->content_handler(r));
        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "content phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc != RP_DECLINED) {
        rp_http_finalize_request(r, rc);
        return RP_OK;
    }

    /* rc == RP_DECLINED */

    ph++;

    if (ph->checker) {
        r->phase_handler++;
        return RP_AGAIN;
    }

    /* no content handler was found */

    if (r->uri.data[r->uri.len - 1] == '/') {

        if (rp_http_map_uri_to_path(r, &path, &root, 0) != NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "directory index of \"%s\" is forbidden", path.data);
        }

        rp_http_finalize_request(r, RP_HTTP_FORBIDDEN);
        return RP_OK;
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0, "no handler found");

    rp_http_finalize_request(r, RP_HTTP_NOT_FOUND);
    return RP_OK;
}


void
rp_http_update_location_config(rp_http_request_t *r)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (r->method & clcf->limit_except) {
        r->loc_conf = clcf->limit_except_loc_conf;
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    }

    if (r == r->main) {
        rp_set_connection_log(r->connection, clcf->error_log);
    }

    if ((rp_io.flags & RP_IO_SENDFILE) && clcf->sendfile) {
        r->connection->sendfile = 1;

    } else {
        r->connection->sendfile = 0;
    }

    if (clcf->client_body_in_file_only) {
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file =
            clcf->client_body_in_file_only == RP_HTTP_REQUEST_BODY_FILE_CLEAN;
        r->request_body_file_log_level = RP_LOG_NOTICE;

    } else {
        r->request_body_file_log_level = RP_LOG_WARN;
    }

    r->request_body_in_single_buf = clcf->client_body_in_single_buffer;

    if (r->keepalive) {
        if (clcf->keepalive_timeout == 0) {
            r->keepalive = 0;

        } else if (r->connection->requests >= clcf->keepalive_requests) {
            r->keepalive = 0;

        } else if (r->headers_in.msie6
                   && r->method == RP_HTTP_POST
                   && (clcf->keepalive_disable
                       & RP_HTTP_KEEPALIVE_DISABLE_MSIE6))
        {
            /*
             * MSIE may wait for some time if an response for
             * a POST request was sent over a keepalive connection
             */
            r->keepalive = 0;

        } else if (r->headers_in.safari
                   && (clcf->keepalive_disable
                       & RP_HTTP_KEEPALIVE_DISABLE_SAFARI))
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
        r->connection->tcp_nopush = RP_TCP_NOPUSH_DISABLED;
    }

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }
}


/*
 * RP_OK       - exact or regex match
 * RP_DONE     - auto redirect
 * RP_AGAIN    - inclusive match
 * RP_ERROR    - regex error
 * RP_DECLINED - no match
 */

static rp_int_t
rp_http_core_find_location(rp_http_request_t *r)
{
    rp_int_t                  rc;
    rp_http_core_loc_conf_t  *pclcf;
#if (RP_PCRE)
    rp_int_t                  n;
    rp_uint_t                 noregex;
    rp_http_core_loc_conf_t  *clcf, **clcfp;

    noregex = 0;
#endif

    pclcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rc = rp_http_core_find_static_location(r, pclcf->static_locations);

    if (rc == RP_AGAIN) {

#if (RP_PCRE)
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        noregex = clcf->noregex;
#endif

        /* look up nested locations */

        rc = rp_http_core_find_location(r);
    }

    if (rc == RP_OK || rc == RP_DONE) {
        return rc;
    }

    /* rc == RP_DECLINED or rc == RP_AGAIN in nested location */

#if (RP_PCRE)

    if (noregex == 0 && pclcf->regex_locations) {

        for (clcfp = pclcf->regex_locations; *clcfp; clcfp++) {

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: ~ \"%V\"", &(*clcfp)->name);

            n = rp_http_regex_exec(r, (*clcfp)->regex, &r->uri);

            if (n == RP_OK) {
                r->loc_conf = (*clcfp)->loc_conf;

                /* look up nested locations */

                rc = rp_http_core_find_location(r);

                return (rc == RP_ERROR) ? rc : RP_OK;
            }

            if (n == RP_DECLINED) {
                continue;
            }

            return RP_ERROR;
        }
    }
#endif

    return rc;
}


/*
 * RP_OK       - exact match
 * RP_DONE     - auto redirect
 * RP_AGAIN    - inclusive match
 * RP_DECLINED - no match
 */

static rp_int_t
rp_http_core_find_static_location(rp_http_request_t *r,
    rp_http_location_tree_node_t *node)
{
    u_char     *uri;
    size_t      len, n;
    rp_int_t   rc, rv;

    len = r->uri.len;
    uri = r->uri.data;

    rv = RP_DECLINED;

    for ( ;; ) {

        if (node == NULL) {
            return rv;
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "test location: \"%*s\"",
                       (size_t) node->len, node->name);

        n = (len <= (size_t) node->len) ? len : node->len;

        rc = rp_filename_cmp(uri, node->name, n);

        if (rc != 0) {
            node = (rc < 0) ? node->left : node->right;

            continue;
        }

        if (len > (size_t) node->len) {

            if (node->inclusive) {

                r->loc_conf = node->inclusive->loc_conf;
                rv = RP_AGAIN;

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
                return RP_OK;

            } else {
                r->loc_conf = node->inclusive->loc_conf;
                return RP_AGAIN;
            }
        }

        /* len < node->len */

        if (len + 1 == (size_t) node->len && node->auto_redirect) {

            r->loc_conf = (node->exact) ? node->exact->loc_conf:
                                          node->inclusive->loc_conf;
            rv = RP_DONE;
        }

        node = node->left;
    }
}


void *
rp_http_test_content_type(rp_http_request_t *r, rp_hash_t *types_hash)
{
    u_char      c, *lowcase;
    size_t      len;
    rp_uint_t  i, hash;

    if (types_hash->size == 0) {
        return (void *) 4;
    }

    if (r->headers_out.content_type.len == 0) {
        return NULL;
    }

    len = r->headers_out.content_type_len;

    if (r->headers_out.content_type_lowcase == NULL) {

        lowcase = rp_pnalloc(r->pool, len);
        if (lowcase == NULL) {
            return NULL;
        }

        r->headers_out.content_type_lowcase = lowcase;

        hash = 0;

        for (i = 0; i < len; i++) {
            c = rp_tolower(r->headers_out.content_type.data[i]);
            hash = rp_hash(hash, c);
            lowcase[i] = c;
        }

        r->headers_out.content_type_hash = hash;
    }

    return rp_hash_find(types_hash, r->headers_out.content_type_hash,
                         r->headers_out.content_type_lowcase, len);
}


rp_int_t
rp_http_set_content_type(rp_http_request_t *r)
{
    u_char                     c, *exten;
    rp_str_t                 *type;
    rp_uint_t                 i, hash;
    rp_http_core_loc_conf_t  *clcf;

    if (r->headers_out.content_type.len) {
        return RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (r->exten.len) {

        hash = 0;

        for (i = 0; i < r->exten.len; i++) {
            c = r->exten.data[i];

            if (c >= 'A' && c <= 'Z') {

                exten = rp_pnalloc(r->pool, r->exten.len);
                if (exten == NULL) {
                    return RP_ERROR;
                }

                hash = rp_hash_strlow(exten, r->exten.data, r->exten.len);

                r->exten.data = exten;

                break;
            }

            hash = rp_hash(hash, c);
        }

        type = rp_hash_find(&clcf->types_hash, hash,
                             r->exten.data, r->exten.len);

        if (type) {
            r->headers_out.content_type_len = type->len;
            r->headers_out.content_type = *type;

            return RP_OK;
        }
    }

    r->headers_out.content_type_len = clcf->default_type.len;
    r->headers_out.content_type = clcf->default_type;

    return RP_OK;
}


void
rp_http_set_exten(rp_http_request_t *r)
{
    rp_int_t  i;

    rp_str_null(&r->exten);

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


rp_int_t
rp_http_set_etag(rp_http_request_t *r)
{
    rp_table_elt_t           *etag;
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (!clcf->etag) {
        return RP_OK;
    }

    etag = rp_list_push(&r->headers_out.headers);
    if (etag == NULL) {
        return RP_ERROR;
    }

    etag->hash = 1;
    rp_str_set(&etag->key, "ETag");

    etag->value.data = rp_pnalloc(r->pool, RP_OFF_T_LEN + RP_TIME_T_LEN + 3);
    if (etag->value.data == NULL) {
        etag->hash = 0;
        return RP_ERROR;
    }

    etag->value.len = rp_sprintf(etag->value.data, "\"%xT-%xO\"",
                                  r->headers_out.last_modified_time,
                                  r->headers_out.content_length_n)
                      - etag->value.data;

    r->headers_out.etag = etag;

    return RP_OK;
}


void
rp_http_weak_etag(rp_http_request_t *r)
{
    size_t            len;
    u_char           *p;
    rp_table_elt_t  *etag;

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

    p = rp_pnalloc(r->pool, etag->value.len + 2);
    if (p == NULL) {
        r->headers_out.etag->hash = 0;
        r->headers_out.etag = NULL;
        return;
    }

    len = rp_sprintf(p, "W/%V", &etag->value) - p;

    etag->value.data = p;
    etag->value.len = len;
}


rp_int_t
rp_http_send_response(rp_http_request_t *r, rp_uint_t status,
    rp_str_t *ct, rp_http_complex_value_t *cv)
{
    rp_int_t     rc;
    rp_str_t     val;
    rp_buf_t    *b;
    rp_chain_t   out;

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    r->headers_out.status = status;

    if (rp_http_complex_value(r, cv, &val) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (status == RP_HTTP_MOVED_PERMANENTLY
        || status == RP_HTTP_MOVED_TEMPORARILY
        || status == RP_HTTP_SEE_OTHER
        || status == RP_HTTP_TEMPORARY_REDIRECT
        || status == RP_HTTP_PERMANENT_REDIRECT)
    {
        rp_http_clear_location(r);

        r->headers_out.location = rp_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->hash = 1;
        rp_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = val;

        return status;
    }

    r->headers_out.content_length_n = val.len;

    if (ct) {
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;

    } else {
        if (rp_http_set_content_type(r) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (r->method == RP_HTTP_HEAD || (r != r->main && val.len == 0)) {
        return rp_http_send_header(r);
    }

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = val.data;
    b->last = val.data + val.len;
    b->memory = val.len ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        return rc;
    }

    return rp_http_output_filter(r, &out);
}


rp_int_t
rp_http_send_header(rp_http_request_t *r)
{
    if (r->post_action) {
        return RP_OK;
    }

    if (r->header_sent) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "header already sent");
        return RP_ERROR;
    }

    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return rp_http_top_header_filter(r);
}


rp_int_t
rp_http_output_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t          rc;
    rp_connection_t  *c;

    c = r->connection;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http output filter \"%V?%V\"", &r->uri, &r->args);

    rc = rp_http_top_body_filter(r, in);

    if (rc == RP_ERROR) {
        /* RP_ERROR may be returned by any filter */
        c->error = 1;
    }

    return rc;
}


u_char *
rp_http_map_uri_to_path(rp_http_request_t *r, rp_str_t *path,
    size_t *root_length, size_t reserved)
{
    u_char                    *last;
    size_t                     alias;
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    alias = clcf->alias;

    if (alias && !r->valid_location) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "\"alias\" cannot be used in location \"%V\" "
                      "where URI was rewritten", &clcf->name);
        return NULL;
    }

    if (clcf->root_lengths == NULL) {

        *root_length = clcf->root.len;

        path->len = clcf->root.len + reserved + r->uri.len - alias + 1;

        path->data = rp_pnalloc(r->pool, path->len);
        if (path->data == NULL) {
            return NULL;
        }

        last = rp_copy(path->data, clcf->root.data, clcf->root.len);

    } else {

        if (alias == RP_MAX_SIZE_T_VALUE) {
            reserved += r->add_uri_to_alias ? r->uri.len + 1 : 1;

        } else {
            reserved += r->uri.len - alias + 1;
        }

        if (rp_http_script_run(r, path, clcf->root_lengths->elts, reserved,
                                clcf->root_values->elts)
            == NULL)
        {
            return NULL;
        }

        if (rp_get_full_name(r->pool, (rp_str_t *) &rp_cycle->prefix, path)
            != RP_OK)
        {
            return NULL;
        }

        *root_length = path->len - reserved;
        last = path->data + *root_length;

        if (alias == RP_MAX_SIZE_T_VALUE) {
            if (!r->add_uri_to_alias) {
                *last = '\0';
                return last;
            }

            alias = 0;
        }
    }

    last = rp_copy(last, r->uri.data + alias, r->uri.len - alias);
    *last = '\0';

    return last;
}


rp_int_t
rp_http_auth_basic_user(rp_http_request_t *r)
{
    rp_str_t   auth, encoded;
    rp_uint_t  len;

    if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return RP_DECLINED;
    }

    if (r->headers_in.authorization == NULL) {
        r->headers_in.user.data = (u_char *) "";
        return RP_DECLINED;
    }

    encoded = r->headers_in.authorization->value;

    if (encoded.len < sizeof("Basic ") - 1
        || rp_strncasecmp(encoded.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1)
           != 0)
    {
        r->headers_in.user.data = (u_char *) "";
        return RP_DECLINED;
    }

    encoded.len -= sizeof("Basic ") - 1;
    encoded.data += sizeof("Basic ") - 1;

    while (encoded.len && encoded.data[0] == ' ') {
        encoded.len--;
        encoded.data++;
    }

    if (encoded.len == 0) {
        r->headers_in.user.data = (u_char *) "";
        return RP_DECLINED;
    }

    auth.len = rp_base64_decoded_length(encoded.len);
    auth.data = rp_pnalloc(r->pool, auth.len + 1);
    if (auth.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&auth, &encoded) != RP_OK) {
        r->headers_in.user.data = (u_char *) "";
        return RP_DECLINED;
    }

    auth.data[auth.len] = '\0';

    for (len = 0; len < auth.len; len++) {
        if (auth.data[len] == ':') {
            break;
        }
    }

    if (len == 0 || len == auth.len) {
        r->headers_in.user.data = (u_char *) "";
        return RP_DECLINED;
    }

    r->headers_in.user.len = len;
    r->headers_in.user.data = auth.data;
    r->headers_in.passwd.len = auth.len - len - 1;
    r->headers_in.passwd.data = &auth.data[len + 1];

    return RP_OK;
}


#if (RP_HTTP_GZIP)

rp_int_t
rp_http_gzip_ok(rp_http_request_t *r)
{
    time_t                     date, expires;
    rp_uint_t                 p;
    rp_array_t               *cc;
    rp_table_elt_t           *e, *d, *ae;
    rp_http_core_loc_conf_t  *clcf;

    r->gzip_tested = 1;

    if (r != r->main) {
        return RP_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return RP_DECLINED;
    }

    if (ae->value.len < sizeof("gzip") - 1) {
        return RP_DECLINED;
    }

    /*
     * test first for the most common case "gzip,...":
     *   MSIE:    "gzip, deflate"
     *   Firefox: "gzip,deflate"
     *   Chrome:  "gzip,deflate,sdch"
     *   Safari:  "gzip, deflate"
     *   Opera:   "gzip, deflate"
     */

    if (rp_memcmp(ae->value.data, "gzip,", 5) != 0
        && rp_http_gzip_accept_encoding(&ae->value) != RP_OK)
    {
        return RP_DECLINED;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (r->headers_in.msie6 && clcf->gzip_disable_msie6) {
        return RP_DECLINED;
    }

    if (r->http_version < clcf->gzip_http_version) {
        return RP_DECLINED;
    }

    if (r->headers_in.via == NULL) {
        goto ok;
    }

    p = clcf->gzip_proxied;

    if (p & RP_HTTP_GZIP_PROXIED_OFF) {
        return RP_DECLINED;
    }

    if (p & RP_HTTP_GZIP_PROXIED_ANY) {
        goto ok;
    }

    if (r->headers_in.authorization && (p & RP_HTTP_GZIP_PROXIED_AUTH)) {
        goto ok;
    }

    e = r->headers_out.expires;

    if (e) {

        if (!(p & RP_HTTP_GZIP_PROXIED_EXPIRED)) {
            return RP_DECLINED;
        }

        expires = rp_parse_http_time(e->value.data, e->value.len);
        if (expires == RP_ERROR) {
            return RP_DECLINED;
        }

        d = r->headers_out.date;

        if (d) {
            date = rp_parse_http_time(d->value.data, d->value.len);
            if (date == RP_ERROR) {
                return RP_DECLINED;
            }

        } else {
            date = rp_time();
        }

        if (expires < date) {
            goto ok;
        }

        return RP_DECLINED;
    }

    cc = &r->headers_out.cache_control;

    if (cc->elts) {

        if ((p & RP_HTTP_GZIP_PROXIED_NO_CACHE)
            && rp_http_parse_multi_header_lines(cc, &rp_http_gzip_no_cache,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        if ((p & RP_HTTP_GZIP_PROXIED_NO_STORE)
            && rp_http_parse_multi_header_lines(cc, &rp_http_gzip_no_store,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        if ((p & RP_HTTP_GZIP_PROXIED_PRIVATE)
            && rp_http_parse_multi_header_lines(cc, &rp_http_gzip_private,
                                                 NULL)
               >= 0)
        {
            goto ok;
        }

        return RP_DECLINED;
    }

    if ((p & RP_HTTP_GZIP_PROXIED_NO_LM) && r->headers_out.last_modified) {
        return RP_DECLINED;
    }

    if ((p & RP_HTTP_GZIP_PROXIED_NO_ETAG) && r->headers_out.etag) {
        return RP_DECLINED;
    }

ok:

#if (RP_PCRE)

    if (clcf->gzip_disable && r->headers_in.user_agent) {

        if (rp_regex_exec_array(clcf->gzip_disable,
                                 &r->headers_in.user_agent->value,
                                 r->connection->log)
            != RP_DECLINED)
        {
            return RP_DECLINED;
        }
    }

#endif

    r->gzip_ok = 1;

    return RP_OK;
}


/*
 * gzip is enabled for the following quantities:
 *     "gzip; q=0.001" ... "gzip; q=1.000"
 * gzip is disabled for the following quantities:
 *     "gzip; q=0" ... "gzip; q=0.000", and for any invalid cases
 */

static rp_int_t
rp_http_gzip_accept_encoding(rp_str_t *ae)
{
    u_char  *p, *start, *last;

    start = ae->data;
    last = start + ae->len;

    for ( ;; ) {
        p = rp_strcasestrn(start, "gzip", 4 - 1);
        if (p == NULL) {
            return RP_DECLINED;
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
            return RP_OK;
        case ';':
            goto quantity;
        case ' ':
            continue;
        default:
            return RP_DECLINED;
        }
    }

    return RP_OK;

quantity:

    while (p < last) {
        switch (*p++) {
        case 'q':
        case 'Q':
            goto equal;
        case ' ':
            continue;
        default:
            return RP_DECLINED;
        }
    }

    return RP_OK;

equal:

    if (p + 2 > last || *p++ != '=') {
        return RP_DECLINED;
    }

    if (rp_http_gzip_quantity(p, last) == 0) {
        return RP_DECLINED;
    }

    return RP_OK;
}


static rp_uint_t
rp_http_gzip_quantity(u_char *p, u_char *last)
{
    u_char      c;
    rp_uint_t  n, q;

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


rp_int_t
rp_http_subrequest(rp_http_request_t *r,
    rp_str_t *uri, rp_str_t *args, rp_http_request_t **psr,
    rp_http_post_subrequest_t *ps, rp_uint_t flags)
{
    rp_time_t                    *tp;
    rp_connection_t              *c;
    rp_http_request_t            *sr;
    rp_http_core_srv_conf_t      *cscf;
    rp_http_postponed_request_t  *pr, *p;

    if (r->subrequests == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        return RP_ERROR;
    }

    /*
     * 1000 is reserved for other purposes.
     */
    if (r->main->count >= 65535 - 1000) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "request reference counter overflow "
                      "while processing \"%V\"", uri);
        return RP_ERROR;
    }

    if (r->subrequest_in_memory) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "nested in-memory subrequest \"%V\"", uri);
        return RP_ERROR;
    }

    sr = rp_pcalloc(r->pool, sizeof(rp_http_request_t));
    if (sr == NULL) {
        return RP_ERROR;
    }

    sr->signature = RP_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = rp_pcalloc(r->pool, sizeof(void *) * rp_http_max_module);
    if (sr->ctx == NULL) {
        return RP_ERROR;
    }

    if (rp_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_list_init(&sr->headers_out.trailers, r->pool, 4,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in = r->headers_in;

    rp_http_clear_content_length(sr);
    rp_http_clear_accept_ranges(sr);
    rp_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (RP_HTTP_V2)
    sr->stream = r->stream;
#endif

    sr->method = RP_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & RP_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & RP_HTTP_SUBREQUEST_WAITED) != 0;
    sr->background = (flags & RP_HTTP_SUBREQUEST_BACKGROUND) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = rp_http_core_get_method;
    sr->http_protocol = r->http_protocol;
    sr->schema = r->schema;

    rp_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = rp_http_request_empty_handler;
    sr->write_event_handler = rp_http_handler;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    if (sr->subrequest_in_memory) {
        sr->filter_need_in_memory = 1;
    }

    if (!sr->background) {
        if (c->data == r && r->postponed == NULL) {
            c->data = sr;
        }

        pr = rp_palloc(r->pool, sizeof(rp_http_postponed_request_t));
        if (pr == NULL) {
            return RP_ERROR;
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

    sr->uri_changes = RP_HTTP_MAX_URI_CHANGES + 1;
    sr->subrequests = r->subrequests - 1;

    tp = rp_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    if (flags & RP_HTTP_SUBREQUEST_CLONE) {
        sr->method = r->method;
        sr->method_name = r->method_name;
        sr->loc_conf = r->loc_conf;
        sr->valid_location = r->valid_location;
        sr->valid_unparsed_uri = r->valid_unparsed_uri;
        sr->content_handler = r->content_handler;
        sr->phase_handler = r->phase_handler;
        sr->write_event_handler = rp_http_core_run_phases;

#if (RP_PCRE)
        sr->ncaptures = r->ncaptures;
        sr->captures = r->captures;
        sr->captures_data = r->captures_data;
        sr->realloc_captures = 1;
        r->realloc_captures = 1;
#endif

        rp_http_update_location_config(sr);
    }

    return rp_http_post_request(sr, NULL);
}


rp_int_t
rp_http_internal_redirect(rp_http_request_t *r,
    rp_str_t *uri, rp_str_t *args)
{
    rp_http_core_srv_conf_t  *cscf;

    r->uri_changes--;

    if (r->uri_changes == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while internally redirecting to \"%V\"", uri);

        r->main->count++;
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_DONE;
    }

    r->uri = *uri;

    if (args) {
        r->args = *args;

    } else {
        rp_str_null(&r->args);
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%V?%V\"", uri, &r->args);

    rp_http_set_exten(r);

    /* clear the modules contexts */
    rp_memzero(r->ctx, sizeof(void *) * rp_http_max_module);

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    rp_http_update_location_config(r);

#if (RP_HTTP_CACHE)
    r->cache = NULL;
#endif

    r->internal = 1;
    r->valid_unparsed_uri = 0;
    r->add_uri_to_alias = 0;
    r->main->count++;

    rp_http_handler(r);

    return RP_DONE;
}


rp_int_t
rp_http_named_location(rp_http_request_t *r, rp_str_t *name)
{
    rp_http_core_srv_conf_t    *cscf;
    rp_http_core_loc_conf_t   **clcfp;
    rp_http_core_main_conf_t   *cmcf;

    r->main->count++;
    r->uri_changes--;

    if (r->uri_changes == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while redirect to named location \"%V\"", name);

        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_DONE;
    }

    if (r->uri.len == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "empty URI in redirect to named location \"%V\"", name);

        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_DONE;
    }

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    if (cscf->named_locations) {

        for (clcfp = cscf->named_locations; *clcfp; clcfp++) {

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: \"%V\"", &(*clcfp)->name);

            if (name->len != (*clcfp)->name.len
                || rp_strncmp(name->data, (*clcfp)->name.data, name->len) != 0)
            {
                continue;
            }

            rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "using location: %V \"%V?%V\"",
                           name, &r->uri, &r->args);

            r->internal = 1;
            r->content_handler = NULL;
            r->uri_changed = 0;
            r->loc_conf = (*clcfp)->loc_conf;

            /* clear the modules contexts */
            rp_memzero(r->ctx, sizeof(void *) * rp_http_max_module);

            rp_http_update_location_config(r);

            cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

            r->phase_handler = cmcf->phase_engine.location_rewrite_index;

            r->write_event_handler = rp_http_core_run_phases;
            rp_http_core_run_phases(r);

            return RP_DONE;
        }
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "could not find named location \"%V\"", name);

    rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);

    return RP_DONE;
}


rp_http_cleanup_t *
rp_http_cleanup_add(rp_http_request_t *r, size_t size)
{
    rp_http_cleanup_t  *cln;

    r = r->main;

    cln = rp_palloc(r->pool, sizeof(rp_http_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = rp_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cleanup add: %p", cln);

    return cln;
}


rp_int_t
rp_http_set_disable_symlinks(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, rp_str_t *path, rp_open_file_info_t *of)
{
#if (RP_HAVE_OPENAT)
    u_char     *p;
    rp_str_t   from;

    of->disable_symlinks = clcf->disable_symlinks;

    if (clcf->disable_symlinks_from == NULL) {
        return RP_OK;
    }

    if (rp_http_complex_value(r, clcf->disable_symlinks_from, &from)
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (from.len == 0
        || from.len > path->len
        || rp_memcmp(path->data, from.data, from.len) != 0)
    {
        return RP_OK;
    }

    if (from.len == path->len) {
        of->disable_symlinks = RP_DISABLE_SYMLINKS_OFF;
        return RP_OK;
    }

    p = path->data + from.len;

    if (*p == '/') {
        of->disable_symlinks_from = from.len;
        return RP_OK;
    }

    p--;

    if (*p == '/') {
        of->disable_symlinks_from = from.len - 1;
    }
#endif

    return RP_OK;
}


rp_int_t
rp_http_get_forwarded_addr(rp_http_request_t *r, rp_addr_t *addr,
    rp_array_t *headers, rp_str_t *value, rp_array_t *proxies,
    int recursive)
{
    rp_int_t          rc;
    rp_uint_t         i, found;
    rp_table_elt_t  **h;

    if (headers == NULL) {
        return rp_http_get_forwarded_addr_internal(r, addr, value->data,
                                                    value->len, proxies,
                                                    recursive);
    }

    i = headers->nelts;
    h = headers->elts;

    rc = RP_DECLINED;

    found = 0;

    while (i-- > 0) {
        rc = rp_http_get_forwarded_addr_internal(r, addr, h[i]->value.data,
                                                  h[i]->value.len, proxies,
                                                  recursive);

        if (!recursive) {
            break;
        }

        if (rc == RP_DECLINED && found) {
            rc = RP_DONE;
            break;
        }

        if (rc != RP_OK) {
            break;
        }

        found = 1;
    }

    return rc;
}


static rp_int_t
rp_http_get_forwarded_addr_internal(rp_http_request_t *r, rp_addr_t *addr,
    u_char *xff, size_t xfflen, rp_array_t *proxies, int recursive)
{
    u_char      *p;
    rp_addr_t   paddr;
    rp_uint_t   found;

    found = 0;

    do {

        if (rp_cidr_match(addr->sockaddr, proxies) != RP_OK) {
            return found ? RP_DONE : RP_DECLINED;
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

        if (rp_parse_addr_port(r->pool, &paddr, p, xfflen - (p - xff))
            != RP_OK)
        {
            return found ? RP_DONE : RP_DECLINED;
        }

        *addr = paddr;
        found = 1;
        xfflen = p - 1 - xff;

    } while (recursive && p > xff);

    return RP_OK;
}


static char *
rp_http_core_server(rp_conf_t *cf, rp_command_t *cmd, void *dummy)
{
    char                        *rv;
    void                        *mconf;
    size_t                       len;
    u_char                      *p;
    rp_uint_t                   i;
    rp_conf_t                   pcf;
    rp_http_module_t           *module;
    struct sockaddr_in          *sin;
    rp_http_conf_ctx_t         *ctx, *http_ctx;
    rp_http_listen_opt_t        lsopt;
    rp_http_core_srv_conf_t    *cscf, **cscfp;
    rp_http_core_main_conf_t   *cmcf;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }


    /* the server configuration context */

    cscf = ctx->srv_conf[rp_http_core_module.ctx_index];
    cscf->ctx = ctx;


    cmcf = ctx->main_conf[rp_http_core_module.ctx_index];

    cscfp = rp_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_HTTP_SRV_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == RP_CONF_OK && !cscf->listen) {
        rp_memzero(&lsopt, sizeof(rp_http_listen_opt_t));

        p = rp_pcalloc(cf->pool, sizeof(struct sockaddr_in));
        if (p == NULL) {
            return RP_CONF_ERROR;
        }

        lsopt.sockaddr = (struct sockaddr *) p;

        sin = (struct sockaddr_in *) p;

        sin->sin_family = AF_INET;
#if (RP_WIN32)
        sin->sin_port = htons(80);
#else
        sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
#endif
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = RP_LISTEN_BACKLOG;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (RP_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
#if (RP_HAVE_TCP_FASTOPEN)
        lsopt.fastopen = -1;
#endif
        lsopt.wildcard = 1;

        len = RP_INET_ADDRSTRLEN + sizeof(":65535") - 1;

        p = rp_pnalloc(cf->pool, len);
        if (p == NULL) {
            return RP_CONF_ERROR;
        }

        lsopt.addr_text.data = p;
        lsopt.addr_text.len = rp_sock_ntop(lsopt.sockaddr, lsopt.socklen, p,
                                            len, 1);

        if (rp_http_add_listen(cf, cscf, &lsopt) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return rv;
}


static char *
rp_http_core_location(rp_conf_t *cf, rp_command_t *cmd, void *dummy)
{
    char                      *rv;
    u_char                    *mod;
    size_t                     len;
    rp_str_t                 *value, *name;
    rp_uint_t                 i;
    rp_conf_t                 save;
    rp_http_module_t         *module;
    rp_http_conf_ctx_t       *ctx, *pctx;
    rp_http_core_loc_conf_t  *clcf, *pclcf;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[cf->cycle->modules[i]->ctx_index] == NULL) {
                return RP_CONF_ERROR;
            }
        }
    }

    clcf = ctx->loc_conf[rp_http_core_module.ctx_index];
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

            if (rp_http_core_regex_location(cf, clcf, name, 0) != RP_OK) {
                return RP_CONF_ERROR;
            }

        } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {

            if (rp_http_core_regex_location(cf, clcf, name, 1) != RP_OK) {
                return RP_CONF_ERROR;
            }

        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%V\"", &value[1]);
            return RP_CONF_ERROR;
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

                if (rp_http_core_regex_location(cf, clcf, name, 1) != RP_OK) {
                    return RP_CONF_ERROR;
                }

            } else {
                if (rp_http_core_regex_location(cf, clcf, name, 0) != RP_OK) {
                    return RP_CONF_ERROR;
                }
            }

        } else {

            clcf->name = *name;

            if (name->data[0] == '@') {
                clcf->named = 1;
            }
        }
    }

    pclcf = pctx->loc_conf[rp_http_core_module.ctx_index];

    if (cf->cmd_type == RP_HTTP_LOC_CONF) {

        /* nested location */

#if 0
        clcf->prev_location = pclcf;
#endif

        if (pclcf->exact_match) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the exact location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RP_CONF_ERROR;
        }

        if (pclcf->named) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the named location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RP_CONF_ERROR;
        }

        if (clcf->named) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "named location \"%V\" can be "
                               "on the server level only",
                               &clcf->name);
            return RP_CONF_ERROR;
        }

        len = pclcf->name.len;

#if (RP_PCRE)
        if (clcf->regex == NULL
            && rp_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
#else
        if (rp_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
#endif
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "location \"%V\" is outside location \"%V\"",
                               &clcf->name, &pclcf->name);
            return RP_CONF_ERROR;
        }
    }

    if (rp_http_add_location(cf, &pclcf->locations, clcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_HTTP_LOC_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static rp_int_t
rp_http_core_regex_location(rp_conf_t *cf, rp_http_core_loc_conf_t *clcf,
    rp_str_t *regex, rp_uint_t caseless)
{
#if (RP_PCRE)
    rp_regex_compile_t  rc;
    u_char               errstr[RP_MAX_CONF_ERRSTR];

    rp_memzero(&rc, sizeof(rp_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = RP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (RP_HAVE_CASELESS_FILESYSTEM)
    rc.options = RP_REGEX_CASELESS;
#else
    rc.options = caseless ? RP_REGEX_CASELESS : 0;
#endif

    clcf->regex = rp_http_regex_compile(cf, &rc);
    if (clcf->regex == NULL) {
        return RP_ERROR;
    }

    clcf->name = *regex;

    return RP_OK;

#else

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return RP_ERROR;

#endif
}


static char *
rp_http_core_types(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    char        *rv;
    rp_conf_t   save;

    if (clcf->types == NULL) {
        clcf->types = rp_array_create(cf->pool, 64, sizeof(rp_hash_key_t));
        if (clcf->types == NULL) {
            return RP_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = rp_http_core_type;
    cf->handler_conf = conf;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
rp_http_core_type(rp_conf_t *cf, rp_command_t *dummy, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t       *value, *content_type, *old;
    rp_uint_t       i, n, hash;
    rp_hash_key_t  *type;

    value = cf->args->elts;

    if (rp_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return RP_CONF_ERROR;
        }

        return rp_conf_include(cf, dummy, conf);
    }

    content_type = rp_palloc(cf->pool, sizeof(rp_str_t));
    if (content_type == NULL) {
        return RP_CONF_ERROR;
    }

    *content_type = value[0];

    for (i = 1; i < cf->args->nelts; i++) {

        hash = rp_hash_strlow(value[i].data, value[i].data, value[i].len);

        type = clcf->types->elts;
        for (n = 0; n < clcf->types->nelts; n++) {
            if (rp_strcmp(value[i].data, type[n].key.data) == 0) {
                old = type[n].value;
                type[n].value = content_type;

                rp_conf_log_error(RP_LOG_WARN, cf, 0,
                                   "duplicate extension \"%V\", "
                                   "content type: \"%V\", "
                                   "previous content type: \"%V\"",
                                   &value[i], content_type, old);
                goto next;
            }
        }


        type = rp_array_push(clcf->types);
        if (type == NULL) {
            return RP_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = content_type;

    next:
        continue;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_core_preconfiguration(rp_conf_t *cf)
{
    return rp_http_variables_add_core_vars(cf);
}


static rp_int_t
rp_http_core_postconfiguration(rp_conf_t *cf)
{
    rp_http_top_request_body_filter = rp_http_request_body_save_filter;

    return RP_OK;
}


static void *
rp_http_core_create_main_conf(rp_conf_t *cf)
{
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_pcalloc(cf->pool, sizeof(rp_http_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rp_http_core_srv_conf_t *))
        != RP_OK)
    {
        return NULL;
    }

    cmcf->server_names_hash_max_size = RP_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = RP_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = RP_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = RP_CONF_UNSET_UINT;

    return cmcf;
}


static char *
rp_http_core_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_http_core_main_conf_t *cmcf = conf;

    rp_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
    rp_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
                             rp_cacheline_size);

    cmcf->server_names_hash_bucket_size =
            rp_align(cmcf->server_names_hash_bucket_size, rp_cacheline_size);


    rp_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    rp_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               rp_align(cmcf->variables_hash_bucket_size, rp_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return RP_CONF_OK;
}


static void *
rp_http_core_create_srv_conf(rp_conf_t *cf)
{
    rp_http_core_srv_conf_t  *cscf;

    cscf = rp_pcalloc(cf->pool, sizeof(rp_http_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->client_large_buffers.num = 0;
     */

    if (rp_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(rp_http_server_name_t))
        != RP_OK)
    {
        return NULL;
    }

    cscf->connection_pool_size = RP_CONF_UNSET_SIZE;
    cscf->request_pool_size = RP_CONF_UNSET_SIZE;
    cscf->client_header_timeout = RP_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = RP_CONF_UNSET_SIZE;
    cscf->ignore_invalid_headers = RP_CONF_UNSET;
    cscf->merge_slashes = RP_CONF_UNSET;
    cscf->underscores_in_headers = RP_CONF_UNSET;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
rp_http_core_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_core_srv_conf_t *prev = parent;
    rp_http_core_srv_conf_t *conf = child;

    rp_str_t                name;
    rp_http_server_name_t  *sn;

    /* TODO: it does not merge, it inits only */

    rp_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 64 * sizeof(void *));
    rp_conf_merge_size_value(conf->request_pool_size,
                              prev->request_pool_size, 4096);
    rp_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);
    rp_conf_merge_size_value(conf->client_header_buffer_size,
                              prev->client_header_buffer_size, 1024);
    rp_conf_merge_bufs_value(conf->large_client_header_buffers,
                              prev->large_client_header_buffers,
                              4, 8192);

    if (conf->large_client_header_buffers.size < conf->connection_pool_size) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the \"large_client_header_buffers\" size must be "
                           "equal to or greater than \"connection_pool_size\"");
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->ignore_invalid_headers,
                              prev->ignore_invalid_headers, 1);

    rp_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);

    rp_conf_merge_value(conf->underscores_in_headers,
                              prev->underscores_in_headers, 0);

    if (conf->server_names.nelts == 0) {
        /* the array has 4 empty preallocated elements, so push cannot fail */
        sn = rp_array_push(&conf->server_names);
#if (RP_PCRE)
        sn->regex = NULL;
#endif
        sn->server = conf;
        rp_str_set(&sn->name, "");
    }

    sn = conf->server_names.elts;
    name = sn[0].name;

#if (RP_PCRE)
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
    conf->server_name.data = rp_pstrdup(cf->pool, &name);
    if (conf->server_name.data == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static void *
rp_http_core_create_loc_conf(rp_conf_t *cf)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_pcalloc(cf->pool, sizeof(rp_http_core_loc_conf_t));
    if (clcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
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

    clcf->client_max_body_size = RP_CONF_UNSET;
    clcf->client_body_buffer_size = RP_CONF_UNSET_SIZE;
    clcf->client_body_timeout = RP_CONF_UNSET_MSEC;
    clcf->satisfy = RP_CONF_UNSET_UINT;
    clcf->auth_delay = RP_CONF_UNSET_MSEC;
    clcf->if_modified_since = RP_CONF_UNSET_UINT;
    clcf->max_ranges = RP_CONF_UNSET_UINT;
    clcf->client_body_in_file_only = RP_CONF_UNSET_UINT;
    clcf->client_body_in_single_buffer = RP_CONF_UNSET;
    clcf->internal = RP_CONF_UNSET;
    clcf->sendfile = RP_CONF_UNSET;
    clcf->sendfile_max_chunk = RP_CONF_UNSET_SIZE;
    clcf->subrequest_output_buffer_size = RP_CONF_UNSET_SIZE;
    clcf->aio = RP_CONF_UNSET;
    clcf->aio_write = RP_CONF_UNSET;
#if (RP_THREADS)
    clcf->thread_pool = RP_CONF_UNSET_PTR;
    clcf->thread_pool_value = RP_CONF_UNSET_PTR;
#endif
    clcf->read_ahead = RP_CONF_UNSET_SIZE;
    clcf->directio = RP_CONF_UNSET;
    clcf->directio_alignment = RP_CONF_UNSET;
    clcf->tcp_nopush = RP_CONF_UNSET;
    clcf->tcp_nodelay = RP_CONF_UNSET;
    clcf->send_timeout = RP_CONF_UNSET_MSEC;
    clcf->send_lowat = RP_CONF_UNSET_SIZE;
    clcf->postpone_output = RP_CONF_UNSET_SIZE;
    clcf->keepalive_timeout = RP_CONF_UNSET_MSEC;
    clcf->keepalive_header = RP_CONF_UNSET;
    clcf->keepalive_requests = RP_CONF_UNSET_UINT;
    clcf->lingering_close = RP_CONF_UNSET_UINT;
    clcf->lingering_time = RP_CONF_UNSET_MSEC;
    clcf->lingering_timeout = RP_CONF_UNSET_MSEC;
    clcf->resolver_timeout = RP_CONF_UNSET_MSEC;
    clcf->reset_timedout_connection = RP_CONF_UNSET;
    clcf->absolute_redirect = RP_CONF_UNSET;
    clcf->server_name_in_redirect = RP_CONF_UNSET;
    clcf->port_in_redirect = RP_CONF_UNSET;
    clcf->msie_padding = RP_CONF_UNSET;
    clcf->msie_refresh = RP_CONF_UNSET;
    clcf->log_not_found = RP_CONF_UNSET;
    clcf->log_subrequest = RP_CONF_UNSET;
    clcf->recursive_error_pages = RP_CONF_UNSET;
    clcf->chunked_transfer_encoding = RP_CONF_UNSET;
    clcf->etag = RP_CONF_UNSET;
    clcf->server_tokens = RP_CONF_UNSET_UINT;
    clcf->types_hash_max_size = RP_CONF_UNSET_UINT;
    clcf->types_hash_bucket_size = RP_CONF_UNSET_UINT;

    clcf->open_file_cache = RP_CONF_UNSET_PTR;
    clcf->open_file_cache_valid = RP_CONF_UNSET;
    clcf->open_file_cache_min_uses = RP_CONF_UNSET_UINT;
    clcf->open_file_cache_errors = RP_CONF_UNSET;
    clcf->open_file_cache_events = RP_CONF_UNSET;

#if (RP_HTTP_GZIP)
    clcf->gzip_vary = RP_CONF_UNSET;
    clcf->gzip_http_version = RP_CONF_UNSET_UINT;
#if (RP_PCRE)
    clcf->gzip_disable = RP_CONF_UNSET_PTR;
#endif
    clcf->gzip_disable_msie6 = 3;
#if (RP_HTTP_DEGRADATION)
    clcf->gzip_disable_degradation = 3;
#endif
#endif

#if (RP_HAVE_OPENAT)
    clcf->disable_symlinks = RP_CONF_UNSET_UINT;
    clcf->disable_symlinks_from = RP_CONF_UNSET_PTR;
#endif

    return clcf;
}


static rp_str_t  rp_http_core_text_html_type = rp_string("text/html");
static rp_str_t  rp_http_core_image_gif_type = rp_string("image/gif");
static rp_str_t  rp_http_core_image_jpeg_type = rp_string("image/jpeg");

static rp_hash_key_t  rp_http_core_default_types[] = {
    { rp_string("html"), 0, &rp_http_core_text_html_type },
    { rp_string("gif"), 0, &rp_http_core_image_gif_type },
    { rp_string("jpg"), 0, &rp_http_core_image_jpeg_type },
    { rp_null_string, 0, NULL }
};


static char *
rp_http_core_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_core_loc_conf_t *prev = parent;
    rp_http_core_loc_conf_t *conf = child;

    rp_uint_t        i;
    rp_hash_key_t   *type;
    rp_hash_init_t   types_hash;

    if (conf->root.data == NULL) {

        conf->alias = prev->alias;
        conf->root = prev->root;
        conf->root_lengths = prev->root_lengths;
        conf->root_values = prev->root_values;

        if (prev->root.data == NULL) {
            rp_str_set(&conf->root, "html");

            if (rp_conf_full_name(cf->cycle, &conf->root, 0) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }

    if (conf->post_action.data == NULL) {
        conf->post_action = prev->post_action;
    }

    rp_conf_merge_uint_value(conf->types_hash_max_size,
                              prev->types_hash_max_size, 1024);

    rp_conf_merge_uint_value(conf->types_hash_bucket_size,
                              prev->types_hash_bucket_size, 64);

    conf->types_hash_bucket_size = rp_align(conf->types_hash_bucket_size,
                                             rp_cacheline_size);

    /*
     * the special handling of the "types" directive in the "http" section
     * to inherit the http's conf->types_hash to all servers
     */

    if (prev->types && prev->types_hash.buckets == NULL) {

        types_hash.hash = &prev->types_hash;
        types_hash.key = rp_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (rp_hash_init(&types_hash, prev->types->elts, prev->types->nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    if (conf->types == NULL) {
        conf->types = prev->types;
        conf->types_hash = prev->types_hash;
    }

    if (conf->types == NULL) {
        conf->types = rp_array_create(cf->pool, 3, sizeof(rp_hash_key_t));
        if (conf->types == NULL) {
            return RP_CONF_ERROR;
        }

        for (i = 0; rp_http_core_default_types[i].key.len; i++) {
            type = rp_array_push(conf->types);
            if (type == NULL) {
                return RP_CONF_ERROR;
            }

            type->key = rp_http_core_default_types[i].key;
            type->key_hash =
                       rp_hash_key_lc(rp_http_core_default_types[i].key.data,
                                       rp_http_core_default_types[i].key.len);
            type->value = rp_http_core_default_types[i].value;
        }
    }

    if (conf->types_hash.buckets == NULL) {

        types_hash.hash = &conf->types_hash;
        types_hash.key = rp_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (rp_hash_init(&types_hash, conf->types->elts, conf->types->nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
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

    rp_conf_merge_str_value(conf->default_type,
                              prev->default_type, "text/plain");

    rp_conf_merge_off_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1 * 1024 * 1024);
    rp_conf_merge_size_value(conf->client_body_buffer_size,
                              prev->client_body_buffer_size,
                              (size_t) 2 * rp_pagesize);
    rp_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 60000);

    rp_conf_merge_bitmask_value(conf->keepalive_disable,
                              prev->keepalive_disable,
                              (RP_CONF_BITMASK_SET
                               |RP_HTTP_KEEPALIVE_DISABLE_MSIE6));
    rp_conf_merge_uint_value(conf->satisfy, prev->satisfy,
                              RP_HTTP_SATISFY_ALL);
    rp_conf_merge_msec_value(conf->auth_delay, prev->auth_delay, 0);
    rp_conf_merge_uint_value(conf->if_modified_since, prev->if_modified_since,
                              RP_HTTP_IMS_EXACT);
    rp_conf_merge_uint_value(conf->max_ranges, prev->max_ranges,
                              RP_MAX_INT32_VALUE);
    rp_conf_merge_uint_value(conf->client_body_in_file_only,
                              prev->client_body_in_file_only,
                              RP_HTTP_REQUEST_BODY_FILE_OFF);
    rp_conf_merge_value(conf->client_body_in_single_buffer,
                              prev->client_body_in_single_buffer, 0);
    rp_conf_merge_value(conf->internal, prev->internal, 0);
    rp_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    rp_conf_merge_size_value(conf->sendfile_max_chunk,
                              prev->sendfile_max_chunk, 0);
    rp_conf_merge_size_value(conf->subrequest_output_buffer_size,
                              prev->subrequest_output_buffer_size,
                              (size_t) rp_pagesize);
    rp_conf_merge_value(conf->aio, prev->aio, RP_HTTP_AIO_OFF);
    rp_conf_merge_value(conf->aio_write, prev->aio_write, 0);
#if (RP_THREADS)
    rp_conf_merge_ptr_value(conf->thread_pool, prev->thread_pool, NULL);
    rp_conf_merge_ptr_value(conf->thread_pool_value, prev->thread_pool_value,
                             NULL);
#endif
    rp_conf_merge_size_value(conf->read_ahead, prev->read_ahead, 0);
    rp_conf_merge_off_value(conf->directio, prev->directio,
                              RP_OPEN_FILE_DIRECTIO_OFF);
    rp_conf_merge_off_value(conf->directio_alignment, prev->directio_alignment,
                              512);
    rp_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    rp_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    rp_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    rp_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
    rp_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);

    if (conf->limit_rate == NULL) {
        conf->limit_rate = prev->limit_rate;
    }

    if (conf->limit_rate_after == NULL) {
        conf->limit_rate_after = prev->limit_rate_after;
    }

    rp_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);
    rp_conf_merge_sec_value(conf->keepalive_header,
                              prev->keepalive_header, 0);
    rp_conf_merge_uint_value(conf->keepalive_requests,
                              prev->keepalive_requests, 100);
    rp_conf_merge_uint_value(conf->lingering_close,
                              prev->lingering_close, RP_HTTP_LINGERING_ON);
    rp_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    rp_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);
    rp_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in http {} context
             * to inherit it in all servers
             */

            prev->resolver = rp_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return RP_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (rp_conf_merge_path_value(cf, &conf->client_body_temp_path,
                              prev->client_body_temp_path,
                              &rp_http_client_temp_path)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->reset_timedout_connection,
                              prev->reset_timedout_connection, 0);
    rp_conf_merge_value(conf->absolute_redirect,
                              prev->absolute_redirect, 1);
    rp_conf_merge_value(conf->server_name_in_redirect,
                              prev->server_name_in_redirect, 0);
    rp_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 1);
    rp_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);
    rp_conf_merge_value(conf->msie_refresh, prev->msie_refresh, 0);
    rp_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);
    rp_conf_merge_value(conf->log_subrequest, prev->log_subrequest, 0);
    rp_conf_merge_value(conf->recursive_error_pages,
                              prev->recursive_error_pages, 0);
    rp_conf_merge_value(conf->chunked_transfer_encoding,
                              prev->chunked_transfer_encoding, 1);
    rp_conf_merge_value(conf->etag, prev->etag, 1);

    rp_conf_merge_uint_value(conf->server_tokens, prev->server_tokens,
                              RP_HTTP_SERVER_TOKENS_ON);

    rp_conf_merge_ptr_value(conf->open_file_cache,
                              prev->open_file_cache, NULL);

    rp_conf_merge_sec_value(conf->open_file_cache_valid,
                              prev->open_file_cache_valid, 60);

    rp_conf_merge_uint_value(conf->open_file_cache_min_uses,
                              prev->open_file_cache_min_uses, 1);

    rp_conf_merge_sec_value(conf->open_file_cache_errors,
                              prev->open_file_cache_errors, 0);

    rp_conf_merge_sec_value(conf->open_file_cache_events,
                              prev->open_file_cache_events, 0);
#if (RP_HTTP_GZIP)

    rp_conf_merge_value(conf->gzip_vary, prev->gzip_vary, 0);
    rp_conf_merge_uint_value(conf->gzip_http_version, prev->gzip_http_version,
                              RP_HTTP_VERSION_11);
    rp_conf_merge_bitmask_value(conf->gzip_proxied, prev->gzip_proxied,
                              (RP_CONF_BITMASK_SET|RP_HTTP_GZIP_PROXIED_OFF));

#if (RP_PCRE)
    rp_conf_merge_ptr_value(conf->gzip_disable, prev->gzip_disable, NULL);
#endif

    if (conf->gzip_disable_msie6 == 3) {
        conf->gzip_disable_msie6 =
            (prev->gzip_disable_msie6 == 3) ? 0 : prev->gzip_disable_msie6;
    }

#if (RP_HTTP_DEGRADATION)

    if (conf->gzip_disable_degradation == 3) {
        conf->gzip_disable_degradation =
            (prev->gzip_disable_degradation == 3) ?
                 0 : prev->gzip_disable_degradation;
    }

#endif
#endif

#if (RP_HAVE_OPENAT)
    rp_conf_merge_uint_value(conf->disable_symlinks, prev->disable_symlinks,
                              RP_DISABLE_SYMLINKS_OFF);
    rp_conf_merge_ptr_value(conf->disable_symlinks_from,
                             prev->disable_symlinks_from, NULL);
#endif

    return RP_CONF_OK;
}


static char *
rp_http_core_listen(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_srv_conf_t *cscf = conf;

    rp_str_t              *value, size;
    rp_url_t               u;
    rp_uint_t              n;
    rp_http_listen_opt_t   lsopt;

    cscf->listen = 1;

    value = cf->args->elts;

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 80;

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return RP_CONF_ERROR;
    }

    rp_memzero(&lsopt, sizeof(rp_http_listen_opt_t));

    lsopt.backlog = RP_LISTEN_BACKLOG;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (RP_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
#if (RP_HAVE_TCP_FASTOPEN)
    lsopt.fastopen = -1;
#endif
#if (RP_HAVE_INET6)
    lsopt.ipv6only = 1;
#endif

    for (n = 2; n < cf->args->nelts; n++) {

        if (rp_strcmp(value[n].data, "default_server") == 0
            || rp_strcmp(value[n].data, "default") == 0)
        {
            lsopt.default_server = 1;
            continue;
        }

        if (rp_strcmp(value[n].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

#if (RP_HAVE_SETFIB)
        if (rp_strncmp(value[n].data, "setfib=", 7) == 0) {
            lsopt.setfib = rp_atoi(value[n].data + 7, value[n].len - 7);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.setfib == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[n]);
                return RP_CONF_ERROR;
            }

            continue;
        }
#endif

#if (RP_HAVE_TCP_FASTOPEN)
        if (rp_strncmp(value[n].data, "fastopen=", 9) == 0) {
            lsopt.fastopen = rp_atoi(value[n].data + 9, value[n].len - 9);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.fastopen == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[n]);
                return RP_CONF_ERROR;
            }

            continue;
        }
#endif

        if (rp_strncmp(value[n].data, "backlog=", 8) == 0) {
            lsopt.backlog = rp_atoi(value[n].data + 8, value[n].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == RP_ERROR || lsopt.backlog == 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.rcvbuf = rp_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.sndbuf = rp_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[n].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (rp_strcmp(value[n].data, "deferred") == 0) {
#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rp_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
#if (RP_HAVE_INET6 && defined IPV6_V6ONLY)
            if (rp_strcmp(&value[n].data[10], "n") == 0) {
                lsopt.ipv6only = 1;

            } else if (rp_strcmp(&value[n].data[10], "ff") == 0) {
                lsopt.ipv6only = 0;

            } else {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[n].data[9]);
                return RP_CONF_ERROR;
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strcmp(value[n].data, "reuseport") == 0) {
#if (RP_HAVE_REUSEPORT)
            lsopt.reuseport = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rp_strcmp(value[n].data, "ssl") == 0) {
#if (RP_HTTP_SSL)
            lsopt.ssl = 1;
            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rp_http_ssl_module");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strcmp(value[n].data, "http2") == 0) {
#if (RP_HTTP_V2)
            lsopt.http2 = 1;
            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the \"http2\" parameter requires "
                               "rp_http_v2_module");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strcmp(value[n].data, "spdy") == 0) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "invalid parameter \"spdy\": "
                               "rp_http_spdy_module was superseded "
                               "by rp_http_v2_module");
            continue;
        }

        if (rp_strncmp(value[n].data, "so_keepalive=", 13) == 0) {

            if (rp_strcmp(&value[n].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (rp_strcmp(&value[n].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (RP_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                rp_str_t   s;

                end = value[n].data + value[n].len;
                s.data = value[n].data + 13;

                p = rp_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = rp_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) RP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = rp_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = rp_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) RP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = rp_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == RP_ERROR) {
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

                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return RP_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (RP_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[n].data[13]);
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strcmp(value[n].data, "proxy_protocol") == 0) {
            lsopt.proxy_protocol = 1;
            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[n]);
        return RP_CONF_ERROR;
    }

    for (n = 0; n < u.naddrs; n++) {
        lsopt.sockaddr = u.addrs[n].sockaddr;
        lsopt.socklen = u.addrs[n].socklen;
        lsopt.addr_text = u.addrs[n].name;
        lsopt.wildcard = rp_inet_wildcard(lsopt.sockaddr);

        if (rp_http_add_listen(cf, cscf, &lsopt) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_http_core_server_name(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    rp_str_t               *value;
    rp_uint_t               i;
    rp_http_server_name_t  *sn;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return RP_CONF_ERROR;
        }

        if (rp_strchr(value[i].data, '/')) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }

        sn = rp_array_push(&cscf->server_names);
        if (sn == NULL) {
            return RP_CONF_ERROR;
        }

#if (RP_PCRE)
        sn->regex = NULL;
#endif
        sn->server = cscf;

        if (rp_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;

        } else {
            sn->name = value[i];
        }

        if (value[i].data[0] != '~') {
            rp_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

#if (RP_PCRE)
        {
        u_char               *p;
        rp_regex_compile_t   rc;
        u_char                errstr[RP_MAX_CONF_ERRSTR];

        if (value[i].len == 1) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "empty regex in server name \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }

        value[i].len--;
        value[i].data++;

        rp_memzero(&rc, sizeof(rp_regex_compile_t));

        rc.pattern = value[i];
        rc.err.len = RP_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        for (p = value[i].data; p < value[i].data + value[i].len; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                rc.options = RP_REGEX_CASELESS;
                break;
            }
        }

        sn->regex = rp_http_regex_compile(cf, &rc);
        if (sn->regex == NULL) {
            return RP_CONF_ERROR;
        }

        sn->name = value[i];
        cscf->captures = (rc.captures > 0);
        }
#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return RP_CONF_ERROR;
#endif
    }

    return RP_CONF_OK;
}


static char *
rp_http_core_root(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t                  *value;
    rp_int_t                   alias;
    rp_uint_t                  n;
    rp_http_script_compile_t   sc;

    alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;

    if (clcf->root.data) {

        if ((clcf->alias != 0) == alias) {
            return "is duplicate";
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" directive is duplicate, "
                           "\"%s\" directive was specified earlier",
                           &cmd->name, clcf->alias ? "alias" : "root");

        return RP_CONF_ERROR;
    }

    if (clcf->named && alias) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the \"alias\" directive cannot be used "
                           "inside the named location");

        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    if (rp_strstr(value[1].data, "$document_root")
        || rp_strstr(value[1].data, "${document_root}"))
    {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the $document_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return RP_CONF_ERROR;
    }

    if (rp_strstr(value[1].data, "$realpath_root")
        || rp_strstr(value[1].data, "${realpath_root}"))
    {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the $realpath_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return RP_CONF_ERROR;
    }

    clcf->alias = alias ? clcf->name.len : 0;
    clcf->root = value[1];

    if (!alias && clcf->root.len > 0
        && clcf->root.data[clcf->root.len - 1] == '/')
    {
        clcf->root.len--;
    }

    if (clcf->root.data[0] != '$') {
        if (rp_conf_full_name(cf->cycle, &clcf->root, 0) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    n = rp_http_script_variables_count(&clcf->root);

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));
    sc.variables = n;

#if (RP_PCRE)
    if (alias && clcf->regex) {
        clcf->alias = RP_MAX_SIZE_T_VALUE;
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

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static rp_http_method_name_t  rp_methods_names[] = {
    { (u_char *) "GET",       (uint32_t) ~RP_HTTP_GET },
    { (u_char *) "HEAD",      (uint32_t) ~RP_HTTP_HEAD },
    { (u_char *) "POST",      (uint32_t) ~RP_HTTP_POST },
    { (u_char *) "PUT",       (uint32_t) ~RP_HTTP_PUT },
    { (u_char *) "DELETE",    (uint32_t) ~RP_HTTP_DELETE },
    { (u_char *) "MKCOL",     (uint32_t) ~RP_HTTP_MKCOL },
    { (u_char *) "COPY",      (uint32_t) ~RP_HTTP_COPY },
    { (u_char *) "MOVE",      (uint32_t) ~RP_HTTP_MOVE },
    { (u_char *) "OPTIONS",   (uint32_t) ~RP_HTTP_OPTIONS },
    { (u_char *) "PROPFIND",  (uint32_t) ~RP_HTTP_PROPFIND },
    { (u_char *) "PROPPATCH", (uint32_t) ~RP_HTTP_PROPPATCH },
    { (u_char *) "LOCK",      (uint32_t) ~RP_HTTP_LOCK },
    { (u_char *) "UNLOCK",    (uint32_t) ~RP_HTTP_UNLOCK },
    { (u_char *) "PATCH",     (uint32_t) ~RP_HTTP_PATCH },
    { NULL, 0 }
};


static char *
rp_http_core_limit_except(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *pclcf = conf;

    char                      *rv;
    void                      *mconf;
    rp_str_t                 *value;
    rp_uint_t                 i;
    rp_conf_t                 save;
    rp_http_module_t         *module;
    rp_http_conf_ctx_t       *ctx, *pctx;
    rp_http_method_name_t    *name;
    rp_http_core_loc_conf_t  *clcf;

    if (pclcf->limit_except) {
        return "is duplicate";
    }

    pclcf->limit_except = 0xffffffff;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        for (name = rp_methods_names; name->name; name++) {

            if (rp_strcasecmp(value[i].data, name->name) == 0) {
                pclcf->limit_except &= name->method;
                goto next;
            }
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid method \"%V\"", &value[i]);
        return RP_CONF_ERROR;

    next:
        continue;
    }

    if (!(pclcf->limit_except & RP_HTTP_GET)) {
        pclcf->limit_except &= (uint32_t) ~RP_HTTP_HEAD;
    }

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }


    clcf = ctx->loc_conf[rp_http_core_module.ctx_index];
    pclcf->limit_except_loc_conf = ctx->loc_conf;
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;
    clcf->lmt_excpt = 1;

    if (rp_http_add_location(cf, &pclcf->locations, clcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_HTTP_LMT_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
rp_http_core_set_aio(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t  *value;

    if (clcf->aio != RP_CONF_UNSET) {
        return "is duplicate";
    }

#if (RP_THREADS)
    clcf->thread_pool = NULL;
    clcf->thread_pool_value = NULL;
#endif

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        clcf->aio = RP_HTTP_AIO_OFF;
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[1].data, "on") == 0) {
#if (RP_HAVE_FILE_AIO)
        clcf->aio = RP_HTTP_AIO_ON;
        return RP_CONF_OK;
#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"aio on\" "
                           "is unsupported on this platform");
        return RP_CONF_ERROR;
#endif
    }

#if (RP_HAVE_AIO_SENDFILE)

    if (rp_strcmp(value[1].data, "sendfile") == 0) {
        clcf->aio = RP_HTTP_AIO_ON;

        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "the \"sendfile\" parameter of "
                           "the \"aio\" directive is deprecated");
        return RP_CONF_OK;
    }

#endif

    if (rp_strncmp(value[1].data, "threads", 7) == 0
        && (value[1].len == 7 || value[1].data[7] == '='))
    {
#if (RP_THREADS)
        rp_str_t                          name;
        rp_thread_pool_t                 *tp;
        rp_http_complex_value_t           cv;
        rp_http_compile_complex_value_t   ccv;

        clcf->aio = RP_HTTP_AIO_THREADS;

        if (value[1].len >= 8) {
            name.len = value[1].len - 8;
            name.data = value[1].data + 8;

            rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &name;
            ccv.complex_value = &cv;

            if (rp_http_compile_complex_value(&ccv) != RP_OK) {
                return RP_CONF_ERROR;
            }

            if (cv.lengths != NULL) {
                clcf->thread_pool_value = rp_palloc(cf->pool,
                                    sizeof(rp_http_complex_value_t));
                if (clcf->thread_pool_value == NULL) {
                    return RP_CONF_ERROR;
                }

                *clcf->thread_pool_value = cv;

                return RP_CONF_OK;
            }

            tp = rp_thread_pool_add(cf, &name);

        } else {
            tp = rp_thread_pool_add(cf, NULL);
        }

        if (tp == NULL) {
            return RP_CONF_ERROR;
        }

        clcf->thread_pool = tp;

        return RP_CONF_OK;
#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"aio threads\" "
                           "is unsupported on this platform");
        return RP_CONF_ERROR;
#endif
    }

    return "invalid value";
}


static char *
rp_http_core_directio(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t  *value;

    if (clcf->directio != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        clcf->directio = RP_OPEN_FILE_DIRECTIO_OFF;
        return RP_CONF_OK;
    }

    clcf->directio = rp_parse_offset(&value[1]);
    if (clcf->directio == (off_t) RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


static char *
rp_http_core_error_page(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    u_char                            *p;
    rp_int_t                          overwrite;
    rp_str_t                         *value, uri, args;
    rp_uint_t                         i, n;
    rp_http_err_page_t               *err;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    if (clcf->error_pages == NULL) {
        clcf->error_pages = rp_array_create(cf->pool, 4,
                                             sizeof(rp_http_err_page_t));
        if (clcf->error_pages == NULL) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    i = cf->args->nelts - 2;

    if (value[i].data[0] == '=') {
        if (i == 1) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }

        if (value[i].len > 1) {
            overwrite = rp_atoi(&value[i].data[1], value[i].len - 1);

            if (overwrite == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
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

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &uri;
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    rp_str_null(&args);

    if (cv.lengths == NULL && uri.len && uri.data[0] == '/') {
        p = (u_char *) rp_strchr(uri.data, '?');

        if (p) {
            cv.value.len = p - uri.data;
            cv.value.data = uri.data;
            p++;
            args.len = (uri.data + uri.len) - p;
            args.data = p;
        }
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        err = rp_array_push(clcf->error_pages);
        if (err == NULL) {
            return RP_CONF_ERROR;
        }

        err->status = rp_atoi(value[i].data, value[i].len);

        if (err->status == RP_ERROR || err->status == 499) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }

        if (err->status < 300 || err->status > 599) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "value \"%V\" must be between 300 and 599",
                               &value[i]);
            return RP_CONF_ERROR;
        }

        err->overwrite = overwrite;

        if (overwrite == -1) {
            switch (err->status) {
                case RP_HTTP_TO_HTTPS:
                case RP_HTTPS_CERT_ERROR:
                case RP_HTTPS_NO_CERT:
                case RP_HTTP_REQUEST_HEADER_TOO_LARGE:
                    err->overwrite = RP_HTTP_BAD_REQUEST;
            }
        }

        err->value = cv;
        err->args = args;
    }

    return RP_CONF_OK;
}


static char *
rp_http_core_open_file_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    time_t       inactive;
    rp_str_t   *value, s;
    rp_int_t    max;
    rp_uint_t   i;

    if (clcf->open_file_cache != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "max=", 4) == 0) {

            max = rp_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rp_parse_time(&s, 1);
            if (inactive == (time_t) RP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rp_strcmp(value[i].data, "off") == 0) {

            clcf->open_file_cache = NULL;

            continue;
        }

    failed:

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid \"open_file_cache\" parameter \"%V\"",
                           &value[i]);
        return RP_CONF_ERROR;
    }

    if (clcf->open_file_cache == NULL) {
        return RP_CONF_OK;
    }

    if (max == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                        "\"open_file_cache\" must have the \"max\" parameter");
        return RP_CONF_ERROR;
    }

    clcf->open_file_cache = rp_open_file_cache_init(cf->pool, max, inactive);
    if (clcf->open_file_cache) {
        return RP_CONF_OK;
    }

    return RP_CONF_ERROR;
}


static char *
rp_http_core_error_log(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    return rp_log_set_log(cf, &clcf->error_log);
}


static char *
rp_http_core_keepalive(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t  *value;

    if (clcf->keepalive_timeout != RP_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->keepalive_timeout = rp_parse_time(&value[1], 0);

    if (clcf->keepalive_timeout == (rp_msec_t) RP_ERROR) {
        return "invalid value";
    }

    if (cf->args->nelts == 2) {
        return RP_CONF_OK;
    }

    clcf->keepalive_header = rp_parse_time(&value[2], 1);

    if (clcf->keepalive_header == (time_t) RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


static char *
rp_http_core_internal(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    if (clcf->internal != RP_CONF_UNSET) {
        return "is duplicate";
    }

    clcf->internal = 1;

    return RP_CONF_OK;
}


static char *
rp_http_core_resolver(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf = conf;

    rp_str_t  *value;

    if (clcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->resolver = rp_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (clcf->resolver == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


#if (RP_HTTP_GZIP)

static char *
rp_http_gzip_disable(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf = conf;

#if (RP_PCRE)

    rp_str_t            *value;
    rp_uint_t            i;
    rp_regex_elt_t      *re;
    rp_regex_compile_t   rc;
    u_char                errstr[RP_MAX_CONF_ERRSTR];

    if (clcf->gzip_disable == RP_CONF_UNSET_PTR) {
        clcf->gzip_disable = rp_array_create(cf->pool, 2,
                                              sizeof(rp_regex_elt_t));
        if (clcf->gzip_disable == NULL) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    rp_memzero(&rc, sizeof(rp_regex_compile_t));

    rc.pool = cf->pool;
    rc.err.len = RP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (RP_HTTP_DEGRADATION)

        if (rp_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        re = rp_array_push(clcf->gzip_disable);
        if (re == NULL) {
            return RP_CONF_ERROR;
        }

        rc.pattern = value[i];
        rc.options = RP_REGEX_CASELESS;

        if (rp_regex_compile(&rc) != RP_OK) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0, "%V", &rc.err);
            return RP_CONF_ERROR;
        }

        re->regex = rc.regex;
        re->name = value[i].data;
    }

    return RP_CONF_OK;

#else
    rp_str_t   *value;
    rp_uint_t   i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (rp_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (RP_HTTP_DEGRADATION)

        if (rp_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "without PCRE library \"gzip_disable\" supports "
                           "builtin \"msie6\" and \"degradation\" mask only");

        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;

#endif
}

#endif


#if (RP_HAVE_OPENAT)

static char *
rp_http_disable_symlinks(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t *clcf = conf;

    rp_str_t                         *value;
    rp_uint_t                         i;
    rp_http_compile_complex_value_t   ccv;

    if (clcf->disable_symlinks != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "off") == 0) {
            clcf->disable_symlinks = RP_DISABLE_SYMLINKS_OFF;
            continue;
        }

        if (rp_strcmp(value[i].data, "if_not_owner") == 0) {
            clcf->disable_symlinks = RP_DISABLE_SYMLINKS_NOTOWNER;
            continue;
        }

        if (rp_strcmp(value[i].data, "on") == 0) {
            clcf->disable_symlinks = RP_DISABLE_SYMLINKS_ON;
            continue;
        }

        if (rp_strncmp(value[i].data, "from=", 5) == 0) {
            value[i].len -= 5;
            value[i].data += 5;

            rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = rp_palloc(cf->pool,
                                           sizeof(rp_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return RP_CONF_ERROR;
            }

            if (rp_http_compile_complex_value(&ccv) != RP_OK) {
                return RP_CONF_ERROR;
            }

            clcf->disable_symlinks_from = ccv.complex_value;

            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RP_CONF_ERROR;
    }

    if (clcf->disable_symlinks == RP_CONF_UNSET_UINT) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"off\", \"on\" "
                           "or \"if_not_owner\" parameter",
                           &cmd->name);
        return RP_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        clcf->disable_symlinks_from = NULL;
        return RP_CONF_OK;
    }

    if (clcf->disable_symlinks_from == RP_CONF_UNSET_PTR) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "duplicate parameters \"%V %V\"",
                           &value[1], &value[2]);
        return RP_CONF_ERROR;
    }

    if (clcf->disable_symlinks == RP_DISABLE_SYMLINKS_OFF) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"from=\" cannot be used with \"off\" parameter");
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}

#endif


static char *
rp_http_core_lowat_check(rp_conf_t *cf, void *post, void *data)
{
#if (RP_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= rp_freebsd_net_inet_tcp_sendspace) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           rp_freebsd_net_inet_tcp_sendspace);

        return RP_CONF_ERROR;
    }

#elif !(RP_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return RP_CONF_OK;
}


static char *
rp_http_core_pool_size(rp_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < RP_MIN_POOL_SIZE) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           RP_MIN_POOL_SIZE);
        return RP_CONF_ERROR;
    }

    if (*sp % RP_POOL_ALIGNMENT) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           RP_POOL_ALIGNMENT);
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
