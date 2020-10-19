
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_H_INCLUDED_
#define _RAP_HTTP_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct rap_http_request_s     rap_http_request_t;
typedef struct rap_http_upstream_s    rap_http_upstream_t;
typedef struct rap_http_cache_s       rap_http_cache_t;
typedef struct rap_http_file_cache_s  rap_http_file_cache_t;
typedef struct rap_http_log_ctx_s     rap_http_log_ctx_t;
typedef struct rap_http_chunked_s     rap_http_chunked_t;
typedef struct rap_http_v2_stream_s   rap_http_v2_stream_t;

typedef rap_int_t (*rap_http_header_handler_pt)(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
typedef u_char *(*rap_http_log_handler_pt)(rap_http_request_t *r,
    rap_http_request_t *sr, u_char *buf, size_t len);


#include <rap_http_variables.h>
#include <rap_http_config.h>
#include <rap_http_request.h>
#include <rap_http_script.h>
#include <rap_http_upstream.h>
#include <rap_http_upstream_round_robin.h>
#include <rap_http_core_module.h>

#if (RAP_HTTP_V2)
#include <rap_http_v2.h>
#endif
#if (RAP_HTTP_CACHE)
#include <rap_http_cache.h>
#endif
#if (RAP_HTTP_SSI)
#include <rap_http_ssi_filter_module.h>
#endif
#if (RAP_HTTP_SSL)
#include <rap_http_ssl_module.h>
#endif


struct rap_http_log_ctx_s {
    rap_connection_t    *connection;
    rap_http_request_t  *request;
    rap_http_request_t  *current_request;
};


struct rap_http_chunked_s {
    rap_uint_t           state;
    off_t                size;
    off_t                length;
};


typedef struct {
    rap_uint_t           http_version;
    rap_uint_t           code;
    rap_uint_t           count;
    u_char              *start;
    u_char              *end;
} rap_http_status_t;


#define rap_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define rap_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


rap_int_t rap_http_add_location(rap_conf_t *cf, rap_queue_t **locations,
    rap_http_core_loc_conf_t *clcf);
rap_int_t rap_http_add_listen(rap_conf_t *cf, rap_http_core_srv_conf_t *cscf,
    rap_http_listen_opt_t *lsopt);


void rap_http_init_connection(rap_connection_t *c);
void rap_http_close_connection(rap_connection_t *c);

#if (RAP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
int rap_http_ssl_servername(rap_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#if (RAP_HTTP_SSL && defined SSL_R_CERT_CB_ERROR)
int rap_http_ssl_certificate(rap_ssl_conn_t *ssl_conn, void *arg);
#endif


rap_int_t rap_http_parse_request_line(rap_http_request_t *r, rap_buf_t *b);
rap_int_t rap_http_parse_uri(rap_http_request_t *r);
rap_int_t rap_http_parse_complex_uri(rap_http_request_t *r,
    rap_uint_t merge_slashes);
rap_int_t rap_http_parse_status_line(rap_http_request_t *r, rap_buf_t *b,
    rap_http_status_t *status);
rap_int_t rap_http_parse_unsafe_uri(rap_http_request_t *r, rap_str_t *uri,
    rap_str_t *args, rap_uint_t *flags);
rap_int_t rap_http_parse_header_line(rap_http_request_t *r, rap_buf_t *b,
    rap_uint_t allow_underscores);
rap_int_t rap_http_parse_multi_header_lines(rap_array_t *headers,
    rap_str_t *name, rap_str_t *value);
rap_int_t rap_http_parse_set_cookie_lines(rap_array_t *headers,
    rap_str_t *name, rap_str_t *value);
rap_int_t rap_http_arg(rap_http_request_t *r, u_char *name, size_t len,
    rap_str_t *value);
void rap_http_split_args(rap_http_request_t *r, rap_str_t *uri,
    rap_str_t *args);
rap_int_t rap_http_parse_chunked(rap_http_request_t *r, rap_buf_t *b,
    rap_http_chunked_t *ctx);


rap_http_request_t *rap_http_create_request(rap_connection_t *c);
rap_int_t rap_http_process_request_uri(rap_http_request_t *r);
rap_int_t rap_http_process_request_header(rap_http_request_t *r);
void rap_http_process_request(rap_http_request_t *r);
void rap_http_update_location_config(rap_http_request_t *r);
void rap_http_handler(rap_http_request_t *r);
void rap_http_run_posted_requests(rap_connection_t *c);
rap_int_t rap_http_post_request(rap_http_request_t *r,
    rap_http_posted_request_t *pr);
void rap_http_finalize_request(rap_http_request_t *r, rap_int_t rc);
void rap_http_free_request(rap_http_request_t *r, rap_int_t rc);

void rap_http_empty_handler(rap_event_t *wev);
void rap_http_request_empty_handler(rap_http_request_t *r);


#define RAP_HTTP_LAST   1
#define RAP_HTTP_FLUSH  2

rap_int_t rap_http_send_special(rap_http_request_t *r, rap_uint_t flags);


rap_int_t rap_http_read_client_request_body(rap_http_request_t *r,
    rap_http_client_body_handler_pt post_handler);
rap_int_t rap_http_read_unbuffered_request_body(rap_http_request_t *r);

rap_int_t rap_http_send_header(rap_http_request_t *r);
rap_int_t rap_http_special_response_handler(rap_http_request_t *r,
    rap_int_t error);
rap_int_t rap_http_filter_finalize_request(rap_http_request_t *r,
    rap_module_t *m, rap_int_t error);
void rap_http_clean_header(rap_http_request_t *r);


rap_int_t rap_http_discard_request_body(rap_http_request_t *r);
void rap_http_discarded_request_body_handler(rap_http_request_t *r);
void rap_http_block_reading(rap_http_request_t *r);
void rap_http_test_reading(rap_http_request_t *r);


char *rap_http_types_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_http_merge_types(rap_conf_t *cf, rap_array_t **keys,
    rap_hash_t *types_hash, rap_array_t **prev_keys,
    rap_hash_t *prev_types_hash, rap_str_t *default_types);
rap_int_t rap_http_set_default_types(rap_conf_t *cf, rap_array_t **types,
    rap_str_t *default_type);

#if (RAP_HTTP_DEGRADATION)
rap_uint_t  rap_http_degraded(rap_http_request_t *);
#endif


extern rap_module_t  rap_http_module;

extern rap_str_t  rap_http_html_default_types[];


extern rap_http_output_header_filter_pt  rap_http_top_header_filter;
extern rap_http_output_body_filter_pt    rap_http_top_body_filter;
extern rap_http_request_body_filter_pt   rap_http_top_request_body_filter;


#endif /* _RAP_HTTP_H_INCLUDED_ */
