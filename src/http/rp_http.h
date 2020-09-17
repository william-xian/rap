
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_H_INCLUDED_
#define _RP_HTTP_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct rp_http_request_s     rp_http_request_t;
typedef struct rp_http_upstream_s    rp_http_upstream_t;
typedef struct rp_http_cache_s       rp_http_cache_t;
typedef struct rp_http_file_cache_s  rp_http_file_cache_t;
typedef struct rp_http_log_ctx_s     rp_http_log_ctx_t;
typedef struct rp_http_chunked_s     rp_http_chunked_t;
typedef struct rp_http_v2_stream_s   rp_http_v2_stream_t;

typedef rp_int_t (*rp_http_header_handler_pt)(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
typedef u_char *(*rp_http_log_handler_pt)(rp_http_request_t *r,
    rp_http_request_t *sr, u_char *buf, size_t len);


#include <rp_http_variables.h>
#include <rp_http_config.h>
#include <rp_http_request.h>
#include <rp_http_script.h>
#include <rp_http_upstream.h>
#include <rp_http_upstream_round_robin.h>
#include <rp_http_core_module.h>

#if (RP_HTTP_V2)
#include <rp_http_v2.h>
#endif
#if (RP_HTTP_CACHE)
#include <rp_http_cache.h>
#endif
#if (RP_HTTP_SSI)
#include <rp_http_ssi_filter_module.h>
#endif
#if (RP_HTTP_SSL)
#include <rp_http_ssl_module.h>
#endif


struct rp_http_log_ctx_s {
    rp_connection_t    *connection;
    rp_http_request_t  *request;
    rp_http_request_t  *current_request;
};


struct rp_http_chunked_s {
    rp_uint_t           state;
    off_t                size;
    off_t                length;
};


typedef struct {
    rp_uint_t           http_version;
    rp_uint_t           code;
    rp_uint_t           count;
    u_char              *start;
    u_char              *end;
} rp_http_status_t;


#define rp_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define rp_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


rp_int_t rp_http_add_location(rp_conf_t *cf, rp_queue_t **locations,
    rp_http_core_loc_conf_t *clcf);
rp_int_t rp_http_add_listen(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_listen_opt_t *lsopt);


void rp_http_init_connection(rp_connection_t *c);
void rp_http_close_connection(rp_connection_t *c);

#if (RP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
int rp_http_ssl_servername(rp_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#if (RP_HTTP_SSL && defined SSL_R_CERT_CB_ERROR)
int rp_http_ssl_certificate(rp_ssl_conn_t *ssl_conn, void *arg);
#endif


rp_int_t rp_http_parse_request_line(rp_http_request_t *r, rp_buf_t *b);
rp_int_t rp_http_parse_uri(rp_http_request_t *r);
rp_int_t rp_http_parse_complex_uri(rp_http_request_t *r,
    rp_uint_t merge_slashes);
rp_int_t rp_http_parse_status_line(rp_http_request_t *r, rp_buf_t *b,
    rp_http_status_t *status);
rp_int_t rp_http_parse_unsafe_uri(rp_http_request_t *r, rp_str_t *uri,
    rp_str_t *args, rp_uint_t *flags);
rp_int_t rp_http_parse_header_line(rp_http_request_t *r, rp_buf_t *b,
    rp_uint_t allow_underscores);
rp_int_t rp_http_parse_multi_header_lines(rp_array_t *headers,
    rp_str_t *name, rp_str_t *value);
rp_int_t rp_http_parse_set_cookie_lines(rp_array_t *headers,
    rp_str_t *name, rp_str_t *value);
rp_int_t rp_http_arg(rp_http_request_t *r, u_char *name, size_t len,
    rp_str_t *value);
void rp_http_split_args(rp_http_request_t *r, rp_str_t *uri,
    rp_str_t *args);
rp_int_t rp_http_parse_chunked(rp_http_request_t *r, rp_buf_t *b,
    rp_http_chunked_t *ctx);


rp_http_request_t *rp_http_create_request(rp_connection_t *c);
rp_int_t rp_http_process_request_uri(rp_http_request_t *r);
rp_int_t rp_http_process_request_header(rp_http_request_t *r);
void rp_http_process_request(rp_http_request_t *r);
void rp_http_update_location_config(rp_http_request_t *r);
void rp_http_handler(rp_http_request_t *r);
void rp_http_run_posted_requests(rp_connection_t *c);
rp_int_t rp_http_post_request(rp_http_request_t *r,
    rp_http_posted_request_t *pr);
void rp_http_finalize_request(rp_http_request_t *r, rp_int_t rc);
void rp_http_free_request(rp_http_request_t *r, rp_int_t rc);

void rp_http_empty_handler(rp_event_t *wev);
void rp_http_request_empty_handler(rp_http_request_t *r);


#define RP_HTTP_LAST   1
#define RP_HTTP_FLUSH  2

rp_int_t rp_http_send_special(rp_http_request_t *r, rp_uint_t flags);


rp_int_t rp_http_read_client_request_body(rp_http_request_t *r,
    rp_http_client_body_handler_pt post_handler);
rp_int_t rp_http_read_unbuffered_request_body(rp_http_request_t *r);

rp_int_t rp_http_send_header(rp_http_request_t *r);
rp_int_t rp_http_special_response_handler(rp_http_request_t *r,
    rp_int_t error);
rp_int_t rp_http_filter_finalize_request(rp_http_request_t *r,
    rp_module_t *m, rp_int_t error);
void rp_http_clean_header(rp_http_request_t *r);


rp_int_t rp_http_discard_request_body(rp_http_request_t *r);
void rp_http_discarded_request_body_handler(rp_http_request_t *r);
void rp_http_block_reading(rp_http_request_t *r);
void rp_http_test_reading(rp_http_request_t *r);


char *rp_http_types_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_http_merge_types(rp_conf_t *cf, rp_array_t **keys,
    rp_hash_t *types_hash, rp_array_t **prev_keys,
    rp_hash_t *prev_types_hash, rp_str_t *default_types);
rp_int_t rp_http_set_default_types(rp_conf_t *cf, rp_array_t **types,
    rp_str_t *default_type);

#if (RP_HTTP_DEGRADATION)
rp_uint_t  rp_http_degraded(rp_http_request_t *);
#endif


extern rp_module_t  rp_http_module;

extern rp_str_t  rp_http_html_default_types[];


extern rp_http_output_header_filter_pt  rp_http_top_header_filter;
extern rp_http_output_body_filter_pt    rp_http_top_body_filter;
extern rp_http_request_body_filter_pt   rp_http_top_request_body_filter;


#endif /* _RP_HTTP_H_INCLUDED_ */
