
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_REQUEST_H_INCLUDED_
#define _RAP_HTTP_REQUEST_H_INCLUDED_


#define RAP_HTTP_MAX_URI_CHANGES           10
#define RAP_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define RAP_HTTP_LC_HEADER_LEN             32


#define RAP_HTTP_DISCARD_BUFFER_SIZE       4096
#define RAP_HTTP_LINGERING_BUFFER_SIZE     4096


#define RAP_HTTP_VERSION_9                 9
#define RAP_HTTP_VERSION_10                1000
#define RAP_HTTP_VERSION_11                1001
#define RAP_HTTP_VERSION_20                2000

#define RAP_HTTP_UNKNOWN                   0x0001
#define RAP_HTTP_GET                       0x0002
#define RAP_HTTP_HEAD                      0x0004
#define RAP_HTTP_POST                      0x0008
#define RAP_HTTP_PUT                       0x0010
#define RAP_HTTP_DELETE                    0x0020
#define RAP_HTTP_MKCOL                     0x0040
#define RAP_HTTP_COPY                      0x0080
#define RAP_HTTP_MOVE                      0x0100
#define RAP_HTTP_OPTIONS                   0x0200
#define RAP_HTTP_PROPFIND                  0x0400
#define RAP_HTTP_PROPPATCH                 0x0800
#define RAP_HTTP_LOCK                      0x1000
#define RAP_HTTP_UNLOCK                    0x2000
#define RAP_HTTP_PATCH                     0x4000
#define RAP_HTTP_TRACE                     0x8000

#define RAP_HTTP_CONNECTION_CLOSE          1
#define RAP_HTTP_CONNECTION_KEEP_ALIVE     2


#define RAP_NONE                           1


#define RAP_HTTP_PARSE_HEADER_DONE         1

#define RAP_HTTP_CLIENT_ERROR              10
#define RAP_HTTP_PARSE_INVALID_METHOD      10
#define RAP_HTTP_PARSE_INVALID_REQUEST     11
#define RAP_HTTP_PARSE_INVALID_VERSION     12
#define RAP_HTTP_PARSE_INVALID_09_METHOD   13

#define RAP_HTTP_PARSE_INVALID_HEADER      14


/* unused                                  1 */
#define RAP_HTTP_SUBREQUEST_IN_MEMORY      2
#define RAP_HTTP_SUBREQUEST_WAITED         4
#define RAP_HTTP_SUBREQUEST_CLONE          8
#define RAP_HTTP_SUBREQUEST_BACKGROUND     16

#define RAP_HTTP_LOG_UNSAFE                1


#define RAP_HTTP_CONTINUE                  100
#define RAP_HTTP_SWITCHING_PROTOCOLS       101
#define RAP_HTTP_PROCESSING                102

#define RAP_HTTP_OK                        200
#define RAP_HTTP_CREATED                   201
#define RAP_HTTP_ACCEPTED                  202
#define RAP_HTTP_NO_CONTENT                204
#define RAP_HTTP_PARTIAL_CONTENT           206

#define RAP_HTTP_SPECIAL_RESPONSE          300
#define RAP_HTTP_MOVED_PERMANENTLY         301
#define RAP_HTTP_MOVED_TEMPORARILY         302
#define RAP_HTTP_SEE_OTHER                 303
#define RAP_HTTP_NOT_MODIFIED              304
#define RAP_HTTP_TEMPORARY_REDIRECT        307
#define RAP_HTTP_PERMANENT_REDIRECT        308

#define RAP_HTTP_BAD_REQUEST               400
#define RAP_HTTP_UNAUTHORIZED              401
#define RAP_HTTP_FORBIDDEN                 403
#define RAP_HTTP_NOT_FOUND                 404
#define RAP_HTTP_NOT_ALLOWED               405
#define RAP_HTTP_REQUEST_TIME_OUT          408
#define RAP_HTTP_CONFLICT                  409
#define RAP_HTTP_LENGTH_REQUIRED           411
#define RAP_HTTP_PRECONDITION_FAILED       412
#define RAP_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define RAP_HTTP_REQUEST_URI_TOO_LARGE     414
#define RAP_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define RAP_HTTP_RANGE_NOT_SATISFIABLE     416
#define RAP_HTTP_MISDIRECTED_REQUEST       421
#define RAP_HTTP_TOO_MANY_REQUESTS         429


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define RAP_HTTP_CLOSE                     444

#define RAP_HTTP_RAP_CODES               494

#define RAP_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define RAP_HTTPS_CERT_ERROR               495
#define RAP_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define RAP_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define RAP_HTTP_CLIENT_CLOSED_REQUEST     499


#define RAP_HTTP_INTERNAL_SERVER_ERROR     500
#define RAP_HTTP_NOT_IMPLEMENTED           501
#define RAP_HTTP_BAD_GATEWAY               502
#define RAP_HTTP_SERVICE_UNAVAILABLE       503
#define RAP_HTTP_GATEWAY_TIME_OUT          504
#define RAP_HTTP_VERSION_NOT_SUPPORTED     505
#define RAP_HTTP_INSUFFICIENT_STORAGE      507


#define RAP_HTTP_LOWLEVEL_BUFFERED         0xf0
#define RAP_HTTP_WRITE_BUFFERED            0x10
#define RAP_HTTP_GZIP_BUFFERED             0x20
#define RAP_HTTP_SSI_BUFFERED              0x01
#define RAP_HTTP_SUB_BUFFERED              0x02
#define RAP_HTTP_COPY_BUFFERED             0x04


typedef enum {
    RAP_HTTP_INITING_REQUEST_STATE = 0,
    RAP_HTTP_READING_REQUEST_STATE,
    RAP_HTTP_PROCESS_REQUEST_STATE,

    RAP_HTTP_CONNECT_UPSTREAM_STATE,
    RAP_HTTP_WRITING_UPSTREAM_STATE,
    RAP_HTTP_READING_UPSTREAM_STATE,

    RAP_HTTP_WRITING_REQUEST_STATE,
    RAP_HTTP_LINGERING_CLOSE_STATE,
    RAP_HTTP_KEEPALIVE_STATE
} rap_http_state_e;


typedef struct {
    rap_str_t                         name;
    rap_uint_t                        offset;
    rap_http_header_handler_pt        handler;
} rap_http_header_t;


typedef struct {
    rap_str_t                         name;
    rap_uint_t                        offset;
} rap_http_header_out_t;


typedef struct {
    rap_list_t                        headers;

    rap_table_elt_t                  *host;
    rap_table_elt_t                  *connection;
    rap_table_elt_t                  *if_modified_since;
    rap_table_elt_t                  *if_unmodified_since;
    rap_table_elt_t                  *if_match;
    rap_table_elt_t                  *if_none_match;
    rap_table_elt_t                  *user_agent;
    rap_table_elt_t                  *referer;
    rap_table_elt_t                  *content_length;
    rap_table_elt_t                  *content_range;
    rap_table_elt_t                  *content_type;

    rap_table_elt_t                  *range;
    rap_table_elt_t                  *if_range;

    rap_table_elt_t                  *transfer_encoding;
    rap_table_elt_t                  *te;
    rap_table_elt_t                  *expect;
    rap_table_elt_t                  *upgrade;

#if (RAP_HTTP_GZIP || RAP_HTTP_HEADERS)
    rap_table_elt_t                  *accept_encoding;
    rap_table_elt_t                  *via;
#endif

    rap_table_elt_t                  *authorization;

    rap_table_elt_t                  *keep_alive;

#if (RAP_HTTP_X_FORWARDED_FOR)
    rap_array_t                       x_forwarded_for;
#endif

#if (RAP_HTTP_REALIP)
    rap_table_elt_t                  *x_real_ip;
#endif

#if (RAP_HTTP_HEADERS)
    rap_table_elt_t                  *accept;
    rap_table_elt_t                  *accept_language;
#endif

#if (RAP_HTTP_DAV)
    rap_table_elt_t                  *depth;
    rap_table_elt_t                  *destination;
    rap_table_elt_t                  *overwrite;
    rap_table_elt_t                  *date;
#endif

    rap_str_t                         user;
    rap_str_t                         passwd;

    rap_array_t                       cookies;

    rap_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          chunked:1;
    unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} rap_http_headers_in_t;


typedef struct {
    rap_list_t                        headers;
    rap_list_t                        trailers;

    rap_uint_t                        status;
    rap_str_t                         status_line;

    rap_table_elt_t                  *server;
    rap_table_elt_t                  *date;
    rap_table_elt_t                  *content_length;
    rap_table_elt_t                  *content_encoding;
    rap_table_elt_t                  *location;
    rap_table_elt_t                  *refresh;
    rap_table_elt_t                  *last_modified;
    rap_table_elt_t                  *content_range;
    rap_table_elt_t                  *accept_ranges;
    rap_table_elt_t                  *www_authenticate;
    rap_table_elt_t                  *expires;
    rap_table_elt_t                  *etag;

    rap_str_t                        *override_charset;

    size_t                            content_type_len;
    rap_str_t                         content_type;
    rap_str_t                         charset;
    u_char                           *content_type_lowcase;
    rap_uint_t                        content_type_hash;

    rap_array_t                       cache_control;
    rap_array_t                       link;

    off_t                             content_length_n;
    off_t                             content_offset;
    time_t                            date_time;
    time_t                            last_modified_time;
} rap_http_headers_out_t;


typedef void (*rap_http_client_body_handler_pt)(rap_http_request_t *r);

typedef struct {
    rap_temp_file_t                  *temp_file;
    rap_chain_t                      *bufs;
    rap_buf_t                        *buf;
    off_t                             rest;
    off_t                             received;
    rap_chain_t                      *free;
    rap_chain_t                      *busy;
    rap_http_chunked_t               *chunked;
    rap_http_client_body_handler_pt   post_handler;
} rap_http_request_body_t;


typedef struct rap_http_addr_conf_s  rap_http_addr_conf_t;

typedef struct {
    rap_http_addr_conf_t             *addr_conf;
    rap_http_conf_ctx_t              *conf_ctx;

#if (RAP_HTTP_SSL || RAP_COMPAT)
    rap_str_t                        *ssl_servername;
#if (RAP_PCRE)
    rap_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    rap_chain_t                      *busy;
    rap_int_t                         nbusy;

    rap_chain_t                      *free;

    unsigned                          ssl:1;
    unsigned                          proxy_protocol:1;
} rap_http_connection_t;


typedef void (*rap_http_cleanup_pt)(void *data);

typedef struct rap_http_cleanup_s  rap_http_cleanup_t;

struct rap_http_cleanup_s {
    rap_http_cleanup_pt               handler;
    void                             *data;
    rap_http_cleanup_t               *next;
};


typedef rap_int_t (*rap_http_post_subrequest_pt)(rap_http_request_t *r,
    void *data, rap_int_t rc);

typedef struct {
    rap_http_post_subrequest_pt       handler;
    void                             *data;
} rap_http_post_subrequest_t;


typedef struct rap_http_postponed_request_s  rap_http_postponed_request_t;

struct rap_http_postponed_request_s {
    rap_http_request_t               *request;
    rap_chain_t                      *out;
    rap_http_postponed_request_t     *next;
};


typedef struct rap_http_posted_request_s  rap_http_posted_request_t;

struct rap_http_posted_request_s {
    rap_http_request_t               *request;
    rap_http_posted_request_t        *next;
};


typedef rap_int_t (*rap_http_handler_pt)(rap_http_request_t *r);
typedef void (*rap_http_event_handler_pt)(rap_http_request_t *r);


struct rap_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    rap_connection_t                 *connection;

    void                            **ctx;
    void                            **main_conf;
    void                            **srv_conf;
    void                            **loc_conf;

    rap_http_event_handler_pt         read_event_handler;
    rap_http_event_handler_pt         write_event_handler;

#if (RAP_HTTP_CACHE)
    rap_http_cache_t                 *cache;
#endif

    rap_http_upstream_t              *upstream;
    rap_array_t                      *upstream_states;
                                         /* of rap_http_upstream_state_t */

    rap_pool_t                       *pool;
    rap_buf_t                        *header_in;

    rap_http_headers_in_t             headers_in;
    rap_http_headers_out_t            headers_out;

    rap_http_request_body_t          *request_body;

    time_t                            lingering_time;
    time_t                            start_sec;
    rap_msec_t                        start_msec;

    rap_uint_t                        method;
    rap_uint_t                        http_version;

    rap_str_t                         request_line;
    rap_str_t                         uri;
    rap_str_t                         args;
    rap_str_t                         exten;
    rap_str_t                         unparsed_uri;

    rap_str_t                         method_name;
    rap_str_t                         http_protocol;
    rap_str_t                         schema;

    rap_chain_t                      *out;
    rap_http_request_t               *main;
    rap_http_request_t               *parent;
    rap_http_postponed_request_t     *postponed;
    rap_http_post_subrequest_t       *post_subrequest;
    rap_http_posted_request_t        *posted_requests;

    rap_int_t                         phase_handler;
    rap_http_handler_pt               content_handler;
    rap_uint_t                        access_code;

    rap_http_variable_value_t        *variables;

#if (RAP_PCRE)
    rap_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;
    size_t                            limit_rate_after;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    off_t                             request_length;

    rap_uint_t                        err_status;

    rap_http_connection_t            *http_connection;
    rap_http_v2_stream_t             *stream;

    rap_http_log_handler_pt           log_handler;

    rap_http_cleanup_t               *cleanup;

    unsigned                          count:16;
    unsigned                          subrequests:8;
    unsigned                          blocked:8;

    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;
    unsigned                          uri_changed:1;
    unsigned                          uri_changes:4;

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;
    unsigned                          request_body_no_buffering:1;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (RAP_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (RAP_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

#if (RAP_PCRE)
    unsigned                          realloc_captures:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * rap_http_limit_conn_module and rap_http_limit_req_module
     * we use the bit fields in the request structure
     */
    unsigned                          limit_conn_status:2;
    unsigned                          limit_req_status:3;

    unsigned                          limit_rate_set:1;
    unsigned                          limit_rate_after_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;
    unsigned                          expect_trailers:1;
    unsigned                          keepalive:1;
    unsigned                          lingering_close:1;
    unsigned                          discard_body:1;
    unsigned                          reading_body:1;
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          preserve_body:1;
    unsigned                          allow_ranges:1;
    unsigned                          subrequest_ranges:1;
    unsigned                          single_range:1;
    unsigned                          disable_not_modified:1;
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
    unsigned                          stat_processing:1;

    unsigned                          background:1;
    unsigned                          health_check:1;

    /* used to parse HTTP headers */

    rap_uint_t                        state;

    rap_uint_t                        header_hash;
    rap_uint_t                        lowcase_index;
    u_char                            lowcase_header[RAP_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via rap_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    rap_http_posted_request_t         terminal_posted_request;
} rap_http_ephemeral_t;


#define rap_http_ephemeral(r)  (void *) (&r->uri_start)


extern rap_http_header_t       rap_http_headers_in[];
extern rap_http_header_out_t   rap_http_headers_out[];


#define rap_http_set_log_request(log, r)                                      \
    ((rap_http_log_ctx_t *) log->data)->current_request = r


#endif /* _RAP_HTTP_REQUEST_H_INCLUDED_ */
