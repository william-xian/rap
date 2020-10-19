/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RAP_HTTP_V2_H_INCLUDED_
#define _RAP_HTTP_V2_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_V2_ALPN_ADVERTISE       "\x02h2"
#define RAP_HTTP_V2_NPN_ADVERTISE        RAP_HTTP_V2_ALPN_ADVERTISE

#define RAP_HTTP_V2_STATE_BUFFER_SIZE    16

#define RAP_HTTP_V2_DEFAULT_FRAME_SIZE   (1 << 14)
#define RAP_HTTP_V2_MAX_FRAME_SIZE       ((1 << 24) - 1)

#define RAP_HTTP_V2_INT_OCTETS           4
#define RAP_HTTP_V2_MAX_FIELD                                                 \
    (127 + (1 << (RAP_HTTP_V2_INT_OCTETS - 1) * 7) - 1)

#define RAP_HTTP_V2_STREAM_ID_SIZE       4

#define RAP_HTTP_V2_FRAME_HEADER_SIZE    9

/* frame types */
#define RAP_HTTP_V2_DATA_FRAME           0x0
#define RAP_HTTP_V2_HEADERS_FRAME        0x1
#define RAP_HTTP_V2_PRIORITY_FRAME       0x2
#define RAP_HTTP_V2_RST_STREAM_FRAME     0x3
#define RAP_HTTP_V2_SETTINGS_FRAME       0x4
#define RAP_HTTP_V2_PUSH_PROMISE_FRAME   0x5
#define RAP_HTTP_V2_PING_FRAME           0x6
#define RAP_HTTP_V2_GOAWAY_FRAME         0x7
#define RAP_HTTP_V2_WINDOW_UPDATE_FRAME  0x8
#define RAP_HTTP_V2_CONTINUATION_FRAME   0x9

/* frame flags */
#define RAP_HTTP_V2_NO_FLAG              0x00
#define RAP_HTTP_V2_ACK_FLAG             0x01
#define RAP_HTTP_V2_END_STREAM_FLAG      0x01
#define RAP_HTTP_V2_END_HEADERS_FLAG     0x04
#define RAP_HTTP_V2_PADDED_FLAG          0x08
#define RAP_HTTP_V2_PRIORITY_FLAG        0x20

#define RAP_HTTP_V2_MAX_WINDOW           ((1U << 31) - 1)
#define RAP_HTTP_V2_DEFAULT_WINDOW       65535

#define RAP_HTTP_V2_DEFAULT_WEIGHT       16


typedef struct rap_http_v2_connection_s   rap_http_v2_connection_t;
typedef struct rap_http_v2_node_s         rap_http_v2_node_t;
typedef struct rap_http_v2_out_frame_s    rap_http_v2_out_frame_t;


typedef u_char *(*rap_http_v2_handler_pt) (rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);


typedef struct {
    rap_str_t                        name;
    rap_str_t                        value;
} rap_http_v2_header_t;


typedef struct {
    rap_uint_t                       sid;
    size_t                           length;
    size_t                           padding;
    unsigned                         flags:8;

    unsigned                         incomplete:1;
    unsigned                         keep_pool:1;

    /* HPACK */
    unsigned                         parse_name:1;
    unsigned                         parse_value:1;
    unsigned                         index:1;
    rap_http_v2_header_t             header;
    size_t                           header_limit;
    u_char                           field_state;
    u_char                          *field_start;
    u_char                          *field_end;
    size_t                           field_rest;
    rap_pool_t                      *pool;

    rap_http_v2_stream_t            *stream;

    u_char                           buffer[RAP_HTTP_V2_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    rap_http_v2_handler_pt           handler;
} rap_http_v2_state_t;



typedef struct {
    rap_http_v2_header_t           **entries;

    rap_uint_t                       added;
    rap_uint_t                       deleted;
    rap_uint_t                       reused;
    rap_uint_t                       allocated;

    size_t                           size;
    size_t                           free;
    u_char                          *storage;
    u_char                          *pos;
} rap_http_v2_hpack_t;


struct rap_http_v2_connection_s {
    rap_connection_t                *connection;
    rap_http_connection_t           *http_connection;

    off_t                            total_bytes;
    off_t                            payload_bytes;

    rap_uint_t                       processing;
    rap_uint_t                       frames;
    rap_uint_t                       idle;
    rap_uint_t                       priority_limit;

    rap_uint_t                       pushing;
    rap_uint_t                       concurrent_pushes;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    size_t                           frame_size;

    rap_queue_t                      waiting;

    rap_http_v2_state_t              state;

    rap_http_v2_hpack_t              hpack;

    rap_pool_t                      *pool;

    rap_http_v2_out_frame_t         *free_frames;
    rap_connection_t                *free_fake_connections;

    rap_http_v2_node_t             **streams_index;

    rap_http_v2_out_frame_t         *last_out;

    rap_queue_t                      dependencies;
    rap_queue_t                      closed;

    rap_uint_t                       last_sid;
    rap_uint_t                       last_push;

    unsigned                         closed_nodes:8;
    unsigned                         settings_ack:1;
    unsigned                         table_update:1;
    unsigned                         blocked:1;
    unsigned                         goaway:1;
    unsigned                         push_disabled:1;
};


struct rap_http_v2_node_s {
    rap_uint_t                       id;
    rap_http_v2_node_t              *index;
    rap_http_v2_node_t              *parent;
    rap_queue_t                      queue;
    rap_queue_t                      children;
    rap_queue_t                      reuse;
    rap_uint_t                       rank;
    rap_uint_t                       weight;
    double                           rel_weight;
    rap_http_v2_stream_t            *stream;
};


struct rap_http_v2_stream_s {
    rap_http_request_t              *request;
    rap_http_v2_connection_t        *connection;
    rap_http_v2_node_t              *node;

    rap_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    rap_buf_t                       *preread;

    rap_uint_t                       frames;

    rap_http_v2_out_frame_t         *free_frames;
    rap_chain_t                     *free_frame_headers;
    rap_chain_t                     *free_bufs;

    rap_queue_t                      queue;

    rap_array_t                     *cookies;

    rap_pool_t                      *pool;

    unsigned                         waiting:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         rst_sent:1;
    unsigned                         no_flow_control:1;
    unsigned                         skip_data:1;
};


struct rap_http_v2_out_frame_s {
    rap_http_v2_out_frame_t         *next;
    rap_chain_t                     *first;
    rap_chain_t                     *last;
    rap_int_t                      (*handler)(rap_http_v2_connection_t *h2c,
                                        rap_http_v2_out_frame_t *frame);

    rap_http_v2_stream_t            *stream;
    size_t                           length;

    unsigned                         blocked:1;
    unsigned                         fin:1;
};


static rap_inline void
rap_http_v2_queue_frame(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }

        if ((*out)->stream->node->rank < frame->stream->node->rank
            || ((*out)->stream->node->rank == frame->stream->node->rank
                && (*out)->stream->node->rel_weight
                   >= frame->stream->node->rel_weight))
        {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static rap_inline void
rap_http_v2_queue_blocked_frame(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static rap_inline void
rap_http_v2_queue_ordered_frame(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    frame->next = h2c->last_out;
    h2c->last_out = frame;
}


void rap_http_v2_init(rap_event_t *rev);

rap_int_t rap_http_v2_read_request_body(rap_http_request_t *r);
rap_int_t rap_http_v2_read_unbuffered_request_body(rap_http_request_t *r);

rap_http_v2_stream_t *rap_http_v2_push_stream(rap_http_v2_stream_t *parent,
    rap_str_t *path);

void rap_http_v2_close_stream(rap_http_v2_stream_t *stream, rap_int_t rc);

rap_int_t rap_http_v2_send_output_queue(rap_http_v2_connection_t *h2c);


rap_str_t *rap_http_v2_get_static_name(rap_uint_t index);
rap_str_t *rap_http_v2_get_static_value(rap_uint_t index);

rap_int_t rap_http_v2_get_indexed_header(rap_http_v2_connection_t *h2c,
    rap_uint_t index, rap_uint_t name_only);
rap_int_t rap_http_v2_add_header(rap_http_v2_connection_t *h2c,
    rap_http_v2_header_t *header);
rap_int_t rap_http_v2_table_size(rap_http_v2_connection_t *h2c, size_t size);


rap_int_t rap_http_v2_huff_decode(u_char *state, u_char *src, size_t len,
    u_char **dst, rap_uint_t last, rap_log_t *log);
size_t rap_http_v2_huff_encode(u_char *src, size_t len, u_char *dst,
    rap_uint_t lower);


#define rap_http_v2_prefix(bits)  ((1 << (bits)) - 1)


#if (RAP_HAVE_NONALIGNED)

#define rap_http_v2_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define rap_http_v2_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#else

#define rap_http_v2_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define rap_http_v2_parse_uint32(p)                                           \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif

#define rap_http_v2_parse_length(p)  ((p) >> 8)
#define rap_http_v2_parse_type(p)    ((p) & 0xff)
#define rap_http_v2_parse_sid(p)     (rap_http_v2_parse_uint32(p) & 0x7fffffff)
#define rap_http_v2_parse_window(p)  (rap_http_v2_parse_uint32(p) & 0x7fffffff)


#define rap_http_v2_write_uint16_aligned(p, s)                                \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
#define rap_http_v2_write_uint32_aligned(p, s)                                \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#if (RAP_HAVE_NONALIGNED)

#define rap_http_v2_write_uint16  rap_http_v2_write_uint16_aligned
#define rap_http_v2_write_uint32  rap_http_v2_write_uint32_aligned

#else

#define rap_http_v2_write_uint16(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define rap_http_v2_write_uint32(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif

#define rap_http_v2_write_len_and_type(p, l, t)                               \
    rap_http_v2_write_uint32_aligned(p, (l) << 8 | (t))

#define rap_http_v2_write_sid  rap_http_v2_write_uint32


#define rap_http_v2_indexed(i)      (128 + (i))
#define rap_http_v2_inc_indexed(i)  (64 + (i))

#define rap_http_v2_write_name(dst, src, len, tmp)                            \
    rap_http_v2_string_encode(dst, src, len, tmp, 1)
#define rap_http_v2_write_value(dst, src, len, tmp)                           \
    rap_http_v2_string_encode(dst, src, len, tmp, 0)

#define RAP_HTTP_V2_ENCODE_RAW            0
#define RAP_HTTP_V2_ENCODE_HUFF           0x80

#define RAP_HTTP_V2_AUTHORITY_INDEX       1

#define RAP_HTTP_V2_METHOD_INDEX          2
#define RAP_HTTP_V2_METHOD_GET_INDEX      2
#define RAP_HTTP_V2_METHOD_POST_INDEX     3

#define RAP_HTTP_V2_PATH_INDEX            4
#define RAP_HTTP_V2_PATH_ROOT_INDEX       4

#define RAP_HTTP_V2_SCHEME_HTTP_INDEX     6
#define RAP_HTTP_V2_SCHEME_HTTPS_INDEX    7

#define RAP_HTTP_V2_STATUS_INDEX          8
#define RAP_HTTP_V2_STATUS_200_INDEX      8
#define RAP_HTTP_V2_STATUS_204_INDEX      9
#define RAP_HTTP_V2_STATUS_206_INDEX      10
#define RAP_HTTP_V2_STATUS_304_INDEX      11
#define RAP_HTTP_V2_STATUS_400_INDEX      12
#define RAP_HTTP_V2_STATUS_404_INDEX      13
#define RAP_HTTP_V2_STATUS_500_INDEX      14

#define RAP_HTTP_V2_ACCEPT_ENCODING_INDEX 16
#define RAP_HTTP_V2_ACCEPT_LANGUAGE_INDEX 17
#define RAP_HTTP_V2_CONTENT_LENGTH_INDEX  28
#define RAP_HTTP_V2_CONTENT_TYPE_INDEX    31
#define RAP_HTTP_V2_DATE_INDEX            33
#define RAP_HTTP_V2_LAST_MODIFIED_INDEX   44
#define RAP_HTTP_V2_LOCATION_INDEX        46
#define RAP_HTTP_V2_SERVER_INDEX          54
#define RAP_HTTP_V2_USER_AGENT_INDEX      58
#define RAP_HTTP_V2_VARY_INDEX            59


u_char *rap_http_v2_string_encode(u_char *dst, u_char *src, size_t len,
    u_char *tmp, rap_uint_t lower);


#endif /* _RAP_HTTP_V2_H_INCLUDED_ */
