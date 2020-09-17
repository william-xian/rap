/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RP_HTTP_V2_H_INCLUDED_
#define _RP_HTTP_V2_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_V2_ALPN_ADVERTISE       "\x02h2"
#define RP_HTTP_V2_NPN_ADVERTISE        RP_HTTP_V2_ALPN_ADVERTISE

#define RP_HTTP_V2_STATE_BUFFER_SIZE    16

#define RP_HTTP_V2_DEFAULT_FRAME_SIZE   (1 << 14)
#define RP_HTTP_V2_MAX_FRAME_SIZE       ((1 << 24) - 1)

#define RP_HTTP_V2_INT_OCTETS           4
#define RP_HTTP_V2_MAX_FIELD                                                 \
    (127 + (1 << (RP_HTTP_V2_INT_OCTETS - 1) * 7) - 1)

#define RP_HTTP_V2_STREAM_ID_SIZE       4

#define RP_HTTP_V2_FRAME_HEADER_SIZE    9

/* frame types */
#define RP_HTTP_V2_DATA_FRAME           0x0
#define RP_HTTP_V2_HEADERS_FRAME        0x1
#define RP_HTTP_V2_PRIORITY_FRAME       0x2
#define RP_HTTP_V2_RST_STREAM_FRAME     0x3
#define RP_HTTP_V2_SETTINGS_FRAME       0x4
#define RP_HTTP_V2_PUSH_PROMISE_FRAME   0x5
#define RP_HTTP_V2_PING_FRAME           0x6
#define RP_HTTP_V2_GOAWAY_FRAME         0x7
#define RP_HTTP_V2_WINDOW_UPDATE_FRAME  0x8
#define RP_HTTP_V2_CONTINUATION_FRAME   0x9

/* frame flags */
#define RP_HTTP_V2_NO_FLAG              0x00
#define RP_HTTP_V2_ACK_FLAG             0x01
#define RP_HTTP_V2_END_STREAM_FLAG      0x01
#define RP_HTTP_V2_END_HEADERS_FLAG     0x04
#define RP_HTTP_V2_PADDED_FLAG          0x08
#define RP_HTTP_V2_PRIORITY_FLAG        0x20

#define RP_HTTP_V2_MAX_WINDOW           ((1U << 31) - 1)
#define RP_HTTP_V2_DEFAULT_WINDOW       65535

#define RP_HTTP_V2_DEFAULT_WEIGHT       16


typedef struct rp_http_v2_connection_s   rp_http_v2_connection_t;
typedef struct rp_http_v2_node_s         rp_http_v2_node_t;
typedef struct rp_http_v2_out_frame_s    rp_http_v2_out_frame_t;


typedef u_char *(*rp_http_v2_handler_pt) (rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);


typedef struct {
    rp_str_t                        name;
    rp_str_t                        value;
} rp_http_v2_header_t;


typedef struct {
    rp_uint_t                       sid;
    size_t                           length;
    size_t                           padding;
    unsigned                         flags:8;

    unsigned                         incomplete:1;
    unsigned                         keep_pool:1;

    /* HPACK */
    unsigned                         parse_name:1;
    unsigned                         parse_value:1;
    unsigned                         index:1;
    rp_http_v2_header_t             header;
    size_t                           header_limit;
    u_char                           field_state;
    u_char                          *field_start;
    u_char                          *field_end;
    size_t                           field_rest;
    rp_pool_t                      *pool;

    rp_http_v2_stream_t            *stream;

    u_char                           buffer[RP_HTTP_V2_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    rp_http_v2_handler_pt           handler;
} rp_http_v2_state_t;



typedef struct {
    rp_http_v2_header_t           **entries;

    rp_uint_t                       added;
    rp_uint_t                       deleted;
    rp_uint_t                       reused;
    rp_uint_t                       allocated;

    size_t                           size;
    size_t                           free;
    u_char                          *storage;
    u_char                          *pos;
} rp_http_v2_hpack_t;


struct rp_http_v2_connection_s {
    rp_connection_t                *connection;
    rp_http_connection_t           *http_connection;

    off_t                            total_bytes;
    off_t                            payload_bytes;

    rp_uint_t                       processing;
    rp_uint_t                       frames;
    rp_uint_t                       idle;
    rp_uint_t                       priority_limit;

    rp_uint_t                       pushing;
    rp_uint_t                       concurrent_pushes;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    size_t                           frame_size;

    rp_queue_t                      waiting;

    rp_http_v2_state_t              state;

    rp_http_v2_hpack_t              hpack;

    rp_pool_t                      *pool;

    rp_http_v2_out_frame_t         *free_frames;
    rp_connection_t                *free_fake_connections;

    rp_http_v2_node_t             **streams_index;

    rp_http_v2_out_frame_t         *last_out;

    rp_queue_t                      dependencies;
    rp_queue_t                      closed;

    rp_uint_t                       last_sid;
    rp_uint_t                       last_push;

    unsigned                         closed_nodes:8;
    unsigned                         settings_ack:1;
    unsigned                         table_update:1;
    unsigned                         blocked:1;
    unsigned                         goaway:1;
    unsigned                         push_disabled:1;
};


struct rp_http_v2_node_s {
    rp_uint_t                       id;
    rp_http_v2_node_t              *index;
    rp_http_v2_node_t              *parent;
    rp_queue_t                      queue;
    rp_queue_t                      children;
    rp_queue_t                      reuse;
    rp_uint_t                       rank;
    rp_uint_t                       weight;
    double                           rel_weight;
    rp_http_v2_stream_t            *stream;
};


struct rp_http_v2_stream_s {
    rp_http_request_t              *request;
    rp_http_v2_connection_t        *connection;
    rp_http_v2_node_t              *node;

    rp_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    rp_buf_t                       *preread;

    rp_uint_t                       frames;

    rp_http_v2_out_frame_t         *free_frames;
    rp_chain_t                     *free_frame_headers;
    rp_chain_t                     *free_bufs;

    rp_queue_t                      queue;

    rp_array_t                     *cookies;

    rp_pool_t                      *pool;

    unsigned                         waiting:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         rst_sent:1;
    unsigned                         no_flow_control:1;
    unsigned                         skip_data:1;
};


struct rp_http_v2_out_frame_s {
    rp_http_v2_out_frame_t         *next;
    rp_chain_t                     *first;
    rp_chain_t                     *last;
    rp_int_t                      (*handler)(rp_http_v2_connection_t *h2c,
                                        rp_http_v2_out_frame_t *frame);

    rp_http_v2_stream_t            *stream;
    size_t                           length;

    unsigned                         blocked:1;
    unsigned                         fin:1;
};


static rp_inline void
rp_http_v2_queue_frame(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame)
{
    rp_http_v2_out_frame_t  **out;

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


static rp_inline void
rp_http_v2_queue_blocked_frame(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame)
{
    rp_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static rp_inline void
rp_http_v2_queue_ordered_frame(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame)
{
    frame->next = h2c->last_out;
    h2c->last_out = frame;
}


void rp_http_v2_init(rp_event_t *rev);

rp_int_t rp_http_v2_read_request_body(rp_http_request_t *r);
rp_int_t rp_http_v2_read_unbuffered_request_body(rp_http_request_t *r);

rp_http_v2_stream_t *rp_http_v2_push_stream(rp_http_v2_stream_t *parent,
    rp_str_t *path);

void rp_http_v2_close_stream(rp_http_v2_stream_t *stream, rp_int_t rc);

rp_int_t rp_http_v2_send_output_queue(rp_http_v2_connection_t *h2c);


rp_str_t *rp_http_v2_get_static_name(rp_uint_t index);
rp_str_t *rp_http_v2_get_static_value(rp_uint_t index);

rp_int_t rp_http_v2_get_indexed_header(rp_http_v2_connection_t *h2c,
    rp_uint_t index, rp_uint_t name_only);
rp_int_t rp_http_v2_add_header(rp_http_v2_connection_t *h2c,
    rp_http_v2_header_t *header);
rp_int_t rp_http_v2_table_size(rp_http_v2_connection_t *h2c, size_t size);


rp_int_t rp_http_v2_huff_decode(u_char *state, u_char *src, size_t len,
    u_char **dst, rp_uint_t last, rp_log_t *log);
size_t rp_http_v2_huff_encode(u_char *src, size_t len, u_char *dst,
    rp_uint_t lower);


#define rp_http_v2_prefix(bits)  ((1 << (bits)) - 1)


#if (RP_HAVE_NONALIGNED)

#define rp_http_v2_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define rp_http_v2_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#else

#define rp_http_v2_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define rp_http_v2_parse_uint32(p)                                           \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif

#define rp_http_v2_parse_length(p)  ((p) >> 8)
#define rp_http_v2_parse_type(p)    ((p) & 0xff)
#define rp_http_v2_parse_sid(p)     (rp_http_v2_parse_uint32(p) & 0x7fffffff)
#define rp_http_v2_parse_window(p)  (rp_http_v2_parse_uint32(p) & 0x7fffffff)


#define rp_http_v2_write_uint16_aligned(p, s)                                \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
#define rp_http_v2_write_uint32_aligned(p, s)                                \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#if (RP_HAVE_NONALIGNED)

#define rp_http_v2_write_uint16  rp_http_v2_write_uint16_aligned
#define rp_http_v2_write_uint32  rp_http_v2_write_uint32_aligned

#else

#define rp_http_v2_write_uint16(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define rp_http_v2_write_uint32(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif

#define rp_http_v2_write_len_and_type(p, l, t)                               \
    rp_http_v2_write_uint32_aligned(p, (l) << 8 | (t))

#define rp_http_v2_write_sid  rp_http_v2_write_uint32


#define rp_http_v2_indexed(i)      (128 + (i))
#define rp_http_v2_inc_indexed(i)  (64 + (i))

#define rp_http_v2_write_name(dst, src, len, tmp)                            \
    rp_http_v2_string_encode(dst, src, len, tmp, 1)
#define rp_http_v2_write_value(dst, src, len, tmp)                           \
    rp_http_v2_string_encode(dst, src, len, tmp, 0)

#define RP_HTTP_V2_ENCODE_RAW            0
#define RP_HTTP_V2_ENCODE_HUFF           0x80

#define RP_HTTP_V2_AUTHORITY_INDEX       1

#define RP_HTTP_V2_METHOD_INDEX          2
#define RP_HTTP_V2_METHOD_GET_INDEX      2
#define RP_HTTP_V2_METHOD_POST_INDEX     3

#define RP_HTTP_V2_PATH_INDEX            4
#define RP_HTTP_V2_PATH_ROOT_INDEX       4

#define RP_HTTP_V2_SCHEME_HTTP_INDEX     6
#define RP_HTTP_V2_SCHEME_HTTPS_INDEX    7

#define RP_HTTP_V2_STATUS_INDEX          8
#define RP_HTTP_V2_STATUS_200_INDEX      8
#define RP_HTTP_V2_STATUS_204_INDEX      9
#define RP_HTTP_V2_STATUS_206_INDEX      10
#define RP_HTTP_V2_STATUS_304_INDEX      11
#define RP_HTTP_V2_STATUS_400_INDEX      12
#define RP_HTTP_V2_STATUS_404_INDEX      13
#define RP_HTTP_V2_STATUS_500_INDEX      14

#define RP_HTTP_V2_ACCEPT_ENCODING_INDEX 16
#define RP_HTTP_V2_ACCEPT_LANGUAGE_INDEX 17
#define RP_HTTP_V2_CONTENT_LENGTH_INDEX  28
#define RP_HTTP_V2_CONTENT_TYPE_INDEX    31
#define RP_HTTP_V2_DATE_INDEX            33
#define RP_HTTP_V2_LAST_MODIFIED_INDEX   44
#define RP_HTTP_V2_LOCATION_INDEX        46
#define RP_HTTP_V2_SERVER_INDEX          54
#define RP_HTTP_V2_USER_AGENT_INDEX      58
#define RP_HTTP_V2_VARY_INDEX            59


u_char *rp_http_v2_string_encode(u_char *dst, u_char *src, size_t len,
    u_char *tmp, rp_uint_t lower);


#endif /* _RP_HTTP_V2_H_INCLUDED_ */
