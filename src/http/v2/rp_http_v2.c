
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_http_v2_module.h>


typedef struct {
    rp_str_t           name;
    rp_uint_t          offset;
    rp_uint_t          hash;
    rp_http_header_t  *hh;
} rp_http_v2_parse_header_t;


/* errors */
#define RP_HTTP_V2_NO_ERROR                     0x0
#define RP_HTTP_V2_PROTOCOL_ERROR               0x1
#define RP_HTTP_V2_INTERNAL_ERROR               0x2
#define RP_HTTP_V2_FLOW_CTRL_ERROR              0x3
#define RP_HTTP_V2_SETTINGS_TIMEOUT             0x4
#define RP_HTTP_V2_STREAM_CLOSED                0x5
#define RP_HTTP_V2_SIZE_ERROR                   0x6
#define RP_HTTP_V2_REFUSED_STREAM               0x7
#define RP_HTTP_V2_CANCEL                       0x8
#define RP_HTTP_V2_COMP_ERROR                   0x9
#define RP_HTTP_V2_CONNECT_ERROR                0xa
#define RP_HTTP_V2_ENHANCE_YOUR_CALM            0xb
#define RP_HTTP_V2_INADEQUATE_SECURITY          0xc
#define RP_HTTP_V2_HTTP_1_1_REQUIRED            0xd

/* frame sizes */
#define RP_HTTP_V2_SETTINGS_ACK_SIZE            0
#define RP_HTTP_V2_RST_STREAM_SIZE              4
#define RP_HTTP_V2_PRIORITY_SIZE                5
#define RP_HTTP_V2_PING_SIZE                    8
#define RP_HTTP_V2_GOAWAY_SIZE                  8
#define RP_HTTP_V2_WINDOW_UPDATE_SIZE           4

#define RP_HTTP_V2_SETTINGS_PARAM_SIZE          6

/* settings fields */
#define RP_HTTP_V2_HEADER_TABLE_SIZE_SETTING    0x1
#define RP_HTTP_V2_ENABLE_PUSH_SETTING          0x2
#define RP_HTTP_V2_MAX_STREAMS_SETTING          0x3
#define RP_HTTP_V2_INIT_WINDOW_SIZE_SETTING     0x4
#define RP_HTTP_V2_MAX_FRAME_SIZE_SETTING       0x5

#define RP_HTTP_V2_FRAME_BUFFER_SIZE            24

#define RP_HTTP_V2_ROOT                         (void *) -1


static void rp_http_v2_read_handler(rp_event_t *rev);
static void rp_http_v2_write_handler(rp_event_t *wev);
static void rp_http_v2_handle_connection(rp_http_v2_connection_t *h2c);

static u_char *rp_http_v2_state_proxy_protocol(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_preface(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_preface_end(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_head(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_data(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_read_data(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_headers(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_header_block(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_field_len(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_field_huff(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_field_raw(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_field_skip(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_process_header(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_header_complete(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_handle_continuation(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rp_http_v2_handler_pt handler);
static u_char *rp_http_v2_state_priority(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_rst_stream(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_settings(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_settings_params(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_push_promise(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_ping(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_goaway(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_window_update(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_continuation(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_complete(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_skip_padded(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_skip(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rp_http_v2_state_save(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rp_http_v2_handler_pt handler);
static u_char *rp_http_v2_state_headers_save(rp_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rp_http_v2_handler_pt handler);
static u_char *rp_http_v2_connection_error(rp_http_v2_connection_t *h2c,
    rp_uint_t err);

static rp_int_t rp_http_v2_parse_int(rp_http_v2_connection_t *h2c,
    u_char **pos, u_char *end, rp_uint_t prefix);

static rp_http_v2_stream_t *rp_http_v2_create_stream(
    rp_http_v2_connection_t *h2c, rp_uint_t push);
static rp_http_v2_node_t *rp_http_v2_get_node_by_id(
    rp_http_v2_connection_t *h2c, rp_uint_t sid, rp_uint_t alloc);
static rp_http_v2_node_t *rp_http_v2_get_closed_node(
    rp_http_v2_connection_t *h2c);
#define rp_http_v2_index_size(h2scf)  (h2scf->streams_index_mask + 1)
#define rp_http_v2_index(h2scf, sid)  ((sid >> 1) & h2scf->streams_index_mask)

static rp_int_t rp_http_v2_send_settings(rp_http_v2_connection_t *h2c);
static rp_int_t rp_http_v2_settings_frame_handler(
    rp_http_v2_connection_t *h2c, rp_http_v2_out_frame_t *frame);
static rp_int_t rp_http_v2_send_window_update(rp_http_v2_connection_t *h2c,
    rp_uint_t sid, size_t window);
static rp_int_t rp_http_v2_send_rst_stream(rp_http_v2_connection_t *h2c,
    rp_uint_t sid, rp_uint_t status);
static rp_int_t rp_http_v2_send_goaway(rp_http_v2_connection_t *h2c,
    rp_uint_t status);

static rp_http_v2_out_frame_t *rp_http_v2_get_frame(
    rp_http_v2_connection_t *h2c, size_t length, rp_uint_t type,
    u_char flags, rp_uint_t sid);
static rp_int_t rp_http_v2_frame_handler(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame);

static rp_int_t rp_http_v2_validate_header(rp_http_request_t *r,
    rp_http_v2_header_t *header);
static rp_int_t rp_http_v2_pseudo_header(rp_http_request_t *r,
    rp_http_v2_header_t *header);
static rp_int_t rp_http_v2_parse_path(rp_http_request_t *r,
    rp_str_t *value);
static rp_int_t rp_http_v2_parse_method(rp_http_request_t *r,
    rp_str_t *value);
static rp_int_t rp_http_v2_parse_scheme(rp_http_request_t *r,
    rp_str_t *value);
static rp_int_t rp_http_v2_parse_authority(rp_http_request_t *r,
    rp_str_t *value);
static rp_int_t rp_http_v2_parse_header(rp_http_request_t *r,
    rp_http_v2_parse_header_t *header, rp_str_t *value);
static rp_int_t rp_http_v2_construct_request_line(rp_http_request_t *r);
static rp_int_t rp_http_v2_cookie(rp_http_request_t *r,
    rp_http_v2_header_t *header);
static rp_int_t rp_http_v2_construct_cookie_header(rp_http_request_t *r);
static void rp_http_v2_run_request(rp_http_request_t *r);
static void rp_http_v2_run_request_handler(rp_event_t *ev);
static rp_int_t rp_http_v2_process_request_body(rp_http_request_t *r,
    u_char *pos, size_t size, rp_uint_t last);
static rp_int_t rp_http_v2_filter_request_body(rp_http_request_t *r);
static void rp_http_v2_read_client_request_body_handler(rp_http_request_t *r);

static rp_int_t rp_http_v2_terminate_stream(rp_http_v2_connection_t *h2c,
    rp_http_v2_stream_t *stream, rp_uint_t status);
static void rp_http_v2_close_stream_handler(rp_event_t *ev);
static void rp_http_v2_retry_close_stream_handler(rp_event_t *ev);
static void rp_http_v2_handle_connection_handler(rp_event_t *rev);
static void rp_http_v2_idle_handler(rp_event_t *rev);
static void rp_http_v2_finalize_connection(rp_http_v2_connection_t *h2c,
    rp_uint_t status);

static rp_int_t rp_http_v2_adjust_windows(rp_http_v2_connection_t *h2c,
    ssize_t delta);
static void rp_http_v2_set_dependency(rp_http_v2_connection_t *h2c,
    rp_http_v2_node_t *node, rp_uint_t depend, rp_uint_t exclusive);
static void rp_http_v2_node_children_update(rp_http_v2_node_t *node);

static void rp_http_v2_pool_cleanup(void *data);


static rp_http_v2_handler_pt rp_http_v2_frame_states[] = {
    rp_http_v2_state_data,               /* RP_HTTP_V2_DATA_FRAME */
    rp_http_v2_state_headers,            /* RP_HTTP_V2_HEADERS_FRAME */
    rp_http_v2_state_priority,           /* RP_HTTP_V2_PRIORITY_FRAME */
    rp_http_v2_state_rst_stream,         /* RP_HTTP_V2_RST_STREAM_FRAME */
    rp_http_v2_state_settings,           /* RP_HTTP_V2_SETTINGS_FRAME */
    rp_http_v2_state_push_promise,       /* RP_HTTP_V2_PUSH_PROMISE_FRAME */
    rp_http_v2_state_ping,               /* RP_HTTP_V2_PING_FRAME */
    rp_http_v2_state_goaway,             /* RP_HTTP_V2_GOAWAY_FRAME */
    rp_http_v2_state_window_update,      /* RP_HTTP_V2_WINDOW_UPDATE_FRAME */
    rp_http_v2_state_continuation        /* RP_HTTP_V2_CONTINUATION_FRAME */
};

#define RP_HTTP_V2_FRAME_STATES                                              \
    (sizeof(rp_http_v2_frame_states) / sizeof(rp_http_v2_handler_pt))


static rp_http_v2_parse_header_t  rp_http_v2_parse_headers[] = {
    { rp_string("host"),
      offsetof(rp_http_headers_in_t, host), 0, NULL },

    { rp_string("accept-encoding"),
      offsetof(rp_http_headers_in_t, accept_encoding), 0, NULL },

    { rp_string("accept-language"),
      offsetof(rp_http_headers_in_t, accept_language), 0, NULL },

    { rp_string("user-agent"),
      offsetof(rp_http_headers_in_t, user_agent), 0, NULL },

    { rp_null_string, 0, 0, NULL }
};


void
rp_http_v2_init(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_pool_cleanup_t        *cln;
    rp_http_connection_t     *hc;
    rp_http_v2_srv_conf_t    *h2scf;
    rp_http_v2_main_conf_t   *h2mcf;
    rp_http_v2_connection_t  *h2c;

    c = rev->data;
    hc = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "init http2 connection");

    c->log->action = "processing HTTP/2 connection";

    h2mcf = rp_http_get_module_main_conf(hc->conf_ctx, rp_http_v2_module);

    if (h2mcf->recv_buffer == NULL) {
        h2mcf->recv_buffer = rp_palloc(rp_cycle->pool,
                                        h2mcf->recv_buffer_size);
        if (h2mcf->recv_buffer == NULL) {
            rp_http_close_connection(c);
            return;
        }
    }

    h2c = rp_pcalloc(c->pool, sizeof(rp_http_v2_connection_t));
    if (h2c == NULL) {
        rp_http_close_connection(c);
        return;
    }

    h2c->connection = c;
    h2c->http_connection = hc;

    h2c->send_window = RP_HTTP_V2_DEFAULT_WINDOW;
    h2c->recv_window = RP_HTTP_V2_MAX_WINDOW;

    h2c->init_window = RP_HTTP_V2_DEFAULT_WINDOW;

    h2c->frame_size = RP_HTTP_V2_DEFAULT_FRAME_SIZE;

    h2scf = rp_http_get_module_srv_conf(hc->conf_ctx, rp_http_v2_module);

    h2c->concurrent_pushes = h2scf->concurrent_pushes;
    h2c->priority_limit = h2scf->concurrent_streams;

    h2c->pool = rp_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        rp_http_close_connection(c);
        return;
    }

    cln = rp_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        rp_http_close_connection(c);
        return;
    }

    cln->handler = rp_http_v2_pool_cleanup;
    cln->data = h2c;

    h2c->streams_index = rp_pcalloc(c->pool, rp_http_v2_index_size(h2scf)
                                              * sizeof(rp_http_v2_node_t *));
    if (h2c->streams_index == NULL) {
        rp_http_close_connection(c);
        return;
    }

    if (rp_http_v2_send_settings(h2c) == RP_ERROR) {
        rp_http_close_connection(c);
        return;
    }

    if (rp_http_v2_send_window_update(h2c, 0, RP_HTTP_V2_MAX_WINDOW
                                               - RP_HTTP_V2_DEFAULT_WINDOW)
        == RP_ERROR)
    {
        rp_http_close_connection(c);
        return;
    }

    h2c->state.handler = hc->proxy_protocol ? rp_http_v2_state_proxy_protocol
                                            : rp_http_v2_state_preface;

    rp_queue_init(&h2c->waiting);
    rp_queue_init(&h2c->dependencies);
    rp_queue_init(&h2c->closed);

    c->data = h2c;

    rev->handler = rp_http_v2_read_handler;
    c->write->handler = rp_http_v2_write_handler;

    c->idle = 1;

    rp_http_v2_read_handler(rev);
}


static void
rp_http_v2_read_handler(rp_event_t *rev)
{
    u_char                    *p, *end;
    size_t                     available;
    ssize_t                    n;
    rp_connection_t          *c;
    rp_http_v2_main_conf_t   *h2mcf;
    rp_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http2 read handler");

    h2c->blocked = 1;

    if (c->close) {
        c->close = 0;

        if (c->error) {
            rp_http_v2_finalize_connection(h2c, 0);
            return;
        }

        if (!h2c->goaway) {
            h2c->goaway = 1;

            if (rp_http_v2_send_goaway(h2c, RP_HTTP_V2_NO_ERROR)
                == RP_ERROR)
            {
                rp_http_v2_finalize_connection(h2c, 0);
                return;
            }

            if (rp_http_v2_send_output_queue(h2c) == RP_ERROR) {
                rp_http_v2_finalize_connection(h2c, 0);
                return;
            }
        }

        h2c->blocked = 0;

        return;
    }

    h2mcf = rp_http_get_module_main_conf(h2c->http_connection->conf_ctx,
                                          rp_http_v2_module);

    available = h2mcf->recv_buffer_size - 2 * RP_HTTP_V2_STATE_BUFFER_SIZE;

    do {
        p = h2mcf->recv_buffer;

        rp_memcpy(p, h2c->state.buffer, RP_HTTP_V2_STATE_BUFFER_SIZE);
        end = p + h2c->state.buffer_used;

        n = c->recv(c, end, available);

        if (n == RP_AGAIN) {
            break;
        }

        if (n == 0
            && (h2c->state.incomplete || h2c->processing || h2c->pushing))
        {
            rp_log_error(RP_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        }

        if (n == 0 || n == RP_ERROR) {
            c->error = 1;
            rp_http_v2_finalize_connection(h2c, 0);
            return;
        }

        end += n;

        h2c->state.buffer_used = 0;
        h2c->state.incomplete = 0;

        do {
            p = h2c->state.handler(h2c, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

        h2c->total_bytes += n;

        if (h2c->total_bytes / 8 > h2c->payload_bytes + 1048576) {
            rp_log_error(RP_LOG_INFO, c->log, 0, "http2 flood detected");
            rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_NO_ERROR);
            return;
        }

    } while (rev->ready);

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    if (h2c->last_out && rp_http_v2_send_output_queue(h2c) == RP_ERROR) {
        rp_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (h2c->processing || h2c->pushing) {
        if (rev->timer_set) {
            rp_del_timer(rev);
        }

        return;
    }

    rp_http_v2_handle_connection(h2c);
}


static void
rp_http_v2_write_handler(rp_event_t *wev)
{
    rp_int_t                  rc;
    rp_connection_t          *c;
    rp_http_v2_connection_t  *h2c;

    c = wev->data;
    h2c = c->data;

    if (wev->timedout) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 write event timed out");
        c->error = 1;
        rp_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http2 write handler");

    if (h2c->last_out == NULL && !c->buffered) {

        if (wev->timer_set) {
            rp_del_timer(wev);
        }

        rp_http_v2_handle_connection(h2c);
        return;
    }

    h2c->blocked = 1;

    rc = rp_http_v2_send_output_queue(h2c);

    if (rc == RP_ERROR) {
        rp_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (rc == RP_AGAIN) {
        return;
    }

    rp_http_v2_handle_connection(h2c);
}


rp_int_t
rp_http_v2_send_output_queue(rp_http_v2_connection_t *h2c)
{
    int                        tcp_nodelay;
    rp_chain_t               *cl;
    rp_event_t               *wev;
    rp_connection_t          *c;
    rp_http_v2_out_frame_t   *out, *frame, *fn;
    rp_http_core_loc_conf_t  *clcf;

    c = h2c->connection;
    wev = c->write;

    if (c->error) {
        goto error;
    }

    if (!wev->ready) {
        return RP_AGAIN;
    }

    cl = NULL;
    out = NULL;

    for (frame = h2c->last_out; frame; frame = fn) {
        frame->last->next = cl;
        cl = frame->first;

        fn = frame->next;
        frame->next = out;
        out = frame;

        rp_log_debug4(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame out: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    cl = c->send_chain(c, cl, 0);

    if (cl == RP_CHAIN_ERROR) {
        goto error;
    }

    clcf = rp_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        rp_http_core_module);

    if (rp_handle_write_event(wev, clcf->send_lowat) != RP_OK) {
        goto error;
    }

    if (c->tcp_nopush == RP_TCP_NOPUSH_SET) {
        if (rp_tcp_push(c->fd) == -1) {
            rp_connection_error(c, rp_socket_errno, rp_tcp_push_n " failed");
            goto error;
        }

        c->tcp_nopush = RP_TCP_NOPUSH_UNSET;
        tcp_nodelay = rp_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
        goto error;
    }

    for ( /* void */ ; out; out = fn) {
        fn = out->next;

        if (out->handler(h2c, out) != RP_OK) {
            out->blocked = 1;
            break;
        }

        rp_log_debug4(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame sent: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    frame = NULL;

    for ( /* void */ ; out; out = fn) {
        fn = out->next;
        out->next = frame;
        frame = out;
    }

    h2c->last_out = frame;

    if (!wev->ready) {
        rp_add_timer(wev, clcf->send_timeout);
        return RP_AGAIN;
    }

    if (wev->timer_set) {
        rp_del_timer(wev);
    }

    return RP_OK;

error:

    c->error = 1;

    if (!h2c->blocked) {
        rp_post_event(wev, &rp_posted_events);
    }

    return RP_ERROR;
}


static void
rp_http_v2_handle_connection(rp_http_v2_connection_t *h2c)
{
    rp_int_t                rc;
    rp_connection_t        *c;
    rp_http_v2_srv_conf_t  *h2scf;

    if (h2c->last_out || h2c->processing || h2c->pushing) {
        return;
    }

    c = h2c->connection;

    if (c->error) {
        rp_http_close_connection(c);
        return;
    }

    if (c->buffered) {
        h2c->blocked = 1;

        rc = rp_http_v2_send_output_queue(h2c);

        h2c->blocked = 0;

        if (rc == RP_ERROR) {
            rp_http_close_connection(c);
            return;
        }

        if (rc == RP_AGAIN) {
            return;
        }

        /* rc == RP_OK */
    }

    if (h2c->goaway) {
        rp_http_close_connection(c);
        return;
    }

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);
    if (h2c->state.incomplete) {
        rp_add_timer(c->read, h2scf->recv_timeout);
        return;
    }

    rp_destroy_pool(h2c->pool);

    h2c->pool = NULL;
    h2c->free_frames = NULL;
    h2c->frames = 0;
    h2c->free_fake_connections = NULL;

#if (RP_HTTP_SSL)
    if (c->ssl) {
        rp_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;
    rp_reusable_connection(c, 1);

    c->write->handler = rp_http_empty_handler;
    c->read->handler = rp_http_v2_idle_handler;

    if (c->write->timer_set) {
        rp_del_timer(c->write);
    }

    rp_add_timer(c->read, h2scf->idle_timeout);
}


static u_char *
rp_http_v2_state_proxy_protocol(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_log_t  *log;

    log = h2c->connection->log;
    log->action = "reading PROXY protocol";

    pos = rp_proxy_protocol_read(h2c->connection, pos, end);

    log->action = "processing HTTP/2 connection";

    if (pos == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    return rp_http_v2_state_preface(h2c, pos, end);
}


static u_char *
rp_http_v2_state_preface(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = "PRI * HTTP/2.0\r\n";

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return rp_http_v2_state_save(h2c, pos, end, rp_http_v2_state_preface);
    }

    if (rp_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "invalid http2 connection preface \"%*s\"",
                       sizeof(preface) - 1, pos);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    return rp_http_v2_state_preface_end(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
rp_http_v2_state_preface_end(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = "\r\nSM\r\n\r\n";

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_preface_end);
    }

    if (rp_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "invalid http2 connection preface \"%*s\"",
                       sizeof(preface) - 1, pos);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 preface verified");

    return rp_http_v2_state_head(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
rp_http_v2_state_head(rp_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    uint32_t    head;
    rp_uint_t  type;

    if (end - pos < RP_HTTP_V2_FRAME_HEADER_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end, rp_http_v2_state_head);
    }

    head = rp_http_v2_parse_uint32(pos);

    h2c->state.length = rp_http_v2_parse_length(head);
    h2c->state.flags = pos[4];

    h2c->state.sid = rp_http_v2_parse_sid(&pos[5]);

    pos += RP_HTTP_V2_FRAME_HEADER_SIZE;

    type = rp_http_v2_parse_type(head);

    rp_log_debug4(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame type:%ui f:%Xd l:%uz sid:%ui",
                   type, h2c->state.flags, h2c->state.length, h2c->state.sid);

    if (type >= RP_HTTP_V2_FRAME_STATES) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent frame with unknown type %ui", type);
        return rp_http_v2_state_skip(h2c, pos, end);
    }

    return rp_http_v2_frame_states[type](h2c, pos, end);
}


static u_char *
rp_http_v2_state_data(rp_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t                 size;
    rp_http_v2_node_t    *node;
    rp_http_v2_stream_t  *stream;

    size = h2c->state.length;

    if (h2c->state.flags & RP_HTTP_V2_PADDED_FLAG) {

        if (h2c->state.length == 0) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: 0");

            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
        }

        if (end - pos == 0) {
            return rp_http_v2_state_save(h2c, pos, end,
                                          rp_http_v2_state_data);
        }

        h2c->state.padding = *pos++;

        if (h2c->state.padding >= size) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: %uz, padding: %uz",
                          size, h2c->state.padding);

            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= 1 + h2c->state.padding;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 DATA frame");

    if (size > h2c->recv_window) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received DATA frame length %uz, available window %uz",
                      size, h2c->recv_window);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->recv_window -= size;

    if (h2c->recv_window < RP_HTTP_V2_MAX_WINDOW / 4) {

        if (rp_http_v2_send_window_update(h2c, 0, RP_HTTP_V2_MAX_WINDOW
                                                   - h2c->recv_window)
            == RP_ERROR)
        {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->recv_window = RP_HTTP_V2_MAX_WINDOW;
    }

    node = rp_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream = node->stream;

    if (size > stream->recv_window) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client violated flow control for stream %ui: "
                      "received DATA frame length %uz, available window %uz",
                      node->id, size, stream->recv_window);

        if (rp_http_v2_terminate_stream(h2c, stream,
                                         RP_HTTP_V2_FLOW_CTRL_ERROR)
            == RP_ERROR)
        {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream->recv_window -= size;

    if (stream->no_flow_control
        && stream->recv_window < RP_HTTP_V2_MAX_WINDOW / 4)
    {
        if (rp_http_v2_send_window_update(h2c, node->id,
                                           RP_HTTP_V2_MAX_WINDOW
                                           - stream->recv_window)
            == RP_ERROR)
        {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        stream->recv_window = RP_HTTP_V2_MAX_WINDOW;
    }

    if (stream->in_closed) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame for half-closed stream %ui",
                      node->id);

        if (rp_http_v2_terminate_stream(h2c, stream,
                                         RP_HTTP_V2_STREAM_CLOSED)
            == RP_ERROR)
        {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    h2c->state.stream = stream;

    return rp_http_v2_state_read_data(h2c, pos, end);
}


static u_char *
rp_http_v2_state_read_data(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    rp_buf_t               *buf;
    rp_int_t                rc;
    rp_http_request_t      *r;
    rp_http_v2_stream_t    *stream;
    rp_http_v2_srv_conf_t  *h2scf;

    stream = h2c->state.stream;

    if (stream == NULL) {
        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (stream->skip_data) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    r = stream->request;

    if (r->reading_body && !r->request_body_no_buffering) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    size = end - pos;

    if (size >= h2c->state.length) {
        size = h2c->state.length;
        stream->in_closed = h2c->state.flags & RP_HTTP_V2_END_STREAM_FLAG;
    }

    h2c->payload_bytes += size;

    if (r->request_body) {
        rc = rp_http_v2_process_request_body(r, pos, size, stream->in_closed);

        if (rc != RP_OK) {
            stream->skip_data = 1;
            rp_http_finalize_request(r, rc);
        }

    } else if (size) {
        buf = stream->preread;

        if (buf == NULL) {
            h2scf = rp_http_get_module_srv_conf(r, rp_http_v2_module);

            buf = rp_create_temp_buf(r->pool, h2scf->preread_size);
            if (buf == NULL) {
                return rp_http_v2_connection_error(h2c,
                                                    RP_HTTP_V2_INTERNAL_ERROR);
            }

            stream->preread = buf;
        }

        if (size > (size_t) (buf->end - buf->last)) {
            rp_log_error(RP_LOG_ALERT, h2c->connection->log, 0,
                          "http2 preread buffer overflow");
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        buf->last = rp_cpymem(buf->last, pos, size);
    }

    pos += size;
    h2c->state.length -= size;

    if (h2c->state.length) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_read_data);
    }

    if (h2c->state.padding) {
        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_headers(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    rp_uint_t               padded, priority, depend, dependency, excl, weight;
    rp_uint_t               status;
    rp_http_v2_node_t      *node;
    rp_http_v2_stream_t    *stream;
    rp_http_v2_srv_conf_t  *h2scf;

    padded = h2c->state.flags & RP_HTTP_V2_PADDED_FLAG;
    priority = h2c->state.flags & RP_HTTP_V2_PRIORITY_FLAG;

    size = 0;

    if (padded) {
        size++;
    }

    if (priority) {
        size += sizeof(uint32_t) + 1;
    }

    if (h2c->state.length < size) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect length %uz",
                      h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->state.length == size) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with empty header block");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->goaway) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 HEADERS frame");
        return rp_http_v2_state_skip(h2c, pos, end);
    }

    if ((size_t) (end - pos) < size) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_headers);
    }

    h2c->state.length -= size;

    if (padded) {
        h2c->state.padding = *pos++;

        if (h2c->state.padding > h2c->state.length) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded HEADERS frame "
                          "with incorrect length: %uz, padding: %uz",
                          h2c->state.length, h2c->state.padding);

            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= h2c->state.padding;
    }

    depend = 0;
    excl = 0;
    weight = RP_HTTP_V2_DEFAULT_WEIGHT;

    if (priority) {
        dependency = rp_http_v2_parse_uint32(pos);

        depend = dependency & 0x7fffffff;
        excl = dependency >> 31;
        weight = pos[4] + 1;

        pos += sizeof(uint32_t) + 1;
    }

    rp_log_debug4(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 HEADERS frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid % 2 == 0 || h2c->state.sid <= h2c->last_sid) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect identifier "
                      "%ui, the last was %ui", h2c->state.sid, h2c->last_sid);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->last_sid = h2c->state.sid;

    h2c->state.pool = rp_create_pool(1024, h2c->connection->log);
    if (h2c->state.pool == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    h2c->state.header_limit = h2scf->max_header_size;

    if (h2c->processing >= h2scf->concurrent_streams) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "concurrent streams exceeded %ui", h2c->processing);

        status = RP_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (!h2c->settings_ack
        && !(h2c->state.flags & RP_HTTP_V2_END_STREAM_FLAG)
        && h2scf->preread_size < RP_HTTP_V2_DEFAULT_WINDOW)
    {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent stream with data "
                      "before settings were acknowledged");

        status = RP_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    node = rp_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    if (node->parent) {
        rp_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream = rp_http_v2_create_stream(h2c, 0);
    if (stream == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = stream;

    stream->pool = h2c->state.pool;
    h2c->state.keep_pool = 1;

    stream->request->request_length = h2c->state.length;

    stream->in_closed = h2c->state.flags & RP_HTTP_V2_END_STREAM_FLAG;
    stream->node = node;

    node->stream = stream;

    if (priority || node->parent == NULL) {
        node->weight = weight;
        rp_http_v2_set_dependency(h2c, node, depend, excl);
    }

    if (h2c->connection->requests >= h2scf->max_requests) {
        h2c->goaway = 1;

        if (rp_http_v2_send_goaway(h2c, RP_HTTP_V2_NO_ERROR) == RP_ERROR) {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return rp_http_v2_state_header_block(h2c, pos, end);

rst_stream:

    if (rp_http_v2_send_rst_stream(h2c, h2c->state.sid, status) != RP_OK) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    return rp_http_v2_state_header_block(h2c, pos, end);
}


static u_char *
rp_http_v2_state_header_block(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    u_char      ch;
    rp_int_t   value;
    rp_uint_t  indexed, size_update, prefix;

    if (end - pos < 1) {
        return rp_http_v2_state_headers_save(h2c, pos, end,
                                              rp_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < RP_HTTP_V2_INT_OCTETS)
    {
        return rp_http_v2_handle_continuation(h2c, pos, end,
                                               rp_http_v2_state_header_block);
    }

    size_update = 0;
    indexed = 0;

    ch = *pos;

    if (ch >= (1 << 7)) {
        /* indexed header field */
        indexed = 1;
        prefix = rp_http_v2_prefix(7);

    } else if (ch >= (1 << 6)) {
        /* literal header field with incremental indexing */
        h2c->state.index = 1;
        prefix = rp_http_v2_prefix(6);

    } else if (ch >= (1 << 5)) {
        /* dynamic table size update */
        size_update = 1;
        prefix = rp_http_v2_prefix(5);

    } else if (ch >= (1 << 4)) {
        /* literal header field never indexed */
        prefix = rp_http_v2_prefix(4);

    } else {
        /* literal header field without indexing */
        prefix = rp_http_v2_prefix(4);
    }

    value = rp_http_v2_parse_int(h2c, &pos, end, prefix);

    if (value < 0) {
        if (value == RP_AGAIN) {
            return rp_http_v2_state_headers_save(h2c, pos, end,
                                               rp_http_v2_state_header_block);
        }

        if (value == RP_DECLINED) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent header block with too long %s value",
                          size_update ? "size update" : "header index");

            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
        }

        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (indexed) {
        if (rp_http_v2_get_indexed_header(h2c, value, 0) != RP_OK) {
            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
        }

        return rp_http_v2_state_process_header(h2c, pos, end);
    }

    if (size_update) {
        if (rp_http_v2_table_size(h2c, value) != RP_OK) {
            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
        }

        return rp_http_v2_state_header_complete(h2c, pos, end);
    }

    if (value == 0) {
        h2c->state.parse_name = 1;

    } else if (rp_http_v2_get_indexed_header(h2c, value, 1) != RP_OK) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
    }

    h2c->state.parse_value = 1;

    return rp_http_v2_state_field_len(h2c, pos, end);
}


static u_char *
rp_http_v2_state_field_len(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   alloc;
    rp_int_t                len;
    rp_uint_t               huff;
    rp_http_v2_srv_conf_t  *h2scf;

    if (!(h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < RP_HTTP_V2_INT_OCTETS)
    {
        return rp_http_v2_handle_continuation(h2c, pos, end,
                                               rp_http_v2_state_field_len);
    }

    if (h2c->state.length < 1) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < 1) {
        return rp_http_v2_state_headers_save(h2c, pos, end,
                                              rp_http_v2_state_field_len);
    }

    huff = *pos >> 7;
    len = rp_http_v2_parse_int(h2c, &pos, end, rp_http_v2_prefix(7));

    if (len < 0) {
        if (len == RP_AGAIN) {
            return rp_http_v2_state_headers_save(h2c, pos, end,
                                                  rp_http_v2_state_field_len);
        }

        if (len == RP_DECLINED) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                        "client sent header field with too long length value");

            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
        }

        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 %s string, len:%i",
                   huff ? "encoded" : "raw", len);

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    if ((size_t) len > h2scf->max_field_size) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client exceeded http2_max_field_size limit");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.field_rest = len;

    if (h2c->state.stream == NULL && !h2c->state.index) {
        return rp_http_v2_state_field_skip(h2c, pos, end);
    }

    alloc = (huff ? len * 8 / 5 : len) + 1;

    h2c->state.field_start = rp_pnalloc(h2c->state.pool, alloc);
    if (h2c->state.field_start == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.field_end = h2c->state.field_start;

    if (huff) {
        return rp_http_v2_state_field_huff(h2c, pos, end);
    }

    return rp_http_v2_state_field_raw(h2c, pos, end);
}


static u_char *
rp_http_v2_state_field_huff(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    if (rp_http_v2_huff_decode(&h2c->state.field_state, pos, size,
                                &h2c->state.field_end,
                                h2c->state.field_rest == 0,
                                h2c->connection->log)
        != RP_OK)
    {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid encoded header field");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_COMP_ERROR);
    }

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return rp_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rp_http_v2_state_headers_save(h2c, pos, end,
                                              rp_http_v2_state_field_huff);
    }

    if (h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    return rp_http_v2_handle_continuation(h2c, pos, end,
                                           rp_http_v2_state_field_huff);
}


static u_char *
rp_http_v2_state_field_raw(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    h2c->state.field_end = rp_cpymem(h2c->state.field_end, pos, size);

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return rp_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rp_http_v2_state_headers_save(h2c, pos, end,
                                              rp_http_v2_state_field_raw);
    }

    if (h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    return rp_http_v2_handle_continuation(h2c, pos, end,
                                           rp_http_v2_state_field_raw);
}


static u_char *
rp_http_v2_state_field_skip(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    pos += size;

    if (h2c->state.field_rest == 0) {
        return rp_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_field_skip);
    }

    if (h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    return rp_http_v2_handle_continuation(h2c, pos, end,
                                           rp_http_v2_state_field_skip);
}


static u_char *
rp_http_v2_state_process_header(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                      len;
    rp_int_t                   rc;
    rp_table_elt_t            *h;
    rp_http_header_t          *hh;
    rp_http_request_t         *r;
    rp_http_v2_header_t       *header;
    rp_http_core_srv_conf_t   *cscf;
    rp_http_core_main_conf_t  *cmcf;

    static rp_str_t cookie = rp_string("cookie");

    header = &h2c->state.header;

    if (h2c->state.parse_name) {
        h2c->state.parse_name = 0;

        header->name.len = h2c->state.field_end - h2c->state.field_start;
        header->name.data = h2c->state.field_start;

        if (header->name.len == 0) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent zero header name length");

            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_PROTOCOL_ERROR);
        }

        return rp_http_v2_state_field_len(h2c, pos, end);
    }

    if (h2c->state.parse_value) {
        h2c->state.parse_value = 0;

        header->value.len = h2c->state.field_end - h2c->state.field_start;
        header->value.data = h2c->state.field_start;
    }

    len = header->name.len + header->value.len;

    if (len > h2c->state.header_limit) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client exceeded http2_max_header_size limit");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.header_limit -= len;

    if (h2c->state.index) {
        if (rp_http_v2_add_header(h2c, header) != RP_OK) {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->state.index = 0;
    }

    if (h2c->state.stream == NULL) {
        return rp_http_v2_state_header_complete(h2c, pos, end);
    }

    r = h2c->state.stream->request;

    /* TODO Optimization: validate headers while parsing. */
    if (rp_http_v2_validate_header(r, header) != RP_OK) {
        if (rp_http_v2_terminate_stream(h2c, h2c->state.stream,
                                         RP_HTTP_V2_PROTOCOL_ERROR)
            == RP_ERROR)
        {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        goto error;
    }

    if (header->name.data[0] == ':') {
        rc = rp_http_v2_pseudo_header(r, header);

        if (rc == RP_OK) {
            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http2 header: \":%V: %V\"",
                           &header->name, &header->value);

            return rp_http_v2_state_header_complete(h2c, pos, end);
        }

        if (rc == RP_ABORT) {
            goto error;
        }

        if (rc == RP_DECLINED) {
            rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
            goto error;
        }

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    if (r->invalid_header) {
        cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

        if (cscf->ignore_invalid_headers) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", &header->name);

            return rp_http_v2_state_header_complete(h2c, pos, end);
        }
    }

    if (header->name.len == cookie.len
        && rp_memcmp(header->name.data, cookie.data, cookie.len) == 0)
    {
        if (rp_http_v2_cookie(r, header) != RP_OK) {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

    } else {
        h = rp_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }

        h->key.len = header->name.len;
        h->key.data = header->name.data;

        /*
         * TODO Optimization: precalculate hash
         * and handler for indexed headers.
         */
        h->hash = rp_hash_key(h->key.data, h->key.len);

        h->value.len = header->value.len;
        h->value.data = header->value.data;

        h->lowcase_key = h->key.data;

        cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

        hh = rp_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != RP_OK) {
            goto error;
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header: \"%V: %V\"",
                   &header->name, &header->value);

    return rp_http_v2_state_header_complete(h2c, pos, end);

error:

    h2c->state.stream = NULL;

    return rp_http_v2_state_header_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_header_complete(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_http_v2_stream_t  *stream;

    if (h2c->state.length) {
        if (end - pos > 0) {
            h2c->state.handler = rp_http_v2_state_header_block;
            return pos;
        }

        return rp_http_v2_state_headers_save(h2c, pos, end,
                                              rp_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & RP_HTTP_V2_END_HEADERS_FLAG)) {
        return rp_http_v2_handle_continuation(h2c, pos, end,
                                             rp_http_v2_state_header_complete);
    }

    stream = h2c->state.stream;

    if (stream) {
        rp_http_v2_run_request(stream->request);
    }

    if (!h2c->state.keep_pool) {
        rp_destroy_pool(h2c->state.pool);
    }

    h2c->state.pool = NULL;
    h2c->state.keep_pool = 0;

    if (h2c->state.padding) {
        return rp_http_v2_state_skip_padded(h2c, pos, end);
    }

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_handle_continuation(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, rp_http_v2_handler_pt handler)
{
    u_char    *p;
    size_t     len, skip;
    uint32_t   head;

    len = h2c->state.length;

    if (h2c->state.padding && (size_t) (end - pos) > len) {
        skip = rp_min(h2c->state.padding, (end - pos) - len);

        h2c->state.padding -= skip;

        p = pos;
        pos += skip;
        rp_memmove(pos, p, len);
    }

    if ((size_t) (end - pos) < len + RP_HTTP_V2_FRAME_HEADER_SIZE) {
        return rp_http_v2_state_headers_save(h2c, pos, end, handler);
    }

    p = pos + len;

    head = rp_http_v2_parse_uint32(p);

    if (rp_http_v2_parse_type(head) != RP_HTTP_V2_CONTINUATION_FRAME) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
             "client sent inappropriate frame while CONTINUATION was expected");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->state.flags |= p[4];

    if (h2c->state.sid != rp_http_v2_parse_sid(&p[5])) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                    "client sent CONTINUATION frame with incorrect identifier");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    p = pos;
    pos += RP_HTTP_V2_FRAME_HEADER_SIZE;

    rp_memcpy(pos, p, len);

    len = rp_http_v2_parse_length(head);

    h2c->state.length += len;

    if (h2c->state.stream) {
        h2c->state.stream->request->request_length += len;
    }

    h2c->state.handler = handler;
    return pos;
}


static u_char *
rp_http_v2_state_priority(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_uint_t           depend, dependency, excl, weight;
    rp_http_v2_node_t  *node;

    if (h2c->state.length != RP_HTTP_V2_PRIORITY_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect length %uz",
                      h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (--h2c->priority_limit == 0) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many PRIORITY frames");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    if (end - pos < RP_HTTP_V2_PRIORITY_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_priority);
    }

    dependency = rp_http_v2_parse_uint32(pos);

    depend = dependency & 0x7fffffff;
    excl = dependency >> 31;
    weight = pos[4] + 1;

    pos += RP_HTTP_V2_PRIORITY_SIZE;

    rp_log_debug4(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PRIORITY frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid == 0) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect identifier");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    node = rp_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    node->weight = weight;

    if (node->stream == NULL) {
        if (node->parent == NULL) {
            h2c->closed_nodes++;

        } else {
            rp_queue_remove(&node->reuse);
        }

        rp_queue_insert_tail(&h2c->closed, &node->reuse);
    }

    rp_http_v2_set_dependency(h2c, node, depend, excl);

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_rst_stream(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_uint_t             status;
    rp_event_t           *ev;
    rp_connection_t      *fc;
    rp_http_v2_node_t    *node;
    rp_http_v2_stream_t  *stream;

    if (h2c->state.length != RP_HTTP_V2_RST_STREAM_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect length %uz",
                      h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RP_HTTP_V2_RST_STREAM_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_rst_stream);
    }

    status = rp_http_v2_parse_uint32(pos);

    pos += RP_HTTP_V2_RST_STREAM_SIZE;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 RST_STREAM frame, sid:%ui status:%ui",
                   h2c->state.sid, status);

    if (h2c->state.sid == 0) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect identifier");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    node = rp_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return rp_http_v2_state_complete(h2c, pos, end);
    }

    stream = node->stream;

    stream->in_closed = 1;
    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    switch (status) {

    case RP_HTTP_V2_CANCEL:
        rp_log_error(RP_LOG_INFO, fc->log, 0,
                      "client canceled stream %ui", h2c->state.sid);
        break;

    case RP_HTTP_V2_REFUSED_STREAM:
        rp_log_error(RP_LOG_INFO, fc->log, 0,
                      "client refused stream %ui", h2c->state.sid);
        break;

    case RP_HTTP_V2_INTERNAL_ERROR:
        rp_log_error(RP_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui due to internal error",
                      h2c->state.sid);
        break;

    default:
        rp_log_error(RP_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui with status %ui",
                      h2c->state.sid, status);
        break;
    }

    ev = fc->read;
    ev->handler(ev);

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_settings(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    if (h2c->state.flags == RP_HTTP_V2_ACK_FLAG) {

        if (h2c->state.length != 0) {
            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client sent SETTINGS frame with the ACK flag "
                          "and nonzero length");

            return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
        }

        h2c->settings_ack = 1;

        return rp_http_v2_state_complete(h2c, pos, end);
    }

    if (h2c->state.length % RP_HTTP_V2_SETTINGS_PARAM_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect length %uz",
                      h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 SETTINGS frame");

    return rp_http_v2_state_settings_params(h2c, pos, end);
}


static u_char *
rp_http_v2_state_settings_params(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ssize_t                   window_delta;
    rp_uint_t                id, value;
    rp_http_v2_srv_conf_t   *h2scf;
    rp_http_v2_out_frame_t  *frame;

    window_delta = 0;

    while (h2c->state.length) {
        if (end - pos < RP_HTTP_V2_SETTINGS_PARAM_SIZE) {
            return rp_http_v2_state_save(h2c, pos, end,
                                          rp_http_v2_state_settings_params);
        }

        h2c->state.length -= RP_HTTP_V2_SETTINGS_PARAM_SIZE;

        id = rp_http_v2_parse_uint16(pos);
        value = rp_http_v2_parse_uint32(&pos[2]);

        rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 setting %ui:%ui", id, value);

        switch (id) {

        case RP_HTTP_V2_INIT_WINDOW_SIZE_SETTING:

            if (value > RP_HTTP_V2_MAX_WINDOW) {
                rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "INITIAL_WINDOW_SIZE value %ui", value);

                return rp_http_v2_connection_error(h2c,
                                                  RP_HTTP_V2_FLOW_CTRL_ERROR);
            }

            window_delta = value - h2c->init_window;
            break;

        case RP_HTTP_V2_MAX_FRAME_SIZE_SETTING:

            if (value > RP_HTTP_V2_MAX_FRAME_SIZE
                || value < RP_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "MAX_FRAME_SIZE value %ui", value);

                return rp_http_v2_connection_error(h2c,
                                                    RP_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->frame_size = value;
            break;

        case RP_HTTP_V2_ENABLE_PUSH_SETTING:

            if (value > 1) {
                rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "ENABLE_PUSH value %ui", value);

                return rp_http_v2_connection_error(h2c,
                                                    RP_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->push_disabled = !value;
            break;

        case RP_HTTP_V2_MAX_STREAMS_SETTING:
            h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                                 rp_http_v2_module);

            h2c->concurrent_pushes = rp_min(value, h2scf->concurrent_pushes);
            break;

        case RP_HTTP_V2_HEADER_TABLE_SIZE_SETTING:

            h2c->table_update = 1;
            break;

        default:
            break;
        }

        pos += RP_HTTP_V2_SETTINGS_PARAM_SIZE;
    }

    frame = rp_http_v2_get_frame(h2c, RP_HTTP_V2_SETTINGS_ACK_SIZE,
                                  RP_HTTP_V2_SETTINGS_FRAME,
                                  RP_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    rp_http_v2_queue_ordered_frame(h2c, frame);

    if (window_delta) {
        h2c->init_window += window_delta;

        if (rp_http_v2_adjust_windows(h2c, window_delta) != RP_OK) {
            return rp_http_v2_connection_error(h2c,
                                                RP_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_push_promise(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                  "client sent PUSH_PROMISE frame");

    return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
rp_http_v2_state_ping(rp_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    rp_buf_t                *buf;
    rp_http_v2_out_frame_t  *frame;

    if (h2c->state.length != RP_HTTP_V2_PING_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect length %uz",
                      h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RP_HTTP_V2_PING_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end, rp_http_v2_state_ping);
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PING frame");

    if (h2c->state.flags & RP_HTTP_V2_ACK_FLAG) {
        return rp_http_v2_state_skip(h2c, pos, end);
    }

    frame = rp_http_v2_get_frame(h2c, RP_HTTP_V2_PING_SIZE,
                                  RP_HTTP_V2_PING_FRAME,
                                  RP_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    buf = frame->first->buf;

    buf->last = rp_cpymem(buf->last, pos, RP_HTTP_V2_PING_SIZE);

    rp_http_v2_queue_blocked_frame(h2c, frame);

    return rp_http_v2_state_complete(h2c, pos + RP_HTTP_V2_PING_SIZE, end);
}


static u_char *
rp_http_v2_state_goaway(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
#if (RP_DEBUG)
    rp_uint_t  last_sid, error;
#endif

    if (h2c->state.length < RP_HTTP_V2_GOAWAY_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame "
                      "with incorrect length %uz", h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RP_HTTP_V2_GOAWAY_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end, rp_http_v2_state_goaway);
    }

#if (RP_DEBUG)
    h2c->state.length -= RP_HTTP_V2_GOAWAY_SIZE;

    last_sid = rp_http_v2_parse_sid(pos);
    error = rp_http_v2_parse_uint32(&pos[4]);

    pos += RP_HTTP_V2_GOAWAY_SIZE;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 GOAWAY frame: last sid %ui, error %ui",
                   last_sid, error);
#endif

    return rp_http_v2_state_skip(h2c, pos, end);
}


static u_char *
rp_http_v2_state_window_update(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                 window;
    rp_event_t           *wev;
    rp_queue_t           *q;
    rp_http_v2_node_t    *node;
    rp_http_v2_stream_t  *stream;

    if (h2c->state.length != RP_HTTP_V2_WINDOW_UPDATE_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect length %uz", h2c->state.length);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RP_HTTP_V2_WINDOW_UPDATE_SIZE) {
        return rp_http_v2_state_save(h2c, pos, end,
                                      rp_http_v2_state_window_update);
    }

    window = rp_http_v2_parse_window(pos);

    pos += RP_HTTP_V2_WINDOW_UPDATE_SIZE;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 WINDOW_UPDATE frame sid:%ui window:%uz",
                   h2c->state.sid, window);

    if (window == 0) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect window increment 0");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.sid) {
        node = rp_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

        if (node == NULL || node->stream == NULL) {
            rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "unknown http2 stream");

            return rp_http_v2_state_complete(h2c, pos, end);
        }

        stream = node->stream;

        if (window > (size_t) (RP_HTTP_V2_MAX_WINDOW - stream->send_window)) {

            rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                          "client violated flow control for stream %ui: "
                          "received WINDOW_UPDATE frame "
                          "with window increment %uz "
                          "not allowed for window %z",
                          h2c->state.sid, window, stream->send_window);

            if (rp_http_v2_terminate_stream(h2c, stream,
                                             RP_HTTP_V2_FLOW_CTRL_ERROR)
                == RP_ERROR)
            {
                return rp_http_v2_connection_error(h2c,
                                                    RP_HTTP_V2_INTERNAL_ERROR);
            }

            return rp_http_v2_state_complete(h2c, pos, end);
        }

        stream->send_window += window;

        if (stream->exhausted) {
            stream->exhausted = 0;

            wev = stream->request->connection->write;

            wev->active = 0;
            wev->ready = 1;

            if (!wev->delayed) {
                wev->handler(wev);
            }
        }

        return rp_http_v2_state_complete(h2c, pos, end);
    }

    if (window > RP_HTTP_V2_MAX_WINDOW - h2c->send_window) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received WINDOW_UPDATE frame "
                      "with window increment %uz "
                      "not allowed for window %uz",
                      window, h2c->send_window);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->send_window += window;

    while (!rp_queue_empty(&h2c->waiting)) {
        q = rp_queue_head(&h2c->waiting);

        rp_queue_remove(q);

        stream = rp_queue_data(q, rp_http_v2_stream_t, queue);

        stream->waiting = 0;

        wev = stream->request->connection->write;

        wev->active = 0;
        wev->ready = 1;

        if (!wev->delayed) {
            wev->handler(wev);

            if (h2c->send_window == 0) {
                break;
            }
        }
    }

    return rp_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rp_http_v2_state_continuation(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                  "client sent unexpected CONTINUATION frame");

    return rp_http_v2_connection_error(h2c, RP_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
rp_http_v2_state_complete(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame complete pos:%p end:%p", pos, end);

    if (pos > end) {
        rp_log_error(RP_LOG_ALERT, h2c->connection->log, 0,
                      "receive buffer overrun");

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = NULL;
    h2c->state.handler = rp_http_v2_state_head;

    return pos;
}


static u_char *
rp_http_v2_state_skip_padded(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    h2c->state.length += h2c->state.padding;
    h2c->state.padding = 0;

    return rp_http_v2_state_skip(h2c, pos, end);
}


static u_char *
rp_http_v2_state_skip(rp_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size < h2c->state.length) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 frame skip %uz of %uz", size, h2c->state.length);

        h2c->state.length -= size;
        return rp_http_v2_state_save(h2c, end, end, rp_http_v2_state_skip);
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame skip %uz", h2c->state.length);

    return rp_http_v2_state_complete(h2c, pos + h2c->state.length, end);
}


static u_char *
rp_http_v2_state_save(rp_http_v2_connection_t *h2c, u_char *pos, u_char *end,
    rp_http_v2_handler_pt handler)
{
    size_t  size;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame state save pos:%p end:%p handler:%p",
                   pos, end, handler);

    size = end - pos;

    if (size > RP_HTTP_V2_STATE_BUFFER_SIZE) {
        rp_log_error(RP_LOG_ALERT, h2c->connection->log, 0,
                      "state buffer overflow: %uz bytes required", size);

        return rp_http_v2_connection_error(h2c, RP_HTTP_V2_INTERNAL_ERROR);
    }

    rp_memcpy(h2c->state.buffer, pos, RP_HTTP_V2_STATE_BUFFER_SIZE);

    h2c->state.buffer_used = size;
    h2c->state.handler = handler;
    h2c->state.incomplete = 1;

    return end;
}


static u_char *
rp_http_v2_state_headers_save(rp_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, rp_http_v2_handler_pt handler)
{
    rp_event_t               *rev;
    rp_http_request_t        *r;
    rp_http_core_srv_conf_t  *cscf;

    if (h2c->state.stream) {
        r = h2c->state.stream->request;
        rev = r->connection->read;

        if (!rev->timer_set) {
            cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
            rp_add_timer(rev, cscf->client_header_timeout);
        }
    }

    return rp_http_v2_state_save(h2c, pos, end, handler);
}


static u_char *
rp_http_v2_connection_error(rp_http_v2_connection_t *h2c,
    rp_uint_t err)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 state connection error");

    rp_http_v2_finalize_connection(h2c, err);

    return NULL;
}


static rp_int_t
rp_http_v2_parse_int(rp_http_v2_connection_t *h2c, u_char **pos, u_char *end,
    rp_uint_t prefix)
{
    u_char      *start, *p;
    rp_uint_t   value, octet, shift;

    start = *pos;
    p = start;

    value = *p++ & prefix;

    if (value != prefix) {
        if (h2c->state.length == 0) {
            return RP_ERROR;
        }

        h2c->state.length--;

        *pos = p;
        return value;
    }

    if (end - start > RP_HTTP_V2_INT_OCTETS) {
        end = start + RP_HTTP_V2_INT_OCTETS;
    }

    for (shift = 0; p != end; shift += 7) {
        octet = *p++;

        value += (octet & 0x7f) << shift;

        if (octet < 128) {
            if ((size_t) (p - start) > h2c->state.length) {
                return RP_ERROR;
            }

            h2c->state.length -= p - start;

            *pos = p;
            return value;
        }
    }

    if ((size_t) (end - start) >= h2c->state.length) {
        return RP_ERROR;
    }

    if (end == start + RP_HTTP_V2_INT_OCTETS) {
        return RP_DECLINED;
    }

    return RP_AGAIN;
}


rp_http_v2_stream_t *
rp_http_v2_push_stream(rp_http_v2_stream_t *parent, rp_str_t *path)
{
    rp_int_t                     rc;
    rp_str_t                     value;
    rp_pool_t                   *pool;
    rp_uint_t                    index;
    rp_table_elt_t             **h;
    rp_connection_t             *fc;
    rp_http_request_t           *r;
    rp_http_v2_node_t           *node;
    rp_http_v2_stream_t         *stream;
    rp_http_v2_srv_conf_t       *h2scf;
    rp_http_v2_connection_t     *h2c;
    rp_http_v2_parse_header_t   *header;

    h2c = parent->connection;

    pool = rp_create_pool(1024, h2c->connection->log);
    if (pool == NULL) {
        goto rst_stream;
    }

    node = rp_http_v2_get_node_by_id(h2c, h2c->last_push, 1);

    if (node == NULL) {
        rp_destroy_pool(pool);
        goto rst_stream;
    }

    stream = rp_http_v2_create_stream(h2c, 1);
    if (stream == NULL) {

        if (node->parent == NULL) {
            h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                                 rp_http_v2_module);

            index = rp_http_v2_index(h2scf, h2c->last_push);
            h2c->streams_index[index] = node->index;

            rp_queue_insert_tail(&h2c->closed, &node->reuse);
            h2c->closed_nodes++;
        }

        rp_destroy_pool(pool);
        goto rst_stream;
    }

    if (node->parent) {
        rp_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream->pool = pool;

    r = stream->request;
    fc = r->connection;

    stream->in_closed = 1;
    stream->node = node;

    node->stream = stream;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 push stream sid:%ui "
                   "depends on %ui excl:0 weight:16",
                   h2c->last_push, parent->node->id);

    node->weight = RP_HTTP_V2_DEFAULT_WEIGHT;
    rp_http_v2_set_dependency(h2c, node, parent->node->id, 0);

    r->method_name = rp_http_core_get_method;
    r->method = RP_HTTP_GET;

    r->schema.data = rp_pstrdup(pool, &parent->request->schema);
    if (r->schema.data == NULL) {
        goto close;
    }

    r->schema.len = parent->request->schema.len;

    value.data = rp_pstrdup(pool, path);
    if (value.data == NULL) {
        goto close;
    }

    value.len = path->len;

    rc = rp_http_v2_parse_path(r, &value);

    if (rc != RP_OK) {
        goto error;
    }

    for (header = rp_http_v2_parse_headers; header->name.len; header++) {
        h = (rp_table_elt_t **)
                ((char *) &parent->request->headers_in + header->offset);

        if (*h == NULL) {
            continue;
        }

        value.len = (*h)->value.len;

        value.data = rp_pnalloc(pool, value.len + 1);
        if (value.data == NULL) {
            goto close;
        }

        rp_memcpy(value.data, (*h)->value.data, value.len);
        value.data[value.len] = '\0';

        rc = rp_http_v2_parse_header(r, header, &value);

        if (rc != RP_OK) {
            goto error;
        }
    }

    fc->write->handler = rp_http_v2_run_request_handler;
    rp_post_event(fc->write, &rp_posted_events);

    return stream;

error:

    if (rc == RP_ABORT) {
        /* header handler has already finalized request */
        rp_http_run_posted_requests(fc);
        return NULL;
    }

    if (rc == RP_DECLINED) {
        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        rp_http_run_posted_requests(fc);
        return NULL;
    }

close:

    rp_http_v2_close_stream(stream, RP_HTTP_INTERNAL_SERVER_ERROR);

    return NULL;

rst_stream:

    if (rp_http_v2_send_rst_stream(h2c, h2c->last_push,
                                    RP_HTTP_INTERNAL_SERVER_ERROR)
        != RP_OK)
    {
        h2c->connection->error = 1;
    }

    return NULL;
}


static rp_int_t
rp_http_v2_send_settings(rp_http_v2_connection_t *h2c)
{
    size_t                    len;
    rp_buf_t                *buf;
    rp_chain_t              *cl;
    rp_http_v2_srv_conf_t   *h2scf;
    rp_http_v2_out_frame_t  *frame;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send SETTINGS frame");

    frame = rp_palloc(h2c->pool, sizeof(rp_http_v2_out_frame_t));
    if (frame == NULL) {
        return RP_ERROR;
    }

    cl = rp_alloc_chain_link(h2c->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    len = RP_HTTP_V2_SETTINGS_PARAM_SIZE * 3;

    buf = rp_create_temp_buf(h2c->pool, RP_HTTP_V2_FRAME_HEADER_SIZE + len);
    if (buf == NULL) {
        return RP_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = rp_http_v2_settings_frame_handler;
    frame->stream = NULL;
#if (RP_DEBUG)
    frame->length = len;
#endif
    frame->blocked = 0;

    buf->last = rp_http_v2_write_len_and_type(buf->last, len,
                                               RP_HTTP_V2_SETTINGS_FRAME);

    *buf->last++ = RP_HTTP_V2_NO_FLAG;

    buf->last = rp_http_v2_write_sid(buf->last, 0);

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    buf->last = rp_http_v2_write_uint16(buf->last,
                                         RP_HTTP_V2_MAX_STREAMS_SETTING);
    buf->last = rp_http_v2_write_uint32(buf->last,
                                         h2scf->concurrent_streams);

    buf->last = rp_http_v2_write_uint16(buf->last,
                                         RP_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
    buf->last = rp_http_v2_write_uint32(buf->last, h2scf->preread_size);

    buf->last = rp_http_v2_write_uint16(buf->last,
                                         RP_HTTP_V2_MAX_FRAME_SIZE_SETTING);
    buf->last = rp_http_v2_write_uint32(buf->last,
                                         RP_HTTP_V2_MAX_FRAME_SIZE);

    rp_http_v2_queue_blocked_frame(h2c, frame);

    return RP_OK;
}


static rp_int_t
rp_http_v2_settings_frame_handler(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame)
{
    rp_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return RP_AGAIN;
    }

    rp_free_chain(h2c->pool, frame->first);

    return RP_OK;
}


static rp_int_t
rp_http_v2_send_window_update(rp_http_v2_connection_t *h2c, rp_uint_t sid,
    size_t window)
{
    rp_buf_t                *buf;
    rp_http_v2_out_frame_t  *frame;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send WINDOW_UPDATE frame sid:%ui, window:%uz",
                   sid, window);

    frame = rp_http_v2_get_frame(h2c, RP_HTTP_V2_WINDOW_UPDATE_SIZE,
                                  RP_HTTP_V2_WINDOW_UPDATE_FRAME,
                                  RP_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return RP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rp_http_v2_write_uint32(buf->last, window);

    rp_http_v2_queue_blocked_frame(h2c, frame);

    return RP_OK;
}


static rp_int_t
rp_http_v2_send_rst_stream(rp_http_v2_connection_t *h2c, rp_uint_t sid,
    rp_uint_t status)
{
    rp_buf_t                *buf;
    rp_http_v2_out_frame_t  *frame;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send RST_STREAM frame sid:%ui, status:%ui",
                   sid, status);

    frame = rp_http_v2_get_frame(h2c, RP_HTTP_V2_RST_STREAM_SIZE,
                                  RP_HTTP_V2_RST_STREAM_FRAME,
                                  RP_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return RP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rp_http_v2_write_uint32(buf->last, status);

    rp_http_v2_queue_blocked_frame(h2c, frame);

    return RP_OK;
}


static rp_int_t
rp_http_v2_send_goaway(rp_http_v2_connection_t *h2c, rp_uint_t status)
{
    rp_buf_t                *buf;
    rp_http_v2_out_frame_t  *frame;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send GOAWAY frame: last sid %ui, error %ui",
                   h2c->last_sid, status);

    frame = rp_http_v2_get_frame(h2c, RP_HTTP_V2_GOAWAY_SIZE,
                                  RP_HTTP_V2_GOAWAY_FRAME,
                                  RP_HTTP_V2_NO_FLAG, 0);
    if (frame == NULL) {
        return RP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rp_http_v2_write_sid(buf->last, h2c->last_sid);
    buf->last = rp_http_v2_write_uint32(buf->last, status);

    rp_http_v2_queue_blocked_frame(h2c, frame);

    return RP_OK;
}


static rp_http_v2_out_frame_t *
rp_http_v2_get_frame(rp_http_v2_connection_t *h2c, size_t length,
    rp_uint_t type, u_char flags, rp_uint_t sid)
{
    rp_buf_t                *buf;
    rp_pool_t               *pool;
    rp_http_v2_out_frame_t  *frame;

    frame = h2c->free_frames;

    if (frame) {
        h2c->free_frames = frame->next;

        buf = frame->first->buf;
        buf->pos = buf->start;

        frame->blocked = 0;

    } else if (h2c->frames < 10000) {
        pool = h2c->pool ? h2c->pool : h2c->connection->pool;

        frame = rp_pcalloc(pool, sizeof(rp_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        frame->first = rp_alloc_chain_link(pool);
        if (frame->first == NULL) {
            return NULL;
        }

        buf = rp_create_temp_buf(pool, RP_HTTP_V2_FRAME_BUFFER_SIZE);
        if (buf == NULL) {
            return NULL;
        }

        buf->last_buf = 1;

        frame->first->buf = buf;
        frame->last = frame->first;

        frame->handler = rp_http_v2_frame_handler;

        h2c->frames++;

    } else {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

#if (RP_DEBUG)
    if (length > RP_HTTP_V2_FRAME_BUFFER_SIZE - RP_HTTP_V2_FRAME_HEADER_SIZE)
    {
        rp_log_error(RP_LOG_ALERT, h2c->connection->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }
#endif

    frame->length = length;

    buf->last = rp_http_v2_write_len_and_type(buf->pos, length, type);

    *buf->last++ = flags;

    buf->last = rp_http_v2_write_sid(buf->last, sid);

    return frame;
}


static rp_int_t
rp_http_v2_frame_handler(rp_http_v2_connection_t *h2c,
    rp_http_v2_out_frame_t *frame)
{
    rp_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return RP_AGAIN;
    }

    frame->next = h2c->free_frames;
    h2c->free_frames = frame;

    h2c->total_bytes += RP_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    return RP_OK;
}


static rp_http_v2_stream_t *
rp_http_v2_create_stream(rp_http_v2_connection_t *h2c, rp_uint_t push)
{
    rp_log_t                 *log;
    rp_event_t               *rev, *wev;
    rp_connection_t          *fc;
    rp_http_log_ctx_t        *ctx;
    rp_http_request_t        *r;
    rp_http_v2_stream_t      *stream;
    rp_http_v2_srv_conf_t    *h2scf;
    rp_http_core_srv_conf_t  *cscf;

    fc = h2c->free_fake_connections;

    if (fc) {
        h2c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = rp_palloc(h2c->pool, sizeof(rp_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = rp_palloc(h2c->pool, sizeof(rp_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = rp_palloc(h2c->pool, sizeof(rp_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = rp_palloc(h2c->pool, sizeof(rp_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = rp_palloc(h2c->pool, sizeof(rp_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    rp_memcpy(log, h2c->connection->log, sizeof(rp_log_t));

    log->data = ctx;

    if (push) {
        log->action = "processing pushed request headers";

    } else {
        log->action = "reading client request headers";
    }

    rp_memzero(rev, sizeof(rp_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = rp_http_v2_close_stream_handler;
    rev->log = log;

    rp_memcpy(wev, rev, sizeof(rp_event_t));

    wev->write = 1;

    rp_memcpy(fc, h2c->connection, sizeof(rp_connection_t));

    fc->data = h2c->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = RP_TCP_NODELAY_DISABLED;

    r = rp_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    rp_str_set(&r->http_protocol, "HTTP/2.0");

    r->http_version = RP_HTTP_VERSION_20;
    r->valid_location = 1;

    fc->data = r;
    h2c->connection->requests++;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    r->header_in = rp_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        rp_http_free_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (rp_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        rp_http_free_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = RP_HTTP_CONNECTION_CLOSE;

    stream = rp_pcalloc(r->pool, sizeof(rp_http_v2_stream_t));
    if (stream == NULL) {
        rp_http_free_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->stream = stream;

    stream->request = r;
    stream->connection = h2c;

    h2scf = rp_http_get_module_srv_conf(r, rp_http_v2_module);

    stream->send_window = h2c->init_window;
    stream->recv_window = h2scf->preread_size;

    if (push) {
        h2c->pushing++;

    } else {
        h2c->processing++;
    }

    h2c->priority_limit += h2scf->concurrent_streams;

    return stream;
}


static rp_http_v2_node_t *
rp_http_v2_get_node_by_id(rp_http_v2_connection_t *h2c, rp_uint_t sid,
    rp_uint_t alloc)
{
    rp_uint_t               index;
    rp_http_v2_node_t      *node;
    rp_http_v2_srv_conf_t  *h2scf;

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    index = rp_http_v2_index(h2scf, sid);

    for (node = h2c->streams_index[index]; node; node = node->index) {

        if (node->id == sid) {
            return node;
        }
    }

    if (!alloc) {
        return NULL;
    }

    if (h2c->closed_nodes < 32) {
        node = rp_pcalloc(h2c->connection->pool, sizeof(rp_http_v2_node_t));
        if (node == NULL) {
            return NULL;
        }

    } else {
        node = rp_http_v2_get_closed_node(h2c);
    }

    node->id = sid;

    rp_queue_init(&node->children);

    node->index = h2c->streams_index[index];
    h2c->streams_index[index] = node;

    return node;
}


static rp_http_v2_node_t *
rp_http_v2_get_closed_node(rp_http_v2_connection_t *h2c)
{
    rp_uint_t               weight;
    rp_queue_t             *q, *children;
    rp_http_v2_node_t      *node, **next, *n, *parent, *child;
    rp_http_v2_srv_conf_t  *h2scf;

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    h2c->closed_nodes--;

    q = rp_queue_head(&h2c->closed);

    rp_queue_remove(q);

    node = rp_queue_data(q, rp_http_v2_node_t, reuse);

    next = &h2c->streams_index[rp_http_v2_index(h2scf, node->id)];

    for ( ;; ) {
        n = *next;

        if (n == node) {
            *next = n->index;
            break;
        }

        next = &n->index;
    }

    rp_queue_remove(&node->queue);

    weight = 0;

    for (q = rp_queue_head(&node->children);
         q != rp_queue_sentinel(&node->children);
         q = rp_queue_next(q))
    {
        child = rp_queue_data(q, rp_http_v2_node_t, queue);
        weight += child->weight;
    }

    parent = node->parent;

    for (q = rp_queue_head(&node->children);
         q != rp_queue_sentinel(&node->children);
         q = rp_queue_next(q))
    {
        child = rp_queue_data(q, rp_http_v2_node_t, queue);
        child->parent = parent;
        child->weight = node->weight * child->weight / weight;

        if (child->weight == 0) {
            child->weight = 1;
        }
    }

    if (parent == RP_HTTP_V2_ROOT) {
        node->rank = 0;
        node->rel_weight = 1.0;

        children = &h2c->dependencies;

    } else {
        node->rank = parent->rank;
        node->rel_weight = parent->rel_weight;

        children = &parent->children;
    }

    rp_http_v2_node_children_update(node);
    rp_queue_add(children, &node->children);

    rp_memzero(node, sizeof(rp_http_v2_node_t));

    return node;
}


static rp_int_t
rp_http_v2_validate_header(rp_http_request_t *r, rp_http_v2_header_t *header)
{
    u_char                     ch;
    rp_uint_t                 i;
    rp_http_core_srv_conf_t  *cscf;

    r->invalid_header = 0;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    for (i = (header->name.data[0] == ':'); i != header->name.len; i++) {
        ch = header->name.data[i];

        if ((ch >= 'a' && ch <= 'z')
            || (ch == '-')
            || (ch >= '0' && ch <= '9')
            || (ch == '_' && cscf->underscores_in_headers))
        {
            continue;
        }

        if (ch == '\0' || ch == LF || ch == CR || ch == ':'
            || (ch >= 'A' && ch <= 'Z'))
        {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header name: \"%V\"",
                          &header->name);

            return RP_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != header->value.len; i++) {
        ch = header->value.data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"",
                          &header->name, &header->value);

            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_v2_pseudo_header(rp_http_request_t *r, rp_http_v2_header_t *header)
{
    header->name.len--;
    header->name.data++;

    switch (header->name.len) {
    case 4:
        if (rp_memcmp(header->name.data, "path", sizeof("path") - 1)
            == 0)
        {
            return rp_http_v2_parse_path(r, &header->value);
        }

        break;

    case 6:
        if (rp_memcmp(header->name.data, "method", sizeof("method") - 1)
            == 0)
        {
            return rp_http_v2_parse_method(r, &header->value);
        }

        if (rp_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
            == 0)
        {
            return rp_http_v2_parse_scheme(r, &header->value);
        }

        break;

    case 9:
        if (rp_memcmp(header->name.data, "authority", sizeof("authority") - 1)
            == 0)
        {
            return rp_http_v2_parse_authority(r, &header->value);
        }

        break;
    }

    rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \":%V\"",
                  &header->name);

    return RP_DECLINED;
}


static rp_int_t
rp_http_v2_parse_path(rp_http_request_t *r, rp_str_t *value)
{
    if (r->unparsed_uri.len) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return RP_DECLINED;
    }

    if (value->len == 0) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return RP_DECLINED;
    }

    r->uri_start = value->data;
    r->uri_end = value->data + value->len;

    if (rp_http_parse_uri(r) != RP_OK) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"", value);

        return RP_DECLINED;
    }

    if (rp_http_process_request_uri(r) != RP_OK) {
        /*
         * request has been finalized already
         * in rp_http_process_request_uri()
         */
        return RP_ABORT;
    }

    return RP_OK;
}


static rp_int_t
rp_http_v2_parse_method(rp_http_request_t *r, rp_str_t *value)
{
    size_t         k, len;
    rp_uint_t     n;
    const u_char  *p, *m;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static const struct {
        u_char            len;
        const u_char      method[11];
        uint32_t          value;
    } tests[] = {
        { 3, "GET",       RP_HTTP_GET },
        { 4, "POST",      RP_HTTP_POST },
        { 4, "HEAD",      RP_HTTP_HEAD },
        { 7, "OPTIONS",   RP_HTTP_OPTIONS },
        { 8, "PROPFIND",  RP_HTTP_PROPFIND },
        { 3, "PUT",       RP_HTTP_PUT },
        { 5, "MKCOL",     RP_HTTP_MKCOL },
        { 6, "DELETE",    RP_HTTP_DELETE },
        { 4, "COPY",      RP_HTTP_COPY },
        { 4, "MOVE",      RP_HTTP_MOVE },
        { 9, "PROPPATCH", RP_HTTP_PROPPATCH },
        { 4, "LOCK",      RP_HTTP_LOCK },
        { 6, "UNLOCK",    RP_HTTP_UNLOCK },
        { 5, "PATCH",     RP_HTTP_PATCH },
        { 5, "TRACE",     RP_HTTP_TRACE }
    }, *test;

    if (r->method_name.len) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return RP_DECLINED;
    }

    if (value->len == 0) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return RP_DECLINED;
    }

    r->method_name.len = value->len;
    r->method_name.data = value->data;

    len = r->method_name.len;
    n = sizeof(tests) / sizeof(tests[0]);
    test = tests;

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return RP_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return RP_DECLINED;
        }

        p++;

    } while (--len);

    return RP_OK;
}


static rp_int_t
rp_http_v2_parse_scheme(rp_http_request_t *r, rp_str_t *value)
{
    u_char      c, ch;
    rp_uint_t  i;

    if (r->schema.len) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :scheme header");

        return RP_DECLINED;
    }

    if (value->len == 0) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :scheme header");

        return RP_DECLINED;
    }

    for (i = 0; i < value->len; i++) {
        ch = value->data[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if (((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            && i > 0)
        {
            continue;
        }

        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :scheme header: \"%V\"", value);

        return RP_DECLINED;
    }

    r->schema = *value;

    return RP_OK;
}


static rp_int_t
rp_http_v2_parse_authority(rp_http_request_t *r, rp_str_t *value)
{
    return rp_http_v2_parse_header(r, &rp_http_v2_parse_headers[0], value);
}


static rp_int_t
rp_http_v2_parse_header(rp_http_request_t *r,
    rp_http_v2_parse_header_t *header, rp_str_t *value)
{
    rp_table_elt_t            *h;
    rp_http_core_main_conf_t  *cmcf;

    h = rp_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return RP_ERROR;
    }

    h->key.len = header->name.len;
    h->key.data = header->name.data;
    h->lowcase_key = header->name.data;

    if (header->hh == NULL) {
        header->hash = rp_hash_key(header->name.data, header->name.len);

        cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

        header->hh = rp_hash_find(&cmcf->headers_in_hash, header->hash,
                                   h->lowcase_key, h->key.len);
        if (header->hh == NULL) {
            return RP_ERROR;
        }
    }

    h->hash = header->hash;

    h->value.len = value->len;
    h->value.data = value->data;

    if (header->hh->handler(r, h, header->hh->offset) != RP_OK) {
        /* header handler has already finalized request */
        return RP_ABORT;
    }

    return RP_OK;
}


static rp_int_t
rp_http_v2_construct_request_line(rp_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/2.0";

    if (r->method_name.len == 0
        || r->schema.len == 0
        || r->unparsed_uri.len == 0)
    {
        if (r->method_name.len == 0) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent no :method header");

        } else if (r->schema.len == 0) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent no :scheme header");

        } else {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent no :path header");
        }

        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        return RP_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = rp_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        rp_http_v2_close_stream(r->stream, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    r->request_line.data = p;

    p = rp_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = rp_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    rp_memcpy(p, ending, sizeof(ending));

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 request line: \"%V\"", &r->request_line);

    return RP_OK;
}


static rp_int_t
rp_http_v2_cookie(rp_http_request_t *r, rp_http_v2_header_t *header)
{
    rp_str_t    *val;
    rp_array_t  *cookies;

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        cookies = rp_array_create(r->pool, 2, sizeof(rp_str_t));
        if (cookies == NULL) {
            return RP_ERROR;
        }

        r->stream->cookies = cookies;
    }

    val = rp_array_push(cookies);
    if (val == NULL) {
        return RP_ERROR;
    }

    val->len = header->value.len;
    val->data = header->value.data;

    return RP_OK;
}


static rp_int_t
rp_http_v2_construct_cookie_header(rp_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    rp_str_t                  *vals;
    rp_uint_t                  i;
    rp_array_t                *cookies;
    rp_table_elt_t            *h;
    rp_http_header_t          *hh;
    rp_http_core_main_conf_t  *cmcf;

    static rp_str_t cookie = rp_string("cookie");

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        return RP_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = rp_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        rp_http_v2_close_stream(r->stream, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = rp_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = rp_list_push(&r->headers_in.headers);
    if (h == NULL) {
        rp_http_v2_close_stream(r->stream, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    h->hash = rp_hash(rp_hash(rp_hash(rp_hash(
                                    rp_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    hh = rp_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        rp_http_v2_close_stream(r->stream, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != RP_OK) {
        /*
         * request has been finalized already
         * in rp_http_process_multi_header_lines()
         */
        return RP_ERROR;
    }

    return RP_OK;
}


static void
rp_http_v2_run_request(rp_http_request_t *r)
{
    rp_connection_t          *fc;
    rp_http_v2_connection_t  *h2c;

    fc = r->connection;

    if (rp_http_v2_construct_request_line(r) != RP_OK) {
        goto failed;
    }

    if (rp_http_v2_construct_cookie_header(r) != RP_OK) {
        goto failed;
    }

    r->http_state = RP_HTTP_PROCESS_REQUEST_STATE;

    if (rp_http_process_request_header(r) != RP_OK) {
        goto failed;
    }

    if (r->headers_in.content_length_n > 0 && r->stream->in_closed) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        goto failed;
    }

    if (r->headers_in.content_length_n == -1 && !r->stream->in_closed) {
        r->headers_in.chunked = 1;
    }

    h2c = r->stream->connection;

    h2c->payload_bytes += r->request_length;

    rp_http_process_request(r);

failed:

    rp_http_run_posted_requests(fc);
}


static void
rp_http_v2_run_request_handler(rp_event_t *ev)
{
    rp_connection_t    *fc;
    rp_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 run request handler");

    rp_http_v2_run_request(r);
}


rp_int_t
rp_http_v2_read_request_body(rp_http_request_t *r)
{
    off_t                      len;
    size_t                     size;
    rp_buf_t                 *buf;
    rp_int_t                  rc;
    rp_http_v2_stream_t      *stream;
    rp_http_v2_srv_conf_t    *h2scf;
    rp_http_request_body_t   *rb;
    rp_http_core_loc_conf_t  *clcf;
    rp_http_v2_connection_t  *h2c;

    stream = r->stream;
    rb = r->request_body;

    if (stream->skip_data) {
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return RP_OK;
    }

    h2scf = rp_http_get_module_srv_conf(r, rp_http_v2_module);
    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    len = r->headers_in.content_length_n;

    if (r->request_body_no_buffering && !stream->in_closed) {

        if (len < 0 || len > (off_t) clcf->client_body_buffer_size) {
            len = clcf->client_body_buffer_size;
        }

        /*
         * We need a room to store data up to the stream's initial window size,
         * at least until this window will be exhausted.
         */

        if (len < (off_t) h2scf->preread_size) {
            len = h2scf->preread_size;
        }

        if (len > RP_HTTP_V2_MAX_WINDOW) {
            len = RP_HTTP_V2_MAX_WINDOW;
        }

        rb->buf = rp_create_temp_buf(r->pool, (size_t) len);

    } else if (len >= 0 && len <= (off_t) clcf->client_body_buffer_size
               && !r->request_body_in_file_only)
    {
        rb->buf = rp_create_temp_buf(r->pool, (size_t) len);

    } else {
        rb->buf = rp_calloc_buf(r->pool);

        if (rb->buf != NULL) {
            rb->buf->sync = 1;
        }
    }

    if (rb->buf == NULL) {
        stream->skip_data = 1;
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rb->rest = 1;

    buf = stream->preread;

    if (stream->in_closed) {
        r->request_body_no_buffering = 0;

        if (buf) {
            rc = rp_http_v2_process_request_body(r, buf->pos,
                                                  buf->last - buf->pos, 1);
            rp_pfree(r->pool, buf->start);
            return rc;
        }

        return rp_http_v2_process_request_body(r, NULL, 0, 1);
    }

    if (buf) {
        rc = rp_http_v2_process_request_body(r, buf->pos,
                                              buf->last - buf->pos, 0);

        rp_pfree(r->pool, buf->start);

        if (rc != RP_OK) {
            stream->skip_data = 1;
            return rc;
        }
    }

    if (r->request_body_no_buffering) {
        size = (size_t) len - h2scf->preread_size;

    } else {
        stream->no_flow_control = 1;
        size = RP_HTTP_V2_MAX_WINDOW - stream->recv_window;
    }

    if (size) {
        if (rp_http_v2_send_window_update(stream->connection,
                                           stream->node->id, size)
            == RP_ERROR)
        {
            stream->skip_data = 1;
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        h2c = stream->connection;

        if (!h2c->blocked) {
            if (rp_http_v2_send_output_queue(h2c) == RP_ERROR) {
                stream->skip_data = 1;
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        stream->recv_window += size;
    }

    if (!buf) {
        rp_add_timer(r->connection->read, clcf->client_body_timeout);
    }

    r->read_event_handler = rp_http_v2_read_client_request_body_handler;
    r->write_event_handler = rp_http_request_empty_handler;

    return RP_AGAIN;
}


static rp_int_t
rp_http_v2_process_request_body(rp_http_request_t *r, u_char *pos,
    size_t size, rp_uint_t last)
{
    rp_buf_t                 *buf;
    rp_int_t                  rc;
    rp_connection_t          *fc;
    rp_http_request_body_t   *rb;
    rp_http_core_loc_conf_t  *clcf;

    fc = r->connection;
    rb = r->request_body;
    buf = rb->buf;

    if (size) {
        if (buf->sync) {
            buf->pos = buf->start = pos;
            buf->last = buf->end = pos + size;

            r->request_body_in_file_only = 1;

        } else {
            if (size > (size_t) (buf->end - buf->last)) {
                rp_log_error(RP_LOG_INFO, fc->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return RP_HTTP_BAD_REQUEST;
            }

            buf->last = rp_cpymem(buf->last, pos, size);
        }
    }

    if (last) {
        rb->rest = 0;

        if (fc->read->timer_set) {
            rp_del_timer(fc->read);
        }

        if (r->request_body_no_buffering) {
            rp_post_event(fc->read, &rp_posted_events);
            return RP_OK;
        }

        rc = rp_http_v2_filter_request_body(r);

        if (rc != RP_OK) {
            return rc;
        }

        if (buf->sync) {
            /* prevent reusing this buffer in the upstream module */
            rb->buf = NULL;
        }

        if (r->headers_in.chunked) {
            r->headers_in.content_length_n = rb->received;
        }

        r->read_event_handler = rp_http_block_reading;
        rb->post_handler(r);

        return RP_OK;
    }

    if (size == 0) {
        return RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    rp_add_timer(fc->read, clcf->client_body_timeout);

    if (r->request_body_no_buffering) {
        rp_post_event(fc->read, &rp_posted_events);
        return RP_OK;
    }

    if (buf->sync) {
        return rp_http_v2_filter_request_body(r);
    }

    return RP_OK;
}


static rp_int_t
rp_http_v2_filter_request_body(rp_http_request_t *r)
{
    rp_buf_t                 *b, *buf;
    rp_int_t                  rc;
    rp_chain_t               *cl;
    rp_http_request_body_t   *rb;
    rp_http_core_loc_conf_t  *clcf;

    rb = r->request_body;
    buf = rb->buf;

    if (buf->pos == buf->last && rb->rest) {
        cl = NULL;
        goto update;
    }

    cl = rp_chain_get_free_buf(r->pool, &rb->free);
    if (cl == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    rp_memzero(b, sizeof(rp_buf_t));

    if (buf->pos != buf->last) {
        r->request_length += buf->last - buf->pos;
        rb->received += buf->last - buf->pos;

        if (r->headers_in.content_length_n != -1) {
            if (rb->received > r->headers_in.content_length_n) {
                rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return RP_HTTP_BAD_REQUEST;
            }

        } else {
            clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

            if (clcf->client_max_body_size
                && rb->received > clcf->client_max_body_size)
            {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked body: "
                              "%O bytes", rb->received);

                return RP_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }

        b->temporary = 1;
        b->pos = buf->pos;
        b->last = buf->last;
        b->start = b->pos;
        b->end = b->last;

        buf->pos = buf->last;
    }

    if (!rb->rest) {
        if (r->headers_in.content_length_n != -1
            && r->headers_in.content_length_n != rb->received)
        {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);

            return RP_HTTP_BAD_REQUEST;
        }

        b->last_buf = 1;
    }

    b->tag = (rp_buf_tag_t) &rp_http_v2_filter_request_body;
    b->flush = r->request_body_no_buffering;

update:

    rc = rp_http_top_request_body_filter(r, cl);

    rp_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
                            (rp_buf_tag_t) &rp_http_v2_filter_request_body);

    return rc;
}


static void
rp_http_v2_read_client_request_body_handler(rp_http_request_t *r)
{
    rp_connection_t  *fc;

    fc = r->connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read client request body handler");

    if (fc->read->timedout) {
        rp_log_error(RP_LOG_INFO, fc->log, RP_ETIMEDOUT, "client timed out");

        fc->timedout = 1;
        r->stream->skip_data = 1;

        rp_http_finalize_request(r, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (fc->error) {
        rp_log_error(RP_LOG_INFO, fc->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        rp_http_finalize_request(r, RP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }
}


rp_int_t
rp_http_v2_read_unbuffered_request_body(rp_http_request_t *r)
{
    size_t                     window;
    rp_buf_t                 *buf;
    rp_int_t                  rc;
    rp_connection_t          *fc;
    rp_http_v2_stream_t      *stream;
    rp_http_v2_connection_t  *h2c;
    rp_http_core_loc_conf_t  *clcf;

    stream = r->stream;
    fc = r->connection;

    if (fc->read->timedout) {
        if (stream->recv_window) {
            stream->skip_data = 1;
            fc->timedout = 1;

            return RP_HTTP_REQUEST_TIME_OUT;
        }

        fc->read->timedout = 0;
    }

    if (fc->error) {
        stream->skip_data = 1;
        return RP_HTTP_BAD_REQUEST;
    }

    rc = rp_http_v2_filter_request_body(r);

    if (rc != RP_OK) {
        stream->skip_data = 1;
        return rc;
    }

    if (!r->request_body->rest) {
        return RP_OK;
    }

    if (r->request_body->busy != NULL) {
        return RP_AGAIN;
    }

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    window = buf->end - buf->start;
    h2c = stream->connection;

    if (h2c->state.stream == stream) {
        window -= h2c->state.length;
    }

    if (window <= stream->recv_window) {
        if (window < stream->recv_window) {
            rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");
            stream->skip_data = 1;
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        return RP_AGAIN;
    }

    if (rp_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == RP_ERROR)
    {
        stream->skip_data = 1;
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_v2_send_output_queue(h2c) == RP_ERROR) {
        stream->skip_data = 1;
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stream->recv_window == 0) {
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
        rp_add_timer(fc->read, clcf->client_body_timeout);
    }

    stream->recv_window = window;

    return RP_AGAIN;
}


static rp_int_t
rp_http_v2_terminate_stream(rp_http_v2_connection_t *h2c,
    rp_http_v2_stream_t *stream, rp_uint_t status)
{
    rp_event_t       *rev;
    rp_connection_t  *fc;

    if (stream->rst_sent) {
        return RP_OK;
    }

    if (rp_http_v2_send_rst_stream(h2c, stream->node->id, status)
        == RP_ERROR)
    {
        return RP_ERROR;
    }

    stream->rst_sent = 1;
    stream->skip_data = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    rev->handler(rev);

    return RP_OK;
}


void
rp_http_v2_close_stream(rp_http_v2_stream_t *stream, rp_int_t rc)
{
    rp_pool_t                *pool;
    rp_uint_t                 push;
    rp_event_t               *ev;
    rp_connection_t          *fc;
    rp_http_v2_node_t        *node;
    rp_http_v2_connection_t  *h2c;

    h2c = stream->connection;
    node = stream->node;

    rp_log_debug4(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 close stream %ui, queued %ui, "
                   "processing %ui, pushing %ui",
                   node->id, stream->queued, h2c->processing, h2c->pushing);

    fc = stream->request->connection;

    if (stream->queued) {
        fc->error = 1;
        fc->write->handler = rp_http_v2_retry_close_stream_handler;
        fc->read->handler = rp_http_v2_retry_close_stream_handler;
        return;
    }

    if (!stream->rst_sent && !h2c->connection->error) {

        if (!stream->out_closed) {
            if (rp_http_v2_send_rst_stream(h2c, node->id,
                                      fc->timedout ? RP_HTTP_V2_PROTOCOL_ERROR
                                                   : RP_HTTP_V2_INTERNAL_ERROR)
                != RP_OK)
            {
                h2c->connection->error = 1;
            }

        } else if (!stream->in_closed) {
            if (rp_http_v2_send_rst_stream(h2c, node->id, RP_HTTP_V2_NO_ERROR)
                != RP_OK)
            {
                h2c->connection->error = 1;
            }
        }
    }

    if (h2c->state.stream == stream) {
        h2c->state.stream = NULL;
    }

    push = stream->node->id % 2 == 0;

    node->stream = NULL;

    rp_queue_insert_tail(&h2c->closed, &node->reuse);
    h2c->closed_nodes++;

    /*
     * This pool keeps decoded request headers which can be used by log phase
     * handlers in rp_http_free_request().
     *
     * The pointer is stored into local variable because the stream object
     * will be destroyed after a call to rp_http_free_request().
     */
    pool = stream->pool;

    h2c->frames -= stream->frames;

    rp_http_free_request(stream->request, rc);

    if (pool != h2c->state.pool) {
        rp_destroy_pool(pool);

    } else {
        /* pool will be destroyed when the complete header is parsed */
        h2c->state.keep_pool = 0;
    }

    ev = fc->read;

    if (ev->timer_set) {
        rp_del_timer(ev);
    }

    if (ev->posted) {
        rp_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->timer_set) {
        rp_del_timer(ev);
    }

    if (ev->posted) {
        rp_delete_posted_event(ev);
    }

    fc->data = h2c->free_fake_connections;
    h2c->free_fake_connections = fc;

    if (push) {
        h2c->pushing--;

    } else {
        h2c->processing--;
    }

    if (h2c->processing || h2c->pushing || h2c->blocked) {
        return;
    }

    ev = h2c->connection->read;

    ev->handler = rp_http_v2_handle_connection_handler;
    rp_post_event(ev, &rp_posted_events);
}


static void
rp_http_v2_close_stream_handler(rp_event_t *ev)
{
    rp_connection_t    *fc;
    rp_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 close stream handler");

    if (ev->timedout) {
        rp_log_error(RP_LOG_INFO, fc->log, RP_ETIMEDOUT, "client timed out");

        fc->timedout = 1;

        rp_http_v2_close_stream(r->stream, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rp_http_v2_close_stream(r->stream, 0);
}


static void
rp_http_v2_retry_close_stream_handler(rp_event_t *ev)
{
    rp_connection_t    *fc;
    rp_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 retry close stream handler");

    rp_http_v2_close_stream(r->stream, 0);
}


static void
rp_http_v2_handle_connection_handler(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_http_v2_connection_t  *h2c;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http2 handle connection handler");

    c = rev->data;
    h2c = c->data;

    if (c->error) {
        rp_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rev->handler = rp_http_v2_read_handler;

    if (rev->ready) {
        rp_http_v2_read_handler(rev);
        return;
    }

    if (h2c->last_out && rp_http_v2_send_output_queue(h2c) == RP_ERROR) {
        rp_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rp_http_v2_handle_connection(c->data);
}


static void
rp_http_v2_idle_handler(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_http_v2_srv_conf_t    *h2scf;
    rp_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http2 idle handler");

    if (rev->timedout || c->close) {
        rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_NO_ERROR);
        return;
    }

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            rp_log_error(RP_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "idle connection", &c->addr_text);
#if (RP_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            rp_http_close_connection(c);
            return;
        }
    }

#endif

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    if (h2c->idle++ > 10 * h2scf->max_requests) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");
        rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_NO_ERROR);
        return;
    }

    c->destroyed = 0;
    rp_reusable_connection(c, 0);

    h2c->pool = rp_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        rp_http_v2_finalize_connection(h2c, RP_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    c->write->handler = rp_http_v2_write_handler;

    rev->handler = rp_http_v2_read_handler;
    rp_http_v2_read_handler(rev);
}


static void
rp_http_v2_finalize_connection(rp_http_v2_connection_t *h2c,
    rp_uint_t status)
{
    rp_uint_t               i, size;
    rp_event_t             *ev;
    rp_connection_t        *c, *fc;
    rp_http_request_t      *r;
    rp_http_v2_node_t      *node;
    rp_http_v2_stream_t    *stream;
    rp_http_v2_srv_conf_t  *h2scf;

    c = h2c->connection;

    h2c->blocked = 1;

    if (!c->error && !h2c->goaway) {
        if (rp_http_v2_send_goaway(h2c, status) != RP_ERROR) {
            (void) rp_http_v2_send_output_queue(h2c);
        }
    }

    c->error = 1;

    if (!h2c->processing && !h2c->pushing) {
        rp_http_close_connection(c);
        return;
    }

    c->read->handler = rp_http_empty_handler;
    c->write->handler = rp_http_empty_handler;

    h2c->last_out = NULL;

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    size = rp_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            stream->waiting = 0;

            r = stream->request;
            fc = r->connection;

            fc->error = 1;

            if (stream->queued) {
                stream->queued = 0;

                ev = fc->write;
                ev->active = 0;
                ev->ready = 1;

            } else {
                ev = fc->read;
            }

            ev->eof = 1;
            ev->handler(ev);
        }
    }

    h2c->blocked = 0;

    if (h2c->processing || h2c->pushing) {
        return;
    }

    rp_http_close_connection(c);
}


static rp_int_t
rp_http_v2_adjust_windows(rp_http_v2_connection_t *h2c, ssize_t delta)
{
    rp_uint_t               i, size;
    rp_event_t             *wev;
    rp_http_v2_node_t      *node;
    rp_http_v2_stream_t    *stream;
    rp_http_v2_srv_conf_t  *h2scf;

    h2scf = rp_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rp_http_v2_module);

    size = rp_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            if (delta > 0
                && stream->send_window
                      > (ssize_t) (RP_HTTP_V2_MAX_WINDOW - delta))
            {
                if (rp_http_v2_terminate_stream(h2c, stream,
                                                 RP_HTTP_V2_FLOW_CTRL_ERROR)
                    == RP_ERROR)
                {
                    return RP_ERROR;
                }

                continue;
            }

            stream->send_window += delta;

            rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui adjusted window: %z",
                           node->id, stream->send_window);

            if (stream->send_window > 0 && stream->exhausted) {
                stream->exhausted = 0;

                wev = stream->request->connection->write;

                wev->active = 0;
                wev->ready = 1;

                if (!wev->delayed) {
                    wev->handler(wev);
                }
            }
        }
    }

    return RP_OK;
}


static void
rp_http_v2_set_dependency(rp_http_v2_connection_t *h2c,
    rp_http_v2_node_t *node, rp_uint_t depend, rp_uint_t exclusive)
{
    rp_queue_t         *children, *q;
    rp_http_v2_node_t  *parent, *child, *next;

    parent = depend ? rp_http_v2_get_node_by_id(h2c, depend, 0) : NULL;

    if (parent == NULL) {
        parent = RP_HTTP_V2_ROOT;

        if (depend != 0) {
            exclusive = 0;
        }

        node->rank = 1;
        node->rel_weight = (1.0 / 256) * node->weight;

        children = &h2c->dependencies;

    } else {
        if (node->parent != NULL) {

            for (next = parent->parent;
                 next != RP_HTTP_V2_ROOT && next->rank >= node->rank;
                 next = next->parent)
            {
                if (next != node) {
                    continue;
                }

                rp_queue_remove(&parent->queue);
                rp_queue_insert_after(&node->queue, &parent->queue);

                parent->parent = node->parent;

                if (node->parent == RP_HTTP_V2_ROOT) {
                    parent->rank = 1;
                    parent->rel_weight = (1.0 / 256) * parent->weight;

                } else {
                    parent->rank = node->parent->rank + 1;
                    parent->rel_weight = (node->parent->rel_weight / 256)
                                         * parent->weight;
                }

                if (!exclusive) {
                    rp_http_v2_node_children_update(parent);
                }

                break;
            }
        }

        node->rank = parent->rank + 1;
        node->rel_weight = (parent->rel_weight / 256) * node->weight;

        if (parent->stream == NULL) {
            rp_queue_remove(&parent->reuse);
            rp_queue_insert_tail(&h2c->closed, &parent->reuse);
        }

        children = &parent->children;
    }

    if (exclusive) {
        for (q = rp_queue_head(children);
             q != rp_queue_sentinel(children);
             q = rp_queue_next(q))
        {
            child = rp_queue_data(q, rp_http_v2_node_t, queue);
            child->parent = node;
        }

        rp_queue_add(&node->children, children);
        rp_queue_init(children);
    }

    if (node->parent != NULL) {
        rp_queue_remove(&node->queue);
    }

    rp_queue_insert_tail(children, &node->queue);

    node->parent = parent;

    rp_http_v2_node_children_update(node);
}


static void
rp_http_v2_node_children_update(rp_http_v2_node_t *node)
{
    rp_queue_t         *q;
    rp_http_v2_node_t  *child;

    for (q = rp_queue_head(&node->children);
         q != rp_queue_sentinel(&node->children);
         q = rp_queue_next(q))
    {
        child = rp_queue_data(q, rp_http_v2_node_t, queue);

        child->rank = node->rank + 1;
        child->rel_weight = (node->rel_weight / 256) * child->weight;

        rp_http_v2_node_children_update(child);
    }
}


static void
rp_http_v2_pool_cleanup(void *data)
{
    rp_http_v2_connection_t  *h2c = data;

    if (h2c->state.pool) {
        rp_destroy_pool(h2c->state.pool);
    }

    if (h2c->pool) {
        rp_destroy_pool(h2c->pool);
    }
}
