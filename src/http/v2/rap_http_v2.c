
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_http_v2_module.h>


typedef struct {
    rap_str_t           name;
    rap_uint_t          offset;
    rap_uint_t          hash;
    rap_http_header_t  *hh;
} rap_http_v2_parse_header_t;


/* errors */
#define RAP_HTTP_V2_NO_ERROR                     0x0
#define RAP_HTTP_V2_PROTOCOL_ERROR               0x1
#define RAP_HTTP_V2_INTERNAL_ERROR               0x2
#define RAP_HTTP_V2_FLOW_CTRL_ERROR              0x3
#define RAP_HTTP_V2_SETTINGS_TIMEOUT             0x4
#define RAP_HTTP_V2_STREAM_CLOSED                0x5
#define RAP_HTTP_V2_SIZE_ERROR                   0x6
#define RAP_HTTP_V2_REFUSED_STREAM               0x7
#define RAP_HTTP_V2_CANCEL                       0x8
#define RAP_HTTP_V2_COMP_ERROR                   0x9
#define RAP_HTTP_V2_CONNECT_ERROR                0xa
#define RAP_HTTP_V2_ENHANCE_YOUR_CALM            0xb
#define RAP_HTTP_V2_INADEQUATE_SECURITY          0xc
#define RAP_HTTP_V2_HTTP_1_1_REQUIRED            0xd

/* frame sizes */
#define RAP_HTTP_V2_SETTINGS_ACK_SIZE            0
#define RAP_HTTP_V2_RST_STREAM_SIZE              4
#define RAP_HTTP_V2_PRIORITY_SIZE                5
#define RAP_HTTP_V2_PING_SIZE                    8
#define RAP_HTTP_V2_GOAWAY_SIZE                  8
#define RAP_HTTP_V2_WINDOW_UPDATE_SIZE           4

#define RAP_HTTP_V2_SETTINGS_PARAM_SIZE          6

/* settings fields */
#define RAP_HTTP_V2_HEADER_TABLE_SIZE_SETTING    0x1
#define RAP_HTTP_V2_ENABLE_PUSH_SETTING          0x2
#define RAP_HTTP_V2_MAX_STREAMS_SETTING          0x3
#define RAP_HTTP_V2_INIT_WINDOW_SIZE_SETTING     0x4
#define RAP_HTTP_V2_MAX_FRAME_SIZE_SETTING       0x5

#define RAP_HTTP_V2_FRAME_BUFFER_SIZE            24

#define RAP_HTTP_V2_ROOT                         (void *) -1


static void rap_http_v2_read_handler(rap_event_t *rev);
static void rap_http_v2_write_handler(rap_event_t *wev);
static void rap_http_v2_handle_connection(rap_http_v2_connection_t *h2c);

static u_char *rap_http_v2_state_proxy_protocol(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_preface(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_preface_end(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_head(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_data(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_read_data(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_headers(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_header_block(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_field_len(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_field_huff(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_field_raw(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_field_skip(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_process_header(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_header_complete(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_handle_continuation(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rap_http_v2_handler_pt handler);
static u_char *rap_http_v2_state_priority(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_rst_stream(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_settings(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_settings_params(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_push_promise(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_ping(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_goaway(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_window_update(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_continuation(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_complete(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_skip_padded(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_skip(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *rap_http_v2_state_save(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rap_http_v2_handler_pt handler);
static u_char *rap_http_v2_state_headers_save(rap_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, rap_http_v2_handler_pt handler);
static u_char *rap_http_v2_connection_error(rap_http_v2_connection_t *h2c,
    rap_uint_t err);

static rap_int_t rap_http_v2_parse_int(rap_http_v2_connection_t *h2c,
    u_char **pos, u_char *end, rap_uint_t prefix);

static rap_http_v2_stream_t *rap_http_v2_create_stream(
    rap_http_v2_connection_t *h2c, rap_uint_t push);
static rap_http_v2_node_t *rap_http_v2_get_node_by_id(
    rap_http_v2_connection_t *h2c, rap_uint_t sid, rap_uint_t alloc);
static rap_http_v2_node_t *rap_http_v2_get_closed_node(
    rap_http_v2_connection_t *h2c);
#define rap_http_v2_index_size(h2scf)  (h2scf->streams_index_mask + 1)
#define rap_http_v2_index(h2scf, sid)  ((sid >> 1) & h2scf->streams_index_mask)

static rap_int_t rap_http_v2_send_settings(rap_http_v2_connection_t *h2c);
static rap_int_t rap_http_v2_settings_frame_handler(
    rap_http_v2_connection_t *h2c, rap_http_v2_out_frame_t *frame);
static rap_int_t rap_http_v2_send_window_update(rap_http_v2_connection_t *h2c,
    rap_uint_t sid, size_t window);
static rap_int_t rap_http_v2_send_rst_stream(rap_http_v2_connection_t *h2c,
    rap_uint_t sid, rap_uint_t status);
static rap_int_t rap_http_v2_send_goaway(rap_http_v2_connection_t *h2c,
    rap_uint_t status);

static rap_http_v2_out_frame_t *rap_http_v2_get_frame(
    rap_http_v2_connection_t *h2c, size_t length, rap_uint_t type,
    u_char flags, rap_uint_t sid);
static rap_int_t rap_http_v2_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame);

static rap_int_t rap_http_v2_validate_header(rap_http_request_t *r,
    rap_http_v2_header_t *header);
static rap_int_t rap_http_v2_pseudo_header(rap_http_request_t *r,
    rap_http_v2_header_t *header);
static rap_int_t rap_http_v2_parse_path(rap_http_request_t *r,
    rap_str_t *value);
static rap_int_t rap_http_v2_parse_method(rap_http_request_t *r,
    rap_str_t *value);
static rap_int_t rap_http_v2_parse_scheme(rap_http_request_t *r,
    rap_str_t *value);
static rap_int_t rap_http_v2_parse_authority(rap_http_request_t *r,
    rap_str_t *value);
static rap_int_t rap_http_v2_parse_header(rap_http_request_t *r,
    rap_http_v2_parse_header_t *header, rap_str_t *value);
static rap_int_t rap_http_v2_construct_request_line(rap_http_request_t *r);
static rap_int_t rap_http_v2_cookie(rap_http_request_t *r,
    rap_http_v2_header_t *header);
static rap_int_t rap_http_v2_construct_cookie_header(rap_http_request_t *r);
static void rap_http_v2_run_request(rap_http_request_t *r);
static void rap_http_v2_run_request_handler(rap_event_t *ev);
static rap_int_t rap_http_v2_process_request_body(rap_http_request_t *r,
    u_char *pos, size_t size, rap_uint_t last);
static rap_int_t rap_http_v2_filter_request_body(rap_http_request_t *r);
static void rap_http_v2_read_client_request_body_handler(rap_http_request_t *r);

static rap_int_t rap_http_v2_terminate_stream(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream, rap_uint_t status);
static void rap_http_v2_close_stream_handler(rap_event_t *ev);
static void rap_http_v2_retry_close_stream_handler(rap_event_t *ev);
static void rap_http_v2_handle_connection_handler(rap_event_t *rev);
static void rap_http_v2_idle_handler(rap_event_t *rev);
static void rap_http_v2_finalize_connection(rap_http_v2_connection_t *h2c,
    rap_uint_t status);

static rap_int_t rap_http_v2_adjust_windows(rap_http_v2_connection_t *h2c,
    ssize_t delta);
static void rap_http_v2_set_dependency(rap_http_v2_connection_t *h2c,
    rap_http_v2_node_t *node, rap_uint_t depend, rap_uint_t exclusive);
static void rap_http_v2_node_children_update(rap_http_v2_node_t *node);

static void rap_http_v2_pool_cleanup(void *data);


static rap_http_v2_handler_pt rap_http_v2_frame_states[] = {
    rap_http_v2_state_data,               /* RAP_HTTP_V2_DATA_FRAME */
    rap_http_v2_state_headers,            /* RAP_HTTP_V2_HEADERS_FRAME */
    rap_http_v2_state_priority,           /* RAP_HTTP_V2_PRIORITY_FRAME */
    rap_http_v2_state_rst_stream,         /* RAP_HTTP_V2_RST_STREAM_FRAME */
    rap_http_v2_state_settings,           /* RAP_HTTP_V2_SETTINGS_FRAME */
    rap_http_v2_state_push_promise,       /* RAP_HTTP_V2_PUSH_PROMISE_FRAME */
    rap_http_v2_state_ping,               /* RAP_HTTP_V2_PING_FRAME */
    rap_http_v2_state_goaway,             /* RAP_HTTP_V2_GOAWAY_FRAME */
    rap_http_v2_state_window_update,      /* RAP_HTTP_V2_WINDOW_UPDATE_FRAME */
    rap_http_v2_state_continuation        /* RAP_HTTP_V2_CONTINUATION_FRAME */
};

#define RAP_HTTP_V2_FRAME_STATES                                              \
    (sizeof(rap_http_v2_frame_states) / sizeof(rap_http_v2_handler_pt))


static rap_http_v2_parse_header_t  rap_http_v2_parse_headers[] = {
    { rap_string("host"),
      offsetof(rap_http_headers_in_t, host), 0, NULL },

    { rap_string("accept-encoding"),
      offsetof(rap_http_headers_in_t, accept_encoding), 0, NULL },

    { rap_string("accept-language"),
      offsetof(rap_http_headers_in_t, accept_language), 0, NULL },

    { rap_string("user-agent"),
      offsetof(rap_http_headers_in_t, user_agent), 0, NULL },

    { rap_null_string, 0, 0, NULL }
};


void
rap_http_v2_init(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_pool_cleanup_t        *cln;
    rap_http_connection_t     *hc;
    rap_http_v2_srv_conf_t    *h2scf;
    rap_http_v2_main_conf_t   *h2mcf;
    rap_http_v2_connection_t  *h2c;

    c = rev->data;
    hc = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "init http2 connection");

    c->log->action = "processing HTTP/2 connection";

    h2mcf = rap_http_get_module_main_conf(hc->conf_ctx, rap_http_v2_module);

    if (h2mcf->recv_buffer == NULL) {
        h2mcf->recv_buffer = rap_palloc(rap_cycle->pool,
                                        h2mcf->recv_buffer_size);
        if (h2mcf->recv_buffer == NULL) {
            rap_http_close_connection(c);
            return;
        }
    }

    h2c = rap_pcalloc(c->pool, sizeof(rap_http_v2_connection_t));
    if (h2c == NULL) {
        rap_http_close_connection(c);
        return;
    }

    h2c->connection = c;
    h2c->http_connection = hc;

    h2c->send_window = RAP_HTTP_V2_DEFAULT_WINDOW;
    h2c->recv_window = RAP_HTTP_V2_MAX_WINDOW;

    h2c->init_window = RAP_HTTP_V2_DEFAULT_WINDOW;

    h2c->frame_size = RAP_HTTP_V2_DEFAULT_FRAME_SIZE;

    h2scf = rap_http_get_module_srv_conf(hc->conf_ctx, rap_http_v2_module);

    h2c->concurrent_pushes = h2scf->concurrent_pushes;
    h2c->priority_limit = h2scf->concurrent_streams;

    h2c->pool = rap_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        rap_http_close_connection(c);
        return;
    }

    cln = rap_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        rap_http_close_connection(c);
        return;
    }

    cln->handler = rap_http_v2_pool_cleanup;
    cln->data = h2c;

    h2c->streams_index = rap_pcalloc(c->pool, rap_http_v2_index_size(h2scf)
                                              * sizeof(rap_http_v2_node_t *));
    if (h2c->streams_index == NULL) {
        rap_http_close_connection(c);
        return;
    }

    if (rap_http_v2_send_settings(h2c) == RAP_ERROR) {
        rap_http_close_connection(c);
        return;
    }

    if (rap_http_v2_send_window_update(h2c, 0, RAP_HTTP_V2_MAX_WINDOW
                                               - RAP_HTTP_V2_DEFAULT_WINDOW)
        == RAP_ERROR)
    {
        rap_http_close_connection(c);
        return;
    }

    h2c->state.handler = hc->proxy_protocol ? rap_http_v2_state_proxy_protocol
                                            : rap_http_v2_state_preface;

    rap_queue_init(&h2c->waiting);
    rap_queue_init(&h2c->dependencies);
    rap_queue_init(&h2c->closed);

    c->data = h2c;

    rev->handler = rap_http_v2_read_handler;
    c->write->handler = rap_http_v2_write_handler;

    c->idle = 1;

    rap_http_v2_read_handler(rev);
}


static void
rap_http_v2_read_handler(rap_event_t *rev)
{
    u_char                    *p, *end;
    size_t                     available;
    ssize_t                    n;
    rap_connection_t          *c;
    rap_http_v2_main_conf_t   *h2mcf;
    rap_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http2 read handler");

    h2c->blocked = 1;

    if (c->close) {
        c->close = 0;

        if (c->error) {
            rap_http_v2_finalize_connection(h2c, 0);
            return;
        }

        if (!h2c->goaway) {
            h2c->goaway = 1;

            if (rap_http_v2_send_goaway(h2c, RAP_HTTP_V2_NO_ERROR)
                == RAP_ERROR)
            {
                rap_http_v2_finalize_connection(h2c, 0);
                return;
            }

            if (rap_http_v2_send_output_queue(h2c) == RAP_ERROR) {
                rap_http_v2_finalize_connection(h2c, 0);
                return;
            }
        }

        h2c->blocked = 0;

        return;
    }

    h2mcf = rap_http_get_module_main_conf(h2c->http_connection->conf_ctx,
                                          rap_http_v2_module);

    available = h2mcf->recv_buffer_size - 2 * RAP_HTTP_V2_STATE_BUFFER_SIZE;

    do {
        p = h2mcf->recv_buffer;

        rap_memcpy(p, h2c->state.buffer, RAP_HTTP_V2_STATE_BUFFER_SIZE);
        end = p + h2c->state.buffer_used;

        n = c->recv(c, end, available);

        if (n == RAP_AGAIN) {
            break;
        }

        if (n == 0
            && (h2c->state.incomplete || h2c->processing || h2c->pushing))
        {
            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        }

        if (n == 0 || n == RAP_ERROR) {
            c->error = 1;
            rap_http_v2_finalize_connection(h2c, 0);
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
            rap_log_error(RAP_LOG_INFO, c->log, 0, "http2 flood detected");
            rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_NO_ERROR);
            return;
        }

    } while (rev->ready);

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    if (h2c->last_out && rap_http_v2_send_output_queue(h2c) == RAP_ERROR) {
        rap_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (h2c->processing || h2c->pushing) {
        if (rev->timer_set) {
            rap_del_timer(rev);
        }

        return;
    }

    rap_http_v2_handle_connection(h2c);
}


static void
rap_http_v2_write_handler(rap_event_t *wev)
{
    rap_int_t                  rc;
    rap_connection_t          *c;
    rap_http_v2_connection_t  *h2c;

    c = wev->data;
    h2c = c->data;

    if (wev->timedout) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 write event timed out");
        c->error = 1;
        rap_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http2 write handler");

    if (h2c->last_out == NULL && !c->buffered) {

        if (wev->timer_set) {
            rap_del_timer(wev);
        }

        rap_http_v2_handle_connection(h2c);
        return;
    }

    h2c->blocked = 1;

    rc = rap_http_v2_send_output_queue(h2c);

    if (rc == RAP_ERROR) {
        rap_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (rc == RAP_AGAIN) {
        return;
    }

    rap_http_v2_handle_connection(h2c);
}


rap_int_t
rap_http_v2_send_output_queue(rap_http_v2_connection_t *h2c)
{
    int                        tcp_nodelay;
    rap_chain_t               *cl;
    rap_event_t               *wev;
    rap_connection_t          *c;
    rap_http_v2_out_frame_t   *out, *frame, *fn;
    rap_http_core_loc_conf_t  *clcf;

    c = h2c->connection;
    wev = c->write;

    if (c->error) {
        goto error;
    }

    if (!wev->ready) {
        return RAP_AGAIN;
    }

    cl = NULL;
    out = NULL;

    for (frame = h2c->last_out; frame; frame = fn) {
        frame->last->next = cl;
        cl = frame->first;

        fn = frame->next;
        frame->next = out;
        out = frame;

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame out: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    cl = c->send_chain(c, cl, 0);

    if (cl == RAP_CHAIN_ERROR) {
        goto error;
    }

    clcf = rap_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        rap_http_core_module);

    if (rap_handle_write_event(wev, clcf->send_lowat) != RAP_OK) {
        goto error;
    }

    if (c->tcp_nopush == RAP_TCP_NOPUSH_SET) {
        if (rap_tcp_push(c->fd) == -1) {
            rap_connection_error(c, rap_socket_errno, rap_tcp_push_n " failed");
            goto error;
        }

        c->tcp_nopush = RAP_TCP_NOPUSH_UNSET;
        tcp_nodelay = rap_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
        goto error;
    }

    for ( /* void */ ; out; out = fn) {
        fn = out->next;

        if (out->handler(h2c, out) != RAP_OK) {
            out->blocked = 1;
            break;
        }

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, c->log, 0,
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
        rap_add_timer(wev, clcf->send_timeout);
        return RAP_AGAIN;
    }

    if (wev->timer_set) {
        rap_del_timer(wev);
    }

    return RAP_OK;

error:

    c->error = 1;

    if (!h2c->blocked) {
        rap_post_event(wev, &rap_posted_events);
    }

    return RAP_ERROR;
}


static void
rap_http_v2_handle_connection(rap_http_v2_connection_t *h2c)
{
    rap_int_t                rc;
    rap_connection_t        *c;
    rap_http_v2_srv_conf_t  *h2scf;

    if (h2c->last_out || h2c->processing || h2c->pushing) {
        return;
    }

    c = h2c->connection;

    if (c->error) {
        rap_http_close_connection(c);
        return;
    }

    if (c->buffered) {
        h2c->blocked = 1;

        rc = rap_http_v2_send_output_queue(h2c);

        h2c->blocked = 0;

        if (rc == RAP_ERROR) {
            rap_http_close_connection(c);
            return;
        }

        if (rc == RAP_AGAIN) {
            return;
        }

        /* rc == RAP_OK */
    }

    if (h2c->goaway) {
        rap_http_close_connection(c);
        return;
    }

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);
    if (h2c->state.incomplete) {
        rap_add_timer(c->read, h2scf->recv_timeout);
        return;
    }

    rap_destroy_pool(h2c->pool);

    h2c->pool = NULL;
    h2c->free_frames = NULL;
    h2c->frames = 0;
    h2c->free_fake_connections = NULL;

#if (RAP_HTTP_SSL)
    if (c->ssl) {
        rap_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;
    rap_reusable_connection(c, 1);

    c->write->handler = rap_http_empty_handler;
    c->read->handler = rap_http_v2_idle_handler;

    if (c->write->timer_set) {
        rap_del_timer(c->write);
    }

    rap_add_timer(c->read, h2scf->idle_timeout);
}


static u_char *
rap_http_v2_state_proxy_protocol(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_log_t  *log;

    log = h2c->connection->log;
    log->action = "reading PROXY protocol";

    pos = rap_proxy_protocol_read(h2c->connection, pos, end);

    log->action = "processing HTTP/2 connection";

    if (pos == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    return rap_http_v2_state_preface(h2c, pos, end);
}


static u_char *
rap_http_v2_state_preface(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = "PRI * HTTP/2.0\r\n";

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return rap_http_v2_state_save(h2c, pos, end, rap_http_v2_state_preface);
    }

    if (rap_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "invalid http2 connection preface \"%*s\"",
                       sizeof(preface) - 1, pos);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    return rap_http_v2_state_preface_end(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
rap_http_v2_state_preface_end(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = "\r\nSM\r\n\r\n";

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_preface_end);
    }

    if (rap_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "invalid http2 connection preface \"%*s\"",
                       sizeof(preface) - 1, pos);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 preface verified");

    return rap_http_v2_state_head(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
rap_http_v2_state_head(rap_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    uint32_t    head;
    rap_uint_t  type;

    if (end - pos < RAP_HTTP_V2_FRAME_HEADER_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end, rap_http_v2_state_head);
    }

    head = rap_http_v2_parse_uint32(pos);

    h2c->state.length = rap_http_v2_parse_length(head);
    h2c->state.flags = pos[4];

    h2c->state.sid = rap_http_v2_parse_sid(&pos[5]);

    pos += RAP_HTTP_V2_FRAME_HEADER_SIZE;

    type = rap_http_v2_parse_type(head);

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame type:%ui f:%Xd l:%uz sid:%ui",
                   type, h2c->state.flags, h2c->state.length, h2c->state.sid);

    if (type >= RAP_HTTP_V2_FRAME_STATES) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent frame with unknown type %ui", type);
        return rap_http_v2_state_skip(h2c, pos, end);
    }

    return rap_http_v2_frame_states[type](h2c, pos, end);
}


static u_char *
rap_http_v2_state_data(rap_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t                 size;
    rap_http_v2_node_t    *node;
    rap_http_v2_stream_t  *stream;

    size = h2c->state.length;

    if (h2c->state.flags & RAP_HTTP_V2_PADDED_FLAG) {

        if (h2c->state.length == 0) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: 0");

            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
        }

        if (end - pos == 0) {
            return rap_http_v2_state_save(h2c, pos, end,
                                          rap_http_v2_state_data);
        }

        h2c->state.padding = *pos++;

        if (h2c->state.padding >= size) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: %uz, padding: %uz",
                          size, h2c->state.padding);

            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= 1 + h2c->state.padding;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 DATA frame");

    if (size > h2c->recv_window) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received DATA frame length %uz, available window %uz",
                      size, h2c->recv_window);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->recv_window -= size;

    if (h2c->recv_window < RAP_HTTP_V2_MAX_WINDOW / 4) {

        if (rap_http_v2_send_window_update(h2c, 0, RAP_HTTP_V2_MAX_WINDOW
                                                   - h2c->recv_window)
            == RAP_ERROR)
        {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->recv_window = RAP_HTTP_V2_MAX_WINDOW;
    }

    node = rap_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream = node->stream;

    if (size > stream->recv_window) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client violated flow control for stream %ui: "
                      "received DATA frame length %uz, available window %uz",
                      node->id, size, stream->recv_window);

        if (rap_http_v2_terminate_stream(h2c, stream,
                                         RAP_HTTP_V2_FLOW_CTRL_ERROR)
            == RAP_ERROR)
        {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream->recv_window -= size;

    if (stream->no_flow_control
        && stream->recv_window < RAP_HTTP_V2_MAX_WINDOW / 4)
    {
        if (rap_http_v2_send_window_update(h2c, node->id,
                                           RAP_HTTP_V2_MAX_WINDOW
                                           - stream->recv_window)
            == RAP_ERROR)
        {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        stream->recv_window = RAP_HTTP_V2_MAX_WINDOW;
    }

    if (stream->in_closed) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame for half-closed stream %ui",
                      node->id);

        if (rap_http_v2_terminate_stream(h2c, stream,
                                         RAP_HTTP_V2_STREAM_CLOSED)
            == RAP_ERROR)
        {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    h2c->state.stream = stream;

    return rap_http_v2_state_read_data(h2c, pos, end);
}


static u_char *
rap_http_v2_state_read_data(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    rap_buf_t               *buf;
    rap_int_t                rc;
    rap_http_request_t      *r;
    rap_http_v2_stream_t    *stream;
    rap_http_v2_srv_conf_t  *h2scf;

    stream = h2c->state.stream;

    if (stream == NULL) {
        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (stream->skip_data) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    r = stream->request;

    if (r->reading_body && !r->request_body_no_buffering) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    size = end - pos;

    if (size >= h2c->state.length) {
        size = h2c->state.length;
        stream->in_closed = h2c->state.flags & RAP_HTTP_V2_END_STREAM_FLAG;
    }

    h2c->payload_bytes += size;

    if (r->request_body) {
        rc = rap_http_v2_process_request_body(r, pos, size, stream->in_closed);

        if (rc != RAP_OK) {
            stream->skip_data = 1;
            rap_http_finalize_request(r, rc);
        }

    } else if (size) {
        buf = stream->preread;

        if (buf == NULL) {
            h2scf = rap_http_get_module_srv_conf(r, rap_http_v2_module);

            buf = rap_create_temp_buf(r->pool, h2scf->preread_size);
            if (buf == NULL) {
                return rap_http_v2_connection_error(h2c,
                                                    RAP_HTTP_V2_INTERNAL_ERROR);
            }

            stream->preread = buf;
        }

        if (size > (size_t) (buf->end - buf->last)) {
            rap_log_error(RAP_LOG_ALERT, h2c->connection->log, 0,
                          "http2 preread buffer overflow");
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        buf->last = rap_cpymem(buf->last, pos, size);
    }

    pos += size;
    h2c->state.length -= size;

    if (h2c->state.length) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_read_data);
    }

    if (h2c->state.padding) {
        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_headers(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    rap_uint_t               padded, priority, depend, dependency, excl, weight;
    rap_uint_t               status;
    rap_http_v2_node_t      *node;
    rap_http_v2_stream_t    *stream;
    rap_http_v2_srv_conf_t  *h2scf;

    padded = h2c->state.flags & RAP_HTTP_V2_PADDED_FLAG;
    priority = h2c->state.flags & RAP_HTTP_V2_PRIORITY_FLAG;

    size = 0;

    if (padded) {
        size++;
    }

    if (priority) {
        size += sizeof(uint32_t) + 1;
    }

    if (h2c->state.length < size) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect length %uz",
                      h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->state.length == size) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with empty header block");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->goaway) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 HEADERS frame");
        return rap_http_v2_state_skip(h2c, pos, end);
    }

    if ((size_t) (end - pos) < size) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_headers);
    }

    h2c->state.length -= size;

    if (padded) {
        h2c->state.padding = *pos++;

        if (h2c->state.padding > h2c->state.length) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded HEADERS frame "
                          "with incorrect length: %uz, padding: %uz",
                          h2c->state.length, h2c->state.padding);

            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= h2c->state.padding;
    }

    depend = 0;
    excl = 0;
    weight = RAP_HTTP_V2_DEFAULT_WEIGHT;

    if (priority) {
        dependency = rap_http_v2_parse_uint32(pos);

        depend = dependency & 0x7fffffff;
        excl = dependency >> 31;
        weight = pos[4] + 1;

        pos += sizeof(uint32_t) + 1;
    }

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 HEADERS frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid % 2 == 0 || h2c->state.sid <= h2c->last_sid) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect identifier "
                      "%ui, the last was %ui", h2c->state.sid, h2c->last_sid);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->last_sid = h2c->state.sid;

    h2c->state.pool = rap_create_pool(1024, h2c->connection->log);
    if (h2c->state.pool == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    h2c->state.header_limit = h2scf->max_header_size;

    if (h2c->processing >= h2scf->concurrent_streams) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "concurrent streams exceeded %ui", h2c->processing);

        status = RAP_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (!h2c->settings_ack
        && !(h2c->state.flags & RAP_HTTP_V2_END_STREAM_FLAG)
        && h2scf->preread_size < RAP_HTTP_V2_DEFAULT_WINDOW)
    {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent stream with data "
                      "before settings were acknowledged");

        status = RAP_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    node = rap_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    if (node->parent) {
        rap_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream = rap_http_v2_create_stream(h2c, 0);
    if (stream == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = stream;

    stream->pool = h2c->state.pool;
    h2c->state.keep_pool = 1;

    stream->request->request_length = h2c->state.length;

    stream->in_closed = h2c->state.flags & RAP_HTTP_V2_END_STREAM_FLAG;
    stream->node = node;

    node->stream = stream;

    if (priority || node->parent == NULL) {
        node->weight = weight;
        rap_http_v2_set_dependency(h2c, node, depend, excl);
    }

    if (h2c->connection->requests >= h2scf->max_requests) {
        h2c->goaway = 1;

        if (rap_http_v2_send_goaway(h2c, RAP_HTTP_V2_NO_ERROR) == RAP_ERROR) {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return rap_http_v2_state_header_block(h2c, pos, end);

rst_stream:

    if (rap_http_v2_send_rst_stream(h2c, h2c->state.sid, status) != RAP_OK) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    return rap_http_v2_state_header_block(h2c, pos, end);
}


static u_char *
rap_http_v2_state_header_block(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    u_char      ch;
    rap_int_t   value;
    rap_uint_t  indexed, size_update, prefix;

    if (end - pos < 1) {
        return rap_http_v2_state_headers_save(h2c, pos, end,
                                              rap_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < RAP_HTTP_V2_INT_OCTETS)
    {
        return rap_http_v2_handle_continuation(h2c, pos, end,
                                               rap_http_v2_state_header_block);
    }

    size_update = 0;
    indexed = 0;

    ch = *pos;

    if (ch >= (1 << 7)) {
        /* indexed header field */
        indexed = 1;
        prefix = rap_http_v2_prefix(7);

    } else if (ch >= (1 << 6)) {
        /* literal header field with incremental indexing */
        h2c->state.index = 1;
        prefix = rap_http_v2_prefix(6);

    } else if (ch >= (1 << 5)) {
        /* dynamic table size update */
        size_update = 1;
        prefix = rap_http_v2_prefix(5);

    } else if (ch >= (1 << 4)) {
        /* literal header field never indexed */
        prefix = rap_http_v2_prefix(4);

    } else {
        /* literal header field without indexing */
        prefix = rap_http_v2_prefix(4);
    }

    value = rap_http_v2_parse_int(h2c, &pos, end, prefix);

    if (value < 0) {
        if (value == RAP_AGAIN) {
            return rap_http_v2_state_headers_save(h2c, pos, end,
                                               rap_http_v2_state_header_block);
        }

        if (value == RAP_DECLINED) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent header block with too long %s value",
                          size_update ? "size update" : "header index");

            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
        }

        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (indexed) {
        if (rap_http_v2_get_indexed_header(h2c, value, 0) != RAP_OK) {
            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
        }

        return rap_http_v2_state_process_header(h2c, pos, end);
    }

    if (size_update) {
        if (rap_http_v2_table_size(h2c, value) != RAP_OK) {
            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
        }

        return rap_http_v2_state_header_complete(h2c, pos, end);
    }

    if (value == 0) {
        h2c->state.parse_name = 1;

    } else if (rap_http_v2_get_indexed_header(h2c, value, 1) != RAP_OK) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
    }

    h2c->state.parse_value = 1;

    return rap_http_v2_state_field_len(h2c, pos, end);
}


static u_char *
rap_http_v2_state_field_len(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   alloc;
    rap_int_t                len;
    rap_uint_t               huff;
    rap_http_v2_srv_conf_t  *h2scf;

    if (!(h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < RAP_HTTP_V2_INT_OCTETS)
    {
        return rap_http_v2_handle_continuation(h2c, pos, end,
                                               rap_http_v2_state_field_len);
    }

    if (h2c->state.length < 1) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < 1) {
        return rap_http_v2_state_headers_save(h2c, pos, end,
                                              rap_http_v2_state_field_len);
    }

    huff = *pos >> 7;
    len = rap_http_v2_parse_int(h2c, &pos, end, rap_http_v2_prefix(7));

    if (len < 0) {
        if (len == RAP_AGAIN) {
            return rap_http_v2_state_headers_save(h2c, pos, end,
                                                  rap_http_v2_state_field_len);
        }

        if (len == RAP_DECLINED) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                        "client sent header field with too long length value");

            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
        }

        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 %s string, len:%i",
                   huff ? "encoded" : "raw", len);

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    if ((size_t) len > h2scf->max_field_size) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client exceeded http2_max_field_size limit");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.field_rest = len;

    if (h2c->state.stream == NULL && !h2c->state.index) {
        return rap_http_v2_state_field_skip(h2c, pos, end);
    }

    alloc = (huff ? len * 8 / 5 : len) + 1;

    h2c->state.field_start = rap_pnalloc(h2c->state.pool, alloc);
    if (h2c->state.field_start == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.field_end = h2c->state.field_start;

    if (huff) {
        return rap_http_v2_state_field_huff(h2c, pos, end);
    }

    return rap_http_v2_state_field_raw(h2c, pos, end);
}


static u_char *
rap_http_v2_state_field_huff(rap_http_v2_connection_t *h2c, u_char *pos,
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

    if (rap_http_v2_huff_decode(&h2c->state.field_state, pos, size,
                                &h2c->state.field_end,
                                h2c->state.field_rest == 0,
                                h2c->connection->log)
        != RAP_OK)
    {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid encoded header field");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_COMP_ERROR);
    }

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return rap_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rap_http_v2_state_headers_save(h2c, pos, end,
                                              rap_http_v2_state_field_huff);
    }

    if (h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    return rap_http_v2_handle_continuation(h2c, pos, end,
                                           rap_http_v2_state_field_huff);
}


static u_char *
rap_http_v2_state_field_raw(rap_http_v2_connection_t *h2c, u_char *pos,
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

    h2c->state.field_end = rap_cpymem(h2c->state.field_end, pos, size);

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return rap_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rap_http_v2_state_headers_save(h2c, pos, end,
                                              rap_http_v2_state_field_raw);
    }

    if (h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    return rap_http_v2_handle_continuation(h2c, pos, end,
                                           rap_http_v2_state_field_raw);
}


static u_char *
rap_http_v2_state_field_skip(rap_http_v2_connection_t *h2c, u_char *pos,
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
        return rap_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_field_skip);
    }

    if (h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    return rap_http_v2_handle_continuation(h2c, pos, end,
                                           rap_http_v2_state_field_skip);
}


static u_char *
rap_http_v2_state_process_header(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                      len;
    rap_int_t                   rc;
    rap_table_elt_t            *h;
    rap_http_header_t          *hh;
    rap_http_request_t         *r;
    rap_http_v2_header_t       *header;
    rap_http_core_srv_conf_t   *cscf;
    rap_http_core_main_conf_t  *cmcf;

    static rap_str_t cookie = rap_string("cookie");

    header = &h2c->state.header;

    if (h2c->state.parse_name) {
        h2c->state.parse_name = 0;

        header->name.len = h2c->state.field_end - h2c->state.field_start;
        header->name.data = h2c->state.field_start;

        if (header->name.len == 0) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent zero header name length");

            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_PROTOCOL_ERROR);
        }

        return rap_http_v2_state_field_len(h2c, pos, end);
    }

    if (h2c->state.parse_value) {
        h2c->state.parse_value = 0;

        header->value.len = h2c->state.field_end - h2c->state.field_start;
        header->value.data = h2c->state.field_start;
    }

    len = header->name.len + header->value.len;

    if (len > h2c->state.header_limit) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client exceeded http2_max_header_size limit");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.header_limit -= len;

    if (h2c->state.index) {
        if (rap_http_v2_add_header(h2c, header) != RAP_OK) {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->state.index = 0;
    }

    if (h2c->state.stream == NULL) {
        return rap_http_v2_state_header_complete(h2c, pos, end);
    }

    r = h2c->state.stream->request;

    /* TODO Optimization: validate headers while parsing. */
    if (rap_http_v2_validate_header(r, header) != RAP_OK) {
        if (rap_http_v2_terminate_stream(h2c, h2c->state.stream,
                                         RAP_HTTP_V2_PROTOCOL_ERROR)
            == RAP_ERROR)
        {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        goto error;
    }

    if (header->name.data[0] == ':') {
        rc = rap_http_v2_pseudo_header(r, header);

        if (rc == RAP_OK) {
            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http2 header: \":%V: %V\"",
                           &header->name, &header->value);

            return rap_http_v2_state_header_complete(h2c, pos, end);
        }

        if (rc == RAP_ABORT) {
            goto error;
        }

        if (rc == RAP_DECLINED) {
            rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
            goto error;
        }

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    if (r->invalid_header) {
        cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

        if (cscf->ignore_invalid_headers) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", &header->name);

            return rap_http_v2_state_header_complete(h2c, pos, end);
        }
    }

    if (header->name.len == cookie.len
        && rap_memcmp(header->name.data, cookie.data, cookie.len) == 0)
    {
        if (rap_http_v2_cookie(r, header) != RAP_OK) {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

    } else {
        h = rap_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }

        h->key.len = header->name.len;
        h->key.data = header->name.data;

        /*
         * TODO Optimization: precalculate hash
         * and handler for indexed headers.
         */
        h->hash = rap_hash_key(h->key.data, h->key.len);

        h->value.len = header->value.len;
        h->value.data = header->value.data;

        h->lowcase_key = h->key.data;

        cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

        hh = rap_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != RAP_OK) {
            goto error;
        }
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header: \"%V: %V\"",
                   &header->name, &header->value);

    return rap_http_v2_state_header_complete(h2c, pos, end);

error:

    h2c->state.stream = NULL;

    return rap_http_v2_state_header_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_header_complete(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_http_v2_stream_t  *stream;

    if (h2c->state.length) {
        if (end - pos > 0) {
            h2c->state.handler = rap_http_v2_state_header_block;
            return pos;
        }

        return rap_http_v2_state_headers_save(h2c, pos, end,
                                              rap_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & RAP_HTTP_V2_END_HEADERS_FLAG)) {
        return rap_http_v2_handle_continuation(h2c, pos, end,
                                             rap_http_v2_state_header_complete);
    }

    stream = h2c->state.stream;

    if (stream) {
        rap_http_v2_run_request(stream->request);
    }

    if (!h2c->state.keep_pool) {
        rap_destroy_pool(h2c->state.pool);
    }

    h2c->state.pool = NULL;
    h2c->state.keep_pool = 0;

    if (h2c->state.padding) {
        return rap_http_v2_state_skip_padded(h2c, pos, end);
    }

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_handle_continuation(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, rap_http_v2_handler_pt handler)
{
    u_char    *p;
    size_t     len, skip;
    uint32_t   head;

    len = h2c->state.length;

    if (h2c->state.padding && (size_t) (end - pos) > len) {
        skip = rap_min(h2c->state.padding, (end - pos) - len);

        h2c->state.padding -= skip;

        p = pos;
        pos += skip;
        rap_memmove(pos, p, len);
    }

    if ((size_t) (end - pos) < len + RAP_HTTP_V2_FRAME_HEADER_SIZE) {
        return rap_http_v2_state_headers_save(h2c, pos, end, handler);
    }

    p = pos + len;

    head = rap_http_v2_parse_uint32(p);

    if (rap_http_v2_parse_type(head) != RAP_HTTP_V2_CONTINUATION_FRAME) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
             "client sent inappropriate frame while CONTINUATION was expected");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->state.flags |= p[4];

    if (h2c->state.sid != rap_http_v2_parse_sid(&p[5])) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                    "client sent CONTINUATION frame with incorrect identifier");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    p = pos;
    pos += RAP_HTTP_V2_FRAME_HEADER_SIZE;

    rap_memcpy(pos, p, len);

    len = rap_http_v2_parse_length(head);

    h2c->state.length += len;

    if (h2c->state.stream) {
        h2c->state.stream->request->request_length += len;
    }

    h2c->state.handler = handler;
    return pos;
}


static u_char *
rap_http_v2_state_priority(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_uint_t           depend, dependency, excl, weight;
    rap_http_v2_node_t  *node;

    if (h2c->state.length != RAP_HTTP_V2_PRIORITY_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect length %uz",
                      h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (--h2c->priority_limit == 0) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many PRIORITY frames");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    if (end - pos < RAP_HTTP_V2_PRIORITY_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_priority);
    }

    dependency = rap_http_v2_parse_uint32(pos);

    depend = dependency & 0x7fffffff;
    excl = dependency >> 31;
    weight = pos[4] + 1;

    pos += RAP_HTTP_V2_PRIORITY_SIZE;

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PRIORITY frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid == 0) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect identifier");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    node = rap_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    node->weight = weight;

    if (node->stream == NULL) {
        if (node->parent == NULL) {
            h2c->closed_nodes++;

        } else {
            rap_queue_remove(&node->reuse);
        }

        rap_queue_insert_tail(&h2c->closed, &node->reuse);
    }

    rap_http_v2_set_dependency(h2c, node, depend, excl);

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_rst_stream(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_uint_t             status;
    rap_event_t           *ev;
    rap_connection_t      *fc;
    rap_http_v2_node_t    *node;
    rap_http_v2_stream_t  *stream;

    if (h2c->state.length != RAP_HTTP_V2_RST_STREAM_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect length %uz",
                      h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RAP_HTTP_V2_RST_STREAM_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_rst_stream);
    }

    status = rap_http_v2_parse_uint32(pos);

    pos += RAP_HTTP_V2_RST_STREAM_SIZE;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 RST_STREAM frame, sid:%ui status:%ui",
                   h2c->state.sid, status);

    if (h2c->state.sid == 0) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect identifier");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    node = rap_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return rap_http_v2_state_complete(h2c, pos, end);
    }

    stream = node->stream;

    stream->in_closed = 1;
    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    switch (status) {

    case RAP_HTTP_V2_CANCEL:
        rap_log_error(RAP_LOG_INFO, fc->log, 0,
                      "client canceled stream %ui", h2c->state.sid);
        break;

    case RAP_HTTP_V2_REFUSED_STREAM:
        rap_log_error(RAP_LOG_INFO, fc->log, 0,
                      "client refused stream %ui", h2c->state.sid);
        break;

    case RAP_HTTP_V2_INTERNAL_ERROR:
        rap_log_error(RAP_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui due to internal error",
                      h2c->state.sid);
        break;

    default:
        rap_log_error(RAP_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui with status %ui",
                      h2c->state.sid, status);
        break;
    }

    ev = fc->read;
    ev->handler(ev);

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_settings(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    if (h2c->state.flags == RAP_HTTP_V2_ACK_FLAG) {

        if (h2c->state.length != 0) {
            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client sent SETTINGS frame with the ACK flag "
                          "and nonzero length");

            return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
        }

        h2c->settings_ack = 1;

        return rap_http_v2_state_complete(h2c, pos, end);
    }

    if (h2c->state.length % RAP_HTTP_V2_SETTINGS_PARAM_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect length %uz",
                      h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 SETTINGS frame");

    return rap_http_v2_state_settings_params(h2c, pos, end);
}


static u_char *
rap_http_v2_state_settings_params(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ssize_t                   window_delta;
    rap_uint_t                id, value;
    rap_http_v2_srv_conf_t   *h2scf;
    rap_http_v2_out_frame_t  *frame;

    window_delta = 0;

    while (h2c->state.length) {
        if (end - pos < RAP_HTTP_V2_SETTINGS_PARAM_SIZE) {
            return rap_http_v2_state_save(h2c, pos, end,
                                          rap_http_v2_state_settings_params);
        }

        h2c->state.length -= RAP_HTTP_V2_SETTINGS_PARAM_SIZE;

        id = rap_http_v2_parse_uint16(pos);
        value = rap_http_v2_parse_uint32(&pos[2]);

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 setting %ui:%ui", id, value);

        switch (id) {

        case RAP_HTTP_V2_INIT_WINDOW_SIZE_SETTING:

            if (value > RAP_HTTP_V2_MAX_WINDOW) {
                rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "INITIAL_WINDOW_SIZE value %ui", value);

                return rap_http_v2_connection_error(h2c,
                                                  RAP_HTTP_V2_FLOW_CTRL_ERROR);
            }

            window_delta = value - h2c->init_window;
            break;

        case RAP_HTTP_V2_MAX_FRAME_SIZE_SETTING:

            if (value > RAP_HTTP_V2_MAX_FRAME_SIZE
                || value < RAP_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "MAX_FRAME_SIZE value %ui", value);

                return rap_http_v2_connection_error(h2c,
                                                    RAP_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->frame_size = value;
            break;

        case RAP_HTTP_V2_ENABLE_PUSH_SETTING:

            if (value > 1) {
                rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "ENABLE_PUSH value %ui", value);

                return rap_http_v2_connection_error(h2c,
                                                    RAP_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->push_disabled = !value;
            break;

        case RAP_HTTP_V2_MAX_STREAMS_SETTING:
            h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                                 rap_http_v2_module);

            h2c->concurrent_pushes = rap_min(value, h2scf->concurrent_pushes);
            break;

        case RAP_HTTP_V2_HEADER_TABLE_SIZE_SETTING:

            h2c->table_update = 1;
            break;

        default:
            break;
        }

        pos += RAP_HTTP_V2_SETTINGS_PARAM_SIZE;
    }

    frame = rap_http_v2_get_frame(h2c, RAP_HTTP_V2_SETTINGS_ACK_SIZE,
                                  RAP_HTTP_V2_SETTINGS_FRAME,
                                  RAP_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    rap_http_v2_queue_ordered_frame(h2c, frame);

    if (window_delta) {
        h2c->init_window += window_delta;

        if (rap_http_v2_adjust_windows(h2c, window_delta) != RAP_OK) {
            return rap_http_v2_connection_error(h2c,
                                                RAP_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_push_promise(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                  "client sent PUSH_PROMISE frame");

    return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
rap_http_v2_state_ping(rap_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    rap_buf_t                *buf;
    rap_http_v2_out_frame_t  *frame;

    if (h2c->state.length != RAP_HTTP_V2_PING_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect length %uz",
                      h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RAP_HTTP_V2_PING_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end, rap_http_v2_state_ping);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PING frame");

    if (h2c->state.flags & RAP_HTTP_V2_ACK_FLAG) {
        return rap_http_v2_state_skip(h2c, pos, end);
    }

    frame = rap_http_v2_get_frame(h2c, RAP_HTTP_V2_PING_SIZE,
                                  RAP_HTTP_V2_PING_FRAME,
                                  RAP_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    buf = frame->first->buf;

    buf->last = rap_cpymem(buf->last, pos, RAP_HTTP_V2_PING_SIZE);

    rap_http_v2_queue_blocked_frame(h2c, frame);

    return rap_http_v2_state_complete(h2c, pos + RAP_HTTP_V2_PING_SIZE, end);
}


static u_char *
rap_http_v2_state_goaway(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
#if (RAP_DEBUG)
    rap_uint_t  last_sid, error;
#endif

    if (h2c->state.length < RAP_HTTP_V2_GOAWAY_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame "
                      "with incorrect length %uz", h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RAP_HTTP_V2_GOAWAY_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end, rap_http_v2_state_goaway);
    }

#if (RAP_DEBUG)
    h2c->state.length -= RAP_HTTP_V2_GOAWAY_SIZE;

    last_sid = rap_http_v2_parse_sid(pos);
    error = rap_http_v2_parse_uint32(&pos[4]);

    pos += RAP_HTTP_V2_GOAWAY_SIZE;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 GOAWAY frame: last sid %ui, error %ui",
                   last_sid, error);
#endif

    return rap_http_v2_state_skip(h2c, pos, end);
}


static u_char *
rap_http_v2_state_window_update(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                 window;
    rap_event_t           *wev;
    rap_queue_t           *q;
    rap_http_v2_node_t    *node;
    rap_http_v2_stream_t  *stream;

    if (h2c->state.length != RAP_HTTP_V2_WINDOW_UPDATE_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect length %uz", h2c->state.length);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < RAP_HTTP_V2_WINDOW_UPDATE_SIZE) {
        return rap_http_v2_state_save(h2c, pos, end,
                                      rap_http_v2_state_window_update);
    }

    window = rap_http_v2_parse_window(pos);

    pos += RAP_HTTP_V2_WINDOW_UPDATE_SIZE;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 WINDOW_UPDATE frame sid:%ui window:%uz",
                   h2c->state.sid, window);

    if (window == 0) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect window increment 0");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.sid) {
        node = rap_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

        if (node == NULL || node->stream == NULL) {
            rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "unknown http2 stream");

            return rap_http_v2_state_complete(h2c, pos, end);
        }

        stream = node->stream;

        if (window > (size_t) (RAP_HTTP_V2_MAX_WINDOW - stream->send_window)) {

            rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                          "client violated flow control for stream %ui: "
                          "received WINDOW_UPDATE frame "
                          "with window increment %uz "
                          "not allowed for window %z",
                          h2c->state.sid, window, stream->send_window);

            if (rap_http_v2_terminate_stream(h2c, stream,
                                             RAP_HTTP_V2_FLOW_CTRL_ERROR)
                == RAP_ERROR)
            {
                return rap_http_v2_connection_error(h2c,
                                                    RAP_HTTP_V2_INTERNAL_ERROR);
            }

            return rap_http_v2_state_complete(h2c, pos, end);
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

        return rap_http_v2_state_complete(h2c, pos, end);
    }

    if (window > RAP_HTTP_V2_MAX_WINDOW - h2c->send_window) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received WINDOW_UPDATE frame "
                      "with window increment %uz "
                      "not allowed for window %uz",
                      window, h2c->send_window);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->send_window += window;

    while (!rap_queue_empty(&h2c->waiting)) {
        q = rap_queue_head(&h2c->waiting);

        rap_queue_remove(q);

        stream = rap_queue_data(q, rap_http_v2_stream_t, queue);

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

    return rap_http_v2_state_complete(h2c, pos, end);
}


static u_char *
rap_http_v2_state_continuation(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                  "client sent unexpected CONTINUATION frame");

    return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
rap_http_v2_state_complete(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame complete pos:%p end:%p", pos, end);

    if (pos > end) {
        rap_log_error(RAP_LOG_ALERT, h2c->connection->log, 0,
                      "receive buffer overrun");

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = NULL;
    h2c->state.handler = rap_http_v2_state_head;

    return pos;
}


static u_char *
rap_http_v2_state_skip_padded(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    h2c->state.length += h2c->state.padding;
    h2c->state.padding = 0;

    return rap_http_v2_state_skip(h2c, pos, end);
}


static u_char *
rap_http_v2_state_skip(rap_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size < h2c->state.length) {
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 frame skip %uz of %uz", size, h2c->state.length);

        h2c->state.length -= size;
        return rap_http_v2_state_save(h2c, end, end, rap_http_v2_state_skip);
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame skip %uz", h2c->state.length);

    return rap_http_v2_state_complete(h2c, pos + h2c->state.length, end);
}


static u_char *
rap_http_v2_state_save(rap_http_v2_connection_t *h2c, u_char *pos, u_char *end,
    rap_http_v2_handler_pt handler)
{
    size_t  size;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame state save pos:%p end:%p handler:%p",
                   pos, end, handler);

    size = end - pos;

    if (size > RAP_HTTP_V2_STATE_BUFFER_SIZE) {
        rap_log_error(RAP_LOG_ALERT, h2c->connection->log, 0,
                      "state buffer overflow: %uz bytes required", size);

        return rap_http_v2_connection_error(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
    }

    rap_memcpy(h2c->state.buffer, pos, RAP_HTTP_V2_STATE_BUFFER_SIZE);

    h2c->state.buffer_used = size;
    h2c->state.handler = handler;
    h2c->state.incomplete = 1;

    return end;
}


static u_char *
rap_http_v2_state_headers_save(rap_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, rap_http_v2_handler_pt handler)
{
    rap_event_t               *rev;
    rap_http_request_t        *r;
    rap_http_core_srv_conf_t  *cscf;

    if (h2c->state.stream) {
        r = h2c->state.stream->request;
        rev = r->connection->read;

        if (!rev->timer_set) {
            cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
            rap_add_timer(rev, cscf->client_header_timeout);
        }
    }

    return rap_http_v2_state_save(h2c, pos, end, handler);
}


static u_char *
rap_http_v2_connection_error(rap_http_v2_connection_t *h2c,
    rap_uint_t err)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 state connection error");

    rap_http_v2_finalize_connection(h2c, err);

    return NULL;
}


static rap_int_t
rap_http_v2_parse_int(rap_http_v2_connection_t *h2c, u_char **pos, u_char *end,
    rap_uint_t prefix)
{
    u_char      *start, *p;
    rap_uint_t   value, octet, shift;

    start = *pos;
    p = start;

    value = *p++ & prefix;

    if (value != prefix) {
        if (h2c->state.length == 0) {
            return RAP_ERROR;
        }

        h2c->state.length--;

        *pos = p;
        return value;
    }

    if (end - start > RAP_HTTP_V2_INT_OCTETS) {
        end = start + RAP_HTTP_V2_INT_OCTETS;
    }

    for (shift = 0; p != end; shift += 7) {
        octet = *p++;

        value += (octet & 0x7f) << shift;

        if (octet < 128) {
            if ((size_t) (p - start) > h2c->state.length) {
                return RAP_ERROR;
            }

            h2c->state.length -= p - start;

            *pos = p;
            return value;
        }
    }

    if ((size_t) (end - start) >= h2c->state.length) {
        return RAP_ERROR;
    }

    if (end == start + RAP_HTTP_V2_INT_OCTETS) {
        return RAP_DECLINED;
    }

    return RAP_AGAIN;
}


rap_http_v2_stream_t *
rap_http_v2_push_stream(rap_http_v2_stream_t *parent, rap_str_t *path)
{
    rap_int_t                     rc;
    rap_str_t                     value;
    rap_pool_t                   *pool;
    rap_uint_t                    index;
    rap_table_elt_t             **h;
    rap_connection_t             *fc;
    rap_http_request_t           *r;
    rap_http_v2_node_t           *node;
    rap_http_v2_stream_t         *stream;
    rap_http_v2_srv_conf_t       *h2scf;
    rap_http_v2_connection_t     *h2c;
    rap_http_v2_parse_header_t   *header;

    h2c = parent->connection;

    pool = rap_create_pool(1024, h2c->connection->log);
    if (pool == NULL) {
        goto rst_stream;
    }

    node = rap_http_v2_get_node_by_id(h2c, h2c->last_push, 1);

    if (node == NULL) {
        rap_destroy_pool(pool);
        goto rst_stream;
    }

    stream = rap_http_v2_create_stream(h2c, 1);
    if (stream == NULL) {

        if (node->parent == NULL) {
            h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                                 rap_http_v2_module);

            index = rap_http_v2_index(h2scf, h2c->last_push);
            h2c->streams_index[index] = node->index;

            rap_queue_insert_tail(&h2c->closed, &node->reuse);
            h2c->closed_nodes++;
        }

        rap_destroy_pool(pool);
        goto rst_stream;
    }

    if (node->parent) {
        rap_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream->pool = pool;

    r = stream->request;
    fc = r->connection;

    stream->in_closed = 1;
    stream->node = node;

    node->stream = stream;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 push stream sid:%ui "
                   "depends on %ui excl:0 weight:16",
                   h2c->last_push, parent->node->id);

    node->weight = RAP_HTTP_V2_DEFAULT_WEIGHT;
    rap_http_v2_set_dependency(h2c, node, parent->node->id, 0);

    r->method_name = rap_http_core_get_method;
    r->method = RAP_HTTP_GET;

    r->schema.data = rap_pstrdup(pool, &parent->request->schema);
    if (r->schema.data == NULL) {
        goto close;
    }

    r->schema.len = parent->request->schema.len;

    value.data = rap_pstrdup(pool, path);
    if (value.data == NULL) {
        goto close;
    }

    value.len = path->len;

    rc = rap_http_v2_parse_path(r, &value);

    if (rc != RAP_OK) {
        goto error;
    }

    for (header = rap_http_v2_parse_headers; header->name.len; header++) {
        h = (rap_table_elt_t **)
                ((char *) &parent->request->headers_in + header->offset);

        if (*h == NULL) {
            continue;
        }

        value.len = (*h)->value.len;

        value.data = rap_pnalloc(pool, value.len + 1);
        if (value.data == NULL) {
            goto close;
        }

        rap_memcpy(value.data, (*h)->value.data, value.len);
        value.data[value.len] = '\0';

        rc = rap_http_v2_parse_header(r, header, &value);

        if (rc != RAP_OK) {
            goto error;
        }
    }

    fc->write->handler = rap_http_v2_run_request_handler;
    rap_post_event(fc->write, &rap_posted_events);

    return stream;

error:

    if (rc == RAP_ABORT) {
        /* header handler has already finalized request */
        rap_http_run_posted_requests(fc);
        return NULL;
    }

    if (rc == RAP_DECLINED) {
        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        rap_http_run_posted_requests(fc);
        return NULL;
    }

close:

    rap_http_v2_close_stream(stream, RAP_HTTP_INTERNAL_SERVER_ERROR);

    return NULL;

rst_stream:

    if (rap_http_v2_send_rst_stream(h2c, h2c->last_push,
                                    RAP_HTTP_INTERNAL_SERVER_ERROR)
        != RAP_OK)
    {
        h2c->connection->error = 1;
    }

    return NULL;
}


static rap_int_t
rap_http_v2_send_settings(rap_http_v2_connection_t *h2c)
{
    size_t                    len;
    rap_buf_t                *buf;
    rap_chain_t              *cl;
    rap_http_v2_srv_conf_t   *h2scf;
    rap_http_v2_out_frame_t  *frame;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send SETTINGS frame");

    frame = rap_palloc(h2c->pool, sizeof(rap_http_v2_out_frame_t));
    if (frame == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(h2c->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    len = RAP_HTTP_V2_SETTINGS_PARAM_SIZE * 3;

    buf = rap_create_temp_buf(h2c->pool, RAP_HTTP_V2_FRAME_HEADER_SIZE + len);
    if (buf == NULL) {
        return RAP_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = rap_http_v2_settings_frame_handler;
    frame->stream = NULL;
#if (RAP_DEBUG)
    frame->length = len;
#endif
    frame->blocked = 0;

    buf->last = rap_http_v2_write_len_and_type(buf->last, len,
                                               RAP_HTTP_V2_SETTINGS_FRAME);

    *buf->last++ = RAP_HTTP_V2_NO_FLAG;

    buf->last = rap_http_v2_write_sid(buf->last, 0);

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    buf->last = rap_http_v2_write_uint16(buf->last,
                                         RAP_HTTP_V2_MAX_STREAMS_SETTING);
    buf->last = rap_http_v2_write_uint32(buf->last,
                                         h2scf->concurrent_streams);

    buf->last = rap_http_v2_write_uint16(buf->last,
                                         RAP_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
    buf->last = rap_http_v2_write_uint32(buf->last, h2scf->preread_size);

    buf->last = rap_http_v2_write_uint16(buf->last,
                                         RAP_HTTP_V2_MAX_FRAME_SIZE_SETTING);
    buf->last = rap_http_v2_write_uint32(buf->last,
                                         RAP_HTTP_V2_MAX_FRAME_SIZE);

    rap_http_v2_queue_blocked_frame(h2c, frame);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_settings_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return RAP_AGAIN;
    }

    rap_free_chain(h2c->pool, frame->first);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_send_window_update(rap_http_v2_connection_t *h2c, rap_uint_t sid,
    size_t window)
{
    rap_buf_t                *buf;
    rap_http_v2_out_frame_t  *frame;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send WINDOW_UPDATE frame sid:%ui, window:%uz",
                   sid, window);

    frame = rap_http_v2_get_frame(h2c, RAP_HTTP_V2_WINDOW_UPDATE_SIZE,
                                  RAP_HTTP_V2_WINDOW_UPDATE_FRAME,
                                  RAP_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return RAP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rap_http_v2_write_uint32(buf->last, window);

    rap_http_v2_queue_blocked_frame(h2c, frame);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_send_rst_stream(rap_http_v2_connection_t *h2c, rap_uint_t sid,
    rap_uint_t status)
{
    rap_buf_t                *buf;
    rap_http_v2_out_frame_t  *frame;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send RST_STREAM frame sid:%ui, status:%ui",
                   sid, status);

    frame = rap_http_v2_get_frame(h2c, RAP_HTTP_V2_RST_STREAM_SIZE,
                                  RAP_HTTP_V2_RST_STREAM_FRAME,
                                  RAP_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return RAP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rap_http_v2_write_uint32(buf->last, status);

    rap_http_v2_queue_blocked_frame(h2c, frame);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_send_goaway(rap_http_v2_connection_t *h2c, rap_uint_t status)
{
    rap_buf_t                *buf;
    rap_http_v2_out_frame_t  *frame;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send GOAWAY frame: last sid %ui, error %ui",
                   h2c->last_sid, status);

    frame = rap_http_v2_get_frame(h2c, RAP_HTTP_V2_GOAWAY_SIZE,
                                  RAP_HTTP_V2_GOAWAY_FRAME,
                                  RAP_HTTP_V2_NO_FLAG, 0);
    if (frame == NULL) {
        return RAP_ERROR;
    }

    buf = frame->first->buf;

    buf->last = rap_http_v2_write_sid(buf->last, h2c->last_sid);
    buf->last = rap_http_v2_write_uint32(buf->last, status);

    rap_http_v2_queue_blocked_frame(h2c, frame);

    return RAP_OK;
}


static rap_http_v2_out_frame_t *
rap_http_v2_get_frame(rap_http_v2_connection_t *h2c, size_t length,
    rap_uint_t type, u_char flags, rap_uint_t sid)
{
    rap_buf_t                *buf;
    rap_pool_t               *pool;
    rap_http_v2_out_frame_t  *frame;

    frame = h2c->free_frames;

    if (frame) {
        h2c->free_frames = frame->next;

        buf = frame->first->buf;
        buf->pos = buf->start;

        frame->blocked = 0;

    } else if (h2c->frames < 10000) {
        pool = h2c->pool ? h2c->pool : h2c->connection->pool;

        frame = rap_pcalloc(pool, sizeof(rap_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        frame->first = rap_alloc_chain_link(pool);
        if (frame->first == NULL) {
            return NULL;
        }

        buf = rap_create_temp_buf(pool, RAP_HTTP_V2_FRAME_BUFFER_SIZE);
        if (buf == NULL) {
            return NULL;
        }

        buf->last_buf = 1;

        frame->first->buf = buf;
        frame->last = frame->first;

        frame->handler = rap_http_v2_frame_handler;

        h2c->frames++;

    } else {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

#if (RAP_DEBUG)
    if (length > RAP_HTTP_V2_FRAME_BUFFER_SIZE - RAP_HTTP_V2_FRAME_HEADER_SIZE)
    {
        rap_log_error(RAP_LOG_ALERT, h2c->connection->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }
#endif

    frame->length = length;

    buf->last = rap_http_v2_write_len_and_type(buf->pos, length, type);

    *buf->last++ = flags;

    buf->last = rap_http_v2_write_sid(buf->last, sid);

    return frame;
}


static rap_int_t
rap_http_v2_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return RAP_AGAIN;
    }

    frame->next = h2c->free_frames;
    h2c->free_frames = frame;

    h2c->total_bytes += RAP_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    return RAP_OK;
}


static rap_http_v2_stream_t *
rap_http_v2_create_stream(rap_http_v2_connection_t *h2c, rap_uint_t push)
{
    rap_log_t                 *log;
    rap_event_t               *rev, *wev;
    rap_connection_t          *fc;
    rap_http_log_ctx_t        *ctx;
    rap_http_request_t        *r;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_srv_conf_t    *h2scf;
    rap_http_core_srv_conf_t  *cscf;

    fc = h2c->free_fake_connections;

    if (fc) {
        h2c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = rap_palloc(h2c->pool, sizeof(rap_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = rap_palloc(h2c->pool, sizeof(rap_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = rap_palloc(h2c->pool, sizeof(rap_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = rap_palloc(h2c->pool, sizeof(rap_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = rap_palloc(h2c->pool, sizeof(rap_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    rap_memcpy(log, h2c->connection->log, sizeof(rap_log_t));

    log->data = ctx;

    if (push) {
        log->action = "processing pushed request headers";

    } else {
        log->action = "reading client request headers";
    }

    rap_memzero(rev, sizeof(rap_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = rap_http_v2_close_stream_handler;
    rev->log = log;

    rap_memcpy(wev, rev, sizeof(rap_event_t));

    wev->write = 1;

    rap_memcpy(fc, h2c->connection, sizeof(rap_connection_t));

    fc->data = h2c->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = RAP_TCP_NODELAY_DISABLED;

    r = rap_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    rap_str_set(&r->http_protocol, "HTTP/2.0");

    r->http_version = RAP_HTTP_VERSION_20;
    r->valid_location = 1;

    fc->data = r;
    h2c->connection->requests++;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

    r->header_in = rap_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        rap_http_free_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (rap_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        rap_http_free_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = RAP_HTTP_CONNECTION_CLOSE;

    stream = rap_pcalloc(r->pool, sizeof(rap_http_v2_stream_t));
    if (stream == NULL) {
        rap_http_free_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->stream = stream;

    stream->request = r;
    stream->connection = h2c;

    h2scf = rap_http_get_module_srv_conf(r, rap_http_v2_module);

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


static rap_http_v2_node_t *
rap_http_v2_get_node_by_id(rap_http_v2_connection_t *h2c, rap_uint_t sid,
    rap_uint_t alloc)
{
    rap_uint_t               index;
    rap_http_v2_node_t      *node;
    rap_http_v2_srv_conf_t  *h2scf;

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    index = rap_http_v2_index(h2scf, sid);

    for (node = h2c->streams_index[index]; node; node = node->index) {

        if (node->id == sid) {
            return node;
        }
    }

    if (!alloc) {
        return NULL;
    }

    if (h2c->closed_nodes < 32) {
        node = rap_pcalloc(h2c->connection->pool, sizeof(rap_http_v2_node_t));
        if (node == NULL) {
            return NULL;
        }

    } else {
        node = rap_http_v2_get_closed_node(h2c);
    }

    node->id = sid;

    rap_queue_init(&node->children);

    node->index = h2c->streams_index[index];
    h2c->streams_index[index] = node;

    return node;
}


static rap_http_v2_node_t *
rap_http_v2_get_closed_node(rap_http_v2_connection_t *h2c)
{
    rap_uint_t               weight;
    rap_queue_t             *q, *children;
    rap_http_v2_node_t      *node, **next, *n, *parent, *child;
    rap_http_v2_srv_conf_t  *h2scf;

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    h2c->closed_nodes--;

    q = rap_queue_head(&h2c->closed);

    rap_queue_remove(q);

    node = rap_queue_data(q, rap_http_v2_node_t, reuse);

    next = &h2c->streams_index[rap_http_v2_index(h2scf, node->id)];

    for ( ;; ) {
        n = *next;

        if (n == node) {
            *next = n->index;
            break;
        }

        next = &n->index;
    }

    rap_queue_remove(&node->queue);

    weight = 0;

    for (q = rap_queue_head(&node->children);
         q != rap_queue_sentinel(&node->children);
         q = rap_queue_next(q))
    {
        child = rap_queue_data(q, rap_http_v2_node_t, queue);
        weight += child->weight;
    }

    parent = node->parent;

    for (q = rap_queue_head(&node->children);
         q != rap_queue_sentinel(&node->children);
         q = rap_queue_next(q))
    {
        child = rap_queue_data(q, rap_http_v2_node_t, queue);
        child->parent = parent;
        child->weight = node->weight * child->weight / weight;

        if (child->weight == 0) {
            child->weight = 1;
        }
    }

    if (parent == RAP_HTTP_V2_ROOT) {
        node->rank = 0;
        node->rel_weight = 1.0;

        children = &h2c->dependencies;

    } else {
        node->rank = parent->rank;
        node->rel_weight = parent->rel_weight;

        children = &parent->children;
    }

    rap_http_v2_node_children_update(node);
    rap_queue_add(children, &node->children);

    rap_memzero(node, sizeof(rap_http_v2_node_t));

    return node;
}


static rap_int_t
rap_http_v2_validate_header(rap_http_request_t *r, rap_http_v2_header_t *header)
{
    u_char                     ch;
    rap_uint_t                 i;
    rap_http_core_srv_conf_t  *cscf;

    r->invalid_header = 0;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

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
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header name: \"%V\"",
                          &header->name);

            return RAP_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != header->value.len; i++) {
        ch = header->value.data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"",
                          &header->name, &header->value);

            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_pseudo_header(rap_http_request_t *r, rap_http_v2_header_t *header)
{
    header->name.len--;
    header->name.data++;

    switch (header->name.len) {
    case 4:
        if (rap_memcmp(header->name.data, "path", sizeof("path") - 1)
            == 0)
        {
            return rap_http_v2_parse_path(r, &header->value);
        }

        break;

    case 6:
        if (rap_memcmp(header->name.data, "method", sizeof("method") - 1)
            == 0)
        {
            return rap_http_v2_parse_method(r, &header->value);
        }

        if (rap_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
            == 0)
        {
            return rap_http_v2_parse_scheme(r, &header->value);
        }

        break;

    case 9:
        if (rap_memcmp(header->name.data, "authority", sizeof("authority") - 1)
            == 0)
        {
            return rap_http_v2_parse_authority(r, &header->value);
        }

        break;
    }

    rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \":%V\"",
                  &header->name);

    return RAP_DECLINED;
}


static rap_int_t
rap_http_v2_parse_path(rap_http_request_t *r, rap_str_t *value)
{
    if (r->unparsed_uri.len) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return RAP_DECLINED;
    }

    if (value->len == 0) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return RAP_DECLINED;
    }

    r->uri_start = value->data;
    r->uri_end = value->data + value->len;

    if (rap_http_parse_uri(r) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"", value);

        return RAP_DECLINED;
    }

    if (rap_http_process_request_uri(r) != RAP_OK) {
        /*
         * request has been finalized already
         * in rap_http_process_request_uri()
         */
        return RAP_ABORT;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_parse_method(rap_http_request_t *r, rap_str_t *value)
{
    size_t         k, len;
    rap_uint_t     n;
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
        { 3, "GET",       RAP_HTTP_GET },
        { 4, "POST",      RAP_HTTP_POST },
        { 4, "HEAD",      RAP_HTTP_HEAD },
        { 7, "OPTIONS",   RAP_HTTP_OPTIONS },
        { 8, "PROPFIND",  RAP_HTTP_PROPFIND },
        { 3, "PUT",       RAP_HTTP_PUT },
        { 5, "MKCOL",     RAP_HTTP_MKCOL },
        { 6, "DELETE",    RAP_HTTP_DELETE },
        { 4, "COPY",      RAP_HTTP_COPY },
        { 4, "MOVE",      RAP_HTTP_MOVE },
        { 9, "PROPPATCH", RAP_HTTP_PROPPATCH },
        { 4, "LOCK",      RAP_HTTP_LOCK },
        { 6, "UNLOCK",    RAP_HTTP_UNLOCK },
        { 5, "PATCH",     RAP_HTTP_PATCH },
        { 5, "TRACE",     RAP_HTTP_TRACE }
    }, *test;

    if (r->method_name.len) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return RAP_DECLINED;
    }

    if (value->len == 0) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return RAP_DECLINED;
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
            return RAP_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return RAP_DECLINED;
        }

        p++;

    } while (--len);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_parse_scheme(rap_http_request_t *r, rap_str_t *value)
{
    u_char      c, ch;
    rap_uint_t  i;

    if (r->schema.len) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :scheme header");

        return RAP_DECLINED;
    }

    if (value->len == 0) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent empty :scheme header");

        return RAP_DECLINED;
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

        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :scheme header: \"%V\"", value);

        return RAP_DECLINED;
    }

    r->schema = *value;

    return RAP_OK;
}


static rap_int_t
rap_http_v2_parse_authority(rap_http_request_t *r, rap_str_t *value)
{
    return rap_http_v2_parse_header(r, &rap_http_v2_parse_headers[0], value);
}


static rap_int_t
rap_http_v2_parse_header(rap_http_request_t *r,
    rap_http_v2_parse_header_t *header, rap_str_t *value)
{
    rap_table_elt_t            *h;
    rap_http_core_main_conf_t  *cmcf;

    h = rap_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    h->key.len = header->name.len;
    h->key.data = header->name.data;
    h->lowcase_key = header->name.data;

    if (header->hh == NULL) {
        header->hash = rap_hash_key(header->name.data, header->name.len);

        cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

        header->hh = rap_hash_find(&cmcf->headers_in_hash, header->hash,
                                   h->lowcase_key, h->key.len);
        if (header->hh == NULL) {
            return RAP_ERROR;
        }
    }

    h->hash = header->hash;

    h->value.len = value->len;
    h->value.data = value->data;

    if (header->hh->handler(r, h, header->hh->offset) != RAP_OK) {
        /* header handler has already finalized request */
        return RAP_ABORT;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_construct_request_line(rap_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/2.0";

    if (r->method_name.len == 0
        || r->schema.len == 0
        || r->unparsed_uri.len == 0)
    {
        if (r->method_name.len == 0) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent no :method header");

        } else if (r->schema.len == 0) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent no :scheme header");

        } else {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent no :path header");
        }

        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        return RAP_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = rap_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        rap_http_v2_close_stream(r->stream, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    r->request_line.data = p;

    p = rap_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = rap_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    rap_memcpy(p, ending, sizeof(ending));

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 request line: \"%V\"", &r->request_line);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_cookie(rap_http_request_t *r, rap_http_v2_header_t *header)
{
    rap_str_t    *val;
    rap_array_t  *cookies;

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        cookies = rap_array_create(r->pool, 2, sizeof(rap_str_t));
        if (cookies == NULL) {
            return RAP_ERROR;
        }

        r->stream->cookies = cookies;
    }

    val = rap_array_push(cookies);
    if (val == NULL) {
        return RAP_ERROR;
    }

    val->len = header->value.len;
    val->data = header->value.data;

    return RAP_OK;
}


static rap_int_t
rap_http_v2_construct_cookie_header(rap_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    rap_str_t                  *vals;
    rap_uint_t                  i;
    rap_array_t                *cookies;
    rap_table_elt_t            *h;
    rap_http_header_t          *hh;
    rap_http_core_main_conf_t  *cmcf;

    static rap_str_t cookie = rap_string("cookie");

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        return RAP_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = rap_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        rap_http_v2_close_stream(r->stream, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = rap_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = rap_list_push(&r->headers_in.headers);
    if (h == NULL) {
        rap_http_v2_close_stream(r->stream, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    h->hash = rap_hash(rap_hash(rap_hash(rap_hash(
                                    rap_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    hh = rap_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        rap_http_v2_close_stream(r->stream, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != RAP_OK) {
        /*
         * request has been finalized already
         * in rap_http_process_multi_header_lines()
         */
        return RAP_ERROR;
    }

    return RAP_OK;
}


static void
rap_http_v2_run_request(rap_http_request_t *r)
{
    rap_connection_t          *fc;
    rap_http_v2_connection_t  *h2c;

    fc = r->connection;

    if (rap_http_v2_construct_request_line(r) != RAP_OK) {
        goto failed;
    }

    if (rap_http_v2_construct_cookie_header(r) != RAP_OK) {
        goto failed;
    }

    r->http_state = RAP_HTTP_PROCESS_REQUEST_STATE;

    if (rap_http_process_request_header(r) != RAP_OK) {
        goto failed;
    }

    if (r->headers_in.content_length_n > 0 && r->stream->in_closed) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        goto failed;
    }

    if (r->headers_in.content_length_n == -1 && !r->stream->in_closed) {
        r->headers_in.chunked = 1;
    }

    h2c = r->stream->connection;

    h2c->payload_bytes += r->request_length;

    rap_http_process_request(r);

failed:

    rap_http_run_posted_requests(fc);
}


static void
rap_http_v2_run_request_handler(rap_event_t *ev)
{
    rap_connection_t    *fc;
    rap_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 run request handler");

    rap_http_v2_run_request(r);
}


rap_int_t
rap_http_v2_read_request_body(rap_http_request_t *r)
{
    off_t                      len;
    size_t                     size;
    rap_buf_t                 *buf;
    rap_int_t                  rc;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_srv_conf_t    *h2scf;
    rap_http_request_body_t   *rb;
    rap_http_core_loc_conf_t  *clcf;
    rap_http_v2_connection_t  *h2c;

    stream = r->stream;
    rb = r->request_body;

    if (stream->skip_data) {
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return RAP_OK;
    }

    h2scf = rap_http_get_module_srv_conf(r, rap_http_v2_module);
    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

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

        if (len > RAP_HTTP_V2_MAX_WINDOW) {
            len = RAP_HTTP_V2_MAX_WINDOW;
        }

        rb->buf = rap_create_temp_buf(r->pool, (size_t) len);

    } else if (len >= 0 && len <= (off_t) clcf->client_body_buffer_size
               && !r->request_body_in_file_only)
    {
        rb->buf = rap_create_temp_buf(r->pool, (size_t) len);

    } else {
        rb->buf = rap_calloc_buf(r->pool);

        if (rb->buf != NULL) {
            rb->buf->sync = 1;
        }
    }

    if (rb->buf == NULL) {
        stream->skip_data = 1;
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rb->rest = 1;

    buf = stream->preread;

    if (stream->in_closed) {
        r->request_body_no_buffering = 0;

        if (buf) {
            rc = rap_http_v2_process_request_body(r, buf->pos,
                                                  buf->last - buf->pos, 1);
            rap_pfree(r->pool, buf->start);
            return rc;
        }

        return rap_http_v2_process_request_body(r, NULL, 0, 1);
    }

    if (buf) {
        rc = rap_http_v2_process_request_body(r, buf->pos,
                                              buf->last - buf->pos, 0);

        rap_pfree(r->pool, buf->start);

        if (rc != RAP_OK) {
            stream->skip_data = 1;
            return rc;
        }
    }

    if (r->request_body_no_buffering) {
        size = (size_t) len - h2scf->preread_size;

    } else {
        stream->no_flow_control = 1;
        size = RAP_HTTP_V2_MAX_WINDOW - stream->recv_window;
    }

    if (size) {
        if (rap_http_v2_send_window_update(stream->connection,
                                           stream->node->id, size)
            == RAP_ERROR)
        {
            stream->skip_data = 1;
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        h2c = stream->connection;

        if (!h2c->blocked) {
            if (rap_http_v2_send_output_queue(h2c) == RAP_ERROR) {
                stream->skip_data = 1;
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        stream->recv_window += size;
    }

    if (!buf) {
        rap_add_timer(r->connection->read, clcf->client_body_timeout);
    }

    r->read_event_handler = rap_http_v2_read_client_request_body_handler;
    r->write_event_handler = rap_http_request_empty_handler;

    return RAP_AGAIN;
}


static rap_int_t
rap_http_v2_process_request_body(rap_http_request_t *r, u_char *pos,
    size_t size, rap_uint_t last)
{
    rap_buf_t                 *buf;
    rap_int_t                  rc;
    rap_connection_t          *fc;
    rap_http_request_body_t   *rb;
    rap_http_core_loc_conf_t  *clcf;

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
                rap_log_error(RAP_LOG_INFO, fc->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return RAP_HTTP_BAD_REQUEST;
            }

            buf->last = rap_cpymem(buf->last, pos, size);
        }
    }

    if (last) {
        rb->rest = 0;

        if (fc->read->timer_set) {
            rap_del_timer(fc->read);
        }

        if (r->request_body_no_buffering) {
            rap_post_event(fc->read, &rap_posted_events);
            return RAP_OK;
        }

        rc = rap_http_v2_filter_request_body(r);

        if (rc != RAP_OK) {
            return rc;
        }

        if (buf->sync) {
            /* prevent reusing this buffer in the upstream module */
            rb->buf = NULL;
        }

        if (r->headers_in.chunked) {
            r->headers_in.content_length_n = rb->received;
        }

        r->read_event_handler = rap_http_block_reading;
        rb->post_handler(r);

        return RAP_OK;
    }

    if (size == 0) {
        return RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    rap_add_timer(fc->read, clcf->client_body_timeout);

    if (r->request_body_no_buffering) {
        rap_post_event(fc->read, &rap_posted_events);
        return RAP_OK;
    }

    if (buf->sync) {
        return rap_http_v2_filter_request_body(r);
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_filter_request_body(rap_http_request_t *r)
{
    rap_buf_t                 *b, *buf;
    rap_int_t                  rc;
    rap_chain_t               *cl;
    rap_http_request_body_t   *rb;
    rap_http_core_loc_conf_t  *clcf;

    rb = r->request_body;
    buf = rb->buf;

    if (buf->pos == buf->last && rb->rest) {
        cl = NULL;
        goto update;
    }

    cl = rap_chain_get_free_buf(r->pool, &rb->free);
    if (cl == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    rap_memzero(b, sizeof(rap_buf_t));

    if (buf->pos != buf->last) {
        r->request_length += buf->last - buf->pos;
        rb->received += buf->last - buf->pos;

        if (r->headers_in.content_length_n != -1) {
            if (rb->received > r->headers_in.content_length_n) {
                rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return RAP_HTTP_BAD_REQUEST;
            }

        } else {
            clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

            if (clcf->client_max_body_size
                && rb->received > clcf->client_max_body_size)
            {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked body: "
                              "%O bytes", rb->received);

                return RAP_HTTP_REQUEST_ENTITY_TOO_LARGE;
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
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);

            return RAP_HTTP_BAD_REQUEST;
        }

        b->last_buf = 1;
    }

    b->tag = (rap_buf_tag_t) &rap_http_v2_filter_request_body;
    b->flush = r->request_body_no_buffering;

update:

    rc = rap_http_top_request_body_filter(r, cl);

    rap_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
                            (rap_buf_tag_t) &rap_http_v2_filter_request_body);

    return rc;
}


static void
rap_http_v2_read_client_request_body_handler(rap_http_request_t *r)
{
    rap_connection_t  *fc;

    fc = r->connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read client request body handler");

    if (fc->read->timedout) {
        rap_log_error(RAP_LOG_INFO, fc->log, RAP_ETIMEDOUT, "client timed out");

        fc->timedout = 1;
        r->stream->skip_data = 1;

        rap_http_finalize_request(r, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (fc->error) {
        rap_log_error(RAP_LOG_INFO, fc->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        rap_http_finalize_request(r, RAP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }
}


rap_int_t
rap_http_v2_read_unbuffered_request_body(rap_http_request_t *r)
{
    size_t                     window;
    rap_buf_t                 *buf;
    rap_int_t                  rc;
    rap_connection_t          *fc;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_connection_t  *h2c;
    rap_http_core_loc_conf_t  *clcf;

    stream = r->stream;
    fc = r->connection;

    if (fc->read->timedout) {
        if (stream->recv_window) {
            stream->skip_data = 1;
            fc->timedout = 1;

            return RAP_HTTP_REQUEST_TIME_OUT;
        }

        fc->read->timedout = 0;
    }

    if (fc->error) {
        stream->skip_data = 1;
        return RAP_HTTP_BAD_REQUEST;
    }

    rc = rap_http_v2_filter_request_body(r);

    if (rc != RAP_OK) {
        stream->skip_data = 1;
        return rc;
    }

    if (!r->request_body->rest) {
        return RAP_OK;
    }

    if (r->request_body->busy != NULL) {
        return RAP_AGAIN;
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
            rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");
            stream->skip_data = 1;
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        return RAP_AGAIN;
    }

    if (rap_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == RAP_ERROR)
    {
        stream->skip_data = 1;
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_http_v2_send_output_queue(h2c) == RAP_ERROR) {
        stream->skip_data = 1;
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stream->recv_window == 0) {
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
        rap_add_timer(fc->read, clcf->client_body_timeout);
    }

    stream->recv_window = window;

    return RAP_AGAIN;
}


static rap_int_t
rap_http_v2_terminate_stream(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream, rap_uint_t status)
{
    rap_event_t       *rev;
    rap_connection_t  *fc;

    if (stream->rst_sent) {
        return RAP_OK;
    }

    if (rap_http_v2_send_rst_stream(h2c, stream->node->id, status)
        == RAP_ERROR)
    {
        return RAP_ERROR;
    }

    stream->rst_sent = 1;
    stream->skip_data = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    rev->handler(rev);

    return RAP_OK;
}


void
rap_http_v2_close_stream(rap_http_v2_stream_t *stream, rap_int_t rc)
{
    rap_pool_t                *pool;
    rap_uint_t                 push;
    rap_event_t               *ev;
    rap_connection_t          *fc;
    rap_http_v2_node_t        *node;
    rap_http_v2_connection_t  *h2c;

    h2c = stream->connection;
    node = stream->node;

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 close stream %ui, queued %ui, "
                   "processing %ui, pushing %ui",
                   node->id, stream->queued, h2c->processing, h2c->pushing);

    fc = stream->request->connection;

    if (stream->queued) {
        fc->error = 1;
        fc->write->handler = rap_http_v2_retry_close_stream_handler;
        fc->read->handler = rap_http_v2_retry_close_stream_handler;
        return;
    }

    if (!stream->rst_sent && !h2c->connection->error) {

        if (!stream->out_closed) {
            if (rap_http_v2_send_rst_stream(h2c, node->id,
                                      fc->timedout ? RAP_HTTP_V2_PROTOCOL_ERROR
                                                   : RAP_HTTP_V2_INTERNAL_ERROR)
                != RAP_OK)
            {
                h2c->connection->error = 1;
            }

        } else if (!stream->in_closed) {
            if (rap_http_v2_send_rst_stream(h2c, node->id, RAP_HTTP_V2_NO_ERROR)
                != RAP_OK)
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

    rap_queue_insert_tail(&h2c->closed, &node->reuse);
    h2c->closed_nodes++;

    /*
     * This pool keeps decoded request headers which can be used by log phase
     * handlers in rap_http_free_request().
     *
     * The pointer is stored into local variable because the stream object
     * will be destroyed after a call to rap_http_free_request().
     */
    pool = stream->pool;

    h2c->frames -= stream->frames;

    rap_http_free_request(stream->request, rc);

    if (pool != h2c->state.pool) {
        rap_destroy_pool(pool);

    } else {
        /* pool will be destroyed when the complete header is parsed */
        h2c->state.keep_pool = 0;
    }

    ev = fc->read;

    if (ev->timer_set) {
        rap_del_timer(ev);
    }

    if (ev->posted) {
        rap_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->timer_set) {
        rap_del_timer(ev);
    }

    if (ev->posted) {
        rap_delete_posted_event(ev);
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

    ev->handler = rap_http_v2_handle_connection_handler;
    rap_post_event(ev, &rap_posted_events);
}


static void
rap_http_v2_close_stream_handler(rap_event_t *ev)
{
    rap_connection_t    *fc;
    rap_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 close stream handler");

    if (ev->timedout) {
        rap_log_error(RAP_LOG_INFO, fc->log, RAP_ETIMEDOUT, "client timed out");

        fc->timedout = 1;

        rap_http_v2_close_stream(r->stream, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rap_http_v2_close_stream(r->stream, 0);
}


static void
rap_http_v2_retry_close_stream_handler(rap_event_t *ev)
{
    rap_connection_t    *fc;
    rap_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 retry close stream handler");

    rap_http_v2_close_stream(r->stream, 0);
}


static void
rap_http_v2_handle_connection_handler(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_http_v2_connection_t  *h2c;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http2 handle connection handler");

    c = rev->data;
    h2c = c->data;

    if (c->error) {
        rap_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rev->handler = rap_http_v2_read_handler;

    if (rev->ready) {
        rap_http_v2_read_handler(rev);
        return;
    }

    if (h2c->last_out && rap_http_v2_send_output_queue(h2c) == RAP_ERROR) {
        rap_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rap_http_v2_handle_connection(c->data);
}


static void
rap_http_v2_idle_handler(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_http_v2_srv_conf_t    *h2scf;
    rap_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http2 idle handler");

    if (rev->timedout || c->close) {
        rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_NO_ERROR);
        return;
    }

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            rap_log_error(RAP_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "idle connection", &c->addr_text);
#if (RAP_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            rap_http_close_connection(c);
            return;
        }
    }

#endif

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    if (h2c->idle++ > 10 * h2scf->max_requests) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");
        rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_NO_ERROR);
        return;
    }

    c->destroyed = 0;
    rap_reusable_connection(c, 0);

    h2c->pool = rap_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        rap_http_v2_finalize_connection(h2c, RAP_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    c->write->handler = rap_http_v2_write_handler;

    rev->handler = rap_http_v2_read_handler;
    rap_http_v2_read_handler(rev);
}


static void
rap_http_v2_finalize_connection(rap_http_v2_connection_t *h2c,
    rap_uint_t status)
{
    rap_uint_t               i, size;
    rap_event_t             *ev;
    rap_connection_t        *c, *fc;
    rap_http_request_t      *r;
    rap_http_v2_node_t      *node;
    rap_http_v2_stream_t    *stream;
    rap_http_v2_srv_conf_t  *h2scf;

    c = h2c->connection;

    h2c->blocked = 1;

    if (!c->error && !h2c->goaway) {
        if (rap_http_v2_send_goaway(h2c, status) != RAP_ERROR) {
            (void) rap_http_v2_send_output_queue(h2c);
        }
    }

    c->error = 1;

    if (!h2c->processing && !h2c->pushing) {
        rap_http_close_connection(c);
        return;
    }

    c->read->handler = rap_http_empty_handler;
    c->write->handler = rap_http_empty_handler;

    h2c->last_out = NULL;

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    size = rap_http_v2_index_size(h2scf);

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

    rap_http_close_connection(c);
}


static rap_int_t
rap_http_v2_adjust_windows(rap_http_v2_connection_t *h2c, ssize_t delta)
{
    rap_uint_t               i, size;
    rap_event_t             *wev;
    rap_http_v2_node_t      *node;
    rap_http_v2_stream_t    *stream;
    rap_http_v2_srv_conf_t  *h2scf;

    h2scf = rap_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         rap_http_v2_module);

    size = rap_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            if (delta > 0
                && stream->send_window
                      > (ssize_t) (RAP_HTTP_V2_MAX_WINDOW - delta))
            {
                if (rap_http_v2_terminate_stream(h2c, stream,
                                                 RAP_HTTP_V2_FLOW_CTRL_ERROR)
                    == RAP_ERROR)
                {
                    return RAP_ERROR;
                }

                continue;
            }

            stream->send_window += delta;

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
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

    return RAP_OK;
}


static void
rap_http_v2_set_dependency(rap_http_v2_connection_t *h2c,
    rap_http_v2_node_t *node, rap_uint_t depend, rap_uint_t exclusive)
{
    rap_queue_t         *children, *q;
    rap_http_v2_node_t  *parent, *child, *next;

    parent = depend ? rap_http_v2_get_node_by_id(h2c, depend, 0) : NULL;

    if (parent == NULL) {
        parent = RAP_HTTP_V2_ROOT;

        if (depend != 0) {
            exclusive = 0;
        }

        node->rank = 1;
        node->rel_weight = (1.0 / 256) * node->weight;

        children = &h2c->dependencies;

    } else {
        if (node->parent != NULL) {

            for (next = parent->parent;
                 next != RAP_HTTP_V2_ROOT && next->rank >= node->rank;
                 next = next->parent)
            {
                if (next != node) {
                    continue;
                }

                rap_queue_remove(&parent->queue);
                rap_queue_insert_after(&node->queue, &parent->queue);

                parent->parent = node->parent;

                if (node->parent == RAP_HTTP_V2_ROOT) {
                    parent->rank = 1;
                    parent->rel_weight = (1.0 / 256) * parent->weight;

                } else {
                    parent->rank = node->parent->rank + 1;
                    parent->rel_weight = (node->parent->rel_weight / 256)
                                         * parent->weight;
                }

                if (!exclusive) {
                    rap_http_v2_node_children_update(parent);
                }

                break;
            }
        }

        node->rank = parent->rank + 1;
        node->rel_weight = (parent->rel_weight / 256) * node->weight;

        if (parent->stream == NULL) {
            rap_queue_remove(&parent->reuse);
            rap_queue_insert_tail(&h2c->closed, &parent->reuse);
        }

        children = &parent->children;
    }

    if (exclusive) {
        for (q = rap_queue_head(children);
             q != rap_queue_sentinel(children);
             q = rap_queue_next(q))
        {
            child = rap_queue_data(q, rap_http_v2_node_t, queue);
            child->parent = node;
        }

        rap_queue_add(&node->children, children);
        rap_queue_init(children);
    }

    if (node->parent != NULL) {
        rap_queue_remove(&node->queue);
    }

    rap_queue_insert_tail(children, &node->queue);

    node->parent = parent;

    rap_http_v2_node_children_update(node);
}


static void
rap_http_v2_node_children_update(rap_http_v2_node_t *node)
{
    rap_queue_t         *q;
    rap_http_v2_node_t  *child;

    for (q = rap_queue_head(&node->children);
         q != rap_queue_sentinel(&node->children);
         q = rap_queue_next(q))
    {
        child = rap_queue_data(q, rap_http_v2_node_t, queue);

        child->rank = node->rank + 1;
        child->rel_weight = (node->rel_weight / 256) * child->weight;

        rap_http_v2_node_children_update(child);
    }
}


static void
rap_http_v2_pool_cleanup(void *data)
{
    rap_http_v2_connection_t  *h2c = data;

    if (h2c->state.pool) {
        rap_destroy_pool(h2c->state.pool);
    }

    if (h2c->pool) {
        rap_destroy_pool(h2c->pool);
    }
}
