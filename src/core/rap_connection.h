
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CONNECTION_H_INCLUDED_
#define _RAP_CONNECTION_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct rap_listening_s  rap_listening_t;

struct rap_listening_s {
    rap_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    rap_str_t           addr_text;

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (RAP_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    rap_connection_handler_pt   handler;

    void               *servers;  /* array of rap_http_in_addr_t, for example */

    rap_log_t           log;
    rap_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    rap_msec_t          post_accept_timeout;

    rap_listening_t    *previous;
    rap_connection_t   *connection;

    rap_rbtree_t        rbtree;
    rap_rbtree_node_t   sentinel;

    rap_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (RAP_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (RAP_HAVE_SETFIB)
    int                 setfib;
#endif

#if (RAP_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    RAP_ERROR_ALERT = 0,
    RAP_ERROR_ERR,
    RAP_ERROR_INFO,
    RAP_ERROR_IGNORE_ECONNRESET,
    RAP_ERROR_IGNORE_EINVAL
} rap_connection_log_error_e;


typedef enum {
    RAP_TCP_NODELAY_UNSET = 0,
    RAP_TCP_NODELAY_SET,
    RAP_TCP_NODELAY_DISABLED
} rap_connection_tcp_nodelay_e;


typedef enum {
    RAP_TCP_NOPUSH_UNSET = 0,
    RAP_TCP_NOPUSH_SET,
    RAP_TCP_NOPUSH_DISABLED
} rap_connection_tcp_nopush_e;


#define RAP_LOWLEVEL_BUFFERED  0x0f
#define RAP_SSL_BUFFERED       0x01
#define RAP_HTTP_V2_BUFFERED   0x02


struct rap_connection_s {
    void               *data;
    rap_event_t        *read;
    rap_event_t        *write;

    rap_socket_t        fd;

    rap_recv_pt         recv;
    rap_send_pt         send;
    rap_recv_chain_pt   recv_chain;
    rap_send_chain_pt   send_chain;

    rap_listening_t    *listening;

    off_t               sent;

    rap_log_t          *log;

    rap_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    rap_str_t           addr_text;

    rap_proxy_protocol_t  *proxy_protocol;

#if (RAP_SSL || RAP_COMPAT)
    rap_ssl_connection_t  *ssl;
#endif

    rap_udp_connection_t  *udp;

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    rap_buf_t          *buffer;

    rap_queue_t         queue;

    rap_atomic_uint_t   number;

    rap_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* rap_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* rap_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* rap_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (RAP_HAVE_AIO_SENDFILE || RAP_COMPAT)
    unsigned            busy_count:2;
#endif

#if (RAP_THREADS || RAP_COMPAT)
    rap_thread_task_t  *sendfile_task;
#endif
};


#define rap_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & RAP_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


rap_listening_t *rap_create_listening(rap_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
rap_int_t rap_clone_listening(rap_cycle_t *cycle, rap_listening_t *ls);
rap_int_t rap_set_inherited_sockets(rap_cycle_t *cycle);
rap_int_t rap_open_listening_sockets(rap_cycle_t *cycle);
void rap_configure_listening_sockets(rap_cycle_t *cycle);
void rap_close_listening_sockets(rap_cycle_t *cycle);
void rap_close_connection(rap_connection_t *c);
void rap_close_idle_connections(rap_cycle_t *cycle);
rap_int_t rap_connection_local_sockaddr(rap_connection_t *c, rap_str_t *s,
    rap_uint_t port);
rap_int_t rap_tcp_nodelay(rap_connection_t *c);
rap_int_t rap_connection_error(rap_connection_t *c, rap_err_t err, char *text);

rap_connection_t *rap_get_connection(rap_socket_t s, rap_log_t *log);
void rap_free_connection(rap_connection_t *c);

void rap_reusable_connection(rap_connection_t *c, rap_uint_t reusable);

#endif /* _RAP_CONNECTION_H_INCLUDED_ */
