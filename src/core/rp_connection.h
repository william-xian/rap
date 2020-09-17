
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CONNECTION_H_INCLUDED_
#define _RP_CONNECTION_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct rp_listening_s  rp_listening_t;

struct rp_listening_s {
    rp_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    rp_str_t           addr_text;

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (RP_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    rp_connection_handler_pt   handler;

    void               *servers;  /* array of rp_http_in_addr_t, for example */

    rp_log_t           log;
    rp_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    rp_msec_t          post_accept_timeout;

    rp_listening_t    *previous;
    rp_connection_t   *connection;

    rp_rbtree_t        rbtree;
    rp_rbtree_node_t   sentinel;

    rp_uint_t          worker;

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

#if (RP_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (RP_HAVE_SETFIB)
    int                 setfib;
#endif

#if (RP_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    RP_ERROR_ALERT = 0,
    RP_ERROR_ERR,
    RP_ERROR_INFO,
    RP_ERROR_IGNORE_ECONNRESET,
    RP_ERROR_IGNORE_EINVAL
} rp_connection_log_error_e;


typedef enum {
    RP_TCP_NODELAY_UNSET = 0,
    RP_TCP_NODELAY_SET,
    RP_TCP_NODELAY_DISABLED
} rp_connection_tcp_nodelay_e;


typedef enum {
    RP_TCP_NOPUSH_UNSET = 0,
    RP_TCP_NOPUSH_SET,
    RP_TCP_NOPUSH_DISABLED
} rp_connection_tcp_nopush_e;


#define RP_LOWLEVEL_BUFFERED  0x0f
#define RP_SSL_BUFFERED       0x01
#define RP_HTTP_V2_BUFFERED   0x02


struct rp_connection_s {
    void               *data;
    rp_event_t        *read;
    rp_event_t        *write;

    rp_socket_t        fd;

    rp_recv_pt         recv;
    rp_send_pt         send;
    rp_recv_chain_pt   recv_chain;
    rp_send_chain_pt   send_chain;

    rp_listening_t    *listening;

    off_t               sent;

    rp_log_t          *log;

    rp_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    rp_str_t           addr_text;

    rp_proxy_protocol_t  *proxy_protocol;

#if (RP_SSL || RP_COMPAT)
    rp_ssl_connection_t  *ssl;
#endif

    rp_udp_connection_t  *udp;

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    rp_buf_t          *buffer;

    rp_queue_t         queue;

    rp_atomic_uint_t   number;

    rp_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* rp_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* rp_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* rp_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (RP_HAVE_AIO_SENDFILE || RP_COMPAT)
    unsigned            busy_count:2;
#endif

#if (RP_THREADS || RP_COMPAT)
    rp_thread_task_t  *sendfile_task;
#endif
};


#define rp_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & RP_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


rp_listening_t *rp_create_listening(rp_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
rp_int_t rp_clone_listening(rp_cycle_t *cycle, rp_listening_t *ls);
rp_int_t rp_set_inherited_sockets(rp_cycle_t *cycle);
rp_int_t rp_open_listening_sockets(rp_cycle_t *cycle);
void rp_configure_listening_sockets(rp_cycle_t *cycle);
void rp_close_listening_sockets(rp_cycle_t *cycle);
void rp_close_connection(rp_connection_t *c);
void rp_close_idle_connections(rp_cycle_t *cycle);
rp_int_t rp_connection_local_sockaddr(rp_connection_t *c, rp_str_t *s,
    rp_uint_t port);
rp_int_t rp_tcp_nodelay(rp_connection_t *c);
rp_int_t rp_connection_error(rp_connection_t *c, rp_err_t err, char *text);

rp_connection_t *rp_get_connection(rp_socket_t s, rp_log_t *log);
void rp_free_connection(rp_connection_t *c);

void rp_reusable_connection(rp_connection_t *c, rp_uint_t reusable);

#endif /* _RP_CONNECTION_H_INCLUDED_ */
