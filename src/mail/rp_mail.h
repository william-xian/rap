
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_MAIL_H_INCLUDED_
#define _RP_MAIL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_event_connect.h>

#if (RP_MAIL_SSL)
#include <rp_mail_ssl_module.h>
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} rp_mail_conf_ctx_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;
    rp_str_t               addr_text;

    /* server ctx */
    rp_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                ssl:1;
#if (RP_HAVE_INET6)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
#if (RP_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;
    int                     rcvbuf;
    int                     sndbuf;
} rp_mail_listen_t;


typedef struct {
    rp_mail_conf_ctx_t    *ctx;
    rp_str_t               addr_text;
    rp_uint_t              ssl;    /* unsigned   ssl:1; */
} rp_mail_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    rp_mail_addr_conf_t    conf;
} rp_mail_in_addr_t;


#if (RP_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    rp_mail_addr_conf_t    conf;
} rp_mail_in6_addr_t;

#endif


typedef struct {
    /* rp_mail_in_addr_t or rp_mail_in6_addr_t */
    void                   *addrs;
    rp_uint_t              naddrs;
} rp_mail_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    rp_array_t             addrs;       /* array of rp_mail_conf_addr_t */
} rp_mail_conf_port_t;


typedef struct {
    rp_mail_listen_t       opt;
} rp_mail_conf_addr_t;


typedef struct {
    rp_array_t             servers;     /* rp_mail_core_srv_conf_t */
    rp_array_t             listen;      /* rp_mail_listen_t */
} rp_mail_core_main_conf_t;


#define RP_MAIL_POP3_PROTOCOL  0
#define RP_MAIL_IMAP_PROTOCOL  1
#define RP_MAIL_SMTP_PROTOCOL  2


typedef struct rp_mail_protocol_s  rp_mail_protocol_t;


typedef struct {
    rp_mail_protocol_t    *protocol;

    rp_msec_t              timeout;
    rp_msec_t              resolver_timeout;

    rp_str_t               server_name;

    u_char                 *file_name;
    rp_uint_t              line;

    rp_resolver_t         *resolver;
    rp_log_t              *error_log;

    /* server ctx */
    rp_mail_conf_ctx_t    *ctx;

    rp_uint_t              listen;  /* unsigned  listen:1; */
} rp_mail_core_srv_conf_t;


typedef enum {
    rp_pop3_start = 0,
    rp_pop3_user,
    rp_pop3_passwd,
    rp_pop3_auth_login_username,
    rp_pop3_auth_login_password,
    rp_pop3_auth_plain,
    rp_pop3_auth_cram_md5,
    rp_pop3_auth_external
} rp_pop3_state_e;


typedef enum {
    rp_imap_start = 0,
    rp_imap_auth_login_username,
    rp_imap_auth_login_password,
    rp_imap_auth_plain,
    rp_imap_auth_cram_md5,
    rp_imap_auth_external,
    rp_imap_login,
    rp_imap_user,
    rp_imap_passwd
} rp_imap_state_e;


typedef enum {
    rp_smtp_start = 0,
    rp_smtp_auth_login_username,
    rp_smtp_auth_login_password,
    rp_smtp_auth_plain,
    rp_smtp_auth_cram_md5,
    rp_smtp_auth_external,
    rp_smtp_helo,
    rp_smtp_helo_xclient,
    rp_smtp_helo_from,
    rp_smtp_xclient,
    rp_smtp_xclient_from,
    rp_smtp_xclient_helo,
    rp_smtp_from,
    rp_smtp_to
} rp_smtp_state_e;


typedef struct {
    rp_peer_connection_t   upstream;
    rp_buf_t              *buffer;
} rp_mail_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "MAIL" */

    rp_connection_t       *connection;

    rp_str_t               out;
    rp_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    rp_resolver_ctx_t     *resolver_ctx;

    rp_mail_proxy_ctx_t   *proxy;

    rp_uint_t              mail_state;

    unsigned                protocol:3;
    unsigned                blocked:1;
    unsigned                quit:1;
    unsigned                quoted:1;
    unsigned                backslash:1;
    unsigned                no_sync_literal:1;
    unsigned                starttls:1;
    unsigned                esmtp:1;
    unsigned                auth_method:3;
    unsigned                auth_wait:1;

    rp_str_t               login;
    rp_str_t               passwd;

    rp_str_t               salt;
    rp_str_t               tag;
    rp_str_t               tagged_line;
    rp_str_t               text;

    rp_str_t              *addr_text;
    rp_str_t               host;
    rp_str_t               smtp_helo;
    rp_str_t               smtp_from;
    rp_str_t               smtp_to;

    rp_str_t               cmd;

    rp_uint_t              command;
    rp_array_t             args;

    rp_uint_t              login_attempt;

    /* used to parse POP3/IMAP/SMTP command */

    rp_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    rp_uint_t              literal_len;
} rp_mail_session_t;


typedef struct {
    rp_str_t              *client;
    rp_mail_session_t     *session;
} rp_mail_log_ctx_t;


#define RP_POP3_USER          1
#define RP_POP3_PASS          2
#define RP_POP3_CAPA          3
#define RP_POP3_QUIT          4
#define RP_POP3_NOOP          5
#define RP_POP3_STLS          6
#define RP_POP3_APOP          7
#define RP_POP3_AUTH          8
#define RP_POP3_STAT          9
#define RP_POP3_LIST          10
#define RP_POP3_RETR          11
#define RP_POP3_DELE          12
#define RP_POP3_RSET          13
#define RP_POP3_TOP           14
#define RP_POP3_UIDL          15


#define RP_IMAP_LOGIN         1
#define RP_IMAP_LOGOUT        2
#define RP_IMAP_CAPABILITY    3
#define RP_IMAP_NOOP          4
#define RP_IMAP_STARTTLS      5

#define RP_IMAP_NEXT          6

#define RP_IMAP_AUTHENTICATE  7


#define RP_SMTP_HELO          1
#define RP_SMTP_EHLO          2
#define RP_SMTP_AUTH          3
#define RP_SMTP_QUIT          4
#define RP_SMTP_NOOP          5
#define RP_SMTP_MAIL          6
#define RP_SMTP_RSET          7
#define RP_SMTP_RCPT          8
#define RP_SMTP_DATA          9
#define RP_SMTP_VRFY          10
#define RP_SMTP_EXPN          11
#define RP_SMTP_HELP          12
#define RP_SMTP_STARTTLS      13


#define RP_MAIL_AUTH_PLAIN             0
#define RP_MAIL_AUTH_LOGIN             1
#define RP_MAIL_AUTH_LOGIN_USERNAME    2
#define RP_MAIL_AUTH_APOP              3
#define RP_MAIL_AUTH_CRAM_MD5          4
#define RP_MAIL_AUTH_EXTERNAL          5
#define RP_MAIL_AUTH_NONE              6


#define RP_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define RP_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define RP_MAIL_AUTH_APOP_ENABLED      0x0008
#define RP_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define RP_MAIL_AUTH_EXTERNAL_ENABLED  0x0020
#define RP_MAIL_AUTH_NONE_ENABLED      0x0040


#define RP_MAIL_PARSE_INVALID_COMMAND  20


typedef void (*rp_mail_init_session_pt)(rp_mail_session_t *s,
    rp_connection_t *c);
typedef void (*rp_mail_init_protocol_pt)(rp_event_t *rev);
typedef void (*rp_mail_auth_state_pt)(rp_event_t *rev);
typedef rp_int_t (*rp_mail_parse_command_pt)(rp_mail_session_t *s);


struct rp_mail_protocol_s {
    rp_str_t                   name;
    in_port_t                   port[4];
    rp_uint_t                  type;

    rp_mail_init_session_pt    init_session;
    rp_mail_init_protocol_pt   init_protocol;
    rp_mail_parse_command_pt   parse_command;
    rp_mail_auth_state_pt      auth_state;

    rp_str_t                   internal_server_error;
    rp_str_t                   cert_error;
    rp_str_t                   no_cert;
};


typedef struct {
    rp_mail_protocol_t        *protocol;

    void                       *(*create_main_conf)(rp_conf_t *cf);
    char                       *(*init_main_conf)(rp_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(rp_conf_t *cf);
    char                       *(*merge_srv_conf)(rp_conf_t *cf, void *prev,
                                                  void *conf);
} rp_mail_module_t;


#define RP_MAIL_MODULE         0x4C49414D     /* "MAIL" */

#define RP_MAIL_MAIN_CONF      0x02000000
#define RP_MAIL_SRV_CONF       0x04000000


#define RP_MAIL_MAIN_CONF_OFFSET  offsetof(rp_mail_conf_ctx_t, main_conf)
#define RP_MAIL_SRV_CONF_OFFSET   offsetof(rp_mail_conf_ctx_t, srv_conf)


#define rp_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define rp_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define rp_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define rp_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define rp_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define rp_mail_conf_get_module_main_conf(cf, module)                       \
    ((rp_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define rp_mail_conf_get_module_srv_conf(cf, module)                        \
    ((rp_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (RP_MAIL_SSL)
void rp_mail_starttls_handler(rp_event_t *rev);
rp_int_t rp_mail_starttls_only(rp_mail_session_t *s, rp_connection_t *c);
#endif


void rp_mail_init_connection(rp_connection_t *c);

rp_int_t rp_mail_salt(rp_mail_session_t *s, rp_connection_t *c,
    rp_mail_core_srv_conf_t *cscf);
rp_int_t rp_mail_auth_plain(rp_mail_session_t *s, rp_connection_t *c,
    rp_uint_t n);
rp_int_t rp_mail_auth_login_username(rp_mail_session_t *s,
    rp_connection_t *c, rp_uint_t n);
rp_int_t rp_mail_auth_login_password(rp_mail_session_t *s,
    rp_connection_t *c);
rp_int_t rp_mail_auth_cram_md5_salt(rp_mail_session_t *s,
    rp_connection_t *c, char *prefix, size_t len);
rp_int_t rp_mail_auth_cram_md5(rp_mail_session_t *s, rp_connection_t *c);
rp_int_t rp_mail_auth_external(rp_mail_session_t *s, rp_connection_t *c,
    rp_uint_t n);
rp_int_t rp_mail_auth_parse(rp_mail_session_t *s, rp_connection_t *c);

void rp_mail_send(rp_event_t *wev);
rp_int_t rp_mail_read_command(rp_mail_session_t *s, rp_connection_t *c);
void rp_mail_auth(rp_mail_session_t *s, rp_connection_t *c);
void rp_mail_close_connection(rp_connection_t *c);
void rp_mail_session_internal_server_error(rp_mail_session_t *s);
u_char *rp_mail_log_error(rp_log_t *log, u_char *buf, size_t len);


char *rp_mail_capabilities(rp_conf_t *cf, rp_command_t *cmd, void *conf);


/* STUB */
void rp_mail_proxy_init(rp_mail_session_t *s, rp_addr_t *peer);
void rp_mail_auth_http_init(rp_mail_session_t *s);
/**/


extern rp_uint_t    rp_mail_max_module;
extern rp_module_t  rp_mail_core_module;


#endif /* _RP_MAIL_H_INCLUDED_ */
