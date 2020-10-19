
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_MAIL_H_INCLUDED_
#define _RAP_MAIL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_connect.h>

#if (RAP_MAIL_SSL)
#include <rap_mail_ssl_module.h>
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} rap_mail_conf_ctx_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;
    rap_str_t               addr_text;

    /* server ctx */
    rap_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
    unsigned                ssl:1;
#if (RAP_HAVE_INET6)
    unsigned                ipv6only:1;
#endif
    unsigned                so_keepalive:2;
#if (RAP_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;
    int                     rcvbuf;
    int                     sndbuf;
} rap_mail_listen_t;


typedef struct {
    rap_mail_conf_ctx_t    *ctx;
    rap_str_t               addr_text;
    rap_uint_t              ssl;    /* unsigned   ssl:1; */
} rap_mail_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    rap_mail_addr_conf_t    conf;
} rap_mail_in_addr_t;


#if (RAP_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    rap_mail_addr_conf_t    conf;
} rap_mail_in6_addr_t;

#endif


typedef struct {
    /* rap_mail_in_addr_t or rap_mail_in6_addr_t */
    void                   *addrs;
    rap_uint_t              naddrs;
} rap_mail_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    rap_array_t             addrs;       /* array of rap_mail_conf_addr_t */
} rap_mail_conf_port_t;


typedef struct {
    rap_mail_listen_t       opt;
} rap_mail_conf_addr_t;


typedef struct {
    rap_array_t             servers;     /* rap_mail_core_srv_conf_t */
    rap_array_t             listen;      /* rap_mail_listen_t */
} rap_mail_core_main_conf_t;


#define RAP_MAIL_POP3_PROTOCOL  0
#define RAP_MAIL_IMAP_PROTOCOL  1
#define RAP_MAIL_SMTP_PROTOCOL  2


typedef struct rap_mail_protocol_s  rap_mail_protocol_t;


typedef struct {
    rap_mail_protocol_t    *protocol;

    rap_msec_t              timeout;
    rap_msec_t              resolver_timeout;

    rap_str_t               server_name;

    u_char                 *file_name;
    rap_uint_t              line;

    rap_resolver_t         *resolver;
    rap_log_t              *error_log;

    /* server ctx */
    rap_mail_conf_ctx_t    *ctx;

    rap_uint_t              listen;  /* unsigned  listen:1; */
} rap_mail_core_srv_conf_t;


typedef enum {
    rap_pop3_start = 0,
    rap_pop3_user,
    rap_pop3_passwd,
    rap_pop3_auth_login_username,
    rap_pop3_auth_login_password,
    rap_pop3_auth_plain,
    rap_pop3_auth_cram_md5,
    rap_pop3_auth_external
} rap_pop3_state_e;


typedef enum {
    rap_imap_start = 0,
    rap_imap_auth_login_username,
    rap_imap_auth_login_password,
    rap_imap_auth_plain,
    rap_imap_auth_cram_md5,
    rap_imap_auth_external,
    rap_imap_login,
    rap_imap_user,
    rap_imap_passwd
} rap_imap_state_e;


typedef enum {
    rap_smtp_start = 0,
    rap_smtp_auth_login_username,
    rap_smtp_auth_login_password,
    rap_smtp_auth_plain,
    rap_smtp_auth_cram_md5,
    rap_smtp_auth_external,
    rap_smtp_helo,
    rap_smtp_helo_xclient,
    rap_smtp_helo_from,
    rap_smtp_xclient,
    rap_smtp_xclient_from,
    rap_smtp_xclient_helo,
    rap_smtp_from,
    rap_smtp_to
} rap_smtp_state_e;


typedef struct {
    rap_peer_connection_t   upstream;
    rap_buf_t              *buffer;
} rap_mail_proxy_ctx_t;


typedef struct {
    uint32_t                signature;         /* "MAIL" */

    rap_connection_t       *connection;

    rap_str_t               out;
    rap_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    rap_resolver_ctx_t     *resolver_ctx;

    rap_mail_proxy_ctx_t   *proxy;

    rap_uint_t              mail_state;

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

    rap_str_t               login;
    rap_str_t               passwd;

    rap_str_t               salt;
    rap_str_t               tag;
    rap_str_t               tagged_line;
    rap_str_t               text;

    rap_str_t              *addr_text;
    rap_str_t               host;
    rap_str_t               smtp_helo;
    rap_str_t               smtp_from;
    rap_str_t               smtp_to;

    rap_str_t               cmd;

    rap_uint_t              command;
    rap_array_t             args;

    rap_uint_t              login_attempt;

    /* used to parse POP3/IMAP/SMTP command */

    rap_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    rap_uint_t              literal_len;
} rap_mail_session_t;


typedef struct {
    rap_str_t              *client;
    rap_mail_session_t     *session;
} rap_mail_log_ctx_t;


#define RAP_POP3_USER          1
#define RAP_POP3_PASS          2
#define RAP_POP3_CAPA          3
#define RAP_POP3_QUIT          4
#define RAP_POP3_NOOP          5
#define RAP_POP3_STLS          6
#define RAP_POP3_APOP          7
#define RAP_POP3_AUTH          8
#define RAP_POP3_STAT          9
#define RAP_POP3_LIST          10
#define RAP_POP3_RETR          11
#define RAP_POP3_DELE          12
#define RAP_POP3_RSET          13
#define RAP_POP3_TOP           14
#define RAP_POP3_UIDL          15


#define RAP_IMAP_LOGIN         1
#define RAP_IMAP_LOGOUT        2
#define RAP_IMAP_CAPABILITY    3
#define RAP_IMAP_NOOP          4
#define RAP_IMAP_STARTTLS      5

#define RAP_IMAP_NEXT          6

#define RAP_IMAP_AUTHENTICATE  7


#define RAP_SMTP_HELO          1
#define RAP_SMTP_EHLO          2
#define RAP_SMTP_AUTH          3
#define RAP_SMTP_QUIT          4
#define RAP_SMTP_NOOP          5
#define RAP_SMTP_MAIL          6
#define RAP_SMTP_RSET          7
#define RAP_SMTP_RCPT          8
#define RAP_SMTP_DATA          9
#define RAP_SMTP_VRFY          10
#define RAP_SMTP_EXPN          11
#define RAP_SMTP_HELP          12
#define RAP_SMTP_STARTTLS      13


#define RAP_MAIL_AUTH_PLAIN             0
#define RAP_MAIL_AUTH_LOGIN             1
#define RAP_MAIL_AUTH_LOGIN_USERNAME    2
#define RAP_MAIL_AUTH_APOP              3
#define RAP_MAIL_AUTH_CRAM_MD5          4
#define RAP_MAIL_AUTH_EXTERNAL          5
#define RAP_MAIL_AUTH_NONE              6


#define RAP_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define RAP_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define RAP_MAIL_AUTH_APOP_ENABLED      0x0008
#define RAP_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define RAP_MAIL_AUTH_EXTERNAL_ENABLED  0x0020
#define RAP_MAIL_AUTH_NONE_ENABLED      0x0040


#define RAP_MAIL_PARSE_INVALID_COMMAND  20


typedef void (*rap_mail_init_session_pt)(rap_mail_session_t *s,
    rap_connection_t *c);
typedef void (*rap_mail_init_protocol_pt)(rap_event_t *rev);
typedef void (*rap_mail_auth_state_pt)(rap_event_t *rev);
typedef rap_int_t (*rap_mail_parse_command_pt)(rap_mail_session_t *s);


struct rap_mail_protocol_s {
    rap_str_t                   name;
    in_port_t                   port[4];
    rap_uint_t                  type;

    rap_mail_init_session_pt    init_session;
    rap_mail_init_protocol_pt   init_protocol;
    rap_mail_parse_command_pt   parse_command;
    rap_mail_auth_state_pt      auth_state;

    rap_str_t                   internal_server_error;
    rap_str_t                   cert_error;
    rap_str_t                   no_cert;
};


typedef struct {
    rap_mail_protocol_t        *protocol;

    void                       *(*create_main_conf)(rap_conf_t *cf);
    char                       *(*init_main_conf)(rap_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(rap_conf_t *cf);
    char                       *(*merge_srv_conf)(rap_conf_t *cf, void *prev,
                                                  void *conf);
} rap_mail_module_t;


#define RAP_MAIL_MODULE         0x4C49414D     /* "MAIL" */

#define RAP_MAIL_MAIN_CONF      0x02000000
#define RAP_MAIL_SRV_CONF       0x04000000


#define RAP_MAIL_MAIN_CONF_OFFSET  offsetof(rap_mail_conf_ctx_t, main_conf)
#define RAP_MAIL_SRV_CONF_OFFSET   offsetof(rap_mail_conf_ctx_t, srv_conf)


#define rap_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define rap_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define rap_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define rap_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define rap_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define rap_mail_conf_get_module_main_conf(cf, module)                       \
    ((rap_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define rap_mail_conf_get_module_srv_conf(cf, module)                        \
    ((rap_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (RAP_MAIL_SSL)
void rap_mail_starttls_handler(rap_event_t *rev);
rap_int_t rap_mail_starttls_only(rap_mail_session_t *s, rap_connection_t *c);
#endif


void rap_mail_init_connection(rap_connection_t *c);

rap_int_t rap_mail_salt(rap_mail_session_t *s, rap_connection_t *c,
    rap_mail_core_srv_conf_t *cscf);
rap_int_t rap_mail_auth_plain(rap_mail_session_t *s, rap_connection_t *c,
    rap_uint_t n);
rap_int_t rap_mail_auth_login_username(rap_mail_session_t *s,
    rap_connection_t *c, rap_uint_t n);
rap_int_t rap_mail_auth_login_password(rap_mail_session_t *s,
    rap_connection_t *c);
rap_int_t rap_mail_auth_cram_md5_salt(rap_mail_session_t *s,
    rap_connection_t *c, char *prefix, size_t len);
rap_int_t rap_mail_auth_cram_md5(rap_mail_session_t *s, rap_connection_t *c);
rap_int_t rap_mail_auth_external(rap_mail_session_t *s, rap_connection_t *c,
    rap_uint_t n);
rap_int_t rap_mail_auth_parse(rap_mail_session_t *s, rap_connection_t *c);

void rap_mail_send(rap_event_t *wev);
rap_int_t rap_mail_read_command(rap_mail_session_t *s, rap_connection_t *c);
void rap_mail_auth(rap_mail_session_t *s, rap_connection_t *c);
void rap_mail_close_connection(rap_connection_t *c);
void rap_mail_session_internal_server_error(rap_mail_session_t *s);
u_char *rap_mail_log_error(rap_log_t *log, u_char *buf, size_t len);


char *rap_mail_capabilities(rap_conf_t *cf, rap_command_t *cmd, void *conf);


/* STUB */
void rap_mail_proxy_init(rap_mail_session_t *s, rap_addr_t *peer);
void rap_mail_auth_http_init(rap_mail_session_t *s);
/**/


extern rap_uint_t    rap_mail_max_module;
extern rap_module_t  rap_mail_core_module;


#endif /* _RAP_MAIL_H_INCLUDED_ */
