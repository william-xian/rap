
/*
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define RAP_SYSLOG_MAX_STR                                                    \
    RAP_MAX_ERROR_STR + sizeof("<255>Jan 01 00:00:00 ") - 1                   \
    + (RAP_MAXHOSTNAMELEN - 1) + 1 /* space */                                \
    + 32 /* tag */ + 2 /* colon, space */


static char *rap_syslog_parse_args(rap_conf_t *cf, rap_syslog_peer_t *peer);
static rap_int_t rap_syslog_init_peer(rap_syslog_peer_t *peer);
static void rap_syslog_cleanup(void *data);


static char  *facilities[] = {
    "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp",
    "clock", "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0",
    "local1", "local2", "local3", "local4", "local5", "local6", "local7",
    NULL
};

/* note 'error/warn' like in rap.conf, not 'err/warning' */
static char  *severities[] = {
    "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", NULL
};

static rap_log_t    rap_syslog_dummy_log;
static rap_event_t  rap_syslog_dummy_event;


char *
rap_syslog_process_conf(rap_conf_t *cf, rap_syslog_peer_t *peer)
{
    rap_pool_cleanup_t  *cln;

    peer->facility = RAP_CONF_UNSET_UINT;
    peer->severity = RAP_CONF_UNSET_UINT;

    if (rap_syslog_parse_args(cf, peer) != RAP_CONF_OK) {
        return RAP_CONF_ERROR;
    }

    if (peer->server.sockaddr == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "no syslog server specified");
        return RAP_CONF_ERROR;
    }

    if (peer->facility == RAP_CONF_UNSET_UINT) {
        peer->facility = 23; /* local7 */
    }

    if (peer->severity == RAP_CONF_UNSET_UINT) {
        peer->severity = 6; /* info */
    }

    if (peer->tag.data == NULL) {
        rap_str_set(&peer->tag, "rap");
    }

    peer->conn.fd = (rap_socket_t) -1;

    peer->conn.read = &rap_syslog_dummy_event;
    peer->conn.write = &rap_syslog_dummy_event;

    rap_syslog_dummy_event.log = &rap_syslog_dummy_log;

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_CONF_ERROR;
    }

    cln->data = peer;
    cln->handler = rap_syslog_cleanup;

    return RAP_CONF_OK;
}


static char *
rap_syslog_parse_args(rap_conf_t *cf, rap_syslog_peer_t *peer)
{
    u_char      *p, *comma, c;
    size_t       len;
    rap_str_t   *value;
    rap_url_t    u;
    rap_uint_t   i;

    value = cf->args->elts;

    p = value[1].data + sizeof("syslog:") - 1;

    for ( ;; ) {
        comma = (u_char *) rap_strchr(p, ',');

        if (comma != NULL) {
            len = comma - p;
            *comma = '\0';

        } else {
            len = value[1].data + value[1].len - p;
        }

        if (rap_strncmp(p, "server=", 7) == 0) {

            if (peer->server.sockaddr != NULL) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"server\"");
                return RAP_CONF_ERROR;
            }

            rap_memzero(&u, sizeof(rap_url_t));

            u.url.data = p + 7;
            u.url.len = len - 7;
            u.default_port = 514;

            if (rap_parse_url(cf->pool, &u) != RAP_OK) {
                if (u.err) {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "%s in syslog server \"%V\"",
                                       u.err, &u.url);
                }

                return RAP_CONF_ERROR;
            }

            peer->server = u.addrs[0];

        } else if (rap_strncmp(p, "facility=", 9) == 0) {

            if (peer->facility != RAP_CONF_UNSET_UINT) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"facility\"");
                return RAP_CONF_ERROR;
            }

            for (i = 0; facilities[i] != NULL; i++) {

                if (rap_strcmp(p + 9, facilities[i]) == 0) {
                    peer->facility = i;
                    goto next;
                }
            }

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "unknown syslog facility \"%s\"", p + 9);
            return RAP_CONF_ERROR;

        } else if (rap_strncmp(p, "severity=", 9) == 0) {

            if (peer->severity != RAP_CONF_UNSET_UINT) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"severity\"");
                return RAP_CONF_ERROR;
            }

            for (i = 0; severities[i] != NULL; i++) {

                if (rap_strcmp(p + 9, severities[i]) == 0) {
                    peer->severity = i;
                    goto next;
                }
            }

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "unknown syslog severity \"%s\"", p + 9);
            return RAP_CONF_ERROR;

        } else if (rap_strncmp(p, "tag=", 4) == 0) {

            if (peer->tag.data != NULL) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"tag\"");
                return RAP_CONF_ERROR;
            }

            /*
             * RFC 3164: the TAG is a string of ABNF alphanumeric characters
             * that MUST NOT exceed 32 characters.
             */
            if (len - 4 > 32) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "syslog tag length exceeds 32");
                return RAP_CONF_ERROR;
            }

            for (i = 4; i < len; i++) {
                c = rap_tolower(p[i]);

                if (c < '0' || (c > '9' && c < 'a' && c != '_') || c > 'z') {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "syslog \"tag\" only allows "
                                       "alphanumeric characters "
                                       "and underscore");
                    return RAP_CONF_ERROR;
                }
            }

            peer->tag.data = p + 4;
            peer->tag.len = len - 4;

        } else if (len == 10 && rap_strncmp(p, "nohostname", 10) == 0) {
            peer->nohostname = 1;

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "unknown syslog parameter \"%s\"", p);
            return RAP_CONF_ERROR;
        }

    next:

        if (comma == NULL) {
            break;
        }

        p = comma + 1;
    }

    return RAP_CONF_OK;
}


u_char *
rap_syslog_add_header(rap_syslog_peer_t *peer, u_char *buf)
{
    rap_uint_t  pri;

    pri = peer->facility * 8 + peer->severity;

    if (peer->nohostname) {
        return rap_sprintf(buf, "<%ui>%V %V: ", pri, &rap_cached_syslog_time,
                           &peer->tag);
    }

    return rap_sprintf(buf, "<%ui>%V %V %V: ", pri, &rap_cached_syslog_time,
                       &rap_cycle->hostname, &peer->tag);
}


void
rap_syslog_writer(rap_log_t *log, rap_uint_t level, u_char *buf,
    size_t len)
{
    u_char             *p, msg[RAP_SYSLOG_MAX_STR];
    rap_uint_t          head_len;
    rap_syslog_peer_t  *peer;

    peer = log->wdata;

    if (peer->busy) {
        return;
    }

    peer->busy = 1;
    peer->severity = level - 1;

    p = rap_syslog_add_header(peer, msg);
    head_len = p - msg;

    len -= RAP_LINEFEED_SIZE;

    if (len > RAP_SYSLOG_MAX_STR - head_len) {
        len = RAP_SYSLOG_MAX_STR - head_len;
    }

    p = rap_snprintf(p, len, "%s", buf);

    (void) rap_syslog_send(peer, msg, p - msg);

    peer->busy = 0;
}


ssize_t
rap_syslog_send(rap_syslog_peer_t *peer, u_char *buf, size_t len)
{
    ssize_t  n;

    if (peer->conn.fd == (rap_socket_t) -1) {
        if (rap_syslog_init_peer(peer) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    /* log syslog socket events with valid log */
    peer->conn.log = rap_cycle->log;

    if (rap_send) {
        n = rap_send(&peer->conn, buf, len);

    } else {
        /* event module has not yet set rap_io */
        n = rap_os_io.send(&peer->conn, buf, len);
    }

    if (n == RAP_ERROR) {

        if (rap_close_socket(peer->conn.fd) == -1) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                          rap_close_socket_n " failed");
        }

        peer->conn.fd = (rap_socket_t) -1;
    }

    return n;
}


static rap_int_t
rap_syslog_init_peer(rap_syslog_peer_t *peer)
{
    rap_socket_t  fd;

    fd = rap_socket(peer->server.sockaddr->sa_family, SOCK_DGRAM, 0);
    if (fd == (rap_socket_t) -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                      rap_socket_n " failed");
        return RAP_ERROR;
    }

    if (rap_nonblocking(fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                      rap_nonblocking_n " failed");
        goto failed;
    }

    if (connect(fd, peer->server.sockaddr, peer->server.socklen) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                      "connect() failed");
        goto failed;
    }

    peer->conn.fd = fd;

    /* UDP sockets are always ready to write */
    peer->conn.write->ready = 1;

    return RAP_OK;

failed:

    if (rap_close_socket(fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                      rap_close_socket_n " failed");
    }

    return RAP_ERROR;
}


static void
rap_syslog_cleanup(void *data)
{
    rap_syslog_peer_t  *peer = data;

    /* prevents further use of this peer */
    peer->busy = 1;

    if (peer->conn.fd == (rap_socket_t) -1) {
        return;
    }

    if (rap_close_socket(peer->conn.fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_socket_errno,
                      rap_close_socket_n " failed");
    }
}
