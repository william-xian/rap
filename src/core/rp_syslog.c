
/*
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define RP_SYSLOG_MAX_STR                                                    \
    RP_MAX_ERROR_STR + sizeof("<255>Jan 01 00:00:00 ") - 1                   \
    + (RP_MAXHOSTNAMELEN - 1) + 1 /* space */                                \
    + 32 /* tag */ + 2 /* colon, space */


static char *rp_syslog_parse_args(rp_conf_t *cf, rp_syslog_peer_t *peer);
static rp_int_t rp_syslog_init_peer(rp_syslog_peer_t *peer);
static void rp_syslog_cleanup(void *data);


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

static rp_log_t    rp_syslog_dummy_log;
static rp_event_t  rp_syslog_dummy_event;


char *
rp_syslog_process_conf(rp_conf_t *cf, rp_syslog_peer_t *peer)
{
    rp_pool_cleanup_t  *cln;

    peer->facility = RP_CONF_UNSET_UINT;
    peer->severity = RP_CONF_UNSET_UINT;

    if (rp_syslog_parse_args(cf, peer) != RP_CONF_OK) {
        return RP_CONF_ERROR;
    }

    if (peer->server.sockaddr == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "no syslog server specified");
        return RP_CONF_ERROR;
    }

    if (peer->facility == RP_CONF_UNSET_UINT) {
        peer->facility = 23; /* local7 */
    }

    if (peer->severity == RP_CONF_UNSET_UINT) {
        peer->severity = 6; /* info */
    }

    if (peer->tag.data == NULL) {
        rp_str_set(&peer->tag, "rap");
    }

    peer->conn.fd = (rp_socket_t) -1;

    peer->conn.read = &rp_syslog_dummy_event;
    peer->conn.write = &rp_syslog_dummy_event;

    rp_syslog_dummy_event.log = &rp_syslog_dummy_log;

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RP_CONF_ERROR;
    }

    cln->data = peer;
    cln->handler = rp_syslog_cleanup;

    return RP_CONF_OK;
}


static char *
rp_syslog_parse_args(rp_conf_t *cf, rp_syslog_peer_t *peer)
{
    u_char      *p, *comma, c;
    size_t       len;
    rp_str_t   *value;
    rp_url_t    u;
    rp_uint_t   i;

    value = cf->args->elts;

    p = value[1].data + sizeof("syslog:") - 1;

    for ( ;; ) {
        comma = (u_char *) rp_strchr(p, ',');

        if (comma != NULL) {
            len = comma - p;
            *comma = '\0';

        } else {
            len = value[1].data + value[1].len - p;
        }

        if (rp_strncmp(p, "server=", 7) == 0) {

            if (peer->server.sockaddr != NULL) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"server\"");
                return RP_CONF_ERROR;
            }

            rp_memzero(&u, sizeof(rp_url_t));

            u.url.data = p + 7;
            u.url.len = len - 7;
            u.default_port = 514;

            if (rp_parse_url(cf->pool, &u) != RP_OK) {
                if (u.err) {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "%s in syslog server \"%V\"",
                                       u.err, &u.url);
                }

                return RP_CONF_ERROR;
            }

            peer->server = u.addrs[0];

        } else if (rp_strncmp(p, "facility=", 9) == 0) {

            if (peer->facility != RP_CONF_UNSET_UINT) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"facility\"");
                return RP_CONF_ERROR;
            }

            for (i = 0; facilities[i] != NULL; i++) {

                if (rp_strcmp(p + 9, facilities[i]) == 0) {
                    peer->facility = i;
                    goto next;
                }
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "unknown syslog facility \"%s\"", p + 9);
            return RP_CONF_ERROR;

        } else if (rp_strncmp(p, "severity=", 9) == 0) {

            if (peer->severity != RP_CONF_UNSET_UINT) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"severity\"");
                return RP_CONF_ERROR;
            }

            for (i = 0; severities[i] != NULL; i++) {

                if (rp_strcmp(p + 9, severities[i]) == 0) {
                    peer->severity = i;
                    goto next;
                }
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "unknown syslog severity \"%s\"", p + 9);
            return RP_CONF_ERROR;

        } else if (rp_strncmp(p, "tag=", 4) == 0) {

            if (peer->tag.data != NULL) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "duplicate syslog \"tag\"");
                return RP_CONF_ERROR;
            }

            /*
             * RFC 3164: the TAG is a string of ABNF alphanumeric characters
             * that MUST NOT exceed 32 characters.
             */
            if (len - 4 > 32) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "syslog tag length exceeds 32");
                return RP_CONF_ERROR;
            }

            for (i = 4; i < len; i++) {
                c = rp_tolower(p[i]);

                if (c < '0' || (c > '9' && c < 'a' && c != '_') || c > 'z') {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "syslog \"tag\" only allows "
                                       "alphanumeric characters "
                                       "and underscore");
                    return RP_CONF_ERROR;
                }
            }

            peer->tag.data = p + 4;
            peer->tag.len = len - 4;

        } else if (len == 10 && rp_strncmp(p, "nohostname", 10) == 0) {
            peer->nohostname = 1;

        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "unknown syslog parameter \"%s\"", p);
            return RP_CONF_ERROR;
        }

    next:

        if (comma == NULL) {
            break;
        }

        p = comma + 1;
    }

    return RP_CONF_OK;
}


u_char *
rp_syslog_add_header(rp_syslog_peer_t *peer, u_char *buf)
{
    rp_uint_t  pri;

    pri = peer->facility * 8 + peer->severity;

    if (peer->nohostname) {
        return rp_sprintf(buf, "<%ui>%V %V: ", pri, &rp_cached_syslog_time,
                           &peer->tag);
    }

    return rp_sprintf(buf, "<%ui>%V %V %V: ", pri, &rp_cached_syslog_time,
                       &rp_cycle->hostname, &peer->tag);
}


void
rp_syslog_writer(rp_log_t *log, rp_uint_t level, u_char *buf,
    size_t len)
{
    u_char             *p, msg[RP_SYSLOG_MAX_STR];
    rp_uint_t          head_len;
    rp_syslog_peer_t  *peer;

    peer = log->wdata;

    if (peer->busy) {
        return;
    }

    peer->busy = 1;
    peer->severity = level - 1;

    p = rp_syslog_add_header(peer, msg);
    head_len = p - msg;

    len -= RP_LINEFEED_SIZE;

    if (len > RP_SYSLOG_MAX_STR - head_len) {
        len = RP_SYSLOG_MAX_STR - head_len;
    }

    p = rp_snprintf(p, len, "%s", buf);

    (void) rp_syslog_send(peer, msg, p - msg);

    peer->busy = 0;
}


ssize_t
rp_syslog_send(rp_syslog_peer_t *peer, u_char *buf, size_t len)
{
    ssize_t  n;

    if (peer->conn.fd == (rp_socket_t) -1) {
        if (rp_syslog_init_peer(peer) != RP_OK) {
            return RP_ERROR;
        }
    }

    /* log syslog socket events with valid log */
    peer->conn.log = rp_cycle->log;

    if (rp_send) {
        n = rp_send(&peer->conn, buf, len);

    } else {
        /* event module has not yet set rp_io */
        n = rp_os_io.send(&peer->conn, buf, len);
    }

    if (n == RP_ERROR) {

        if (rp_close_socket(peer->conn.fd) == -1) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                          rp_close_socket_n " failed");
        }

        peer->conn.fd = (rp_socket_t) -1;
    }

    return n;
}


static rp_int_t
rp_syslog_init_peer(rp_syslog_peer_t *peer)
{
    rp_socket_t  fd;

    fd = rp_socket(peer->server.sockaddr->sa_family, SOCK_DGRAM, 0);
    if (fd == (rp_socket_t) -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                      rp_socket_n " failed");
        return RP_ERROR;
    }

    if (rp_nonblocking(fd) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                      rp_nonblocking_n " failed");
        goto failed;
    }

    if (connect(fd, peer->server.sockaddr, peer->server.socklen) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                      "connect() failed");
        goto failed;
    }

    peer->conn.fd = fd;

    /* UDP sockets are always ready to write */
    peer->conn.write->ready = 1;

    return RP_OK;

failed:

    if (rp_close_socket(fd) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                      rp_close_socket_n " failed");
    }

    return RP_ERROR;
}


static void
rp_syslog_cleanup(void *data)
{
    rp_syslog_peer_t  *peer = data;

    /* prevents further use of this peer */
    peer->busy = 1;

    if (peer->conn.fd == (rp_socket_t) -1) {
        return;
    }

    if (rp_close_socket(peer->conn.fd) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_socket_errno,
                      rp_close_socket_n " failed");
    }
}
