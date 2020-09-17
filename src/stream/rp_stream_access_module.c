
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    rp_uint_t        deny;      /* unsigned  deny:1; */
} rp_stream_access_rule_t;

#if (RP_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    rp_uint_t        deny;      /* unsigned  deny:1; */
} rp_stream_access_rule6_t;

#endif

#if (RP_HAVE_UNIX_DOMAIN)

typedef struct {
    rp_uint_t        deny;      /* unsigned  deny:1; */
} rp_stream_access_rule_un_t;

#endif

typedef struct {
    rp_array_t      *rules;     /* array of rp_stream_access_rule_t */
#if (RP_HAVE_INET6)
    rp_array_t      *rules6;    /* array of rp_stream_access_rule6_t */
#endif
#if (RP_HAVE_UNIX_DOMAIN)
    rp_array_t      *rules_un;  /* array of rp_stream_access_rule_un_t */
#endif
} rp_stream_access_srv_conf_t;


static rp_int_t rp_stream_access_handler(rp_stream_session_t *s);
static rp_int_t rp_stream_access_inet(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf, in_addr_t addr);
#if (RP_HAVE_INET6)
static rp_int_t rp_stream_access_inet6(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf, u_char *p);
#endif
#if (RP_HAVE_UNIX_DOMAIN)
static rp_int_t rp_stream_access_unix(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf);
#endif
static rp_int_t rp_stream_access_found(rp_stream_session_t *s,
    rp_uint_t deny);
static char *rp_stream_access_rule(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static void *rp_stream_access_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_access_merge_srv_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_stream_access_init(rp_conf_t *cf);


static rp_command_t  rp_stream_access_commands[] = {

    { rp_string("allow"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_access_rule,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("deny"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_access_rule,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};



static rp_stream_module_t  rp_stream_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_stream_access_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_access_create_srv_conf,     /* create server configuration */
    rp_stream_access_merge_srv_conf       /* merge server configuration */
};


rp_module_t  rp_stream_access_module = {
    RP_MODULE_V1,
    &rp_stream_access_module_ctx,         /* module context */
    rp_stream_access_commands,            /* module directives */
    RP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_stream_access_handler(rp_stream_session_t *s)
{
    struct sockaddr_in            *sin;
    rp_stream_access_srv_conf_t  *ascf;
#if (RP_HAVE_INET6)
    u_char                        *p;
    in_addr_t                      addr;
    struct sockaddr_in6           *sin6;
#endif

    ascf = rp_stream_get_module_srv_conf(s, rp_stream_access_module);

    switch (s->connection->sockaddr->sa_family) {

    case AF_INET:
        if (ascf->rules) {
            sin = (struct sockaddr_in *) s->connection->sockaddr;
            return rp_stream_access_inet(s, ascf, sin->sin_addr.s_addr);
        }
        break;

#if (RP_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (ascf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return rp_stream_access_inet(s, ascf, htonl(addr));
        }

        if (ascf->rules6) {
            return rp_stream_access_inet6(s, ascf, p);
        }

        break;

#endif

#if (RP_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (ascf->rules_un) {
            return rp_stream_access_unix(s, ascf);
        }

        break;

#endif
    }

    return RP_DECLINED;
}


static rp_int_t
rp_stream_access_inet(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf, in_addr_t addr)
{
    rp_uint_t                 i;
    rp_stream_access_rule_t  *rule;

    rule = ascf->rules->elts;
    for (i = 0; i < ascf->rules->nelts; i++) {

        rp_log_debug3(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr) {
            return rp_stream_access_found(s, rule[i].deny);
        }
    }

    return RP_DECLINED;
}


#if (RP_HAVE_INET6)

static rp_int_t
rp_stream_access_inet6(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf, u_char *p)
{
    rp_uint_t                  n;
    rp_uint_t                  i;
    rp_stream_access_rule6_t  *rule6;

    rule6 = ascf->rules6->elts;
    for (i = 0; i < ascf->rules6->nelts; i++) {

#if (RP_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[RP_INET6_ADDRSTRLEN];
        u_char  mt[RP_INET6_ADDRSTRLEN];
        u_char  at[RP_INET6_ADDRSTRLEN];

        cl = rp_inet6_ntop(p, ct, RP_INET6_ADDRSTRLEN);
        ml = rp_inet6_ntop(rule6[i].mask.s6_addr, mt, RP_INET6_ADDRSTRLEN);
        al = rp_inet6_ntop(rule6[i].addr.s6_addr, at, RP_INET6_ADDRSTRLEN);

        rp_log_debug6(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return rp_stream_access_found(s, rule6[i].deny);

    next:
        continue;
    }

    return RP_DECLINED;
}

#endif


#if (RP_HAVE_UNIX_DOMAIN)

static rp_int_t
rp_stream_access_unix(rp_stream_session_t *s,
    rp_stream_access_srv_conf_t *ascf)
{
    rp_uint_t                    i;
    rp_stream_access_rule_un_t  *rule_un;

    rule_un = ascf->rules_un->elts;
    for (i = 0; i < ascf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return rp_stream_access_found(s, rule_un[i].deny);
        }
    }

    return RP_DECLINED;
}

#endif


static rp_int_t
rp_stream_access_found(rp_stream_session_t *s, rp_uint_t deny)
{
    if (deny) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "access forbidden by rule");
        return RP_STREAM_FORBIDDEN;
    }

    return RP_OK;
}


static char *
rp_stream_access_rule(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_access_srv_conf_t *ascf = conf;

    rp_int_t                     rc;
    rp_uint_t                    all;
    rp_str_t                    *value;
    rp_cidr_t                    cidr;
    rp_stream_access_rule_t     *rule;
#if (RP_HAVE_INET6)
    rp_stream_access_rule6_t    *rule6;
#endif
#if (RP_HAVE_UNIX_DOMAIN)
    rp_stream_access_rule_un_t  *rule_un;
#endif

    all = 0;
    rp_memzero(&cidr, sizeof(rp_cidr_t));

    value = cf->args->elts;

    if (value[1].len == 3 && rp_strcmp(value[1].data, "all") == 0) {
        all = 1;

#if (RP_HAVE_UNIX_DOMAIN)
    } else if (value[1].len == 5 && rp_strcmp(value[1].data, "unix:") == 0) {
        cidr.family = AF_UNIX;
#endif

    } else {
        rc = rp_ptocidr(&value[1], &cidr);

        if (rc == RP_ERROR) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        if (rc == RP_DONE) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    if (cidr.family == AF_INET || all) {

        if (ascf->rules == NULL) {
            ascf->rules = rp_array_create(cf->pool, 4,
                                           sizeof(rp_stream_access_rule_t));
            if (ascf->rules == NULL) {
                return RP_CONF_ERROR;
            }
        }

        rule = rp_array_push(ascf->rules);
        if (rule == NULL) {
            return RP_CONF_ERROR;
        }

        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }

#if (RP_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (ascf->rules6 == NULL) {
            ascf->rules6 = rp_array_create(cf->pool, 4,
                                            sizeof(rp_stream_access_rule6_t));
            if (ascf->rules6 == NULL) {
                return RP_CONF_ERROR;
            }
        }

        rule6 = rp_array_push(ascf->rules6);
        if (rule6 == NULL) {
            return RP_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

#if (RP_HAVE_UNIX_DOMAIN)
    if (cidr.family == AF_UNIX || all) {

        if (ascf->rules_un == NULL) {
            ascf->rules_un = rp_array_create(cf->pool, 1,
                                          sizeof(rp_stream_access_rule_un_t));
            if (ascf->rules_un == NULL) {
                return RP_CONF_ERROR;
            }
        }

        rule_un = rp_array_push(ascf->rules_un);
        if (rule_un == NULL) {
            return RP_CONF_ERROR;
        }

        rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return RP_CONF_OK;
}


static void *
rp_stream_access_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_access_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_access_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rp_stream_access_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_access_srv_conf_t  *prev = parent;
    rp_stream_access_srv_conf_t  *conf = child;

    if (conf->rules == NULL
#if (RP_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (RP_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (RP_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (RP_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_stream_access_init(rp_conf_t *cf)
{
    rp_stream_handler_pt        *h;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    h = rp_array_push(&cmcf->phases[RP_STREAM_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_stream_access_handler;

    return RP_OK;
}
