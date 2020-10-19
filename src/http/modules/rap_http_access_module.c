
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    rap_uint_t        deny;      /* unsigned  deny:1; */
} rap_http_access_rule_t;

#if (RAP_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    rap_uint_t        deny;      /* unsigned  deny:1; */
} rap_http_access_rule6_t;

#endif

#if (RAP_HAVE_UNIX_DOMAIN)

typedef struct {
    rap_uint_t        deny;      /* unsigned  deny:1; */
} rap_http_access_rule_un_t;

#endif

typedef struct {
    rap_array_t      *rules;     /* array of rap_http_access_rule_t */
#if (RAP_HAVE_INET6)
    rap_array_t      *rules6;    /* array of rap_http_access_rule6_t */
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    rap_array_t      *rules_un;  /* array of rap_http_access_rule_un_t */
#endif
} rap_http_access_loc_conf_t;


static rap_int_t rap_http_access_handler(rap_http_request_t *r);
static rap_int_t rap_http_access_inet(rap_http_request_t *r,
    rap_http_access_loc_conf_t *alcf, in_addr_t addr);
#if (RAP_HAVE_INET6)
static rap_int_t rap_http_access_inet6(rap_http_request_t *r,
    rap_http_access_loc_conf_t *alcf, u_char *p);
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
static rap_int_t rap_http_access_unix(rap_http_request_t *r,
    rap_http_access_loc_conf_t *alcf);
#endif
static rap_int_t rap_http_access_found(rap_http_request_t *r, rap_uint_t deny);
static char *rap_http_access_rule(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static void *rap_http_access_create_loc_conf(rap_conf_t *cf);
static char *rap_http_access_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_access_init(rap_conf_t *cf);


static rap_command_t  rap_http_access_commands[] = {

    { rap_string("allow"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LMT_CONF
                        |RAP_CONF_TAKE1,
      rap_http_access_rule,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("deny"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LMT_CONF
                        |RAP_CONF_TAKE1,
      rap_http_access_rule,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};



static rap_http_module_t  rap_http_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_access_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_access_create_loc_conf,       /* create location configuration */
    rap_http_access_merge_loc_conf         /* merge location configuration */
};


rap_module_t  rap_http_access_module = {
    RAP_MODULE_V1,
    &rap_http_access_module_ctx,           /* module context */
    rap_http_access_commands,              /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_http_access_handler(rap_http_request_t *r)
{
    struct sockaddr_in          *sin;
    rap_http_access_loc_conf_t  *alcf;
#if (RAP_HAVE_INET6)
    u_char                      *p;
    in_addr_t                    addr;
    struct sockaddr_in6         *sin6;
#endif

    alcf = rap_http_get_module_loc_conf(r, rap_http_access_module);

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (alcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            return rap_http_access_inet(r, alcf, sin->sin_addr.s_addr);
        }
        break;

#if (RAP_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return rap_http_access_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6) {
            return rap_http_access_inet6(r, alcf, p);
        }

        break;

#endif

#if (RAP_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (alcf->rules_un) {
            return rap_http_access_unix(r, alcf);
        }

        break;

#endif
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_access_inet(rap_http_request_t *r, rap_http_access_loc_conf_t *alcf,
    in_addr_t addr)
{
    rap_uint_t               i;
    rap_http_access_rule_t  *rule;

    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

        rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr) {
            return rap_http_access_found(r, rule[i].deny);
        }
    }

    return RAP_DECLINED;
}


#if (RAP_HAVE_INET6)

static rap_int_t
rap_http_access_inet6(rap_http_request_t *r, rap_http_access_loc_conf_t *alcf,
    u_char *p)
{
    rap_uint_t                n;
    rap_uint_t                i;
    rap_http_access_rule6_t  *rule6;

    rule6 = alcf->rules6->elts;
    for (i = 0; i < alcf->rules6->nelts; i++) {

#if (RAP_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[RAP_INET6_ADDRSTRLEN];
        u_char  mt[RAP_INET6_ADDRSTRLEN];
        u_char  at[RAP_INET6_ADDRSTRLEN];

        cl = rap_inet6_ntop(p, ct, RAP_INET6_ADDRSTRLEN);
        ml = rap_inet6_ntop(rule6[i].mask.s6_addr, mt, RAP_INET6_ADDRSTRLEN);
        al = rap_inet6_ntop(rule6[i].addr.s6_addr, at, RAP_INET6_ADDRSTRLEN);

        rap_log_debug6(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return rap_http_access_found(r, rule6[i].deny);

    next:
        continue;
    }

    return RAP_DECLINED;
}

#endif


#if (RAP_HAVE_UNIX_DOMAIN)

static rap_int_t
rap_http_access_unix(rap_http_request_t *r, rap_http_access_loc_conf_t *alcf)
{
    rap_uint_t                  i;
    rap_http_access_rule_un_t  *rule_un;

    rule_un = alcf->rules_un->elts;
    for (i = 0; i < alcf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return rap_http_access_found(r, rule_un[i].deny);
        }
    }

    return RAP_DECLINED;
}

#endif


static rap_int_t
rap_http_access_found(rap_http_request_t *r, rap_uint_t deny)
{
    rap_http_core_loc_conf_t  *clcf;

    if (deny) {
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (clcf->satisfy == RAP_HTTP_SATISFY_ALL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        return RAP_HTTP_FORBIDDEN;
    }

    return RAP_OK;
}


static char *
rap_http_access_rule(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_access_loc_conf_t *alcf = conf;

    rap_int_t                   rc;
    rap_uint_t                  all;
    rap_str_t                  *value;
    rap_cidr_t                  cidr;
    rap_http_access_rule_t     *rule;
#if (RAP_HAVE_INET6)
    rap_http_access_rule6_t    *rule6;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    rap_http_access_rule_un_t  *rule_un;
#endif

    all = 0;
    rap_memzero(&cidr, sizeof(rap_cidr_t));

    value = cf->args->elts;

    if (value[1].len == 3 && rap_strcmp(value[1].data, "all") == 0) {
        all = 1;

#if (RAP_HAVE_UNIX_DOMAIN)
    } else if (value[1].len == 5 && rap_strcmp(value[1].data, "unix:") == 0) {
        cidr.family = AF_UNIX;
#endif

    } else {
        rc = rap_ptocidr(&value[1], &cidr);

        if (rc == RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        if (rc == RAP_DONE) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    if (cidr.family == AF_INET || all) {

        if (alcf->rules == NULL) {
            alcf->rules = rap_array_create(cf->pool, 4,
                                           sizeof(rap_http_access_rule_t));
            if (alcf->rules == NULL) {
                return RAP_CONF_ERROR;
            }
        }

        rule = rap_array_push(alcf->rules);
        if (rule == NULL) {
            return RAP_CONF_ERROR;
        }

        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }

#if (RAP_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (alcf->rules6 == NULL) {
            alcf->rules6 = rap_array_create(cf->pool, 4,
                                            sizeof(rap_http_access_rule6_t));
            if (alcf->rules6 == NULL) {
                return RAP_CONF_ERROR;
            }
        }

        rule6 = rap_array_push(alcf->rules6);
        if (rule6 == NULL) {
            return RAP_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    if (cidr.family == AF_UNIX || all) {

        if (alcf->rules_un == NULL) {
            alcf->rules_un = rap_array_create(cf->pool, 1,
                                            sizeof(rap_http_access_rule_un_t));
            if (alcf->rules_un == NULL) {
                return RAP_CONF_ERROR;
            }
        }

        rule_un = rap_array_push(alcf->rules_un);
        if (rule_un == NULL) {
            return RAP_CONF_ERROR;
        }

        rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return RAP_CONF_OK;
}


static void *
rap_http_access_create_loc_conf(rap_conf_t *cf)
{
    rap_http_access_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rap_http_access_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_access_loc_conf_t  *prev = parent;
    rap_http_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL
#if (RAP_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (RAP_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_access_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_access_handler;

    return RAP_OK;
}
