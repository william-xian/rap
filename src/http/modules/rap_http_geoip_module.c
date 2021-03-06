
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#include <GeoIP.h>
#include <GeoIPCity.h>


#define RAP_GEOIP_COUNTRY_CODE   0
#define RAP_GEOIP_COUNTRY_CODE3  1
#define RAP_GEOIP_COUNTRY_NAME   2


typedef struct {
    GeoIP        *country;
    GeoIP        *org;
    GeoIP        *city;
    rap_array_t  *proxies;    /* array of rap_cidr_t */
    rap_flag_t    proxy_recursive;
#if (RAP_HAVE_GEOIP_V6)
    unsigned      country_v6:1;
    unsigned      org_v6:1;
    unsigned      city_v6:1;
#endif
} rap_http_geoip_conf_t;


typedef struct {
    rap_str_t    *name;
    uintptr_t     data;
} rap_http_geoip_var_t;


typedef const char *(*rap_http_geoip_variable_handler_pt)(GeoIP *,
    u_long addr);


rap_http_geoip_variable_handler_pt rap_http_geoip_country_functions[] = {
    GeoIP_country_code_by_ipnum,
    GeoIP_country_code3_by_ipnum,
    GeoIP_country_name_by_ipnum,
};


#if (RAP_HAVE_GEOIP_V6)

typedef const char *(*rap_http_geoip_variable_handler_v6_pt)(GeoIP *,
    geoipv6_t addr);


rap_http_geoip_variable_handler_v6_pt rap_http_geoip_country_v6_functions[] = {
    GeoIP_country_code_by_ipnum_v6,
    GeoIP_country_code3_by_ipnum_v6,
    GeoIP_country_name_by_ipnum_v6,
};

#endif


static rap_int_t rap_http_geoip_country_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_geoip_org_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_geoip_city_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_geoip_region_name_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_geoip_city_float_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_geoip_city_int_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static GeoIPRecord *rap_http_geoip_get_city_record(rap_http_request_t *r);

static rap_int_t rap_http_geoip_add_variables(rap_conf_t *cf);
static void *rap_http_geoip_create_conf(rap_conf_t *cf);
static char *rap_http_geoip_init_conf(rap_conf_t *cf, void *conf);
static char *rap_http_geoip_country(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_geoip_org(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_geoip_city(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_geoip_proxy(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_geoip_cidr_value(rap_conf_t *cf, rap_str_t *net,
    rap_cidr_t *cidr);
static void rap_http_geoip_cleanup(void *data);


static rap_command_t  rap_http_geoip_commands[] = {

    { rap_string("geoip_country"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE12,
      rap_http_geoip_country,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("geoip_org"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE12,
      rap_http_geoip_org,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("geoip_city"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE12,
      rap_http_geoip_city,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("geoip_proxy"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_http_geoip_proxy,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("geoip_proxy_recursive"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_geoip_conf_t, proxy_recursive),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_geoip_module_ctx = {
    rap_http_geoip_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_geoip_create_conf,            /* create main configuration */
    rap_http_geoip_init_conf,              /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_geoip_module = {
    RAP_MODULE_V1,
    &rap_http_geoip_module_ctx,            /* module context */
    rap_http_geoip_commands,               /* module directives */
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


static rap_http_variable_t  rap_http_geoip_vars[] = {

    { rap_string("geoip_country_code"), NULL,
      rap_http_geoip_country_variable,
      RAP_GEOIP_COUNTRY_CODE, 0, 0 },

    { rap_string("geoip_country_code3"), NULL,
      rap_http_geoip_country_variable,
      RAP_GEOIP_COUNTRY_CODE3, 0, 0 },

    { rap_string("geoip_country_name"), NULL,
      rap_http_geoip_country_variable,
      RAP_GEOIP_COUNTRY_NAME, 0, 0 },

    { rap_string("geoip_org"), NULL,
      rap_http_geoip_org_variable,
      0, 0, 0 },

    { rap_string("geoip_city_continent_code"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, continent_code), 0, 0 },

    { rap_string("geoip_city_country_code"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, country_code), 0, 0 },

    { rap_string("geoip_city_country_code3"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, country_code3), 0, 0 },

    { rap_string("geoip_city_country_name"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, country_name), 0, 0 },

    { rap_string("geoip_region"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, region), 0, 0 },

    { rap_string("geoip_region_name"), NULL,
      rap_http_geoip_region_name_variable,
      0, 0, 0 },

    { rap_string("geoip_city"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, city), 0, 0 },

    { rap_string("geoip_postal_code"), NULL,
      rap_http_geoip_city_variable,
      offsetof(GeoIPRecord, postal_code), 0, 0 },

    { rap_string("geoip_latitude"), NULL,
      rap_http_geoip_city_float_variable,
      offsetof(GeoIPRecord, latitude), 0, 0 },

    { rap_string("geoip_longitude"), NULL,
      rap_http_geoip_city_float_variable,
      offsetof(GeoIPRecord, longitude), 0, 0 },

    { rap_string("geoip_dma_code"), NULL,
      rap_http_geoip_city_int_variable,
      offsetof(GeoIPRecord, dma_code), 0, 0 },

    { rap_string("geoip_area_code"), NULL,
      rap_http_geoip_city_int_variable,
      offsetof(GeoIPRecord, area_code), 0, 0 },

      rap_http_null_variable
};


static u_long
rap_http_geoip_addr(rap_http_request_t *r, rap_http_geoip_conf_t *gcf)
{
    rap_addr_t           addr;
    rap_array_t         *xfwd;
    struct sockaddr_in  *sin;

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;
    /* addr.name = r->connection->addr_text; */

    xfwd = &r->headers_in.x_forwarded_for;

    if (xfwd->nelts > 0 && gcf->proxies != NULL) {
        (void) rap_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                           gcf->proxies, gcf->proxy_recursive);
    }

#if (RAP_HAVE_INET6)

    if (addr.sockaddr->sa_family == AF_INET6) {
        u_char           *p;
        in_addr_t         inaddr;
        struct in6_addr  *inaddr6;

        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            p = inaddr6->s6_addr;

            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            return inaddr;
        }
    }

#endif

    if (addr.sockaddr->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) addr.sockaddr;
    return ntohl(sin->sin_addr.s_addr);
}


#if (RAP_HAVE_GEOIP_V6)

static geoipv6_t
rap_http_geoip_addr_v6(rap_http_request_t *r, rap_http_geoip_conf_t *gcf)
{
    rap_addr_t            addr;
    rap_array_t          *xfwd;
    in_addr_t             addr4;
    struct in6_addr       addr6;
    struct sockaddr_in   *sin;
    struct sockaddr_in6  *sin6;

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;
    /* addr.name = r->connection->addr_text; */

    xfwd = &r->headers_in.x_forwarded_for;

    if (xfwd->nelts > 0 && gcf->proxies != NULL) {
        (void) rap_http_get_forwarded_addr(r, &addr, xfwd, NULL,
                                           gcf->proxies, gcf->proxy_recursive);
    }

    switch (addr.sockaddr->sa_family) {

    case AF_INET:
        /* Produce IPv4-mapped IPv6 address. */
        sin = (struct sockaddr_in *) addr.sockaddr;
        addr4 = ntohl(sin->sin_addr.s_addr);

        rap_memzero(&addr6, sizeof(struct in6_addr));
        addr6.s6_addr[10] = 0xff;
        addr6.s6_addr[11] = 0xff;
        addr6.s6_addr[12] = addr4 >> 24;
        addr6.s6_addr[13] = addr4 >> 16;
        addr6.s6_addr[14] = addr4 >> 8;
        addr6.s6_addr[15] = addr4;
        return addr6;

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr.sockaddr;
        return sin6->sin6_addr;

    default:
        return in6addr_any;
    }
}

#endif


static rap_int_t
rap_http_geoip_country_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_geoip_variable_handler_pt     handler =
        rap_http_geoip_country_functions[data];
#if (RAP_HAVE_GEOIP_V6)
    rap_http_geoip_variable_handler_v6_pt  handler_v6 =
        rap_http_geoip_country_v6_functions[data];
#endif

    const char             *val;
    rap_http_geoip_conf_t  *gcf;

    gcf = rap_http_get_module_main_conf(r, rap_http_geoip_module);

    if (gcf->country == NULL) {
        goto not_found;
    }

#if (RAP_HAVE_GEOIP_V6)
    val = gcf->country_v6
              ? handler_v6(gcf->country, rap_http_geoip_addr_v6(r, gcf))
              : handler(gcf->country, rap_http_geoip_addr(r, gcf));
#else
    val = handler(gcf->country, rap_http_geoip_addr(r, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    v->len = rap_strlen(val);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) val;

    return RAP_OK;

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_geoip_org_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t                  len;
    char                   *val;
    rap_http_geoip_conf_t  *gcf;

    gcf = rap_http_get_module_main_conf(r, rap_http_geoip_module);

    if (gcf->org == NULL) {
        goto not_found;
    }

#if (RAP_HAVE_GEOIP_V6)
    val = gcf->org_v6
              ? GeoIP_name_by_ipnum_v6(gcf->org,
                                       rap_http_geoip_addr_v6(r, gcf))
              : GeoIP_name_by_ipnum(gcf->org,
                                    rap_http_geoip_addr(r, gcf));
#else
    val = GeoIP_name_by_ipnum(gcf->org, rap_http_geoip_addr(r, gcf));
#endif

    if (val == NULL) {
        goto not_found;
    }

    len = rap_strlen(val);
    v->data = rap_pnalloc(r->pool, len);
    if (v->data == NULL) {
        rap_free(val);
        return RAP_ERROR;
    }

    rap_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    rap_free(val);

    return RAP_OK;

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_geoip_city_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    char         *val;
    size_t        len;
    GeoIPRecord  *gr;

    gr = rap_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = *(char **) ((char *) gr + data);
    if (val == NULL) {
        goto no_value;
    }

    len = rap_strlen(val);
    v->data = rap_pnalloc(r->pool, len);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return RAP_ERROR;
    }

    rap_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return RAP_OK;

no_value:

    GeoIPRecord_delete(gr);

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_geoip_region_name_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t        len;
    const char   *val;
    GeoIPRecord  *gr;

    gr = rap_http_geoip_get_city_record(r);
    if (gr == NULL) {
        goto not_found;
    }

    val = GeoIP_region_name_by_code(gr->country_code, gr->region);

    GeoIPRecord_delete(gr);

    if (val == NULL) {
        goto not_found;
    }

    len = rap_strlen(val);
    v->data = rap_pnalloc(r->pool, len);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(v->data, val, len);

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_geoip_city_float_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    float         val;
    GeoIPRecord  *gr;

    gr = rap_http_geoip_get_city_record(r);
    if (gr == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->data = rap_pnalloc(r->pool, RAP_INT64_LEN + 5);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return RAP_ERROR;
    }

    val = *(float *) ((char *) gr + data);

    v->len = rap_sprintf(v->data, "%.4f", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return RAP_OK;
}


static rap_int_t
rap_http_geoip_city_int_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    int           val;
    GeoIPRecord  *gr;

    gr = rap_http_geoip_get_city_record(r);
    if (gr == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->data = rap_pnalloc(r->pool, RAP_INT64_LEN);
    if (v->data == NULL) {
        GeoIPRecord_delete(gr);
        return RAP_ERROR;
    }

    val = *(int *) ((char *) gr + data);

    v->len = rap_sprintf(v->data, "%d", val) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    GeoIPRecord_delete(gr);

    return RAP_OK;
}


static GeoIPRecord *
rap_http_geoip_get_city_record(rap_http_request_t *r)
{
    rap_http_geoip_conf_t  *gcf;

    gcf = rap_http_get_module_main_conf(r, rap_http_geoip_module);

    if (gcf->city) {
#if (RAP_HAVE_GEOIP_V6)
        return gcf->city_v6
                   ? GeoIP_record_by_ipnum_v6(gcf->city,
                                              rap_http_geoip_addr_v6(r, gcf))
                   : GeoIP_record_by_ipnum(gcf->city,
                                           rap_http_geoip_addr(r, gcf));
#else
        return GeoIP_record_by_ipnum(gcf->city, rap_http_geoip_addr(r, gcf));
#endif
    }

    return NULL;
}


static rap_int_t
rap_http_geoip_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_geoip_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static void *
rap_http_geoip_create_conf(rap_conf_t *cf)
{
    rap_pool_cleanup_t     *cln;
    rap_http_geoip_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_geoip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->proxy_recursive = RAP_CONF_UNSET;

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rap_http_geoip_cleanup;
    cln->data = conf;

    return conf;
}


static char *
rap_http_geoip_init_conf(rap_conf_t *cf, void *conf)
{
    rap_http_geoip_conf_t  *gcf = conf;

    rap_conf_init_value(gcf->proxy_recursive, 0);

    return RAP_CONF_OK;
}


static char *
rap_http_geoip_country(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_geoip_conf_t  *gcf = conf;

    rap_str_t  *value;

    if (gcf->country) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->country == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (rap_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    switch (gcf->country->databaseType) {

    case GEOIP_COUNTRY_EDITION:

        return RAP_CONF_OK;

#if (RAP_HAVE_GEOIP_V6)
    case GEOIP_COUNTRY_EDITION_V6:

        gcf->country_v6 = 1;
        return RAP_CONF_OK;
#endif

    default:
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->country->databaseType);
        return RAP_CONF_ERROR;
    }
}


static char *
rap_http_geoip_org(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_geoip_conf_t  *gcf = conf;

    rap_str_t  *value;

    if (gcf->org) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->org == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (rap_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    switch (gcf->org->databaseType) {

    case GEOIP_ISP_EDITION:
    case GEOIP_ORG_EDITION:
    case GEOIP_DOMAIN_EDITION:
    case GEOIP_ASNUM_EDITION:

        return RAP_CONF_OK;

#if (RAP_HAVE_GEOIP_V6)
    case GEOIP_ISP_EDITION_V6:
    case GEOIP_ORG_EDITION_V6:
    case GEOIP_DOMAIN_EDITION_V6:
    case GEOIP_ASNUM_EDITION_V6:

        gcf->org_v6 = 1;
        return RAP_CONF_OK;
#endif

    default:
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid GeoIP database \"%V\" type:%d",
                           &value[1], gcf->org->databaseType);
        return RAP_CONF_ERROR;
    }
}


static char *
rap_http_geoip_city(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_geoip_conf_t  *gcf = conf;

    rap_str_t  *value;

    if (gcf->city) {
        return "is duplicate";
    }

    value = cf->args->elts;

    gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);

    if (gcf->city == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "GeoIP_open(\"%V\") failed", &value[1]);

        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (rap_strcmp(value[2].data, "utf8") == 0) {
            GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    switch (gcf->city->databaseType) {

    case GEOIP_CITY_EDITION_REV0:
    case GEOIP_CITY_EDITION_REV1:

        return RAP_CONF_OK;

#if (RAP_HAVE_GEOIP_V6)
    case GEOIP_CITY_EDITION_REV0_V6:
    case GEOIP_CITY_EDITION_REV1_V6:

        gcf->city_v6 = 1;
        return RAP_CONF_OK;
#endif

    default:
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid GeoIP City database \"%V\" type:%d",
                           &value[1], gcf->city->databaseType);
        return RAP_CONF_ERROR;
    }
}


static char *
rap_http_geoip_proxy(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_geoip_conf_t  *gcf = conf;

    rap_str_t   *value;
    rap_cidr_t  cidr, *c;

    value = cf->args->elts;

    if (rap_http_geoip_cidr_value(cf, &value[1], &cidr) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (gcf->proxies == NULL) {
        gcf->proxies = rap_array_create(cf->pool, 4, sizeof(rap_cidr_t));
        if (gcf->proxies == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    c = rap_array_push(gcf->proxies);
    if (c == NULL) {
        return RAP_CONF_ERROR;
    }

    *c = cidr;

    return RAP_CONF_OK;
}

static rap_int_t
rap_http_geoip_cidr_value(rap_conf_t *cf, rap_str_t *net, rap_cidr_t *cidr)
{
    rap_int_t  rc;

    if (rap_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return RAP_OK;
    }

    rc = rap_ptocidr(net, cidr);

    if (rc == RAP_ERROR) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return RAP_ERROR;
    }

    if (rc == RAP_DONE) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return RAP_OK;
}


static void
rap_http_geoip_cleanup(void *data)
{
    rap_http_geoip_conf_t  *gcf = data;

    if (gcf->country) {
        GeoIP_delete(gcf->country);
    }

    if (gcf->org) {
        GeoIP_delete(gcf->org);
    }

    if (gcf->city) {
        GeoIP_delete(gcf->city);
    }
}
