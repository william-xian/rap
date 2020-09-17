
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_stream_variable_value_t       *value;
    u_short                            start;
    u_short                            end;
} rp_stream_geo_range_t;


typedef struct {
    rp_radix_tree_t                  *tree;
#if (RP_HAVE_INET6)
    rp_radix_tree_t                  *tree6;
#endif
} rp_stream_geo_trees_t;


typedef struct {
    rp_stream_geo_range_t           **low;
    rp_stream_variable_value_t       *default_value;
} rp_stream_geo_high_ranges_t;


typedef struct {
    rp_str_node_t                     sn;
    rp_stream_variable_value_t       *value;
    size_t                             offset;
} rp_stream_geo_variable_value_node_t;


typedef struct {
    rp_stream_variable_value_t       *value;
    rp_str_t                         *net;
    rp_stream_geo_high_ranges_t       high;
    rp_radix_tree_t                  *tree;
#if (RP_HAVE_INET6)
    rp_radix_tree_t                  *tree6;
#endif
    rp_rbtree_t                       rbtree;
    rp_rbtree_node_t                  sentinel;
    rp_pool_t                        *pool;
    rp_pool_t                        *temp_pool;

    size_t                             data_size;

    rp_str_t                          include_name;
    rp_uint_t                         includes;
    rp_uint_t                         entries;

    unsigned                           ranges:1;
    unsigned                           outside_entries:1;
    unsigned                           allow_binary_include:1;
    unsigned                           binary_include:1;
} rp_stream_geo_conf_ctx_t;


typedef struct {
    union {
        rp_stream_geo_trees_t         trees;
        rp_stream_geo_high_ranges_t   high;
    } u;

    rp_int_t                          index;
} rp_stream_geo_ctx_t;


static rp_int_t rp_stream_geo_addr(rp_stream_session_t *s,
    rp_stream_geo_ctx_t *ctx, rp_addr_t *addr);

static char *rp_stream_geo_block(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_geo(rp_conf_t *cf, rp_command_t *dummy, void *conf);
static char *rp_stream_geo_range(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *value);
static char *rp_stream_geo_add_range(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static rp_uint_t rp_stream_geo_delete_range(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static char *rp_stream_geo_cidr(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *value);
static char *rp_stream_geo_cidr_add(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_cidr_t *cidr, rp_str_t *value,
    rp_str_t *net);
static rp_stream_variable_value_t *rp_stream_geo_value(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *value);
static rp_int_t rp_stream_geo_cidr_value(rp_conf_t *cf, rp_str_t *net,
    rp_cidr_t *cidr);
static char *rp_stream_geo_include(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *name);
static rp_int_t rp_stream_geo_include_binary_base(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *name);
static void rp_stream_geo_create_binary_base(rp_stream_geo_conf_ctx_t *ctx);
static u_char *rp_stream_geo_copy_values(u_char *base, u_char *p,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);


static rp_command_t  rp_stream_geo_commands[] = {

    { rp_string("geo"),
      RP_STREAM_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE12,
      rp_stream_geo_block,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_geo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_geo_module = {
    RP_MODULE_V1,
    &rp_stream_geo_module_ctx,            /* module context */
    rp_stream_geo_commands,               /* module directives */
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


typedef struct {
    u_char    GEORNG[6];
    u_char    version;
    u_char    ptr_size;
    uint32_t  endianness;
    uint32_t  crc32;
} rp_stream_geo_header_t;


static rp_stream_geo_header_t  rp_stream_geo_header = {
    { 'G', 'E', 'O', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
};


/* geo range is AF_INET only */

static rp_int_t
rp_stream_geo_cidr_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_stream_geo_ctx_t *ctx = (rp_stream_geo_ctx_t *) data;

    in_addr_t                     inaddr;
    rp_addr_t                    addr;
    struct sockaddr_in           *sin;
    rp_stream_variable_value_t  *vv;
#if (RP_HAVE_INET6)
    u_char                       *p;
    struct in6_addr              *inaddr6;
#endif

    if (rp_stream_geo_addr(s, ctx, &addr) != RP_OK) {
        vv = (rp_stream_variable_value_t *)
                  rp_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        goto done;
    }

    switch (addr.sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
        p = inaddr6->s6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            vv = (rp_stream_variable_value_t *)
                      rp_radix32tree_find(ctx->u.trees.tree, inaddr);

        } else {
            vv = (rp_stream_variable_value_t *)
                      rp_radix128tree_find(ctx->u.trees.tree6, p);
        }

        break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        vv = (rp_stream_variable_value_t *)
                  rp_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr.sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        vv = (rp_stream_variable_value_t *)
                  rp_radix32tree_find(ctx->u.trees.tree, inaddr);

        break;
    }

done:

    *v = *vv;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return RP_OK;
}


static rp_int_t
rp_stream_geo_range_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_stream_geo_ctx_t *ctx = (rp_stream_geo_ctx_t *) data;

    in_addr_t                inaddr;
    rp_addr_t               addr;
    rp_uint_t               n;
    struct sockaddr_in      *sin;
    rp_stream_geo_range_t  *range;
#if (RP_HAVE_INET6)
    u_char                  *p;
    struct in6_addr         *inaddr6;
#endif

    *v = *ctx->u.high.default_value;

    if (rp_stream_geo_addr(s, ctx, &addr) == RP_OK) {

        switch (addr.sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;

            if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
                p = inaddr6->s6_addr;

                inaddr = p[12] << 24;
                inaddr += p[13] << 16;
                inaddr += p[14] << 8;
                inaddr += p[15];

            } else {
                inaddr = INADDR_NONE;
            }

            break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            inaddr = INADDR_NONE;
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) addr.sockaddr;
            inaddr = ntohl(sin->sin_addr.s_addr);
            break;
        }

    } else {
        inaddr = INADDR_NONE;
    }

    if (ctx->u.high.low) {
        range = ctx->u.high.low[inaddr >> 16];

        if (range) {
            n = inaddr & 0xffff;
            do {
                if (n >= (rp_uint_t) range->start
                    && n <= (rp_uint_t) range->end)
                {
                    *v = *range->value;
                    break;
                }
            } while ((++range)->value);
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return RP_OK;
}


static rp_int_t
rp_stream_geo_addr(rp_stream_session_t *s, rp_stream_geo_ctx_t *ctx,
    rp_addr_t *addr)
{
    rp_stream_variable_value_t  *v;

    if (ctx->index == -1) {
        rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo started: %V", &s->connection->addr_text);

        addr->sockaddr = s->connection->sockaddr;
        addr->socklen = s->connection->socklen;
        /* addr->name = s->connection->addr_text; */

        return RP_OK;
    }

    v = rp_stream_get_flushed_variable(s, ctx->index);

    if (v == NULL || v->not_found) {
        rp_log_debug0(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo not found");

        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo started: %v", v);

    if (rp_parse_addr(s->connection->pool, addr, v->data, v->len) == RP_OK) {
        return RP_OK;
    }

    return RP_ERROR;
}


static char *
rp_stream_geo_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                       *rv;
    size_t                      len;
    rp_str_t                  *value, name;
    rp_uint_t                  i;
    rp_conf_t                  save;
    rp_pool_t                 *pool;
    rp_array_t                *a;
    rp_stream_variable_t      *var;
    rp_stream_geo_ctx_t       *geo;
    rp_stream_geo_conf_ctx_t   ctx;
#if (RP_HAVE_INET6)
    static struct in6_addr      zero;
#endif

    value = cf->args->elts;

    geo = rp_palloc(cf->pool, sizeof(rp_stream_geo_ctx_t));
    if (geo == NULL) {
        return RP_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    if (cf->args->nelts == 3) {

        geo->index = rp_stream_get_variable_index(cf, &name);
        if (geo->index == RP_ERROR) {
            return RP_CONF_ERROR;
        }

        name = value[2];

        if (name.data[0] != '$') {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &name);
            return RP_CONF_ERROR;
        }

        name.len--;
        name.data++;

    } else {
        geo->index = -1;
    }

    var = rp_stream_add_variable(cf, &name, RP_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return RP_CONF_ERROR;
    }

    pool = rp_create_pool(RP_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ctx, sizeof(rp_stream_geo_conf_ctx_t));

    ctx.temp_pool = rp_create_pool(RP_DEFAULT_POOL_SIZE, cf->log);
    if (ctx.temp_pool == NULL) {
        rp_destroy_pool(pool);
        return RP_CONF_ERROR;
    }

    rp_rbtree_init(&ctx.rbtree, &ctx.sentinel, rp_str_rbtree_insert_value);

    ctx.pool = cf->pool;
    ctx.data_size = sizeof(rp_stream_geo_header_t)
                  + sizeof(rp_stream_variable_value_t)
                  + 0x10000 * sizeof(rp_stream_geo_range_t *);
    ctx.allow_binary_include = 1;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = rp_stream_geo;
    cf->handler_conf = conf;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RP_CONF_OK) {
        goto failed;
    }

    if (ctx.ranges) {

        if (ctx.high.low && !ctx.binary_include) {
            for (i = 0; i < 0x10000; i++) {
                a = (rp_array_t *) ctx.high.low[i];

                if (a == NULL) {
                    continue;
                }

                if (a->nelts == 0) {
                    ctx.high.low[i] = NULL;
                    continue;
                }

                len = a->nelts * sizeof(rp_stream_geo_range_t);

                ctx.high.low[i] = rp_palloc(cf->pool, len + sizeof(void *));
                if (ctx.high.low[i] == NULL) {
                    goto failed;
                }

                rp_memcpy(ctx.high.low[i], a->elts, len);
                ctx.high.low[i][a->nelts].value = NULL;
                ctx.data_size += len + sizeof(void *);
            }

            if (ctx.allow_binary_include
                && !ctx.outside_entries
                && ctx.entries > 100000
                && ctx.includes == 1)
            {
                rp_stream_geo_create_binary_base(&ctx);
            }
        }

        if (ctx.high.default_value == NULL) {
            ctx.high.default_value = &rp_stream_variable_null_value;
        }

        geo->u.high = ctx.high;

        var->get_handler = rp_stream_geo_range_variable;
        var->data = (uintptr_t) geo;

    } else {
        if (ctx.tree == NULL) {
            ctx.tree = rp_radix_tree_create(cf->pool, -1);
            if (ctx.tree == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree = ctx.tree;

#if (RP_HAVE_INET6)
        if (ctx.tree6 == NULL) {
            ctx.tree6 = rp_radix_tree_create(cf->pool, -1);
            if (ctx.tree6 == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree6 = ctx.tree6;
#endif

        var->get_handler = rp_stream_geo_cidr_variable;
        var->data = (uintptr_t) geo;

        if (rp_radix32tree_insert(ctx.tree, 0, 0,
                                   (uintptr_t) &rp_stream_variable_null_value)
            == RP_ERROR)
        {
            goto failed;
        }

        /* RP_BUSY is okay (default was set explicitly) */

#if (RP_HAVE_INET6)
        if (rp_radix128tree_insert(ctx.tree6, zero.s6_addr, zero.s6_addr,
                                    (uintptr_t) &rp_stream_variable_null_value)
            == RP_ERROR)
        {
            goto failed;
        }
#endif
    }

    rp_destroy_pool(ctx.temp_pool);
    rp_destroy_pool(pool);

    return RP_CONF_OK;

failed:

    rp_destroy_pool(ctx.temp_pool);
    rp_destroy_pool(pool);

    return RP_CONF_ERROR;
}


static char *
rp_stream_geo(rp_conf_t *cf, rp_command_t *dummy, void *conf)
{
    char                       *rv;
    rp_str_t                  *value;
    rp_stream_geo_conf_ctx_t  *ctx;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (rp_strcmp(value[0].data, "ranges") == 0) {

            if (ctx->tree
#if (RP_HAVE_INET6)
                || ctx->tree6
#endif
               )
            {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "the \"ranges\" directive must be "
                                   "the first directive inside \"geo\" block");
                goto failed;
            }

            ctx->ranges = 1;

            rv = RP_CONF_OK;

            goto done;
        }
    }

    if (cf->args->nelts != 2) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid number of the geo parameters");
        goto failed;
    }

    if (rp_strcmp(value[0].data, "include") == 0) {

        rv = rp_stream_geo_include(cf, ctx, &value[1]);

        goto done;
    }

    if (ctx->ranges) {
        rv = rp_stream_geo_range(cf, ctx, value);

    } else {
        rv = rp_stream_geo_cidr(cf, ctx, value);
    }

done:

    rp_reset_pool(cf->pool);

    return rv;

failed:

    rp_reset_pool(cf->pool);

    return RP_CONF_ERROR;
}


static char *
rp_stream_geo_range(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    rp_str_t *value)
{
    u_char      *p, *last;
    in_addr_t    start, end;
    rp_str_t   *net;
    rp_uint_t   del;

    if (rp_strcmp(value[0].data, "default") == 0) {

        if (ctx->high.default_value) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                "duplicate default geo range value: \"%V\", old value: \"%v\"",
                &value[1], ctx->high.default_value);
        }

        ctx->high.default_value = rp_stream_geo_value(cf, ctx, &value[1]);
        if (ctx->high.default_value == NULL) {
            return RP_CONF_ERROR;
        }

        return RP_CONF_OK;
    }

    if (ctx->binary_include) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            ctx->include_name.data);
        return RP_CONF_ERROR;
    }

    if (ctx->high.low == NULL) {
        ctx->high.low = rp_pcalloc(ctx->pool,
                                    0x10000 * sizeof(rp_stream_geo_range_t *));
        if (ctx->high.low == NULL) {
            return RP_CONF_ERROR;
        }
    }

    ctx->entries++;
    ctx->outside_entries = 1;

    if (rp_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    last = net->data + net->len;

    p = rp_strlchr(net->data, last, '-');

    if (p == NULL) {
        goto invalid;
    }

    start = rp_inet_addr(net->data, p - net->data);

    if (start == INADDR_NONE) {
        goto invalid;
    }

    start = ntohl(start);

    p++;

    end = rp_inet_addr(p, last - p);

    if (end == INADDR_NONE) {
        goto invalid;
    }

    end = ntohl(end);

    if (start > end) {
        goto invalid;
    }

    if (del) {
        if (rp_stream_geo_delete_range(cf, ctx, start, end)) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "no address range \"%V\" to delete", net);
        }

        return RP_CONF_OK;
    }

    ctx->value = rp_stream_geo_value(cf, ctx, &value[1]);

    if (ctx->value == NULL) {
        return RP_CONF_ERROR;
    }

    ctx->net = net;

    return rp_stream_geo_add_range(cf, ctx, start, end);

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);

    return RP_CONF_ERROR;
}


/* the add procedure is optimized to add a growing up sequence */

static char *
rp_stream_geo_add_range(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    rp_uint_t               h, i, s, e;
    rp_array_t             *a;
    rp_stream_geo_range_t  *range;

    for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (rp_array_t *) ctx->high.low[h];

        if (a == NULL) {
            a = rp_array_create(ctx->temp_pool, 64,
                                 sizeof(rp_stream_geo_range_t));
            if (a == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->high.low[h] = (rp_stream_geo_range_t *) a;
        }

        i = a->nelts;
        range = a->elts;

        while (i) {

            i--;

            if (e < (rp_uint_t) range[i].start) {
                continue;
            }

            if (s > (rp_uint_t) range[i].end) {

                /* add after the range */

                range = rp_array_push(a);
                if (range == NULL) {
                    return RP_CONF_ERROR;
                }

                range = a->elts;

                rp_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(rp_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                goto next;
            }

            if (s == (rp_uint_t) range[i].start
                && e == (rp_uint_t) range[i].end)
            {
                rp_conf_log_error(RP_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);

                range[i].value = ctx->value;

                goto next;
            }

            if (s > (rp_uint_t) range[i].start
                && e < (rp_uint_t) range[i].end)
            {
                /* split the range and insert the new one */

                range = rp_array_push(a);
                if (range == NULL) {
                    return RP_CONF_ERROR;
                }

                range = rp_array_push(a);
                if (range == NULL) {
                    return RP_CONF_ERROR;
                }

                range = a->elts;

                rp_memmove(&range[i + 3], &range[i + 1],
                           (a->nelts - 3 - i) * sizeof(rp_stream_geo_range_t));

                range[i + 2].start = (u_short) (e + 1);
                range[i + 2].end = range[i].end;
                range[i + 2].value = range[i].value;

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            if (s == (rp_uint_t) range[i].start
                && e < (rp_uint_t) range[i].end)
            {
                /* shift the range start and insert the new range */

                range = rp_array_push(a);
                if (range == NULL) {
                    return RP_CONF_ERROR;
                }

                range = a->elts;

                rp_memmove(&range[i + 1], &range[i],
                           (a->nelts - 1 - i) * sizeof(rp_stream_geo_range_t));

                range[i + 1].start = (u_short) (e + 1);

                range[i].start = (u_short) s;
                range[i].end = (u_short) e;
                range[i].value = ctx->value;

                goto next;
            }

            if (s > (rp_uint_t) range[i].start
                && e == (rp_uint_t) range[i].end)
            {
                /* shift the range end and insert the new range */

                range = rp_array_push(a);
                if (range == NULL) {
                    return RP_CONF_ERROR;
                }

                range = a->elts;

                rp_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(rp_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            s = (rp_uint_t) range[i].start;
            e = (rp_uint_t) range[i].end;

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                         "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
                         ctx->net,
                         h >> 8, h & 0xff, s >> 8, s & 0xff,
                         h >> 8, h & 0xff, e >> 8, e & 0xff);

            return RP_CONF_ERROR;
        }

        /* add the first range */

        range = rp_array_push(a);
        if (range == NULL) {
            return RP_CONF_ERROR;
        }

        range = a->elts;

        rp_memmove(&range[1], &range[0],
                    (a->nelts - 1) * sizeof(rp_stream_geo_range_t));

        range[0].start = (u_short) s;
        range[0].end = (u_short) e;
        range[0].value = ctx->value;

    next:

        if (h == 0xffff) {
            break;
        }
    }

    return RP_CONF_OK;
}


static rp_uint_t
rp_stream_geo_delete_range(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    rp_uint_t               h, i, s, e, warn;
    rp_array_t             *a;
    rp_stream_geo_range_t  *range;

    warn = 0;

    for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {

        h = n >> 16;

        if (n == start) {
            s = n & 0xffff;
        } else {
            s = 0;
        }

        if ((n | 0xffff) > end) {
            e = end & 0xffff;

        } else {
            e = 0xffff;
        }

        a = (rp_array_t *) ctx->high.low[h];

        if (a == NULL || a->nelts == 0) {
            warn = 1;
            goto next;
        }

        range = a->elts;
        for (i = 0; i < a->nelts; i++) {

            if (s == (rp_uint_t) range[i].start
                && e == (rp_uint_t) range[i].end)
            {
                rp_memmove(&range[i], &range[i + 1],
                           (a->nelts - 1 - i) * sizeof(rp_stream_geo_range_t));

                a->nelts--;

                break;
            }

            if (i == a->nelts - 1) {
                warn = 1;
            }
        }

    next:

        if (h == 0xffff) {
            break;
        }
    }

    return warn;
}


static char *
rp_stream_geo_cidr(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    rp_str_t *value)
{
    char        *rv;
    rp_int_t    rc, del;
    rp_str_t   *net;
    rp_cidr_t   cidr;

    if (ctx->tree == NULL) {
        ctx->tree = rp_radix_tree_create(ctx->pool, -1);
        if (ctx->tree == NULL) {
            return RP_CONF_ERROR;
        }
    }

#if (RP_HAVE_INET6)
    if (ctx->tree6 == NULL) {
        ctx->tree6 = rp_radix_tree_create(ctx->pool, -1);
        if (ctx->tree6 == NULL) {
            return RP_CONF_ERROR;
        }
    }
#endif

    if (rp_strcmp(value[0].data, "default") == 0) {
        cidr.family = AF_INET;
        cidr.u.in.addr = 0;
        cidr.u.in.mask = 0;

        rv = rp_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != RP_CONF_OK) {
            return rv;
        }

#if (RP_HAVE_INET6)
        cidr.family = AF_INET6;
        rp_memzero(&cidr.u.in6, sizeof(rp_in6_cidr_t));

        rv = rp_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != RP_CONF_OK) {
            return rv;
        }
#endif

        return RP_CONF_OK;
    }

    if (rp_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    if (rp_stream_geo_cidr_value(cf, net, &cidr) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cidr.family == AF_INET) {
        cidr.u.in.addr = ntohl(cidr.u.in.addr);
        cidr.u.in.mask = ntohl(cidr.u.in.mask);
    }

    if (del) {
        switch (cidr.family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            rc = rp_radix128tree_delete(ctx->tree6,
                                         cidr.u.in6.addr.s6_addr,
                                         cidr.u.in6.mask.s6_addr);
            break;
#endif

        default: /* AF_INET */
            rc = rp_radix32tree_delete(ctx->tree, cidr.u.in.addr,
                                        cidr.u.in.mask);
            break;
        }

        if (rc != RP_OK) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "no network \"%V\" to delete", net);
        }

        return RP_CONF_OK;
    }

    return rp_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], net);
}


static char *
rp_stream_geo_cidr_add(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    rp_cidr_t *cidr, rp_str_t *value, rp_str_t *net)
{
    rp_int_t                     rc;
    rp_stream_variable_value_t  *val, *old;

    val = rp_stream_geo_value(cf, ctx, value);

    if (val == NULL) {
        return RP_CONF_ERROR;
    }

    switch (cidr->family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        rc = rp_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        if (rc == RP_OK) {
            return RP_CONF_OK;
        }

        if (rc == RP_ERROR) {
            return RP_CONF_ERROR;
        }

        /* rc == RP_BUSY */

        old = (rp_stream_variable_value_t *)
                   rp_radix128tree_find(ctx->tree6,
                                         cidr->u.in6.addr.s6_addr);

        rp_conf_log_error(RP_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = rp_radix128tree_delete(ctx->tree6,
                                     cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr);

        if (rc == RP_ERROR) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid radix tree");
            return RP_CONF_ERROR;
        }

        rc = rp_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        break;
#endif

    default: /* AF_INET */
        rc = rp_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        if (rc == RP_OK) {
            return RP_CONF_OK;
        }

        if (rc == RP_ERROR) {
            return RP_CONF_ERROR;
        }

        /* rc == RP_BUSY */

        old = (rp_stream_variable_value_t *)
                   rp_radix32tree_find(ctx->tree, cidr->u.in.addr);

        rp_conf_log_error(RP_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = rp_radix32tree_delete(ctx->tree,
                                    cidr->u.in.addr, cidr->u.in.mask);

        if (rc == RP_ERROR) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid radix tree");
            return RP_CONF_ERROR;
        }

        rc = rp_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        break;
    }

    if (rc == RP_OK) {
        return RP_CONF_OK;
    }

    return RP_CONF_ERROR;
}


static rp_stream_variable_value_t *
rp_stream_geo_value(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    rp_str_t *value)
{
    uint32_t                               hash;
    rp_stream_variable_value_t           *val;
    rp_stream_geo_variable_value_node_t  *gvvn;

    hash = rp_crc32_long(value->data, value->len);

    gvvn = (rp_stream_geo_variable_value_node_t *)
               rp_str_rbtree_lookup(&ctx->rbtree, value, hash);

    if (gvvn) {
        return gvvn->value;
    }

    val = rp_palloc(ctx->pool, sizeof(rp_stream_variable_value_t));
    if (val == NULL) {
        return NULL;
    }

    val->len = value->len;
    val->data = rp_pstrdup(ctx->pool, value);
    if (val->data == NULL) {
        return NULL;
    }

    val->valid = 1;
    val->no_cacheable = 0;
    val->not_found = 0;

    gvvn = rp_palloc(ctx->temp_pool,
                      sizeof(rp_stream_geo_variable_value_node_t));
    if (gvvn == NULL) {
        return NULL;
    }

    gvvn->sn.node.key = hash;
    gvvn->sn.str.len = val->len;
    gvvn->sn.str.data = val->data;
    gvvn->value = val;
    gvvn->offset = 0;

    rp_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);

    ctx->data_size += rp_align(sizeof(rp_stream_variable_value_t)
                                + value->len, sizeof(void *));

    return val;
}


static rp_int_t
rp_stream_geo_cidr_value(rp_conf_t *cf, rp_str_t *net, rp_cidr_t *cidr)
{
    rp_int_t  rc;

    if (rp_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return RP_OK;
    }

    rc = rp_ptocidr(net, cidr);

    if (rc == RP_ERROR) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return RP_ERROR;
    }

    if (rc == RP_DONE) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", net);
    }

    return RP_OK;
}


static char *
rp_stream_geo_include(rp_conf_t *cf, rp_stream_geo_conf_ctx_t *ctx,
    rp_str_t *name)
{
    char       *rv;
    rp_str_t   file;

    file.len = name->len + 4;
    file.data = rp_pnalloc(ctx->temp_pool, name->len + 5);
    if (file.data == NULL) {
        return RP_CONF_ERROR;
    }

    rp_sprintf(file.data, "%V.bin%Z", name);

    if (rp_conf_full_name(cf->cycle, &file, 1) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (ctx->ranges) {
        rp_log_debug1(RP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        switch (rp_stream_geo_include_binary_base(cf, ctx, &file)) {
        case RP_OK:
            return RP_CONF_OK;
        case RP_ERROR:
            return RP_CONF_ERROR;
        default:
            break;
        }
    }

    file.len -= 4;
    file.data[file.len] = '\0';

    ctx->include_name = file;

    if (ctx->outside_entries) {
        ctx->allow_binary_include = 0;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    rv = rp_conf_parse(cf, &file);

    ctx->includes++;
    ctx->outside_entries = 0;

    return rv;
}


static rp_int_t
rp_stream_geo_include_binary_base(rp_conf_t *cf,
    rp_stream_geo_conf_ctx_t *ctx, rp_str_t *name)
{
    u_char                       *base, ch;
    time_t                        mtime;
    size_t                        size, len;
    ssize_t                       n;
    uint32_t                      crc32;
    rp_err_t                     err;
    rp_int_t                     rc;
    rp_uint_t                    i;
    rp_file_t                    file;
    rp_file_info_t               fi;
    rp_stream_geo_range_t       *range, **ranges;
    rp_stream_geo_header_t      *header;
    rp_stream_variable_value_t  *vv;

    rp_memzero(&file, sizeof(rp_file_t));
    file.name = *name;
    file.log = cf->log;

    file.fd = rp_open_file(name->data, RP_FILE_RDONLY, RP_FILE_OPEN, 0);

    if (file.fd == RP_INVALID_FILE) {
        err = rp_errno;
        if (err != RP_ENOENT) {
            rp_conf_log_error(RP_LOG_CRIT, cf, err,
                               rp_open_file_n " \"%s\" failed", name->data);
        }
        return RP_DECLINED;
    }

    if (ctx->outside_entries) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            name->data);
        rc = RP_ERROR;
        goto done;
    }

    if (ctx->binary_include) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "second binary geo range base \"%s\" cannot be mixed with \"%s\"",
            name->data, ctx->include_name.data);
        rc = RP_ERROR;
        goto done;
    }

    if (rp_fd_info(file.fd, &fi) == RP_FILE_ERROR) {
        rp_conf_log_error(RP_LOG_CRIT, cf, rp_errno,
                           rp_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) rp_file_size(&fi);
    mtime = rp_file_mtime(&fi);

    ch = name->data[name->len - 4];
    name->data[name->len - 4] = '\0';

    if (rp_file_info(name->data, &fi) == RP_FILE_ERROR) {
        rp_conf_log_error(RP_LOG_CRIT, cf, rp_errno,
                           rp_file_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    name->data[name->len - 4] = ch;

    if (mtime < rp_file_mtime(&fi)) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "stale binary geo range base \"%s\"", name->data);
        goto failed;
    }

    base = rp_palloc(ctx->pool, size);
    if (base == NULL) {
        goto failed;
    }

    n = rp_read_file(&file, base, size, 0);

    if (n == RP_ERROR) {
        rp_conf_log_error(RP_LOG_CRIT, cf, rp_errno,
                           rp_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    if ((size_t) n != size) {
        rp_conf_log_error(RP_LOG_CRIT, cf, 0,
            rp_read_file_n " \"%s\" returned only %z bytes instead of %z",
            name->data, n, size);
        goto failed;
    }

    header = (rp_stream_geo_header_t *) base;

    if (size < 16 || rp_memcmp(&rp_stream_geo_header, header, 12) != 0) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
             "incompatible binary geo range base \"%s\"", name->data);
        goto failed;
    }

    rp_crc32_init(crc32);

    vv = (rp_stream_variable_value_t *)
            (base + sizeof(rp_stream_geo_header_t));

    while (vv->data) {
        len = rp_align(sizeof(rp_stream_variable_value_t) + vv->len,
                        sizeof(void *));
        rp_crc32_update(&crc32, (u_char *) vv, len);
        vv->data += (size_t) base;
        vv = (rp_stream_variable_value_t *) ((u_char *) vv + len);
    }
    rp_crc32_update(&crc32, (u_char *) vv,
                     sizeof(rp_stream_variable_value_t));
    vv++;

    ranges = (rp_stream_geo_range_t **) vv;

    for (i = 0; i < 0x10000; i++) {
        rp_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
        if (ranges[i]) {
            ranges[i] = (rp_stream_geo_range_t *)
                            ((u_char *) ranges[i] + (size_t) base);
        }
    }

    range = (rp_stream_geo_range_t *) &ranges[0x10000];

    while ((u_char *) range < base + size) {
        while (range->value) {
            rp_crc32_update(&crc32, (u_char *) range,
                             sizeof(rp_stream_geo_range_t));
            range->value = (rp_stream_variable_value_t *)
                               ((u_char *) range->value + (size_t) base);
            range++;
        }
        rp_crc32_update(&crc32, (u_char *) range, sizeof(void *));
        range = (rp_stream_geo_range_t *) ((u_char *) range + sizeof(void *));
    }

    rp_crc32_final(crc32);

    if (crc32 != header->crc32) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                  "CRC32 mismatch in binary geo range base \"%s\"", name->data);
        goto failed;
    }

    rp_conf_log_error(RP_LOG_NOTICE, cf, 0,
                       "using binary geo range base \"%s\"", name->data);

    ctx->include_name = *name;
    ctx->binary_include = 1;
    ctx->high.low = ranges;
    rc = RP_OK;

    goto done;

failed:

    rc = RP_DECLINED;

done:

    if (rp_close_file(file.fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}


static void
rp_stream_geo_create_binary_base(rp_stream_geo_conf_ctx_t *ctx)
{
    u_char                                *p;
    uint32_t                               hash;
    rp_str_t                              s;
    rp_uint_t                             i;
    rp_file_mapping_t                     fm;
    rp_stream_geo_range_t                *r, *range, **ranges;
    rp_stream_geo_header_t               *header;
    rp_stream_geo_variable_value_node_t  *gvvn;

    fm.name = rp_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
    if (fm.name == NULL) {
        return;
    }

    rp_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);

    fm.size = ctx->data_size;
    fm.log = ctx->pool->log;

    rp_log_error(RP_LOG_NOTICE, fm.log, 0,
                  "creating binary geo range base \"%s\"", fm.name);

    if (rp_create_file_mapping(&fm) != RP_OK) {
        return;
    }

    p = rp_cpymem(fm.addr, &rp_stream_geo_header,
                   sizeof(rp_stream_geo_header_t));

    p = rp_stream_geo_copy_values(fm.addr, p, ctx->rbtree.root,
                                   ctx->rbtree.sentinel);

    p += sizeof(rp_stream_variable_value_t);

    ranges = (rp_stream_geo_range_t **) p;

    p += 0x10000 * sizeof(rp_stream_geo_range_t *);

    for (i = 0; i < 0x10000; i++) {
        r = ctx->high.low[i];
        if (r == NULL) {
            continue;
        }

        range = (rp_stream_geo_range_t *) p;
        ranges[i] = (rp_stream_geo_range_t *) (p - (u_char *) fm.addr);

        do {
            s.len = r->value->len;
            s.data = r->value->data;
            hash = rp_crc32_long(s.data, s.len);
            gvvn = (rp_stream_geo_variable_value_node_t *)
                        rp_str_rbtree_lookup(&ctx->rbtree, &s, hash);

            range->value = (rp_stream_variable_value_t *) gvvn->offset;
            range->start = r->start;
            range->end = r->end;
            range++;

        } while ((++r)->value);

        range->value = NULL;

        p = (u_char *) range + sizeof(void *);
    }

    header = fm.addr;
    header->crc32 = rp_crc32_long((u_char *) fm.addr
                                       + sizeof(rp_stream_geo_header_t),
                                   fm.size - sizeof(rp_stream_geo_header_t));

    rp_close_file_mapping(&fm);
}


static u_char *
rp_stream_geo_copy_values(u_char *base, u_char *p, rp_rbtree_node_t *node,
    rp_rbtree_node_t *sentinel)
{
    rp_stream_variable_value_t           *vv;
    rp_stream_geo_variable_value_node_t  *gvvn;

    if (node == sentinel) {
        return p;
    }

    gvvn = (rp_stream_geo_variable_value_node_t *) node;
    gvvn->offset = p - base;

    vv = (rp_stream_variable_value_t *) p;
    *vv = *gvvn->value;
    p += sizeof(rp_stream_variable_value_t);
    vv->data = (u_char *) (p - base);

    p = rp_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);

    p = rp_align_ptr(p, sizeof(void *));

    p = rp_stream_geo_copy_values(base, p, node->left, sentinel);

    return rp_stream_geo_copy_values(base, p, node->right, sentinel);
}
