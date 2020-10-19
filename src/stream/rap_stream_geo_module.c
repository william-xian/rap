
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_stream_variable_value_t       *value;
    u_short                            start;
    u_short                            end;
} rap_stream_geo_range_t;


typedef struct {
    rap_radix_tree_t                  *tree;
#if (RAP_HAVE_INET6)
    rap_radix_tree_t                  *tree6;
#endif
} rap_stream_geo_trees_t;


typedef struct {
    rap_stream_geo_range_t           **low;
    rap_stream_variable_value_t       *default_value;
} rap_stream_geo_high_ranges_t;


typedef struct {
    rap_str_node_t                     sn;
    rap_stream_variable_value_t       *value;
    size_t                             offset;
} rap_stream_geo_variable_value_node_t;


typedef struct {
    rap_stream_variable_value_t       *value;
    rap_str_t                         *net;
    rap_stream_geo_high_ranges_t       high;
    rap_radix_tree_t                  *tree;
#if (RAP_HAVE_INET6)
    rap_radix_tree_t                  *tree6;
#endif
    rap_rbtree_t                       rbtree;
    rap_rbtree_node_t                  sentinel;
    rap_pool_t                        *pool;
    rap_pool_t                        *temp_pool;

    size_t                             data_size;

    rap_str_t                          include_name;
    rap_uint_t                         includes;
    rap_uint_t                         entries;

    unsigned                           ranges:1;
    unsigned                           outside_entries:1;
    unsigned                           allow_binary_include:1;
    unsigned                           binary_include:1;
} rap_stream_geo_conf_ctx_t;


typedef struct {
    union {
        rap_stream_geo_trees_t         trees;
        rap_stream_geo_high_ranges_t   high;
    } u;

    rap_int_t                          index;
} rap_stream_geo_ctx_t;


static rap_int_t rap_stream_geo_addr(rap_stream_session_t *s,
    rap_stream_geo_ctx_t *ctx, rap_addr_t *addr);

static char *rap_stream_geo_block(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_geo(rap_conf_t *cf, rap_command_t *dummy, void *conf);
static char *rap_stream_geo_range(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *value);
static char *rap_stream_geo_add_range(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static rap_uint_t rap_stream_geo_delete_range(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
static char *rap_stream_geo_cidr(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *value);
static char *rap_stream_geo_cidr_add(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_cidr_t *cidr, rap_str_t *value,
    rap_str_t *net);
static rap_stream_variable_value_t *rap_stream_geo_value(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *value);
static rap_int_t rap_stream_geo_cidr_value(rap_conf_t *cf, rap_str_t *net,
    rap_cidr_t *cidr);
static char *rap_stream_geo_include(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *name);
static rap_int_t rap_stream_geo_include_binary_base(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *name);
static void rap_stream_geo_create_binary_base(rap_stream_geo_conf_ctx_t *ctx);
static u_char *rap_stream_geo_copy_values(u_char *base, u_char *p,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);


static rap_command_t  rap_stream_geo_commands[] = {

    { rap_string("geo"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE12,
      rap_stream_geo_block,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_geo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rap_module_t  rap_stream_geo_module = {
    RAP_MODULE_V1,
    &rap_stream_geo_module_ctx,            /* module context */
    rap_stream_geo_commands,               /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


typedef struct {
    u_char    GEORNG[6];
    u_char    version;
    u_char    ptr_size;
    uint32_t  endianness;
    uint32_t  crc32;
} rap_stream_geo_header_t;


static rap_stream_geo_header_t  rap_stream_geo_header = {
    { 'G', 'E', 'O', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
};


/* geo range is AF_INET only */

static rap_int_t
rap_stream_geo_cidr_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_stream_geo_ctx_t *ctx = (rap_stream_geo_ctx_t *) data;

    in_addr_t                     inaddr;
    rap_addr_t                    addr;
    struct sockaddr_in           *sin;
    rap_stream_variable_value_t  *vv;
#if (RAP_HAVE_INET6)
    u_char                       *p;
    struct in6_addr              *inaddr6;
#endif

    if (rap_stream_geo_addr(s, ctx, &addr) != RAP_OK) {
        vv = (rap_stream_variable_value_t *)
                  rap_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        goto done;
    }

    switch (addr.sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
        p = inaddr6->s6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            vv = (rap_stream_variable_value_t *)
                      rap_radix32tree_find(ctx->u.trees.tree, inaddr);

        } else {
            vv = (rap_stream_variable_value_t *)
                      rap_radix128tree_find(ctx->u.trees.tree6, p);
        }

        break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        vv = (rap_stream_variable_value_t *)
                  rap_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr.sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        vv = (rap_stream_variable_value_t *)
                  rap_radix32tree_find(ctx->u.trees.tree, inaddr);

        break;
    }

done:

    *v = *vv;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return RAP_OK;
}


static rap_int_t
rap_stream_geo_range_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_stream_geo_ctx_t *ctx = (rap_stream_geo_ctx_t *) data;

    in_addr_t                inaddr;
    rap_addr_t               addr;
    rap_uint_t               n;
    struct sockaddr_in      *sin;
    rap_stream_geo_range_t  *range;
#if (RAP_HAVE_INET6)
    u_char                  *p;
    struct in6_addr         *inaddr6;
#endif

    *v = *ctx->u.high.default_value;

    if (rap_stream_geo_addr(s, ctx, &addr) == RAP_OK) {

        switch (addr.sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
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

#if (RAP_HAVE_UNIX_DOMAIN)
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
                if (n >= (rap_uint_t) range->start
                    && n <= (rap_uint_t) range->end)
                {
                    *v = *range->value;
                    break;
                }
            } while ((++range)->value);
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo: %v", v);

    return RAP_OK;
}


static rap_int_t
rap_stream_geo_addr(rap_stream_session_t *s, rap_stream_geo_ctx_t *ctx,
    rap_addr_t *addr)
{
    rap_stream_variable_value_t  *v;

    if (ctx->index == -1) {
        rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo started: %V", &s->connection->addr_text);

        addr->sockaddr = s->connection->sockaddr;
        addr->socklen = s->connection->socklen;
        /* addr->name = s->connection->addr_text; */

        return RAP_OK;
    }

    v = rap_stream_get_flushed_variable(s, ctx->index);

    if (v == NULL || v->not_found) {
        rap_log_debug0(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream geo not found");

        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream geo started: %v", v);

    if (rap_parse_addr(s->connection->pool, addr, v->data, v->len) == RAP_OK) {
        return RAP_OK;
    }

    return RAP_ERROR;
}


static char *
rap_stream_geo_block(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char                       *rv;
    size_t                      len;
    rap_str_t                  *value, name;
    rap_uint_t                  i;
    rap_conf_t                  save;
    rap_pool_t                 *pool;
    rap_array_t                *a;
    rap_stream_variable_t      *var;
    rap_stream_geo_ctx_t       *geo;
    rap_stream_geo_conf_ctx_t   ctx;
#if (RAP_HAVE_INET6)
    static struct in6_addr      zero;
#endif

    value = cf->args->elts;

    geo = rap_palloc(cf->pool, sizeof(rap_stream_geo_ctx_t));
    if (geo == NULL) {
        return RAP_CONF_ERROR;
    }

    name = value[1];

    if (name.data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RAP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    if (cf->args->nelts == 3) {

        geo->index = rap_stream_get_variable_index(cf, &name);
        if (geo->index == RAP_ERROR) {
            return RAP_CONF_ERROR;
        }

        name = value[2];

        if (name.data[0] != '$') {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid variable name \"%V\"", &name);
            return RAP_CONF_ERROR;
        }

        name.len--;
        name.data++;

    } else {
        geo->index = -1;
    }

    var = rap_stream_add_variable(cf, &name, RAP_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return RAP_CONF_ERROR;
    }

    pool = rap_create_pool(RAP_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ctx, sizeof(rap_stream_geo_conf_ctx_t));

    ctx.temp_pool = rap_create_pool(RAP_DEFAULT_POOL_SIZE, cf->log);
    if (ctx.temp_pool == NULL) {
        rap_destroy_pool(pool);
        return RAP_CONF_ERROR;
    }

    rap_rbtree_init(&ctx.rbtree, &ctx.sentinel, rap_str_rbtree_insert_value);

    ctx.pool = cf->pool;
    ctx.data_size = sizeof(rap_stream_geo_header_t)
                  + sizeof(rap_stream_variable_value_t)
                  + 0x10000 * sizeof(rap_stream_geo_range_t *);
    ctx.allow_binary_include = 1;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = rap_stream_geo;
    cf->handler_conf = conf;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RAP_CONF_OK) {
        goto failed;
    }

    if (ctx.ranges) {

        if (ctx.high.low && !ctx.binary_include) {
            for (i = 0; i < 0x10000; i++) {
                a = (rap_array_t *) ctx.high.low[i];

                if (a == NULL) {
                    continue;
                }

                if (a->nelts == 0) {
                    ctx.high.low[i] = NULL;
                    continue;
                }

                len = a->nelts * sizeof(rap_stream_geo_range_t);

                ctx.high.low[i] = rap_palloc(cf->pool, len + sizeof(void *));
                if (ctx.high.low[i] == NULL) {
                    goto failed;
                }

                rap_memcpy(ctx.high.low[i], a->elts, len);
                ctx.high.low[i][a->nelts].value = NULL;
                ctx.data_size += len + sizeof(void *);
            }

            if (ctx.allow_binary_include
                && !ctx.outside_entries
                && ctx.entries > 100000
                && ctx.includes == 1)
            {
                rap_stream_geo_create_binary_base(&ctx);
            }
        }

        if (ctx.high.default_value == NULL) {
            ctx.high.default_value = &rap_stream_variable_null_value;
        }

        geo->u.high = ctx.high;

        var->get_handler = rap_stream_geo_range_variable;
        var->data = (uintptr_t) geo;

    } else {
        if (ctx.tree == NULL) {
            ctx.tree = rap_radix_tree_create(cf->pool, -1);
            if (ctx.tree == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree = ctx.tree;

#if (RAP_HAVE_INET6)
        if (ctx.tree6 == NULL) {
            ctx.tree6 = rap_radix_tree_create(cf->pool, -1);
            if (ctx.tree6 == NULL) {
                goto failed;
            }
        }

        geo->u.trees.tree6 = ctx.tree6;
#endif

        var->get_handler = rap_stream_geo_cidr_variable;
        var->data = (uintptr_t) geo;

        if (rap_radix32tree_insert(ctx.tree, 0, 0,
                                   (uintptr_t) &rap_stream_variable_null_value)
            == RAP_ERROR)
        {
            goto failed;
        }

        /* RAP_BUSY is okay (default was set explicitly) */

#if (RAP_HAVE_INET6)
        if (rap_radix128tree_insert(ctx.tree6, zero.s6_addr, zero.s6_addr,
                                    (uintptr_t) &rap_stream_variable_null_value)
            == RAP_ERROR)
        {
            goto failed;
        }
#endif
    }

    rap_destroy_pool(ctx.temp_pool);
    rap_destroy_pool(pool);

    return RAP_CONF_OK;

failed:

    rap_destroy_pool(ctx.temp_pool);
    rap_destroy_pool(pool);

    return RAP_CONF_ERROR;
}


static char *
rap_stream_geo(rap_conf_t *cf, rap_command_t *dummy, void *conf)
{
    char                       *rv;
    rap_str_t                  *value;
    rap_stream_geo_conf_ctx_t  *ctx;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1) {

        if (rap_strcmp(value[0].data, "ranges") == 0) {

            if (ctx->tree
#if (RAP_HAVE_INET6)
                || ctx->tree6
#endif
               )
            {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "the \"ranges\" directive must be "
                                   "the first directive inside \"geo\" block");
                goto failed;
            }

            ctx->ranges = 1;

            rv = RAP_CONF_OK;

            goto done;
        }
    }

    if (cf->args->nelts != 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid number of the geo parameters");
        goto failed;
    }

    if (rap_strcmp(value[0].data, "include") == 0) {

        rv = rap_stream_geo_include(cf, ctx, &value[1]);

        goto done;
    }

    if (ctx->ranges) {
        rv = rap_stream_geo_range(cf, ctx, value);

    } else {
        rv = rap_stream_geo_cidr(cf, ctx, value);
    }

done:

    rap_reset_pool(cf->pool);

    return rv;

failed:

    rap_reset_pool(cf->pool);

    return RAP_CONF_ERROR;
}


static char *
rap_stream_geo_range(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    rap_str_t *value)
{
    u_char      *p, *last;
    in_addr_t    start, end;
    rap_str_t   *net;
    rap_uint_t   del;

    if (rap_strcmp(value[0].data, "default") == 0) {

        if (ctx->high.default_value) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                "duplicate default geo range value: \"%V\", old value: \"%v\"",
                &value[1], ctx->high.default_value);
        }

        ctx->high.default_value = rap_stream_geo_value(cf, ctx, &value[1]);
        if (ctx->high.default_value == NULL) {
            return RAP_CONF_ERROR;
        }

        return RAP_CONF_OK;
    }

    if (ctx->binary_include) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            ctx->include_name.data);
        return RAP_CONF_ERROR;
    }

    if (ctx->high.low == NULL) {
        ctx->high.low = rap_pcalloc(ctx->pool,
                                    0x10000 * sizeof(rap_stream_geo_range_t *));
        if (ctx->high.low == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    ctx->entries++;
    ctx->outside_entries = 1;

    if (rap_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    last = net->data + net->len;

    p = rap_strlchr(net->data, last, '-');

    if (p == NULL) {
        goto invalid;
    }

    start = rap_inet_addr(net->data, p - net->data);

    if (start == INADDR_NONE) {
        goto invalid;
    }

    start = ntohl(start);

    p++;

    end = rap_inet_addr(p, last - p);

    if (end == INADDR_NONE) {
        goto invalid;
    }

    end = ntohl(end);

    if (start > end) {
        goto invalid;
    }

    if (del) {
        if (rap_stream_geo_delete_range(cf, ctx, start, end)) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "no address range \"%V\" to delete", net);
        }

        return RAP_CONF_OK;
    }

    ctx->value = rap_stream_geo_value(cf, ctx, &value[1]);

    if (ctx->value == NULL) {
        return RAP_CONF_ERROR;
    }

    ctx->net = net;

    return rap_stream_geo_add_range(cf, ctx, start, end);

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);

    return RAP_CONF_ERROR;
}


/* the add procedure is optimized to add a growing up sequence */

static char *
rap_stream_geo_add_range(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    rap_uint_t               h, i, s, e;
    rap_array_t             *a;
    rap_stream_geo_range_t  *range;

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

        a = (rap_array_t *) ctx->high.low[h];

        if (a == NULL) {
            a = rap_array_create(ctx->temp_pool, 64,
                                 sizeof(rap_stream_geo_range_t));
            if (a == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->high.low[h] = (rap_stream_geo_range_t *) a;
        }

        i = a->nelts;
        range = a->elts;

        while (i) {

            i--;

            if (e < (rap_uint_t) range[i].start) {
                continue;
            }

            if (s > (rap_uint_t) range[i].end) {

                /* add after the range */

                range = rap_array_push(a);
                if (range == NULL) {
                    return RAP_CONF_ERROR;
                }

                range = a->elts;

                rap_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(rap_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                goto next;
            }

            if (s == (rap_uint_t) range[i].start
                && e == (rap_uint_t) range[i].end)
            {
                rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                    "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
                    ctx->net, ctx->value, range[i].value);

                range[i].value = ctx->value;

                goto next;
            }

            if (s > (rap_uint_t) range[i].start
                && e < (rap_uint_t) range[i].end)
            {
                /* split the range and insert the new one */

                range = rap_array_push(a);
                if (range == NULL) {
                    return RAP_CONF_ERROR;
                }

                range = rap_array_push(a);
                if (range == NULL) {
                    return RAP_CONF_ERROR;
                }

                range = a->elts;

                rap_memmove(&range[i + 3], &range[i + 1],
                           (a->nelts - 3 - i) * sizeof(rap_stream_geo_range_t));

                range[i + 2].start = (u_short) (e + 1);
                range[i + 2].end = range[i].end;
                range[i + 2].value = range[i].value;

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            if (s == (rap_uint_t) range[i].start
                && e < (rap_uint_t) range[i].end)
            {
                /* shift the range start and insert the new range */

                range = rap_array_push(a);
                if (range == NULL) {
                    return RAP_CONF_ERROR;
                }

                range = a->elts;

                rap_memmove(&range[i + 1], &range[i],
                           (a->nelts - 1 - i) * sizeof(rap_stream_geo_range_t));

                range[i + 1].start = (u_short) (e + 1);

                range[i].start = (u_short) s;
                range[i].end = (u_short) e;
                range[i].value = ctx->value;

                goto next;
            }

            if (s > (rap_uint_t) range[i].start
                && e == (rap_uint_t) range[i].end)
            {
                /* shift the range end and insert the new range */

                range = rap_array_push(a);
                if (range == NULL) {
                    return RAP_CONF_ERROR;
                }

                range = a->elts;

                rap_memmove(&range[i + 2], &range[i + 1],
                           (a->nelts - 2 - i) * sizeof(rap_stream_geo_range_t));

                range[i + 1].start = (u_short) s;
                range[i + 1].end = (u_short) e;
                range[i + 1].value = ctx->value;

                range[i].end = (u_short) (s - 1);

                goto next;
            }

            s = (rap_uint_t) range[i].start;
            e = (rap_uint_t) range[i].end;

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                         "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
                         ctx->net,
                         h >> 8, h & 0xff, s >> 8, s & 0xff,
                         h >> 8, h & 0xff, e >> 8, e & 0xff);

            return RAP_CONF_ERROR;
        }

        /* add the first range */

        range = rap_array_push(a);
        if (range == NULL) {
            return RAP_CONF_ERROR;
        }

        range = a->elts;

        rap_memmove(&range[1], &range[0],
                    (a->nelts - 1) * sizeof(rap_stream_geo_range_t));

        range[0].start = (u_short) s;
        range[0].end = (u_short) e;
        range[0].value = ctx->value;

    next:

        if (h == 0xffff) {
            break;
        }
    }

    return RAP_CONF_OK;
}


static rap_uint_t
rap_stream_geo_delete_range(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    in_addr_t start, in_addr_t end)
{
    in_addr_t                n;
    rap_uint_t               h, i, s, e, warn;
    rap_array_t             *a;
    rap_stream_geo_range_t  *range;

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

        a = (rap_array_t *) ctx->high.low[h];

        if (a == NULL || a->nelts == 0) {
            warn = 1;
            goto next;
        }

        range = a->elts;
        for (i = 0; i < a->nelts; i++) {

            if (s == (rap_uint_t) range[i].start
                && e == (rap_uint_t) range[i].end)
            {
                rap_memmove(&range[i], &range[i + 1],
                           (a->nelts - 1 - i) * sizeof(rap_stream_geo_range_t));

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
rap_stream_geo_cidr(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    rap_str_t *value)
{
    char        *rv;
    rap_int_t    rc, del;
    rap_str_t   *net;
    rap_cidr_t   cidr;

    if (ctx->tree == NULL) {
        ctx->tree = rap_radix_tree_create(ctx->pool, -1);
        if (ctx->tree == NULL) {
            return RAP_CONF_ERROR;
        }
    }

#if (RAP_HAVE_INET6)
    if (ctx->tree6 == NULL) {
        ctx->tree6 = rap_radix_tree_create(ctx->pool, -1);
        if (ctx->tree6 == NULL) {
            return RAP_CONF_ERROR;
        }
    }
#endif

    if (rap_strcmp(value[0].data, "default") == 0) {
        cidr.family = AF_INET;
        cidr.u.in.addr = 0;
        cidr.u.in.mask = 0;

        rv = rap_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != RAP_CONF_OK) {
            return rv;
        }

#if (RAP_HAVE_INET6)
        cidr.family = AF_INET6;
        rap_memzero(&cidr.u.in6, sizeof(rap_in6_cidr_t));

        rv = rap_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);

        if (rv != RAP_CONF_OK) {
            return rv;
        }
#endif

        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[0].data, "delete") == 0) {
        net = &value[1];
        del = 1;

    } else {
        net = &value[0];
        del = 0;
    }

    if (rap_stream_geo_cidr_value(cf, net, &cidr) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cidr.family == AF_INET) {
        cidr.u.in.addr = ntohl(cidr.u.in.addr);
        cidr.u.in.mask = ntohl(cidr.u.in.mask);
    }

    if (del) {
        switch (cidr.family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            rc = rap_radix128tree_delete(ctx->tree6,
                                         cidr.u.in6.addr.s6_addr,
                                         cidr.u.in6.mask.s6_addr);
            break;
#endif

        default: /* AF_INET */
            rc = rap_radix32tree_delete(ctx->tree, cidr.u.in.addr,
                                        cidr.u.in.mask);
            break;
        }

        if (rc != RAP_OK) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "no network \"%V\" to delete", net);
        }

        return RAP_CONF_OK;
    }

    return rap_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], net);
}


static char *
rap_stream_geo_cidr_add(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    rap_cidr_t *cidr, rap_str_t *value, rap_str_t *net)
{
    rap_int_t                     rc;
    rap_stream_variable_value_t  *val, *old;

    val = rap_stream_geo_value(cf, ctx, value);

    if (val == NULL) {
        return RAP_CONF_ERROR;
    }

    switch (cidr->family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        rc = rap_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        if (rc == RAP_OK) {
            return RAP_CONF_OK;
        }

        if (rc == RAP_ERROR) {
            return RAP_CONF_ERROR;
        }

        /* rc == RAP_BUSY */

        old = (rap_stream_variable_value_t *)
                   rap_radix128tree_find(ctx->tree6,
                                         cidr->u.in6.addr.s6_addr);

        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = rap_radix128tree_delete(ctx->tree6,
                                     cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr);

        if (rc == RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid radix tree");
            return RAP_CONF_ERROR;
        }

        rc = rap_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
                                     cidr->u.in6.mask.s6_addr,
                                     (uintptr_t) val);

        break;
#endif

    default: /* AF_INET */
        rc = rap_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        if (rc == RAP_OK) {
            return RAP_CONF_OK;
        }

        if (rc == RAP_ERROR) {
            return RAP_CONF_ERROR;
        }

        /* rc == RAP_BUSY */

        old = (rap_stream_variable_value_t *)
                   rap_radix32tree_find(ctx->tree, cidr->u.in.addr);

        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
              "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
              net, val, old);

        rc = rap_radix32tree_delete(ctx->tree,
                                    cidr->u.in.addr, cidr->u.in.mask);

        if (rc == RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid radix tree");
            return RAP_CONF_ERROR;
        }

        rc = rap_radix32tree_insert(ctx->tree, cidr->u.in.addr,
                                    cidr->u.in.mask, (uintptr_t) val);

        break;
    }

    if (rc == RAP_OK) {
        return RAP_CONF_OK;
    }

    return RAP_CONF_ERROR;
}


static rap_stream_variable_value_t *
rap_stream_geo_value(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    rap_str_t *value)
{
    uint32_t                               hash;
    rap_stream_variable_value_t           *val;
    rap_stream_geo_variable_value_node_t  *gvvn;

    hash = rap_crc32_long(value->data, value->len);

    gvvn = (rap_stream_geo_variable_value_node_t *)
               rap_str_rbtree_lookup(&ctx->rbtree, value, hash);

    if (gvvn) {
        return gvvn->value;
    }

    val = rap_palloc(ctx->pool, sizeof(rap_stream_variable_value_t));
    if (val == NULL) {
        return NULL;
    }

    val->len = value->len;
    val->data = rap_pstrdup(ctx->pool, value);
    if (val->data == NULL) {
        return NULL;
    }

    val->valid = 1;
    val->no_cacheable = 0;
    val->not_found = 0;

    gvvn = rap_palloc(ctx->temp_pool,
                      sizeof(rap_stream_geo_variable_value_node_t));
    if (gvvn == NULL) {
        return NULL;
    }

    gvvn->sn.node.key = hash;
    gvvn->sn.str.len = val->len;
    gvvn->sn.str.data = val->data;
    gvvn->value = val;
    gvvn->offset = 0;

    rap_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);

    ctx->data_size += rap_align(sizeof(rap_stream_variable_value_t)
                                + value->len, sizeof(void *));

    return val;
}


static rap_int_t
rap_stream_geo_cidr_value(rap_conf_t *cf, rap_str_t *net, rap_cidr_t *cidr)
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


static char *
rap_stream_geo_include(rap_conf_t *cf, rap_stream_geo_conf_ctx_t *ctx,
    rap_str_t *name)
{
    char       *rv;
    rap_str_t   file;

    file.len = name->len + 4;
    file.data = rap_pnalloc(ctx->temp_pool, name->len + 5);
    if (file.data == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_sprintf(file.data, "%V.bin%Z", name);

    if (rap_conf_full_name(cf->cycle, &file, 1) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (ctx->ranges) {
        rap_log_debug1(RAP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        switch (rap_stream_geo_include_binary_base(cf, ctx, &file)) {
        case RAP_OK:
            return RAP_CONF_OK;
        case RAP_ERROR:
            return RAP_CONF_ERROR;
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

    rap_log_debug1(RAP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    rv = rap_conf_parse(cf, &file);

    ctx->includes++;
    ctx->outside_entries = 0;

    return rv;
}


static rap_int_t
rap_stream_geo_include_binary_base(rap_conf_t *cf,
    rap_stream_geo_conf_ctx_t *ctx, rap_str_t *name)
{
    u_char                       *base, ch;
    time_t                        mtime;
    size_t                        size, len;
    ssize_t                       n;
    uint32_t                      crc32;
    rap_err_t                     err;
    rap_int_t                     rc;
    rap_uint_t                    i;
    rap_file_t                    file;
    rap_file_info_t               fi;
    rap_stream_geo_range_t       *range, **ranges;
    rap_stream_geo_header_t      *header;
    rap_stream_variable_value_t  *vv;

    rap_memzero(&file, sizeof(rap_file_t));
    file.name = *name;
    file.log = cf->log;

    file.fd = rap_open_file(name->data, RAP_FILE_RDONLY, RAP_FILE_OPEN, 0);

    if (file.fd == RAP_INVALID_FILE) {
        err = rap_errno;
        if (err != RAP_ENOENT) {
            rap_conf_log_error(RAP_LOG_CRIT, cf, err,
                               rap_open_file_n " \"%s\" failed", name->data);
        }
        return RAP_DECLINED;
    }

    if (ctx->outside_entries) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
            "binary geo range base \"%s\" cannot be mixed with usual entries",
            name->data);
        rc = RAP_ERROR;
        goto done;
    }

    if (ctx->binary_include) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
            "second binary geo range base \"%s\" cannot be mixed with \"%s\"",
            name->data, ctx->include_name.data);
        rc = RAP_ERROR;
        goto done;
    }

    if (rap_fd_info(file.fd, &fi) == RAP_FILE_ERROR) {
        rap_conf_log_error(RAP_LOG_CRIT, cf, rap_errno,
                           rap_fd_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    size = (size_t) rap_file_size(&fi);
    mtime = rap_file_mtime(&fi);

    ch = name->data[name->len - 4];
    name->data[name->len - 4] = '\0';

    if (rap_file_info(name->data, &fi) == RAP_FILE_ERROR) {
        rap_conf_log_error(RAP_LOG_CRIT, cf, rap_errno,
                           rap_file_info_n " \"%s\" failed", name->data);
        goto failed;
    }

    name->data[name->len - 4] = ch;

    if (mtime < rap_file_mtime(&fi)) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "stale binary geo range base \"%s\"", name->data);
        goto failed;
    }

    base = rap_palloc(ctx->pool, size);
    if (base == NULL) {
        goto failed;
    }

    n = rap_read_file(&file, base, size, 0);

    if (n == RAP_ERROR) {
        rap_conf_log_error(RAP_LOG_CRIT, cf, rap_errno,
                           rap_read_file_n " \"%s\" failed", name->data);
        goto failed;
    }

    if ((size_t) n != size) {
        rap_conf_log_error(RAP_LOG_CRIT, cf, 0,
            rap_read_file_n " \"%s\" returned only %z bytes instead of %z",
            name->data, n, size);
        goto failed;
    }

    header = (rap_stream_geo_header_t *) base;

    if (size < 16 || rap_memcmp(&rap_stream_geo_header, header, 12) != 0) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
             "incompatible binary geo range base \"%s\"", name->data);
        goto failed;
    }

    rap_crc32_init(crc32);

    vv = (rap_stream_variable_value_t *)
            (base + sizeof(rap_stream_geo_header_t));

    while (vv->data) {
        len = rap_align(sizeof(rap_stream_variable_value_t) + vv->len,
                        sizeof(void *));
        rap_crc32_update(&crc32, (u_char *) vv, len);
        vv->data += (size_t) base;
        vv = (rap_stream_variable_value_t *) ((u_char *) vv + len);
    }
    rap_crc32_update(&crc32, (u_char *) vv,
                     sizeof(rap_stream_variable_value_t));
    vv++;

    ranges = (rap_stream_geo_range_t **) vv;

    for (i = 0; i < 0x10000; i++) {
        rap_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
        if (ranges[i]) {
            ranges[i] = (rap_stream_geo_range_t *)
                            ((u_char *) ranges[i] + (size_t) base);
        }
    }

    range = (rap_stream_geo_range_t *) &ranges[0x10000];

    while ((u_char *) range < base + size) {
        while (range->value) {
            rap_crc32_update(&crc32, (u_char *) range,
                             sizeof(rap_stream_geo_range_t));
            range->value = (rap_stream_variable_value_t *)
                               ((u_char *) range->value + (size_t) base);
            range++;
        }
        rap_crc32_update(&crc32, (u_char *) range, sizeof(void *));
        range = (rap_stream_geo_range_t *) ((u_char *) range + sizeof(void *));
    }

    rap_crc32_final(crc32);

    if (crc32 != header->crc32) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                  "CRC32 mismatch in binary geo range base \"%s\"", name->data);
        goto failed;
    }

    rap_conf_log_error(RAP_LOG_NOTICE, cf, 0,
                       "using binary geo range base \"%s\"", name->data);

    ctx->include_name = *name;
    ctx->binary_include = 1;
    ctx->high.low = ranges;
    rc = RAP_OK;

    goto done;

failed:

    rc = RAP_DECLINED;

done:

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", name->data);
    }

    return rc;
}


static void
rap_stream_geo_create_binary_base(rap_stream_geo_conf_ctx_t *ctx)
{
    u_char                                *p;
    uint32_t                               hash;
    rap_str_t                              s;
    rap_uint_t                             i;
    rap_file_mapping_t                     fm;
    rap_stream_geo_range_t                *r, *range, **ranges;
    rap_stream_geo_header_t               *header;
    rap_stream_geo_variable_value_node_t  *gvvn;

    fm.name = rap_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
    if (fm.name == NULL) {
        return;
    }

    rap_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);

    fm.size = ctx->data_size;
    fm.log = ctx->pool->log;

    rap_log_error(RAP_LOG_NOTICE, fm.log, 0,
                  "creating binary geo range base \"%s\"", fm.name);

    if (rap_create_file_mapping(&fm) != RAP_OK) {
        return;
    }

    p = rap_cpymem(fm.addr, &rap_stream_geo_header,
                   sizeof(rap_stream_geo_header_t));

    p = rap_stream_geo_copy_values(fm.addr, p, ctx->rbtree.root,
                                   ctx->rbtree.sentinel);

    p += sizeof(rap_stream_variable_value_t);

    ranges = (rap_stream_geo_range_t **) p;

    p += 0x10000 * sizeof(rap_stream_geo_range_t *);

    for (i = 0; i < 0x10000; i++) {
        r = ctx->high.low[i];
        if (r == NULL) {
            continue;
        }

        range = (rap_stream_geo_range_t *) p;
        ranges[i] = (rap_stream_geo_range_t *) (p - (u_char *) fm.addr);

        do {
            s.len = r->value->len;
            s.data = r->value->data;
            hash = rap_crc32_long(s.data, s.len);
            gvvn = (rap_stream_geo_variable_value_node_t *)
                        rap_str_rbtree_lookup(&ctx->rbtree, &s, hash);

            range->value = (rap_stream_variable_value_t *) gvvn->offset;
            range->start = r->start;
            range->end = r->end;
            range++;

        } while ((++r)->value);

        range->value = NULL;

        p = (u_char *) range + sizeof(void *);
    }

    header = fm.addr;
    header->crc32 = rap_crc32_long((u_char *) fm.addr
                                       + sizeof(rap_stream_geo_header_t),
                                   fm.size - sizeof(rap_stream_geo_header_t));

    rap_close_file_mapping(&fm);
}


static u_char *
rap_stream_geo_copy_values(u_char *base, u_char *p, rap_rbtree_node_t *node,
    rap_rbtree_node_t *sentinel)
{
    rap_stream_variable_value_t           *vv;
    rap_stream_geo_variable_value_node_t  *gvvn;

    if (node == sentinel) {
        return p;
    }

    gvvn = (rap_stream_geo_variable_value_node_t *) node;
    gvvn->offset = p - base;

    vv = (rap_stream_variable_value_t *) p;
    *vv = *gvvn->value;
    p += sizeof(rap_stream_variable_value_t);
    vv->data = (u_char *) (p - base);

    p = rap_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);

    p = rap_align_ptr(p, sizeof(void *));

    p = rap_stream_geo_copy_values(base, p, node->left, sentinel);

    return rap_stream_geo_copy_values(base, p, node->right, sentinel);
}
