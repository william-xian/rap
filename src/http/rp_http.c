
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static char *rp_http_block(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static rp_int_t rp_http_init_phases(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf);
static rp_int_t rp_http_init_headers_in_hash(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf);
static rp_int_t rp_http_init_phase_handlers(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf);

static rp_int_t rp_http_add_addresses(rp_conf_t *cf,
    rp_http_core_srv_conf_t *cscf, rp_http_conf_port_t *port,
    rp_http_listen_opt_t *lsopt);
static rp_int_t rp_http_add_address(rp_conf_t *cf,
    rp_http_core_srv_conf_t *cscf, rp_http_conf_port_t *port,
    rp_http_listen_opt_t *lsopt);
static rp_int_t rp_http_add_server(rp_conf_t *cf,
    rp_http_core_srv_conf_t *cscf, rp_http_conf_addr_t *addr);

static char *rp_http_merge_servers(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf, rp_http_module_t *module,
    rp_uint_t ctx_index);
static char *rp_http_merge_locations(rp_conf_t *cf,
    rp_queue_t *locations, void **loc_conf, rp_http_module_t *module,
    rp_uint_t ctx_index);
static rp_int_t rp_http_init_locations(rp_conf_t *cf,
    rp_http_core_srv_conf_t *cscf, rp_http_core_loc_conf_t *pclcf);
static rp_int_t rp_http_init_static_location_trees(rp_conf_t *cf,
    rp_http_core_loc_conf_t *pclcf);
static rp_int_t rp_http_cmp_locations(const rp_queue_t *one,
    const rp_queue_t *two);
static rp_int_t rp_http_join_exact_locations(rp_conf_t *cf,
    rp_queue_t *locations);
static void rp_http_create_locations_list(rp_queue_t *locations,
    rp_queue_t *q);
static rp_http_location_tree_node_t *
    rp_http_create_locations_tree(rp_conf_t *cf, rp_queue_t *locations,
    size_t prefix);

static rp_int_t rp_http_optimize_servers(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf, rp_array_t *ports);
static rp_int_t rp_http_server_names(rp_conf_t *cf,
    rp_http_core_main_conf_t *cmcf, rp_http_conf_addr_t *addr);
static rp_int_t rp_http_cmp_conf_addrs(const void *one, const void *two);
static int rp_libc_cdecl rp_http_cmp_dns_wildcards(const void *one,
    const void *two);

static rp_int_t rp_http_init_listening(rp_conf_t *cf,
    rp_http_conf_port_t *port);
static rp_listening_t *rp_http_add_listening(rp_conf_t *cf,
    rp_http_conf_addr_t *addr);
static rp_int_t rp_http_add_addrs(rp_conf_t *cf, rp_http_port_t *hport,
    rp_http_conf_addr_t *addr);
#if (RP_HAVE_INET6)
static rp_int_t rp_http_add_addrs6(rp_conf_t *cf, rp_http_port_t *hport,
    rp_http_conf_addr_t *addr);
#endif

rp_uint_t   rp_http_max_module;


rp_http_output_header_filter_pt  rp_http_top_header_filter;
rp_http_output_body_filter_pt    rp_http_top_body_filter;
rp_http_request_body_filter_pt   rp_http_top_request_body_filter;


rp_str_t  rp_http_html_default_types[] = {
    rp_string("text/html"),
    rp_null_string
};


static rp_command_t  rp_http_commands[] = {

    { rp_string("http"),
      RP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_http_block,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_http_module_ctx = {
    rp_string("http"),
    NULL,
    NULL
};


rp_module_t  rp_http_module = {
    RP_MODULE_V1,
    &rp_http_module_ctx,                  /* module context */
    rp_http_commands,                     /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static char *
rp_http_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                        *rv;
    rp_uint_t                   mi, m, s;
    rp_conf_t                   pcf;
    rp_http_module_t           *module;
    rp_http_conf_ctx_t         *ctx;
    rp_http_core_loc_conf_t    *clcf;
    rp_http_core_srv_conf_t   **cscfp;
    rp_http_core_main_conf_t   *cmcf;

    if (*(rp_http_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main http context */

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    *(rp_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    rp_http_max_module = rp_count_modules(cf->cycle, RP_HTTP_MODULE);


    /* the http main_conf context, it is the same in the all http contexts */

    ctx->main_conf = rp_pcalloc(cf->pool,
                                 sizeof(void *) * rp_http_max_module);
    if (ctx->main_conf == NULL) {
        return RP_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return RP_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return RP_CONF_ERROR;
            }
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return RP_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }

    /* parse inside the http{} block */

    cf->module_type = RP_HTTP_MODULE;
    cf->cmd_type = RP_HTTP_MAIN_CONF;
    rv = rp_conf_parse(cf, NULL);

    if (rv != RP_CONF_OK) {
        goto failed;
    }

    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

    cmcf = ctx->main_conf[rp_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init http{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != RP_CONF_OK) {
                goto failed;
            }
        }

        rv = rp_http_merge_servers(cf, cmcf, module, mi);
        if (rv != RP_CONF_OK) {
            goto failed;
        }
    }


    /* create location trees */

    for (s = 0; s < cmcf->servers.nelts; s++) {

        clcf = cscfp[s]->ctx->loc_conf[rp_http_core_module.ctx_index];

        if (rp_http_init_locations(cf, cscfp[s], clcf) != RP_OK) {
            return RP_CONF_ERROR;
        }

        if (rp_http_init_static_location_trees(cf, clcf) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }


    if (rp_http_init_phases(cf, cmcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_http_init_headers_in_hash(cf, cmcf) != RP_OK) {
        return RP_CONF_ERROR;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }

    if (rp_http_variables_init_vars(cf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    *cf = pcf;


    if (rp_http_init_phase_handlers(cf, cmcf) != RP_OK) {
        return RP_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    if (rp_http_optimize_servers(cf, cmcf, cmcf->ports) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}


static rp_int_t
rp_http_init_phases(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf)
{
    if (rp_array_init(&cmcf->phases[RP_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_PRECONTENT_PHASE].handlers,
                       cf->pool, 2, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_http_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    return RP_OK;
}


static rp_int_t
rp_http_init_headers_in_hash(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf)
{
    rp_array_t         headers_in;
    rp_hash_key_t     *hk;
    rp_hash_init_t     hash;
    rp_http_header_t  *header;

    if (rp_array_init(&headers_in, cf->temp_pool, 32, sizeof(rp_hash_key_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    for (header = rp_http_headers_in; header->name.len; header++) {
        hk = rp_array_push(&headers_in);
        if (hk == NULL) {
            return RP_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = rp_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &cmcf->headers_in_hash;
    hash.key = rp_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = rp_align(64, rp_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rp_hash_init(&hash, headers_in.elts, headers_in.nelts) != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}


static rp_int_t
rp_http_init_phase_handlers(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf)
{
    rp_int_t                   j;
    rp_uint_t                  i, n;
    rp_uint_t                  find_config_index, use_rewrite, use_access;
    rp_http_handler_pt        *h;
    rp_http_phase_handler_t   *ph;
    rp_http_phase_handler_pt   checker;

    cmcf->phase_engine.server_rewrite_index = (rp_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (rp_uint_t) -1;
    find_config_index = 0;
    use_rewrite = cmcf->phases[RP_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[RP_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    n = 1                  /* find config phase */
        + use_rewrite      /* post rewrite phase */
        + use_access;      /* post access phase */

    for (i = 0; i < RP_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = rp_pcalloc(cf->pool,
                     n * sizeof(rp_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return RP_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < RP_HTTP_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

        case RP_HTTP_SERVER_REWRITE_PHASE:
            if (cmcf->phase_engine.server_rewrite_index == (rp_uint_t) -1) {
                cmcf->phase_engine.server_rewrite_index = n;
            }
            checker = rp_http_core_rewrite_phase;

            break;

        case RP_HTTP_FIND_CONFIG_PHASE:
            find_config_index = n;

            ph->checker = rp_http_core_find_config_phase;
            n++;
            ph++;

            continue;

        case RP_HTTP_REWRITE_PHASE:
            if (cmcf->phase_engine.location_rewrite_index == (rp_uint_t) -1) {
                cmcf->phase_engine.location_rewrite_index = n;
            }
            checker = rp_http_core_rewrite_phase;

            break;

        case RP_HTTP_POST_REWRITE_PHASE:
            if (use_rewrite) {
                ph->checker = rp_http_core_post_rewrite_phase;
                ph->next = find_config_index;
                n++;
                ph++;
            }

            continue;

        case RP_HTTP_ACCESS_PHASE:
            checker = rp_http_core_access_phase;
            n++;
            break;

        case RP_HTTP_POST_ACCESS_PHASE:
            if (use_access) {
                ph->checker = rp_http_core_post_access_phase;
                ph->next = n;
                ph++;
            }

            continue;

        case RP_HTTP_CONTENT_PHASE:
            checker = rp_http_core_content_phase;
            break;

        default:
            checker = rp_http_core_generic_phase;
        }

        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }

    return RP_OK;
}


static char *
rp_http_merge_servers(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf,
    rp_http_module_t *module, rp_uint_t ctx_index)
{
    char                        *rv;
    rp_uint_t                   s;
    rp_http_conf_ctx_t         *ctx, saved;
    rp_http_core_loc_conf_t    *clcf;
    rp_http_core_srv_conf_t   **cscfp;

    cscfp = cmcf->servers.elts;
    ctx = (rp_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = RP_CONF_OK;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* merge the server{}s' srv_conf's */

        ctx->srv_conf = cscfp[s]->ctx->srv_conf;

        if (module->merge_srv_conf) {
            rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
                                        cscfp[s]->ctx->srv_conf[ctx_index]);
            if (rv != RP_CONF_OK) {
                goto failed;
            }
        }

        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */

            ctx->loc_conf = cscfp[s]->ctx->loc_conf;

            rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
                                        cscfp[s]->ctx->loc_conf[ctx_index]);
            if (rv != RP_CONF_OK) {
                goto failed;
            }

            /* merge the locations{}' loc_conf's */

            clcf = cscfp[s]->ctx->loc_conf[rp_http_core_module.ctx_index];

            rv = rp_http_merge_locations(cf, clcf->locations,
                                          cscfp[s]->ctx->loc_conf,
                                          module, ctx_index);
            if (rv != RP_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}


static char *
rp_http_merge_locations(rp_conf_t *cf, rp_queue_t *locations,
    void **loc_conf, rp_http_module_t *module, rp_uint_t ctx_index)
{
    char                       *rv;
    rp_queue_t                *q;
    rp_http_conf_ctx_t        *ctx, saved;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_location_queue_t  *lq;

    if (locations == NULL) {
        return RP_CONF_OK;
    }

    ctx = (rp_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    for (q = rp_queue_head(locations);
         q != rp_queue_sentinel(locations);
         q = rp_queue_next(q))
    {
        lq = (rp_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
        ctx->loc_conf = clcf->loc_conf;

        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        if (rv != RP_CONF_OK) {
            return rv;
        }

        rv = rp_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
        if (rv != RP_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_init_locations(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_core_loc_conf_t *pclcf)
{
    rp_uint_t                   n;
    rp_queue_t                 *q, *locations, *named, tail;
    rp_http_core_loc_conf_t    *clcf;
    rp_http_location_queue_t   *lq;
    rp_http_core_loc_conf_t   **clcfp;
#if (RP_PCRE)
    rp_uint_t                   r;
    rp_queue_t                 *regex;
#endif

    locations = pclcf->locations;

    if (locations == NULL) {
        return RP_OK;
    }

    rp_queue_sort(locations, rp_http_cmp_locations);

    named = NULL;
    n = 0;
#if (RP_PCRE)
    regex = NULL;
    r = 0;
#endif

    for (q = rp_queue_head(locations);
         q != rp_queue_sentinel(locations);
         q = rp_queue_next(q))
    {
        lq = (rp_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (rp_http_init_locations(cf, NULL, clcf) != RP_OK) {
            return RP_ERROR;
        }

#if (RP_PCRE)

        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        if (clcf->noname) {
            break;
        }
    }

    if (q != rp_queue_sentinel(locations)) {
        rp_queue_split(locations, q, &tail);
    }

    if (named) {
        clcfp = rp_palloc(cf->pool,
                           (n + 1) * sizeof(rp_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return RP_ERROR;
        }

        cscf->named_locations = clcfp;

        for (q = named;
             q != rp_queue_sentinel(locations);
             q = rp_queue_next(q))
        {
            lq = (rp_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        rp_queue_split(locations, named, &tail);
    }

#if (RP_PCRE)

    if (regex) {

        clcfp = rp_palloc(cf->pool,
                           (r + 1) * sizeof(rp_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return RP_ERROR;
        }

        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != rp_queue_sentinel(locations);
             q = rp_queue_next(q))
        {
            lq = (rp_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        rp_queue_split(locations, regex, &tail);
    }

#endif

    return RP_OK;
}


static rp_int_t
rp_http_init_static_location_trees(rp_conf_t *cf,
    rp_http_core_loc_conf_t *pclcf)
{
    rp_queue_t                *q, *locations;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_location_queue_t  *lq;

    locations = pclcf->locations;

    if (locations == NULL) {
        return RP_OK;
    }

    if (rp_queue_empty(locations)) {
        return RP_OK;
    }

    for (q = rp_queue_head(locations);
         q != rp_queue_sentinel(locations);
         q = rp_queue_next(q))
    {
        lq = (rp_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (rp_http_init_static_location_trees(cf, clcf) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (rp_http_join_exact_locations(cf, locations) != RP_OK) {
        return RP_ERROR;
    }

    rp_http_create_locations_list(locations, rp_queue_head(locations));

    pclcf->static_locations = rp_http_create_locations_tree(cf, locations, 0);
    if (pclcf->static_locations == NULL) {
        return RP_ERROR;
    }

    return RP_OK;
}


rp_int_t
rp_http_add_location(rp_conf_t *cf, rp_queue_t **locations,
    rp_http_core_loc_conf_t *clcf)
{
    rp_http_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = rp_palloc(cf->temp_pool,
                                sizeof(rp_http_location_queue_t));
        if (*locations == NULL) {
            return RP_ERROR;
        }

        rp_queue_init(*locations);
    }

    lq = rp_palloc(cf->temp_pool, sizeof(rp_http_location_queue_t));
    if (lq == NULL) {
        return RP_ERROR;
    }

    if (clcf->exact_match
#if (RP_PCRE)
        || clcf->regex
#endif
        || clcf->named || clcf->noname)
    {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;

    rp_queue_init(&lq->list);

    rp_queue_insert_tail(*locations, &lq->queue);

    return RP_OK;
}


static rp_int_t
rp_http_cmp_locations(const rp_queue_t *one, const rp_queue_t *two)
{
    rp_int_t                   rc;
    rp_http_core_loc_conf_t   *first, *second;
    rp_http_location_queue_t  *lq1, *lq2;

    lq1 = (rp_http_location_queue_t *) one;
    lq2 = (rp_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return rp_strcmp(first->name.data, second->name.data);
    }

#if (RP_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = rp_filename_cmp(first->name.data, second->name.data,
                          rp_min(first->name.len, second->name.len) + 1);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static rp_int_t
rp_http_join_exact_locations(rp_conf_t *cf, rp_queue_t *locations)
{
    rp_queue_t                *q, *x;
    rp_http_location_queue_t  *lq, *lx;

    q = rp_queue_head(locations);

    while (q != rp_queue_last(locations)) {

        x = rp_queue_next(q);

        lq = (rp_http_location_queue_t *) q;
        lx = (rp_http_location_queue_t *) x;

        if (lq->name->len == lx->name->len
            && rp_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
               == 0)
        {
            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                rp_log_error(RP_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return RP_ERROR;
            }

            lq->inclusive = lx->inclusive;

            rp_queue_remove(x);

            continue;
        }

        q = rp_queue_next(q);
    }

    return RP_OK;
}


static void
rp_http_create_locations_list(rp_queue_t *locations, rp_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    rp_queue_t                *x, tail;
    rp_http_location_queue_t  *lq, *lx;

    if (q == rp_queue_last(locations)) {
        return;
    }

    lq = (rp_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        rp_http_create_locations_list(locations, rp_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = rp_queue_next(q);
         x != rp_queue_sentinel(locations);
         x = rp_queue_next(x))
    {
        lx = (rp_http_location_queue_t *) x;

        if (len > lx->name->len
            || rp_filename_cmp(name, lx->name->data, len) != 0)
        {
            break;
        }
    }

    q = rp_queue_next(q);

    if (q == x) {
        rp_http_create_locations_list(locations, x);
        return;
    }

    rp_queue_split(locations, q, &tail);
    rp_queue_add(&lq->list, &tail);

    if (x == rp_queue_sentinel(locations)) {
        rp_http_create_locations_list(&lq->list, rp_queue_head(&lq->list));
        return;
    }

    rp_queue_split(&lq->list, x, &tail);
    rp_queue_add(locations, &tail);

    rp_http_create_locations_list(&lq->list, rp_queue_head(&lq->list));

    rp_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static rp_http_location_tree_node_t *
rp_http_create_locations_tree(rp_conf_t *cf, rp_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    rp_queue_t                    *q, tail;
    rp_http_location_queue_t      *lq;
    rp_http_location_tree_node_t  *node;

    q = rp_queue_middle(locations);

    lq = (rp_http_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = rp_palloc(cf->pool,
                      offsetof(rp_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                           || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_char) len;
    rp_memcpy(node->name, &lq->name->data[prefix], len);

    rp_queue_split(locations, q, &tail);

    if (rp_queue_empty(locations)) {
        /*
         * rp_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = rp_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    rp_queue_remove(q);

    if (rp_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = rp_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (rp_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = rp_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}


rp_int_t
rp_http_add_listen(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_listen_opt_t *lsopt)
{
    in_port_t                   p;
    rp_uint_t                  i;
    struct sockaddr            *sa;
    rp_http_conf_port_t       *port;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = rp_array_create(cf->temp_pool, 2,
                                       sizeof(rp_http_conf_port_t));
        if (cmcf->ports == NULL) {
            return RP_ERROR;
        }
    }

    sa = lsopt->sockaddr;
    p = rp_inet_get_port(sa);

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        if (p != port[i].port || sa->sa_family != port[i].family) {
            continue;
        }

        /* a port is already in the port list */

        return rp_http_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    port = rp_array_push(cmcf->ports);
    if (port == NULL) {
        return RP_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;
    port->addrs.elts = NULL;

    return rp_http_add_address(cf, cscf, port, lsopt);
}


static rp_int_t
rp_http_add_addresses(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_conf_port_t *port, rp_http_listen_opt_t *lsopt)
{
    rp_uint_t             i, default_server, proxy_protocol;
    rp_http_conf_addr_t  *addr;
#if (RP_HTTP_SSL)
    rp_uint_t             ssl;
#endif
#if (RP_HTTP_V2)
    rp_uint_t             http2;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (rp_cmp_sockaddr(lsopt->sockaddr, lsopt->socklen,
                             addr[i].opt.sockaddr,
                             addr[i].opt.socklen, 0)
            != RP_OK)
        {
            continue;
        }

        /* the address is already in the address list */

        if (rp_http_add_server(cf, cscf, &addr[i]) != RP_OK) {
            return RP_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;

#if (RP_HTTP_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
#endif
#if (RP_HTTP_V2)
        http2 = lsopt->http2 || addr[i].opt.http2;
#endif

        if (lsopt->set) {

            if (addr[i].opt.set) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "duplicate listen options for %V",
                                   &addr[i].opt.addr_text);
                return RP_ERROR;
            }

            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "a duplicate default server for %V",
                                   &addr[i].opt.addr_text);
                return RP_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;
#if (RP_HTTP_SSL)
        addr[i].opt.ssl = ssl;
#endif
#if (RP_HTTP_V2)
        addr[i].opt.http2 = http2;
#endif

        return RP_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return rp_http_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static rp_int_t
rp_http_add_address(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_conf_port_t *port, rp_http_listen_opt_t *lsopt)
{
    rp_http_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (rp_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(rp_http_conf_addr_t))
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

#if (RP_HTTP_V2 && RP_HTTP_SSL                                              \
     && !defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
     && !defined TLSEXT_TYPE_next_proto_neg)

    if (lsopt->http2 && lsopt->ssl) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "rap was built with OpenSSL that lacks ALPN "
                           "and NPN support, HTTP/2 is not enabled for %V",
                           &lsopt->addr_text);
    }

#endif

    addr = rp_array_push(&port->addrs);
    if (addr == NULL) {
        return RP_ERROR;
    }

    addr->opt = *lsopt;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (RP_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return rp_http_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

static rp_int_t
rp_http_add_server(rp_conf_t *cf, rp_http_core_srv_conf_t *cscf,
    rp_http_conf_addr_t *addr)
{
    rp_uint_t                  i;
    rp_http_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (rp_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(rp_http_core_srv_conf_t *))
            != RP_OK)
        {
            return RP_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "a duplicate listen %V",
                                   &addr->opt.addr_text);
                return RP_ERROR;
            }
        }
    }

    server = rp_array_push(&addr->servers);
    if (server == NULL) {
        return RP_ERROR;
    }

    *server = cscf;

    return RP_OK;
}


static rp_int_t
rp_http_optimize_servers(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf,
    rp_array_t *ports)
{
    rp_uint_t             p, a;
    rp_http_conf_port_t  *port;
    rp_http_conf_addr_t  *addr;

    if (ports == NULL) {
        return RP_OK;
    }

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        rp_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(rp_http_conf_addr_t), rp_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (addr[a].servers.nelts > 1
#if (RP_PCRE)
                || addr[a].default_server->captures
#endif
               )
            {
                if (rp_http_server_names(cf, cmcf, &addr[a]) != RP_OK) {
                    return RP_ERROR;
                }
            }
        }

        if (rp_http_init_listening(cf, &port[p]) != RP_OK) {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_server_names(rp_conf_t *cf, rp_http_core_main_conf_t *cmcf,
    rp_http_conf_addr_t *addr)
{
    rp_int_t                   rc;
    rp_uint_t                  n, s;
    rp_hash_init_t             hash;
    rp_hash_keys_arrays_t      ha;
    rp_http_server_name_t     *name;
    rp_http_core_srv_conf_t  **cscfp;
#if (RP_PCRE)
    rp_uint_t                  regex, i;

    regex = 0;
#endif

    rp_memzero(&ha, sizeof(rp_hash_keys_arrays_t));

    ha.temp_pool = rp_create_pool(RP_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return RP_ERROR;
    }

    ha.pool = cf->pool;

    if (rp_hash_keys_array_init(&ha, RP_HASH_LARGE) != RP_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (RP_PCRE)
            if (name[n].regex) {
                regex++;
                continue;
            }
#endif

            rc = rp_hash_add_key(&ha, &name[n].name, name[n].server,
                                  RP_HASH_WILDCARD_KEY);

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            if (rc == RP_DECLINED) {
                rp_log_error(RP_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %V",
                              &name[n].name, &addr->opt.addr_text);
                return RP_ERROR;
            }

            if (rc == RP_BUSY) {
                rp_log_error(RP_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %V, ignored",
                              &name[n].name, &addr->opt.addr_text);
            }
        }
    }

    hash.key = rp_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;

        if (rp_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != RP_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        rp_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(rp_hash_key_t), rp_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (rp_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != RP_OK)
        {
            goto failed;
        }

        addr->wc_head = (rp_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        rp_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(rp_hash_key_t), rp_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (rp_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != RP_OK)
        {
            goto failed;
        }

        addr->wc_tail = (rp_hash_wildcard_t *) hash.hash;
    }

    rp_destroy_pool(ha.temp_pool);

#if (RP_PCRE)

    if (regex == 0) {
        return RP_OK;
    }

    addr->nregex = regex;
    addr->regex = rp_palloc(cf->pool, regex * sizeof(rp_http_server_name_t));
    if (addr->regex == NULL) {
        return RP_ERROR;
    }

    i = 0;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                addr->regex[i++] = name[n];
            }
        }
    }

#endif

    return RP_OK;

failed:

    rp_destroy_pool(ha.temp_pool);

    return RP_ERROR;
}


static rp_int_t
rp_http_cmp_conf_addrs(const void *one, const void *two)
{
    rp_http_conf_addr_t  *first, *second;

    first = (rp_http_conf_addr_t *) one;
    second = (rp_http_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int rp_libc_cdecl
rp_http_cmp_dns_wildcards(const void *one, const void *two)
{
    rp_hash_key_t  *first, *second;

    first = (rp_hash_key_t *) one;
    second = (rp_hash_key_t *) two;

    return rp_dns_strcmp(first->key.data, second->key.data);
}


static rp_int_t
rp_http_init_listening(rp_conf_t *cf, rp_http_conf_port_t *port)
{
    rp_uint_t                 i, last, bind_wildcard;
    rp_listening_t           *ls;
    rp_http_port_t           *hport;
    rp_http_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].opt.bind) {
            i++;
            continue;
        }

        ls = rp_http_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return RP_ERROR;
        }

        hport = rp_pcalloc(cf->pool, sizeof(rp_http_port_t));
        if (hport == NULL) {
            return RP_ERROR;
        }

        ls->servers = hport;

        hport->naddrs = i + 1;

        switch (ls->sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            if (rp_http_add_addrs6(cf, hport, addr) != RP_OK) {
                return RP_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (rp_http_add_addrs(cf, hport, addr) != RP_OK) {
                return RP_ERROR;
            }
            break;
        }

        addr++;
        last--;
    }

    return RP_OK;
}


static rp_listening_t *
rp_http_add_listening(rp_conf_t *cf, rp_http_conf_addr_t *addr)
{
    rp_listening_t           *ls;
    rp_http_core_loc_conf_t  *clcf;
    rp_http_core_srv_conf_t  *cscf;

    ls = rp_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;

    ls->handler = rp_http_init_connection;

    cscf = addr->default_server;
    ls->pool_size = cscf->connection_pool_size;
    ls->post_accept_timeout = cscf->client_header_timeout;

    clcf = cscf->ctx->loc_conf[rp_http_core_module.ctx_index];

    ls->logp = clcf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = rp_accept_log_error;

#if (RP_WIN32)
    {
    rp_iocp_conf_t  *iocpcf = NULL;

    if (rp_get_conf(cf->cycle->conf_ctx, rp_events_module)) {
        iocpcf = rp_event_get_conf(cf->cycle->conf_ctx, rp_iocp_module);
    }
    if (iocpcf && iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (RP_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (RP_HAVE_INET6)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (RP_HAVE_SETFIB)
    ls->setfib = addr->opt.setfib;
#endif

#if (RP_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

#if (RP_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    return ls;
}


static rp_int_t
rp_http_add_addrs(rp_conf_t *cf, rp_http_port_t *hport,
    rp_http_conf_addr_t *addr)
{
    rp_uint_t                 i;
    rp_http_in_addr_t        *addrs;
    struct sockaddr_in        *sin;
    rp_http_virtual_names_t  *vn;

    hport->addrs = rp_pcalloc(cf->pool,
                               hport->naddrs * sizeof(rp_http_in_addr_t));
    if (hport->addrs == NULL) {
        return RP_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (RP_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (RP_HTTP_V2)
        addrs[i].conf.http2 = addr[i].opt.http2;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (RP_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = rp_palloc(cf->pool, sizeof(rp_http_virtual_names_t));
        if (vn == NULL) {
            return RP_ERROR;
        }

        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (RP_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return RP_OK;
}


#if (RP_HAVE_INET6)

static rp_int_t
rp_http_add_addrs6(rp_conf_t *cf, rp_http_port_t *hport,
    rp_http_conf_addr_t *addr)
{
    rp_uint_t                 i;
    rp_http_in6_addr_t       *addrs6;
    struct sockaddr_in6       *sin6;
    rp_http_virtual_names_t  *vn;

    hport->addrs = rp_pcalloc(cf->pool,
                               hport->naddrs * sizeof(rp_http_in6_addr_t));
    if (hport->addrs == NULL) {
        return RP_ERROR;
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (RP_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (RP_HTTP_V2)
        addrs6[i].conf.http2 = addr[i].opt.http2;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (RP_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = rp_palloc(cf->pool, sizeof(rp_http_virtual_names_t));
        if (vn == NULL) {
            return RP_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (RP_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return RP_OK;
}

#endif


char *
rp_http_types_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_array_t     **types;
    rp_str_t        *value, *default_type;
    rp_uint_t        i, n, hash;
    rp_hash_key_t   *type;

    types = (rp_array_t **) (p + cmd->offset);

    if (*types == (void *) -1) {
        return RP_CONF_OK;
    }

    default_type = cmd->post;

    if (*types == NULL) {
        *types = rp_array_create(cf->temp_pool, 1, sizeof(rp_hash_key_t));
        if (*types == NULL) {
            return RP_CONF_ERROR;
        }

        if (default_type) {
            type = rp_array_push(*types);
            if (type == NULL) {
                return RP_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = rp_hash_key(default_type->data,
                                          default_type->len);
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 1 && value[i].data[0] == '*') {
            *types = (void *) -1;
            return RP_CONF_OK;
        }

        hash = rp_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            if (rp_strcmp(value[i].data, type[n].key.data) == 0) {
                rp_conf_log_error(RP_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                goto next;
            }
        }

        type = rp_array_push(*types);
        if (type == NULL) {
            return RP_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;

    next:

        continue;
    }

    return RP_CONF_OK;
}


char *
rp_http_merge_types(rp_conf_t *cf, rp_array_t **keys, rp_hash_t *types_hash,
    rp_array_t **prev_keys, rp_hash_t *prev_types_hash,
    rp_str_t *default_types)
{
    rp_hash_init_t  hash;

    if (*keys) {

        if (*keys == (void *) -1) {
            return RP_CONF_OK;
        }

        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (rp_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != RP_OK) {
            return RP_CONF_ERROR;
        }

        return RP_CONF_OK;
    }

    if (prev_types_hash->buckets == NULL) {

        if (*prev_keys == NULL) {

            if (rp_http_set_default_types(cf, prev_keys, default_types)
                != RP_OK)
            {
                return RP_CONF_ERROR;
            }

        } else if (*prev_keys == (void *) -1) {
            *keys = *prev_keys;
            return RP_CONF_OK;
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        if (rp_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return RP_CONF_OK;

}


rp_int_t
rp_http_set_default_types(rp_conf_t *cf, rp_array_t **types,
    rp_str_t *default_type)
{
    rp_hash_key_t  *type;

    *types = rp_array_create(cf->temp_pool, 1, sizeof(rp_hash_key_t));
    if (*types == NULL) {
        return RP_ERROR;
    }

    while (default_type->len) {

        type = rp_array_push(*types);
        if (type == NULL) {
            return RP_ERROR;
        }

        type->key = *default_type;
        type->key_hash = rp_hash_key(default_type->data,
                                      default_type->len);
        type->value = (void *) 4;

        default_type++;
    }

    return RP_OK;
}
