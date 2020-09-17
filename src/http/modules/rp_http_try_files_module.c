
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t           *lengths;
    rp_array_t           *values;
    rp_str_t              name;

    unsigned               code:10;
    unsigned               test_dir:1;
} rp_http_try_file_t;


typedef struct {
    rp_http_try_file_t   *try_files;
} rp_http_try_files_loc_conf_t;


static rp_int_t rp_http_try_files_handler(rp_http_request_t *r);
static char *rp_http_try_files(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static void *rp_http_try_files_create_loc_conf(rp_conf_t *cf);
static rp_int_t rp_http_try_files_init(rp_conf_t *cf);


static rp_command_t  rp_http_try_files_commands[] = {

    { rp_string("try_files"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_2MORE,
      rp_http_try_files,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_try_files_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_try_files_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_try_files_create_loc_conf,    /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_try_files_module = {
    RP_MODULE_V1,
    &rp_http_try_files_module_ctx,        /* module context */
    rp_http_try_files_commands,           /* module directives */
    RP_HTTP_MODULE,                       /* module type */
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
rp_http_try_files_handler(rp_http_request_t *r)
{
    size_t                          len, root, alias, reserve, allocated;
    u_char                         *p, *name;
    rp_str_t                       path, args;
    rp_uint_t                      test_dir;
    rp_http_try_file_t            *tf;
    rp_open_file_info_t            of;
    rp_http_script_code_pt         code;
    rp_http_script_engine_t        e;
    rp_http_core_loc_conf_t       *clcf;
    rp_http_script_len_code_pt     lcode;
    rp_http_try_files_loc_conf_t  *tlcf;

    tlcf = rp_http_get_module_loc_conf(r, rp_http_try_files_module);

    if (tlcf->try_files == NULL) {
        return RP_DECLINED;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "try files handler");

    allocated = 0;
    root = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    tf = tlcf->try_files;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    alias = clcf->alias;

    for ( ;; ) {

        if (tf->lengths) {
            rp_memzero(&e, sizeof(rp_http_script_engine_t));

            e.ip = tf->lengths->elts;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(rp_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

        } else {
            len = tf->name.len;
        }

        if (!alias) {
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == RP_MAX_SIZE_T_VALUE) {
            reserve = len;

        } else {
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;

            if (rp_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;
        }

        if (tf->values == NULL) {

            /* tf->name.len includes the terminating '\0' */

            rp_memcpy(name, tf->name.data, tf->name.len);

            path.len = (name + tf->name.len - 1) - path.data;

        } else {
            e.ip = tf->values->elts;
            e.pos = name;
            e.flushed = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(rp_http_script_code_pt *) e.ip;
                code((rp_http_script_engine_t *) &e);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';

            if (alias && alias != RP_MAX_SIZE_T_VALUE
                && rp_strncmp(name, r->uri.data, alias) == 0)
            {
                rp_memmove(name, name + alias, len - alias);
                path.len -= alias;
            }
        }

        test_dir = tf->test_dir;

        tf++;

        rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trying to use %s: \"%s\" \"%s\"",
                       test_dir ? "dir" : "file", name, path.data);

        if (tf->lengths == NULL && tf->name.len == 0) {

            if (tf->code) {
                return tf->code;
            }

            path.len -= root;
            path.data += root;

            if (path.data[0] == '@') {
                (void) rp_http_named_location(r, &path);

            } else {
                rp_http_split_args(r, &path, &args);

                (void) rp_http_internal_redirect(r, &path, &args);
            }

            rp_http_finalize_request(r, RP_DONE);
            return RP_DONE;
        }

        rp_memzero(&of, sizeof(rp_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (rp_http_set_disable_symlinks(r, clcf, &path, &of) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rp_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != RP_OK)
        {
            if (of.err == 0) {
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (of.err != RP_ENOENT
                && of.err != RP_ENOTDIR
                && of.err != RP_ENAMETOOLONG)
            {
                rp_log_error(RP_LOG_CRIT, r->connection->log, of.err,
                              "%s \"%s\" failed", of.failed, path.data);
            }

            continue;
        }

        if (of.is_dir != test_dir) {
            continue;
        }

        path.len -= root;
        path.data += root;

        if (!alias) {
            r->uri = path;

        } else if (alias == RP_MAX_SIZE_T_VALUE) {
            if (!test_dir) {
                r->uri = path;
                r->add_uri_to_alias = 1;
            }

        } else {
            name = r->uri.data;

            r->uri.len = alias + path.len;
            r->uri.data = rp_pnalloc(r->pool, r->uri.len);
            if (r->uri.data == NULL) {
                r->uri.len = 0;
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = rp_copy(r->uri.data, name, alias);
            rp_memcpy(p, path.data, path.len);
        }

        rp_http_set_exten(r);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "try file uri: \"%V\"", &r->uri);

        return RP_DECLINED;
    }

    /* not reached */
}


static char *
rp_http_try_files(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_try_files_loc_conf_t *tlcf = conf;

    rp_str_t                  *value;
    rp_int_t                   code;
    rp_uint_t                  i, n;
    rp_http_try_file_t        *tf;
    rp_http_script_compile_t   sc;

    if (tlcf->try_files) {
        return "is duplicate";
    }

    tf = rp_pcalloc(cf->pool, cf->args->nelts * sizeof(rp_http_try_file_t));
    if (tf == NULL) {
        return RP_CONF_ERROR;
    }

    tlcf->try_files = tf;

    value = cf->args->elts;

    for (i = 0; i < cf->args->nelts - 1; i++) {

        tf[i].name = value[i + 1];

        if (tf[i].name.len > 0
            && tf[i].name.data[tf[i].name.len - 1] == '/'
            && i + 2 < cf->args->nelts)
        {
            tf[i].test_dir = 1;
            tf[i].name.len--;
            tf[i].name.data[tf[i].name.len] = '\0';
        }

        n = rp_http_script_variables_count(&tf[i].name);

        if (n) {
            rp_memzero(&sc, sizeof(rp_http_script_compile_t));

            sc.cf = cf;
            sc.source = &tf[i].name;
            sc.lengths = &tf[i].lengths;
            sc.values = &tf[i].values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;

            if (rp_http_script_compile(&sc) != RP_OK) {
                return RP_CONF_ERROR;
            }

        } else {
            /* add trailing '\0' to length */
            tf[i].name.len++;
        }
    }

    if (tf[i - 1].name.data[0] == '=') {

        code = rp_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);

        if (code == RP_ERROR || code > 999) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid code \"%*s\"",
                               tf[i - 1].name.len - 1, tf[i - 1].name.data);
            return RP_CONF_ERROR;
        }

        tf[i].code = code;
    }

    return RP_CONF_OK;
}


static void *
rp_http_try_files_create_loc_conf(rp_conf_t *cf)
{
    rp_http_try_files_loc_conf_t  *tlcf;

    tlcf = rp_pcalloc(cf->pool, sizeof(rp_http_try_files_loc_conf_t));
    if (tlcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */

    return tlcf;
}


static rp_int_t
rp_http_try_files_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_try_files_handler;

    return RP_OK;
}
