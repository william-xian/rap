
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t           *lengths;
    rap_array_t           *values;
    rap_str_t              name;

    unsigned               code:10;
    unsigned               test_dir:1;
} rap_http_try_file_t;


typedef struct {
    rap_http_try_file_t   *try_files;
} rap_http_try_files_loc_conf_t;


static rap_int_t rap_http_try_files_handler(rap_http_request_t *r);
static char *rap_http_try_files(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static void *rap_http_try_files_create_loc_conf(rap_conf_t *cf);
static rap_int_t rap_http_try_files_init(rap_conf_t *cf);


static rap_command_t  rap_http_try_files_commands[] = {

    { rap_string("try_files"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_2MORE,
      rap_http_try_files,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_try_files_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_try_files_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_try_files_create_loc_conf,    /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_try_files_module = {
    RAP_MODULE_V1,
    &rap_http_try_files_module_ctx,        /* module context */
    rap_http_try_files_commands,           /* module directives */
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
rap_http_try_files_handler(rap_http_request_t *r)
{
    size_t                          len, root, alias, reserve, allocated;
    u_char                         *p, *name;
    rap_str_t                       path, args;
    rap_uint_t                      test_dir;
    rap_http_try_file_t            *tf;
    rap_open_file_info_t            of;
    rap_http_script_code_pt         code;
    rap_http_script_engine_t        e;
    rap_http_core_loc_conf_t       *clcf;
    rap_http_script_len_code_pt     lcode;
    rap_http_try_files_loc_conf_t  *tlcf;

    tlcf = rap_http_get_module_loc_conf(r, rap_http_try_files_module);

    if (tlcf->try_files == NULL) {
        return RAP_DECLINED;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "try files handler");

    allocated = 0;
    root = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    tf = tlcf->try_files;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    alias = clcf->alias;

    for ( ;; ) {

        if (tf->lengths) {
            rap_memzero(&e, sizeof(rap_http_script_engine_t));

            e.ip = tf->lengths->elts;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(rap_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

        } else {
            len = tf->name.len;
        }

        if (!alias) {
            reserve = len > r->uri.len ? len - r->uri.len : 0;

        } else if (alias == RAP_MAX_SIZE_T_VALUE) {
            reserve = len;

        } else {
            reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
        }

        if (reserve > allocated || !allocated) {

            /* 16 bytes are preallocation */
            allocated = reserve + 16;

            if (rap_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            name = path.data + root;
        }

        if (tf->values == NULL) {

            /* tf->name.len includes the terminating '\0' */

            rap_memcpy(name, tf->name.data, tf->name.len);

            path.len = (name + tf->name.len - 1) - path.data;

        } else {
            e.ip = tf->values->elts;
            e.pos = name;
            e.flushed = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';

            if (alias && alias != RAP_MAX_SIZE_T_VALUE
                && rap_strncmp(name, r->uri.data, alias) == 0)
            {
                rap_memmove(name, name + alias, len - alias);
                path.len -= alias;
            }
        }

        test_dir = tf->test_dir;

        tf++;

        rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "trying to use %s: \"%s\" \"%s\"",
                       test_dir ? "dir" : "file", name, path.data);

        if (tf->lengths == NULL && tf->name.len == 0) {

            if (tf->code) {
                return tf->code;
            }

            path.len -= root;
            path.data += root;

            if (path.data[0] == '@') {
                (void) rap_http_named_location(r, &path);

            } else {
                rap_http_split_args(r, &path, &args);

                (void) rap_http_internal_redirect(r, &path, &args);
            }

            rap_http_finalize_request(r, RAP_DONE);
            return RAP_DONE;
        }

        rap_memzero(&of, sizeof(rap_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (rap_http_set_disable_symlinks(r, clcf, &path, &of) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rap_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != RAP_OK)
        {
            if (of.err == 0) {
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (of.err != RAP_ENOENT
                && of.err != RAP_ENOTDIR
                && of.err != RAP_ENAMETOOLONG)
            {
                rap_log_error(RAP_LOG_CRIT, r->connection->log, of.err,
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

        } else if (alias == RAP_MAX_SIZE_T_VALUE) {
            if (!test_dir) {
                r->uri = path;
                r->add_uri_to_alias = 1;
            }

        } else {
            name = r->uri.data;

            r->uri.len = alias + path.len;
            r->uri.data = rap_pnalloc(r->pool, r->uri.len);
            if (r->uri.data == NULL) {
                r->uri.len = 0;
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = rap_copy(r->uri.data, name, alias);
            rap_memcpy(p, path.data, path.len);
        }

        rap_http_set_exten(r);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "try file uri: \"%V\"", &r->uri);

        return RAP_DECLINED;
    }

    /* not reached */
}


static char *
rap_http_try_files(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_try_files_loc_conf_t *tlcf = conf;

    rap_str_t                  *value;
    rap_int_t                   code;
    rap_uint_t                  i, n;
    rap_http_try_file_t        *tf;
    rap_http_script_compile_t   sc;

    if (tlcf->try_files) {
        return "is duplicate";
    }

    tf = rap_pcalloc(cf->pool, cf->args->nelts * sizeof(rap_http_try_file_t));
    if (tf == NULL) {
        return RAP_CONF_ERROR;
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

        n = rap_http_script_variables_count(&tf[i].name);

        if (n) {
            rap_memzero(&sc, sizeof(rap_http_script_compile_t));

            sc.cf = cf;
            sc.source = &tf[i].name;
            sc.lengths = &tf[i].lengths;
            sc.values = &tf[i].values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;

            if (rap_http_script_compile(&sc) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

        } else {
            /* add trailing '\0' to length */
            tf[i].name.len++;
        }
    }

    if (tf[i - 1].name.data[0] == '=') {

        code = rap_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);

        if (code == RAP_ERROR || code > 999) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid code \"%*s\"",
                               tf[i - 1].name.len - 1, tf[i - 1].name.data);
            return RAP_CONF_ERROR;
        }

        tf[i].code = code;
    }

    return RAP_CONF_OK;
}


static void *
rap_http_try_files_create_loc_conf(rap_conf_t *cf)
{
    rap_http_try_files_loc_conf_t  *tlcf;

    tlcf = rap_pcalloc(cf->pool, sizeof(rap_http_try_files_loc_conf_t));
    if (tlcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */

    return tlcf;
}


static rap_int_t
rap_http_try_files_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_try_files_handler;

    return RAP_OK;
}
