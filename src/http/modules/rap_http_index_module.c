
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_str_t                name;
    rap_array_t             *lengths;
    rap_array_t             *values;
} rap_http_index_t;


typedef struct {
    rap_array_t             *indices;    /* array of rap_http_index_t */
    size_t                   max_index_len;
} rap_http_index_loc_conf_t;


#define RAP_HTTP_DEFAULT_INDEX   "index.html"


static rap_int_t rap_http_index_test_dir(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, u_char *path, u_char *last);
static rap_int_t rap_http_index_error(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, u_char *file, rap_err_t err);

static rap_int_t rap_http_index_init(rap_conf_t *cf);
static void *rap_http_index_create_loc_conf(rap_conf_t *cf);
static char *rap_http_index_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static char *rap_http_index_set_index(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_index_commands[] = {

    { rap_string("index"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_index_set_index,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_index_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_index_create_loc_conf,        /* create location configuration */
    rap_http_index_merge_loc_conf          /* merge location configuration */
};


rap_module_t  rap_http_index_module = {
    RAP_MODULE_V1,
    &rap_http_index_module_ctx,            /* module context */
    rap_http_index_commands,               /* module directives */
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


/*
 * Try to open/test the first index file before the test of directory
 * existence because valid requests should prevail over invalid ones.
 * If open()/stat() of a file will fail then stat() of a directory
 * should be faster because kernel may have already cached some data.
 * Besides, Win32 may return ERROR_PATH_NOT_FOUND (RAP_ENOTDIR) at once.
 * Unix has ENOTDIR error; however, it's less helpful than Win32's one:
 * it only indicates that path points to a regular file, not a directory.
 */

static rap_int_t
rap_http_index_handler(rap_http_request_t *r)
{
    u_char                       *p, *name;
    size_t                        len, root, reserve, allocated;
    rap_int_t                     rc;
    rap_str_t                     path, uri;
    rap_uint_t                    i, dir_tested;
    rap_http_index_t             *index;
    rap_open_file_info_t          of;
    rap_http_script_code_pt       code;
    rap_http_script_engine_t      e;
    rap_http_core_loc_conf_t     *clcf;
    rap_http_index_loc_conf_t    *ilcf;
    rap_http_script_len_code_pt   lcode;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RAP_DECLINED;
    }

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD|RAP_HTTP_POST))) {
        return RAP_DECLINED;
    }

    ilcf = rap_http_get_module_loc_conf(r, rap_http_index_module);
    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    allocated = 0;
    root = 0;
    dir_tested = 0;
    name = NULL;
    /* suppress MSVC warning */
    path.data = NULL;

    index = ilcf->indices->elts;
    for (i = 0; i < ilcf->indices->nelts; i++) {

        if (index[i].lengths == NULL) {

            if (index[i].name.data[0] == '/') {
                return rap_http_internal_redirect(r, &index[i].name, &r->args);
            }

            reserve = ilcf->max_index_len;
            len = index[i].name.len;

        } else {
            rap_memzero(&e, sizeof(rap_http_script_engine_t));

            e.ip = index[i].lengths->elts;
            e.request = r;
            e.flushed = 1;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(rap_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

            /* 16 bytes are preallocation */

            reserve = len + 16;
        }

        if (reserve > allocated) {

            name = rap_http_map_uri_to_path(r, &path, &root, reserve);
            if (name == NULL) {
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            allocated = path.data + path.len - name;
        }

        if (index[i].values == NULL) {

            /* index[i].name.len includes the terminating '\0' */

            rap_memcpy(name, index[i].name.data, index[i].name.len);

            path.len = (name + index[i].name.len - 1) - path.data;

        } else {
            e.ip = index[i].values->elts;
            e.pos = name;

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }

            if (*name == '/') {
                uri.len = len - 1;
                uri.data = name;
                return rap_http_internal_redirect(r, &uri, &r->args);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "open index \"%V\"", &path);

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

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, of.err,
                           "%s \"%s\" failed", of.failed, path.data);

#if (RAP_HAVE_OPENAT)
            if (of.err == RAP_EMLINK
                || of.err == RAP_ELOOP)
            {
                return RAP_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == RAP_ENOTDIR
                || of.err == RAP_ENAMETOOLONG
                || of.err == RAP_EACCES)
            {
                return rap_http_index_error(r, clcf, path.data, of.err);
            }

            if (!dir_tested) {
                rc = rap_http_index_test_dir(r, clcf, path.data, name - 1);

                if (rc != RAP_OK) {
                    return rc;
                }

                dir_tested = 1;
            }

            if (of.err == RAP_ENOENT) {
                continue;
            }

            rap_log_error(RAP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);

            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        uri.len = r->uri.len + len - 1;

        if (!clcf->alias) {
            uri.data = path.data + root;

        } else {
            uri.data = rap_pnalloc(r->pool, uri.len);
            if (uri.data == NULL) {
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = rap_copy(uri.data, r->uri.data, r->uri.len);
            rap_memcpy(p, name, len - 1);
        }

        return rap_http_internal_redirect(r, &uri, &r->args);
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_index_test_dir(rap_http_request_t *r, rap_http_core_loc_conf_t *clcf,
    u_char *path, u_char *last)
{
    u_char                c;
    rap_str_t             dir;
    rap_open_file_info_t  of;

    c = *last;
    if (c != '/' || path == last) {
        /* "alias" without trailing slash */
        c = *(++last);
    }
    *last = '\0';

    dir.len = last - path;
    dir.data = path;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http index check dir: \"%V\"", &dir);

    rap_memzero(&of, sizeof(rap_open_file_info_t));

    of.test_dir = 1;
    of.test_only = 1;
    of.valid = clcf->open_file_cache_valid;
    of.errors = clcf->open_file_cache_errors;

    if (rap_http_set_disable_symlinks(r, clcf, &dir, &of) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_open_cached_file(clcf->open_file_cache, &dir, &of, r->pool)
        != RAP_OK)
    {
        if (of.err) {

#if (RAP_HAVE_OPENAT)
            if (of.err == RAP_EMLINK
                || of.err == RAP_ELOOP)
            {
                return RAP_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == RAP_ENOENT) {
                *last = c;
                return rap_http_index_error(r, clcf, dir.data, RAP_ENOENT);
            }

            if (of.err == RAP_EACCES) {

                *last = c;

                /*
                 * rap_http_index_test_dir() is called after the first index
                 * file testing has returned an error distinct from RAP_EACCES.
                 * This means that directory searching is allowed.
                 */

                return RAP_OK;
            }

            rap_log_error(RAP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, dir.data);
        }

        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = c;

    if (of.is_dir) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                  "\"%s\" is not a directory", dir.data);

    return RAP_HTTP_INTERNAL_SERVER_ERROR;
}


static rap_int_t
rap_http_index_error(rap_http_request_t *r, rap_http_core_loc_conf_t  *clcf,
    u_char *file, rap_err_t err)
{
    if (err == RAP_EACCES) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, err,
                      "\"%s\" is forbidden", file);

        return RAP_HTTP_FORBIDDEN;
    }

    if (clcf->log_not_found) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, err,
                      "\"%s\" is not found", file);
    }

    return RAP_HTTP_NOT_FOUND;
}


static void *
rap_http_index_create_loc_conf(rap_conf_t *cf)
{
    rap_http_index_loc_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->indices = NULL;
    conf->max_index_len = 0;

    return conf;
}


static char *
rap_http_index_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_index_loc_conf_t  *prev = parent;
    rap_http_index_loc_conf_t  *conf = child;

    rap_http_index_t  *index;

    if (conf->indices == NULL) {
        conf->indices = prev->indices;
        conf->max_index_len = prev->max_index_len;
    }

    if (conf->indices == NULL) {
        conf->indices = rap_array_create(cf->pool, 1, sizeof(rap_http_index_t));
        if (conf->indices == NULL) {
            return RAP_CONF_ERROR;
        }

        index = rap_array_push(conf->indices);
        if (index == NULL) {
            return RAP_CONF_ERROR;
        }

        index->name.len = sizeof(RAP_HTTP_DEFAULT_INDEX);
        index->name.data = (u_char *) RAP_HTTP_DEFAULT_INDEX;
        index->lengths = NULL;
        index->values = NULL;

        conf->max_index_len = sizeof(RAP_HTTP_DEFAULT_INDEX);

        return RAP_CONF_OK;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_index_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_index_handler;

    return RAP_OK;
}


/* TODO: warn about duplicate indices */

static char *
rap_http_index_set_index(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_index_loc_conf_t *ilcf = conf;

    rap_str_t                  *value;
    rap_uint_t                  i, n;
    rap_http_index_t           *index;
    rap_http_script_compile_t   sc;

    if (ilcf->indices == NULL) {
        ilcf->indices = rap_array_create(cf->pool, 2, sizeof(rap_http_index_t));
        if (ilcf->indices == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].data[0] == '/' && i != cf->args->nelts - 1) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "only the last index in \"index\" directive "
                               "should be absolute");
        }

        if (value[i].len == 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "index \"%V\" in \"index\" directive is invalid",
                               &value[1]);
            return RAP_CONF_ERROR;
        }

        index = rap_array_push(ilcf->indices);
        if (index == NULL) {
            return RAP_CONF_ERROR;
        }

        index->name.len = value[i].len;
        index->name.data = value[i].data;
        index->lengths = NULL;
        index->values = NULL;

        n = rap_http_script_variables_count(&value[i]);

        if (n == 0) {
            if (ilcf->max_index_len < index->name.len) {
                ilcf->max_index_len = index->name.len;
            }

            if (index->name.data[0] == '/') {
                continue;
            }

            /* include the terminating '\0' to the length to use rap_memcpy() */
            index->name.len++;

            continue;
        }

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[i];
        sc.lengths = &index->lengths;
        sc.values = &index->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}
