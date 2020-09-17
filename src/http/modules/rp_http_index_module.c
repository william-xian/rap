
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_str_t                name;
    rp_array_t             *lengths;
    rp_array_t             *values;
} rp_http_index_t;


typedef struct {
    rp_array_t             *indices;    /* array of rp_http_index_t */
    size_t                   max_index_len;
} rp_http_index_loc_conf_t;


#define RP_HTTP_DEFAULT_INDEX   "index.html"


static rp_int_t rp_http_index_test_dir(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, u_char *path, u_char *last);
static rp_int_t rp_http_index_error(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, u_char *file, rp_err_t err);

static rp_int_t rp_http_index_init(rp_conf_t *cf);
static void *rp_http_index_create_loc_conf(rp_conf_t *cf);
static char *rp_http_index_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static char *rp_http_index_set_index(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_index_commands[] = {

    { rp_string("index"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_index_set_index,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_index_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_index_create_loc_conf,        /* create location configuration */
    rp_http_index_merge_loc_conf          /* merge location configuration */
};


rp_module_t  rp_http_index_module = {
    RP_MODULE_V1,
    &rp_http_index_module_ctx,            /* module context */
    rp_http_index_commands,               /* module directives */
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


/*
 * Try to open/test the first index file before the test of directory
 * existence because valid requests should prevail over invalid ones.
 * If open()/stat() of a file will fail then stat() of a directory
 * should be faster because kernel may have already cached some data.
 * Besides, Win32 may return ERROR_PATH_NOT_FOUND (RP_ENOTDIR) at once.
 * Unix has ENOTDIR error; however, it's less helpful than Win32's one:
 * it only indicates that path points to a regular file, not a directory.
 */

static rp_int_t
rp_http_index_handler(rp_http_request_t *r)
{
    u_char                       *p, *name;
    size_t                        len, root, reserve, allocated;
    rp_int_t                     rc;
    rp_str_t                     path, uri;
    rp_uint_t                    i, dir_tested;
    rp_http_index_t             *index;
    rp_open_file_info_t          of;
    rp_http_script_code_pt       code;
    rp_http_script_engine_t      e;
    rp_http_core_loc_conf_t     *clcf;
    rp_http_index_loc_conf_t    *ilcf;
    rp_http_script_len_code_pt   lcode;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RP_DECLINED;
    }

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD|RP_HTTP_POST))) {
        return RP_DECLINED;
    }

    ilcf = rp_http_get_module_loc_conf(r, rp_http_index_module);
    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

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
                return rp_http_internal_redirect(r, &index[i].name, &r->args);
            }

            reserve = ilcf->max_index_len;
            len = index[i].name.len;

        } else {
            rp_memzero(&e, sizeof(rp_http_script_engine_t));

            e.ip = index[i].lengths->elts;
            e.request = r;
            e.flushed = 1;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while (*(uintptr_t *) e.ip) {
                lcode = *(rp_http_script_len_code_pt *) e.ip;
                len += lcode(&e);
            }

            /* 16 bytes are preallocation */

            reserve = len + 16;
        }

        if (reserve > allocated) {

            name = rp_http_map_uri_to_path(r, &path, &root, reserve);
            if (name == NULL) {
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            allocated = path.data + path.len - name;
        }

        if (index[i].values == NULL) {

            /* index[i].name.len includes the terminating '\0' */

            rp_memcpy(name, index[i].name.data, index[i].name.len);

            path.len = (name + index[i].name.len - 1) - path.data;

        } else {
            e.ip = index[i].values->elts;
            e.pos = name;

            while (*(uintptr_t *) e.ip) {
                code = *(rp_http_script_code_pt *) e.ip;
                code((rp_http_script_engine_t *) &e);
            }

            if (*name == '/') {
                uri.len = len - 1;
                uri.data = name;
                return rp_http_internal_redirect(r, &uri, &r->args);
            }

            path.len = e.pos - path.data;

            *e.pos = '\0';
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "open index \"%V\"", &path);

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

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, of.err,
                           "%s \"%s\" failed", of.failed, path.data);

#if (RP_HAVE_OPENAT)
            if (of.err == RP_EMLINK
                || of.err == RP_ELOOP)
            {
                return RP_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == RP_ENOTDIR
                || of.err == RP_ENAMETOOLONG
                || of.err == RP_EACCES)
            {
                return rp_http_index_error(r, clcf, path.data, of.err);
            }

            if (!dir_tested) {
                rc = rp_http_index_test_dir(r, clcf, path.data, name - 1);

                if (rc != RP_OK) {
                    return rc;
                }

                dir_tested = 1;
            }

            if (of.err == RP_ENOENT) {
                continue;
            }

            rp_log_error(RP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);

            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        uri.len = r->uri.len + len - 1;

        if (!clcf->alias) {
            uri.data = path.data + root;

        } else {
            uri.data = rp_pnalloc(r->pool, uri.len);
            if (uri.data == NULL) {
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = rp_copy(uri.data, r->uri.data, r->uri.len);
            rp_memcpy(p, name, len - 1);
        }

        return rp_http_internal_redirect(r, &uri, &r->args);
    }

    return RP_DECLINED;
}


static rp_int_t
rp_http_index_test_dir(rp_http_request_t *r, rp_http_core_loc_conf_t *clcf,
    u_char *path, u_char *last)
{
    u_char                c;
    rp_str_t             dir;
    rp_open_file_info_t  of;

    c = *last;
    if (c != '/' || path == last) {
        /* "alias" without trailing slash */
        c = *(++last);
    }
    *last = '\0';

    dir.len = last - path;
    dir.data = path;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http index check dir: \"%V\"", &dir);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.test_dir = 1;
    of.test_only = 1;
    of.valid = clcf->open_file_cache_valid;
    of.errors = clcf->open_file_cache_errors;

    if (rp_http_set_disable_symlinks(r, clcf, &dir, &of) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_open_cached_file(clcf->open_file_cache, &dir, &of, r->pool)
        != RP_OK)
    {
        if (of.err) {

#if (RP_HAVE_OPENAT)
            if (of.err == RP_EMLINK
                || of.err == RP_ELOOP)
            {
                return RP_HTTP_FORBIDDEN;
            }
#endif

            if (of.err == RP_ENOENT) {
                *last = c;
                return rp_http_index_error(r, clcf, dir.data, RP_ENOENT);
            }

            if (of.err == RP_EACCES) {

                *last = c;

                /*
                 * rp_http_index_test_dir() is called after the first index
                 * file testing has returned an error distinct from RP_EACCES.
                 * This means that directory searching is allowed.
                 */

                return RP_OK;
            }

            rp_log_error(RP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, dir.data);
        }

        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *last = c;

    if (of.is_dir) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                  "\"%s\" is not a directory", dir.data);

    return RP_HTTP_INTERNAL_SERVER_ERROR;
}


static rp_int_t
rp_http_index_error(rp_http_request_t *r, rp_http_core_loc_conf_t  *clcf,
    u_char *file, rp_err_t err)
{
    if (err == RP_EACCES) {
        rp_log_error(RP_LOG_ERR, r->connection->log, err,
                      "\"%s\" is forbidden", file);

        return RP_HTTP_FORBIDDEN;
    }

    if (clcf->log_not_found) {
        rp_log_error(RP_LOG_ERR, r->connection->log, err,
                      "\"%s\" is not found", file);
    }

    return RP_HTTP_NOT_FOUND;
}


static void *
rp_http_index_create_loc_conf(rp_conf_t *cf)
{
    rp_http_index_loc_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->indices = NULL;
    conf->max_index_len = 0;

    return conf;
}


static char *
rp_http_index_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_index_loc_conf_t  *prev = parent;
    rp_http_index_loc_conf_t  *conf = child;

    rp_http_index_t  *index;

    if (conf->indices == NULL) {
        conf->indices = prev->indices;
        conf->max_index_len = prev->max_index_len;
    }

    if (conf->indices == NULL) {
        conf->indices = rp_array_create(cf->pool, 1, sizeof(rp_http_index_t));
        if (conf->indices == NULL) {
            return RP_CONF_ERROR;
        }

        index = rp_array_push(conf->indices);
        if (index == NULL) {
            return RP_CONF_ERROR;
        }

        index->name.len = sizeof(RP_HTTP_DEFAULT_INDEX);
        index->name.data = (u_char *) RP_HTTP_DEFAULT_INDEX;
        index->lengths = NULL;
        index->values = NULL;

        conf->max_index_len = sizeof(RP_HTTP_DEFAULT_INDEX);

        return RP_CONF_OK;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_index_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_index_handler;

    return RP_OK;
}


/* TODO: warn about duplicate indices */

static char *
rp_http_index_set_index(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_index_loc_conf_t *ilcf = conf;

    rp_str_t                  *value;
    rp_uint_t                  i, n;
    rp_http_index_t           *index;
    rp_http_script_compile_t   sc;

    if (ilcf->indices == NULL) {
        ilcf->indices = rp_array_create(cf->pool, 2, sizeof(rp_http_index_t));
        if (ilcf->indices == NULL) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].data[0] == '/' && i != cf->args->nelts - 1) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "only the last index in \"index\" directive "
                               "should be absolute");
        }

        if (value[i].len == 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "index \"%V\" in \"index\" directive is invalid",
                               &value[1]);
            return RP_CONF_ERROR;
        }

        index = rp_array_push(ilcf->indices);
        if (index == NULL) {
            return RP_CONF_ERROR;
        }

        index->name.len = value[i].len;
        index->name.data = value[i].data;
        index->lengths = NULL;
        index->values = NULL;

        n = rp_http_script_variables_count(&value[i]);

        if (n == 0) {
            if (ilcf->max_index_len < index->name.len) {
                ilcf->max_index_len = index->name.len;
            }

            if (index->name.data[0] == '/') {
                continue;
            }

            /* include the terminating '\0' to the length to use rp_memcpy() */
            index->name.len++;

            continue;
        }

        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[i];
        sc.lengths = &index->lengths;
        sc.values = &index->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}
