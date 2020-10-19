
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_flag_t  enable;
} rap_http_random_index_loc_conf_t;


#define RAP_HTTP_RANDOM_INDEX_PREALLOCATE  50


static rap_int_t rap_http_random_index_error(rap_http_request_t *r,
    rap_dir_t *dir, rap_str_t *name);
static rap_int_t rap_http_random_index_init(rap_conf_t *cf);
static void *rap_http_random_index_create_loc_conf(rap_conf_t *cf);
static char *rap_http_random_index_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);


static rap_command_t  rap_http_random_index_commands[] = {

    { rap_string("random_index"),
      RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_random_index_loc_conf_t, enable),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_random_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_random_index_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_random_index_create_loc_conf, /* create location configuration */
    rap_http_random_index_merge_loc_conf   /* merge location configuration */
};


rap_module_t  rap_http_random_index_module = {
    RAP_MODULE_V1,
    &rap_http_random_index_module_ctx,     /* module context */
    rap_http_random_index_commands,        /* module directives */
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
rap_http_random_index_handler(rap_http_request_t *r)
{
    u_char                            *last, *filename;
    size_t                             len, allocated, root;
    rap_err_t                          err;
    rap_int_t                          rc;
    rap_str_t                          path, uri, *name;
    rap_dir_t                          dir;
    rap_uint_t                         n, level;
    rap_array_t                        names;
    rap_http_random_index_loc_conf_t  *rlcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RAP_DECLINED;
    }

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD|RAP_HTTP_POST))) {
        return RAP_DECLINED;
    }

    rlcf = rap_http_get_module_loc_conf(r, rap_http_random_index_module);

    if (!rlcf->enable) {
        return RAP_DECLINED;
    }

#if (RAP_HAVE_D_TYPE)
    len = 0;
#else
    len = RAP_HTTP_RANDOM_INDEX_PREALLOCATE;
#endif

    last = rap_http_map_uri_to_path(r, &path, &root, len);
    if (last == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;

    path.len = last - path.data - 1;
    path.data[path.len] = '\0';

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http random index: \"%s\"", path.data);

    if (rap_open_dir(&path, &dir) == RAP_ERROR) {
        err = rap_errno;

        if (err == RAP_ENOENT
            || err == RAP_ENOTDIR
            || err == RAP_ENAMETOOLONG)
        {
            level = RAP_LOG_ERR;
            rc = RAP_HTTP_NOT_FOUND;

        } else if (err == RAP_EACCES) {
            level = RAP_LOG_ERR;
            rc = RAP_HTTP_FORBIDDEN;

        } else {
            level = RAP_LOG_CRIT;
            rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rap_log_error(level, r->connection->log, err,
                      rap_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

    if (rap_array_init(&names, r->pool, 32, sizeof(rap_str_t)) != RAP_OK) {
        return rap_http_random_index_error(r, &dir, &path);
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        rap_set_errno(0);

        if (rap_read_dir(&dir) == RAP_ERROR) {
            err = rap_errno;

            if (err != RAP_ENOMOREFILES) {
                rap_log_error(RAP_LOG_CRIT, r->connection->log, err,
                              rap_read_dir_n " \"%V\" failed", &path);
                return rap_http_random_index_error(r, &dir, &path);
            }

            break;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http random index file: \"%s\"", rap_de_name(&dir));

        if (rap_de_name(&dir)[0] == '.') {
            continue;
        }

        len = rap_de_namelen(&dir);

        if (dir.type == 0 || rap_de_is_link(&dir)) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + RAP_HTTP_RANDOM_INDEX_PREALLOCATE;

                filename = rap_pnalloc(r->pool, allocated);
                if (filename == NULL) {
                    return rap_http_random_index_error(r, &dir, &path);
                }

                last = rap_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            rap_cpystrn(last, rap_de_name(&dir), len + 1);

            if (rap_de_info(filename, &dir) == RAP_FILE_ERROR) {
                err = rap_errno;

                if (err != RAP_ENOENT) {
                    rap_log_error(RAP_LOG_CRIT, r->connection->log, err,
                                  rap_de_info_n " \"%s\" failed", filename);
                    return rap_http_random_index_error(r, &dir, &path);
                }

                if (rap_de_link_info(filename, &dir) == RAP_FILE_ERROR) {
                    rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                                  rap_de_link_info_n " \"%s\" failed",
                                  filename);
                    return rap_http_random_index_error(r, &dir, &path);
                }
            }
        }

        if (!rap_de_is_file(&dir)) {
            continue;
        }

        name = rap_array_push(&names);
        if (name == NULL) {
            return rap_http_random_index_error(r, &dir, &path);
        }

        name->len = len;

        name->data = rap_pnalloc(r->pool, len);
        if (name->data == NULL) {
            return rap_http_random_index_error(r, &dir, &path);
        }

        rap_memcpy(name->data, rap_de_name(&dir), len);
    }

    if (rap_close_dir(&dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_dir_n " \"%V\" failed", &path);
    }

    n = names.nelts;

    if (n == 0) {
        return RAP_DECLINED;
    }

    name = names.elts;

    n = (rap_uint_t) (((uint64_t) rap_random() * n) / 0x80000000);

    uri.len = r->uri.len + name[n].len;

    uri.data = rap_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = rap_copy(uri.data, r->uri.data, r->uri.len);
    rap_memcpy(last, name[n].data, name[n].len);

    return rap_http_internal_redirect(r, &uri, &r->args);
}


static rap_int_t
rap_http_random_index_error(rap_http_request_t *r, rap_dir_t *dir,
    rap_str_t *name)
{
    if (rap_close_dir(dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_dir_n " \"%V\" failed", name);
    }

    return RAP_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
rap_http_random_index_create_loc_conf(rap_conf_t *cf)
{
    rap_http_random_index_loc_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_random_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_random_index_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_random_index_loc_conf_t *prev = parent;
    rap_http_random_index_loc_conf_t *conf = child;

    rap_conf_merge_value(conf->enable, prev->enable, 0);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_random_index_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_random_index_handler;

    return RAP_OK;
}
