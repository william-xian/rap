
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_flag_t  enable;
} rp_http_random_index_loc_conf_t;


#define RP_HTTP_RANDOM_INDEX_PREALLOCATE  50


static rp_int_t rp_http_random_index_error(rp_http_request_t *r,
    rp_dir_t *dir, rp_str_t *name);
static rp_int_t rp_http_random_index_init(rp_conf_t *cf);
static void *rp_http_random_index_create_loc_conf(rp_conf_t *cf);
static char *rp_http_random_index_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);


static rp_command_t  rp_http_random_index_commands[] = {

    { rp_string("random_index"),
      RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_random_index_loc_conf_t, enable),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_random_index_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_random_index_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_random_index_create_loc_conf, /* create location configuration */
    rp_http_random_index_merge_loc_conf   /* merge location configuration */
};


rp_module_t  rp_http_random_index_module = {
    RP_MODULE_V1,
    &rp_http_random_index_module_ctx,     /* module context */
    rp_http_random_index_commands,        /* module directives */
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
rp_http_random_index_handler(rp_http_request_t *r)
{
    u_char                            *last, *filename;
    size_t                             len, allocated, root;
    rp_err_t                          err;
    rp_int_t                          rc;
    rp_str_t                          path, uri, *name;
    rp_dir_t                          dir;
    rp_uint_t                         n, level;
    rp_array_t                        names;
    rp_http_random_index_loc_conf_t  *rlcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RP_DECLINED;
    }

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD|RP_HTTP_POST))) {
        return RP_DECLINED;
    }

    rlcf = rp_http_get_module_loc_conf(r, rp_http_random_index_module);

    if (!rlcf->enable) {
        return RP_DECLINED;
    }

#if (RP_HAVE_D_TYPE)
    len = 0;
#else
    len = RP_HTTP_RANDOM_INDEX_PREALLOCATE;
#endif

    last = rp_http_map_uri_to_path(r, &path, &root, len);
    if (last == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;

    path.len = last - path.data - 1;
    path.data[path.len] = '\0';

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http random index: \"%s\"", path.data);

    if (rp_open_dir(&path, &dir) == RP_ERROR) {
        err = rp_errno;

        if (err == RP_ENOENT
            || err == RP_ENOTDIR
            || err == RP_ENAMETOOLONG)
        {
            level = RP_LOG_ERR;
            rc = RP_HTTP_NOT_FOUND;

        } else if (err == RP_EACCES) {
            level = RP_LOG_ERR;
            rc = RP_HTTP_FORBIDDEN;

        } else {
            level = RP_LOG_CRIT;
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rp_log_error(level, r->connection->log, err,
                      rp_open_dir_n " \"%s\" failed", path.data);

        return rc;
    }

    if (rp_array_init(&names, r->pool, 32, sizeof(rp_str_t)) != RP_OK) {
        return rp_http_random_index_error(r, &dir, &path);
    }

    filename = path.data;
    filename[path.len] = '/';

    for ( ;; ) {
        rp_set_errno(0);

        if (rp_read_dir(&dir) == RP_ERROR) {
            err = rp_errno;

            if (err != RP_ENOMOREFILES) {
                rp_log_error(RP_LOG_CRIT, r->connection->log, err,
                              rp_read_dir_n " \"%V\" failed", &path);
                return rp_http_random_index_error(r, &dir, &path);
            }

            break;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http random index file: \"%s\"", rp_de_name(&dir));

        if (rp_de_name(&dir)[0] == '.') {
            continue;
        }

        len = rp_de_namelen(&dir);

        if (dir.type == 0 || rp_de_is_link(&dir)) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + RP_HTTP_RANDOM_INDEX_PREALLOCATE;

                filename = rp_pnalloc(r->pool, allocated);
                if (filename == NULL) {
                    return rp_http_random_index_error(r, &dir, &path);
                }

                last = rp_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            rp_cpystrn(last, rp_de_name(&dir), len + 1);

            if (rp_de_info(filename, &dir) == RP_FILE_ERROR) {
                err = rp_errno;

                if (err != RP_ENOENT) {
                    rp_log_error(RP_LOG_CRIT, r->connection->log, err,
                                  rp_de_info_n " \"%s\" failed", filename);
                    return rp_http_random_index_error(r, &dir, &path);
                }

                if (rp_de_link_info(filename, &dir) == RP_FILE_ERROR) {
                    rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                                  rp_de_link_info_n " \"%s\" failed",
                                  filename);
                    return rp_http_random_index_error(r, &dir, &path);
                }
            }
        }

        if (!rp_de_is_file(&dir)) {
            continue;
        }

        name = rp_array_push(&names);
        if (name == NULL) {
            return rp_http_random_index_error(r, &dir, &path);
        }

        name->len = len;

        name->data = rp_pnalloc(r->pool, len);
        if (name->data == NULL) {
            return rp_http_random_index_error(r, &dir, &path);
        }

        rp_memcpy(name->data, rp_de_name(&dir), len);
    }

    if (rp_close_dir(&dir) == RP_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_dir_n " \"%V\" failed", &path);
    }

    n = names.nelts;

    if (n == 0) {
        return RP_DECLINED;
    }

    name = names.elts;

    n = (rp_uint_t) (((uint64_t) rp_random() * n) / 0x80000000);

    uri.len = r->uri.len + name[n].len;

    uri.data = rp_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = rp_copy(uri.data, r->uri.data, r->uri.len);
    rp_memcpy(last, name[n].data, name[n].len);

    return rp_http_internal_redirect(r, &uri, &r->args);
}


static rp_int_t
rp_http_random_index_error(rp_http_request_t *r, rp_dir_t *dir,
    rp_str_t *name)
{
    if (rp_close_dir(dir) == RP_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_dir_n " \"%V\" failed", name);
    }

    return RP_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
rp_http_random_index_create_loc_conf(rp_conf_t *cf)
{
    rp_http_random_index_loc_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_random_index_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_random_index_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_random_index_loc_conf_t *prev = parent;
    rp_http_random_index_loc_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_random_index_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_random_index_handler;

    return RP_OK;
}
