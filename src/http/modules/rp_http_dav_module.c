
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_DAV_OFF             2


#define RP_HTTP_DAV_NO_DEPTH        -3
#define RP_HTTP_DAV_INVALID_DEPTH   -2
#define RP_HTTP_DAV_INFINITY_DEPTH  -1


typedef struct {
    rp_uint_t  methods;
    rp_uint_t  access;
    rp_uint_t  min_delete_depth;
    rp_flag_t  create_full_put_path;
} rp_http_dav_loc_conf_t;


typedef struct {
    rp_str_t   path;
    size_t      len;
} rp_http_dav_copy_ctx_t;


static rp_int_t rp_http_dav_handler(rp_http_request_t *r);

static void rp_http_dav_put_handler(rp_http_request_t *r);

static rp_int_t rp_http_dav_delete_handler(rp_http_request_t *r);
static rp_int_t rp_http_dav_delete_path(rp_http_request_t *r,
    rp_str_t *path, rp_uint_t dir);
static rp_int_t rp_http_dav_delete_dir(rp_tree_ctx_t *ctx, rp_str_t *path);
static rp_int_t rp_http_dav_delete_file(rp_tree_ctx_t *ctx, rp_str_t *path);
static rp_int_t rp_http_dav_noop(rp_tree_ctx_t *ctx, rp_str_t *path);

static rp_int_t rp_http_dav_mkcol_handler(rp_http_request_t *r,
    rp_http_dav_loc_conf_t *dlcf);

static rp_int_t rp_http_dav_copy_move_handler(rp_http_request_t *r);
static rp_int_t rp_http_dav_copy_dir(rp_tree_ctx_t *ctx, rp_str_t *path);
static rp_int_t rp_http_dav_copy_dir_time(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static rp_int_t rp_http_dav_copy_tree_file(rp_tree_ctx_t *ctx,
    rp_str_t *path);

static rp_int_t rp_http_dav_depth(rp_http_request_t *r, rp_int_t dflt);
static rp_int_t rp_http_dav_error(rp_log_t *log, rp_err_t err,
    rp_int_t not_found, char *failed, u_char *path);
static rp_int_t rp_http_dav_location(rp_http_request_t *r);
static void *rp_http_dav_create_loc_conf(rp_conf_t *cf);
static char *rp_http_dav_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_dav_init(rp_conf_t *cf);


static rp_conf_bitmask_t  rp_http_dav_methods_mask[] = {
    { rp_string("off"), RP_HTTP_DAV_OFF },
    { rp_string("put"), RP_HTTP_PUT },
    { rp_string("delete"), RP_HTTP_DELETE },
    { rp_string("mkcol"), RP_HTTP_MKCOL },
    { rp_string("copy"), RP_HTTP_COPY },
    { rp_string("move"), RP_HTTP_MOVE },
    { rp_null_string, 0 }
};


static rp_command_t  rp_http_dav_commands[] = {

    { rp_string("dav_methods"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_dav_loc_conf_t, methods),
      &rp_http_dav_methods_mask },

    { rp_string("create_full_put_path"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_dav_loc_conf_t, create_full_put_path),
      NULL },

    { rp_string("min_delete_depth"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_dav_loc_conf_t, min_delete_depth),
      NULL },

    { rp_string("dav_access"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE123,
      rp_conf_set_access_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_dav_loc_conf_t, access),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_dav_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_dav_create_loc_conf,          /* create location configuration */
    rp_http_dav_merge_loc_conf            /* merge location configuration */
};


rp_module_t  rp_http_dav_module = {
    RP_MODULE_V1,
    &rp_http_dav_module_ctx,              /* module context */
    rp_http_dav_commands,                 /* module directives */
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
rp_http_dav_handler(rp_http_request_t *r)
{
    rp_int_t                 rc;
    rp_http_dav_loc_conf_t  *dlcf;

    dlcf = rp_http_get_module_loc_conf(r, rp_http_dav_module);

    if (!(r->method & dlcf->methods)) {
        return RP_DECLINED;
    }

    switch (r->method) {

    case RP_HTTP_PUT:

        if (r->uri.data[r->uri.len - 1] == '/') {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "cannot PUT to a collection");
            return RP_HTTP_CONFLICT;
        }

        if (r->headers_in.content_range) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "PUT with range is unsupported");
            return RP_HTTP_NOT_IMPLEMENTED;
        }

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        rc = rp_http_read_client_request_body(r, rp_http_dav_put_handler);

        if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return RP_DONE;

    case RP_HTTP_DELETE:

        return rp_http_dav_delete_handler(r);

    case RP_HTTP_MKCOL:

        return rp_http_dav_mkcol_handler(r, dlcf);

    case RP_HTTP_COPY:

        return rp_http_dav_copy_move_handler(r);

    case RP_HTTP_MOVE:

        return rp_http_dav_copy_move_handler(r);
    }

    return RP_DECLINED;
}


static void
rp_http_dav_put_handler(rp_http_request_t *r)
{
    size_t                    root;
    time_t                    date;
    rp_str_t                *temp, path;
    rp_uint_t                status;
    rp_file_info_t           fi;
    rp_ext_rename_file_t     ext;
    rp_http_dav_loc_conf_t  *dlcf;

    if (r->request_body == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "PUT request body is unavailable");
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body->temp_file == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "PUT request body must be in a file");
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rp_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    path.len--;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (rp_file_info(path.data, &fi) == RP_FILE_ERROR) {
        status = RP_HTTP_CREATED;

    } else {
        status = RP_HTTP_NO_CONTENT;

        if (rp_is_dir(&fi)) {
            rp_log_error(RP_LOG_ERR, r->connection->log, RP_EISDIR,
                          "\"%s\" could not be created", path.data);

            if (rp_delete_file(temp->data) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                              rp_delete_file_n " \"%s\" failed",
                              temp->data);
            }

            rp_http_finalize_request(r, RP_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = rp_http_get_module_loc_conf(r, rp_http_dav_module);

    ext.access = dlcf->access;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = dlcf->create_full_put_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (r->headers_in.date) {
        date = rp_parse_http_time(r->headers_in.date->value.data,
                                   r->headers_in.date->value.len);

        if (date != RP_ERROR) {
            ext.time = date;
            ext.fd = r->request_body->temp_file->file.fd;
        }
    }

    if (rp_ext_rename_file(temp, &path, &ext) != RP_OK) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (status == RP_HTTP_CREATED) {
        if (rp_http_dav_location(r) != RP_OK) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    rp_http_finalize_request(r, rp_http_send_header(r));
    return;
}


static rp_int_t
rp_http_dav_delete_handler(rp_http_request_t *r)
{
    size_t                    root;
    rp_err_t                 err;
    rp_int_t                 rc, depth;
    rp_uint_t                i, d, dir;
    rp_str_t                 path;
    rp_file_info_t           fi;
    rp_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "DELETE with body is unsupported");
        return RP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dlcf = rp_http_get_module_loc_conf(r, rp_http_dav_module);

    if (dlcf->min_delete_depth) {
        d = 0;

        for (i = 0; i < r->uri.len; /* void */) {
            if (r->uri.data[i++] == '/') {
                if (++d >= dlcf->min_delete_depth && i < r->uri.len) {
                    goto ok;
                }
            }
        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "insufficient URI depth:%i to DELETE", d);
        return RP_HTTP_CONFLICT;
    }

ok:

    if (rp_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http delete filename: \"%s\"", path.data);

    if (rp_link_info(path.data, &fi) == RP_FILE_ERROR) {
        err = rp_errno;

        rc = (err == RP_ENOTDIR) ? RP_HTTP_CONFLICT : RP_HTTP_NOT_FOUND;

        return rp_http_dav_error(r->connection->log, err,
                                  rc, rp_link_info_n, path.data);
    }

    if (rp_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            rp_log_error(RP_LOG_ERR, r->connection->log, RP_EISDIR,
                          "DELETE \"%s\" failed", path.data);
            return RP_HTTP_CONFLICT;
        }

        depth = rp_http_dav_depth(r, RP_HTTP_DAV_INFINITY_DEPTH);

        if (depth != RP_HTTP_DAV_INFINITY_DEPTH) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return RP_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        dir = 1;

    } else {

        /*
         * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
         * because rp_link_info("/file/") returned RP_ENOTDIR above
         */

        depth = rp_http_dav_depth(r, 0);

        if (depth != 0 && depth != RP_HTTP_DAV_INFINITY_DEPTH) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be 0 or infinity");
            return RP_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = rp_http_dav_delete_path(r, &path, dir);

    if (rc == RP_OK) {
        return RP_HTTP_NO_CONTENT;
    }

    return rc;
}


static rp_int_t
rp_http_dav_delete_path(rp_http_request_t *r, rp_str_t *path, rp_uint_t dir)
{
    char            *failed;
    rp_tree_ctx_t   tree;

    if (dir) {

        tree.init_handler = NULL;
        tree.file_handler = rp_http_dav_delete_file;
        tree.pre_tree_handler = rp_http_dav_noop;
        tree.post_tree_handler = rp_http_dav_delete_dir;
        tree.spec_handler = rp_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        /* TODO: 207 */

        if (rp_walk_tree(&tree, path) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rp_delete_dir(path->data) != RP_FILE_ERROR) {
            return RP_OK;
        }

        failed = rp_delete_dir_n;

    } else {

        if (rp_delete_file(path->data) != RP_FILE_ERROR) {
            return RP_OK;
        }

        failed = rp_delete_file_n;
    }

    return rp_http_dav_error(r->connection->log, rp_errno,
                              RP_HTTP_NOT_FOUND, failed, path->data);
}


static rp_int_t
rp_http_dav_delete_dir(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete dir: \"%s\"", path->data);

    if (rp_delete_dir(path->data) == RP_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) rp_http_dav_error(ctx->log, rp_errno, 0, rp_delete_dir_n,
                                  path->data);
    }

    return RP_OK;
}


static rp_int_t
rp_http_dav_delete_file(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete file: \"%s\"", path->data);

    if (rp_delete_file(path->data) == RP_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) rp_http_dav_error(ctx->log, rp_errno, 0, rp_delete_file_n,
                                  path->data);
    }

    return RP_OK;
}


static rp_int_t
rp_http_dav_noop(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    return RP_OK;
}


static rp_int_t
rp_http_dav_mkcol_handler(rp_http_request_t *r, rp_http_dav_loc_conf_t *dlcf)
{
    u_char    *p;
    size_t     root;
    rp_str_t  path;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "MKCOL with body is unsupported");
        return RP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->uri.data[r->uri.len - 1] != '/') {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "MKCOL can create a collection only");
        return RP_HTTP_CONFLICT;
    }

    p = rp_http_map_uri_to_path(r, &path, &root, 0);
    if (p == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *(p - 1) = '\0';

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http mkcol path: \"%s\"", path.data);

    if (rp_create_dir(path.data, rp_dir_access(dlcf->access))
        != RP_FILE_ERROR)
    {
        if (rp_http_dav_location(r) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        return RP_HTTP_CREATED;
    }

    return rp_http_dav_error(r->connection->log, rp_errno,
                              RP_HTTP_CONFLICT, rp_create_dir_n, path.data);
}


static rp_int_t
rp_http_dav_copy_move_handler(rp_http_request_t *r)
{
    u_char                   *p, *host, *last, ch;
    size_t                    len, root;
    rp_err_t                 err;
    rp_int_t                 rc, depth;
    rp_uint_t                overwrite, slash, dir, flags;
    rp_str_t                 path, uri, duri, args;
    rp_tree_ctx_t            tree;
    rp_copy_file_t           cf;
    rp_file_info_t           fi;
    rp_table_elt_t          *dest, *over;
    rp_ext_rename_file_t     ext;
    rp_http_dav_copy_ctx_t   copy;
    rp_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "COPY and MOVE with body are unsupported");
        return RP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dest = r->headers_in.destination;

    if (dest == NULL) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return RP_HTTP_BAD_REQUEST;
    }

    p = dest->value.data;
    /* there is always '\0' even after empty header value */
    if (p[0] == '/') {
        last = p + dest->value.len;
        goto destination_done;
    }

    len = r->headers_in.server.len;

    if (len == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Host\" header");
        return RP_HTTP_BAD_REQUEST;
    }

#if (RP_HTTP_SSL)

    if (r->connection->ssl) {
        if (rp_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("https://") - 1;

    } else
#endif
    {
        if (rp_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("http://") - 1;
    }

    if (rp_strncmp(host, r->headers_in.server.data, len) != 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "\"Destination\" URI \"%V\" is handled by "
                      "different repository than the source URI",
                      &dest->value);
        return RP_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;

    for (p = host + len; p < last; p++) {
        if (*p == '/') {
            goto destination_done;
        }
    }

invalid_destination:

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Destination\" header: \"%V\"",
                  &dest->value);
    return RP_HTTP_BAD_REQUEST;

destination_done:

    duri.len = last - p;
    duri.data = p;
    flags = RP_HTTP_LOG_UNSAFE;

    if (rp_http_parse_unsafe_uri(r, &duri, &args, &flags) != RP_OK) {
        goto invalid_destination;
    }

    if ((r->uri.data[r->uri.len - 1] == '/' && *(last - 1) != '/')
        || (r->uri.data[r->uri.len - 1] != '/' && *(last - 1) == '/'))
    {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "both URI \"%V\" and \"Destination\" URI \"%V\" "
                      "should be either collections or non-collections",
                      &r->uri, &dest->value);
        return RP_HTTP_CONFLICT;
    }

    depth = rp_http_dav_depth(r, RP_HTTP_DAV_INFINITY_DEPTH);

    if (depth != RP_HTTP_DAV_INFINITY_DEPTH) {

        if (r->method == RP_HTTP_COPY) {
            if (depth != 0) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "\"Depth\" header must be 0 or infinity");
                return RP_HTTP_BAD_REQUEST;
            }

        } else {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return RP_HTTP_BAD_REQUEST;
        }
    }

    over = r->headers_in.overwrite;

    if (over) {
        if (over->value.len == 1) {
            ch = over->value.data[0];

            if (ch == 'T' || ch == 't') {
                overwrite = 1;
                goto overwrite_done;
            }

            if (ch == 'F' || ch == 'f') {
                overwrite = 0;
                goto overwrite_done;
            }

        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Overwrite\" header: \"%V\"",
                      &over->value);
        return RP_HTTP_BAD_REQUEST;
    }

    overwrite = 1;

overwrite_done:

    if (rp_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy from: \"%s\"", path.data);

    uri = r->uri;
    r->uri = duri;

    if (rp_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->uri = uri;

    copy.path.len--;  /* omit "\0" */

    if (copy.path.data[copy.path.len - 1] == '/') {
        slash = 1;
        copy.path.len--;
        copy.path.data[copy.path.len] = '\0';

    } else {
        slash = 0;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy to: \"%s\"", copy.path.data);

    if (rp_link_info(copy.path.data, &fi) == RP_FILE_ERROR) {
        err = rp_errno;

        if (err != RP_ENOENT) {
            return rp_http_dav_error(r->connection->log, err,
                                      RP_HTTP_NOT_FOUND, rp_link_info_n,
                                      copy.path.data);
        }

        /* destination does not exist */

        overwrite = 0;
        dir = 0;

    } else {

        /* destination exists */

        if (rp_is_dir(&fi) && !slash) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"%V\" could not be %Ved to collection \"%V\"",
                          &r->uri, &r->method_name, &dest->value);
            return RP_HTTP_CONFLICT;
        }

        if (!overwrite) {
            rp_log_error(RP_LOG_ERR, r->connection->log, RP_EEXIST,
                          "\"%s\" could not be created", copy.path.data);
            return RP_HTTP_PRECONDITION_FAILED;
        }

        dir = rp_is_dir(&fi);
    }

    if (rp_link_info(path.data, &fi) == RP_FILE_ERROR) {
        return rp_http_dav_error(r->connection->log, rp_errno,
                                  RP_HTTP_NOT_FOUND, rp_link_info_n,
                                  path.data);
    }

    if (rp_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "\"%V\" is collection", &r->uri);
            return RP_HTTP_BAD_REQUEST;
        }

        if (overwrite) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http delete: \"%s\"", copy.path.data);

            rc = rp_http_dav_delete_path(r, &copy.path, dir);

            if (rc != RP_OK) {
                return rc;
            }
        }
    }

    if (rp_is_dir(&fi)) {

        path.len -= 2;  /* omit "/\0" */

        if (r->method == RP_HTTP_MOVE) {
            if (rp_rename_file(path.data, copy.path.data) != RP_FILE_ERROR) {
                return RP_HTTP_CREATED;
            }
        }

        if (rp_create_dir(copy.path.data, rp_file_access(&fi))
            == RP_FILE_ERROR)
        {
            return rp_http_dav_error(r->connection->log, rp_errno,
                                      RP_HTTP_NOT_FOUND,
                                      rp_create_dir_n, copy.path.data);
        }

        copy.len = path.len;

        tree.init_handler = NULL;
        tree.file_handler = rp_http_dav_copy_tree_file;
        tree.pre_tree_handler = rp_http_dav_copy_dir;
        tree.post_tree_handler = rp_http_dav_copy_dir_time;
        tree.spec_handler = rp_http_dav_noop;
        tree.data = &copy;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (rp_walk_tree(&tree, &path) == RP_OK) {

            if (r->method == RP_HTTP_MOVE) {
                rc = rp_http_dav_delete_path(r, &path, 1);

                if (rc != RP_OK) {
                    return rc;
                }
            }

            return RP_HTTP_CREATED;
        }

    } else {

        if (r->method == RP_HTTP_MOVE) {

            dlcf = rp_http_get_module_loc_conf(r, rp_http_dav_module);

            ext.access = 0;
            ext.path_access = dlcf->access;
            ext.time = -1;
            ext.create_path = 1;
            ext.delete_file = 0;
            ext.log = r->connection->log;

            if (rp_ext_rename_file(&path, &copy.path, &ext) == RP_OK) {
                return RP_HTTP_NO_CONTENT;
            }

            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        cf.size = rp_file_size(&fi);
        cf.buf_size = 0;
        cf.access = rp_file_access(&fi);
        cf.time = rp_file_mtime(&fi);
        cf.log = r->connection->log;

        if (rp_copy_file(path.data, copy.path.data, &cf) == RP_OK) {
            return RP_HTTP_NO_CONTENT;
        }
    }

    return RP_HTTP_INTERNAL_SERVER_ERROR;
}


static rp_int_t
rp_http_dav_copy_dir(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    rp_http_dav_copy_ctx_t  *copy;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = rp_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return RP_ABORT;
    }

    p = rp_cpymem(dir, copy->path.data, copy->path.len);
    (void) rp_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir to: \"%s\"", dir);

    if (rp_create_dir(dir, rp_dir_access(ctx->access)) == RP_FILE_ERROR) {
        (void) rp_http_dav_error(ctx->log, rp_errno, 0, rp_create_dir_n,
                                  dir);
    }

    rp_free(dir);

    return RP_OK;
}


static rp_int_t
rp_http_dav_copy_dir_time(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    rp_http_dav_copy_ctx_t  *copy;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = rp_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return RP_ABORT;
    }

    p = rp_cpymem(dir, copy->path.data, copy->path.len);
    (void) rp_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time to: \"%s\"", dir);

#if (RP_WIN32)
    {
    rp_fd_t  fd;

    fd = rp_open_file(dir, RP_FILE_RDWR, RP_FILE_OPEN, 0);

    if (fd == RP_INVALID_FILE) {
        (void) rp_http_dav_error(ctx->log, rp_errno, 0, rp_open_file_n, dir);
        goto failed;
    }

    if (rp_set_file_time(NULL, fd, ctx->mtime) != RP_OK) {
        rp_log_error(RP_LOG_ALERT, ctx->log, rp_errno,
                      rp_set_file_time_n " \"%s\" failed", dir);
    }

    if (rp_close_file(fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, ctx->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", dir);
    }
    }

failed:

#else

    if (rp_set_file_time(dir, 0, ctx->mtime) != RP_OK) {
        rp_log_error(RP_LOG_ALERT, ctx->log, rp_errno,
                      rp_set_file_time_n " \"%s\" failed", dir);
    }

#endif

    rp_free(dir);

    return RP_OK;
}


static rp_int_t
rp_http_dav_copy_tree_file(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    rp_copy_file_t           cf;
    rp_http_dav_copy_ctx_t  *copy;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    file = rp_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return RP_ABORT;
    }

    p = rp_cpymem(file, copy->path.data, copy->path.len);
    (void) rp_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file to: \"%s\"", file);

    cf.size = ctx->size;
    cf.buf_size = 0;
    cf.access = ctx->access;
    cf.time = ctx->mtime;
    cf.log = ctx->log;

    (void) rp_copy_file(path->data, file, &cf);

    rp_free(file);

    return RP_OK;
}


static rp_int_t
rp_http_dav_depth(rp_http_request_t *r, rp_int_t dflt)
{
    rp_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return dflt;
    }

    if (depth->value.len == 1) {

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

    } else {

        if (depth->value.len == sizeof("infinity") - 1
            && rp_strcmp(depth->value.data, "infinity") == 0)
        {
            return RP_HTTP_DAV_INFINITY_DEPTH;
        }
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return RP_HTTP_DAV_INVALID_DEPTH;
}


static rp_int_t
rp_http_dav_error(rp_log_t *log, rp_err_t err, rp_int_t not_found,
    char *failed, u_char *path)
{
    rp_int_t   rc;
    rp_uint_t  level;

    if (err == RP_ENOENT || err == RP_ENOTDIR || err == RP_ENAMETOOLONG) {
        level = RP_LOG_ERR;
        rc = not_found;

    } else if (err == RP_EACCES || err == RP_EPERM) {
        level = RP_LOG_ERR;
        rc = RP_HTTP_FORBIDDEN;

    } else if (err == RP_EEXIST) {
        level = RP_LOG_ERR;
        rc = RP_HTTP_NOT_ALLOWED;

    } else if (err == RP_ENOSPC) {
        level = RP_LOG_CRIT;
        rc = RP_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = RP_LOG_CRIT;
        rc = RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_log_error(level, log, err, "%s \"%s\" failed", failed, path);

    return rc;
}


static rp_int_t
rp_http_dav_location(rp_http_request_t *r)
{
    r->headers_out.location = rp_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return RP_ERROR;
    }

    r->headers_out.location->hash = 1;
    rp_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = r->uri;

    return RP_OK;
}


static void *
rp_http_dav_create_loc_conf(rp_conf_t *cf)
{
    rp_http_dav_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->methods = 0;
     */

    conf->min_delete_depth = RP_CONF_UNSET_UINT;
    conf->access = RP_CONF_UNSET_UINT;
    conf->create_full_put_path = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_dav_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_dav_loc_conf_t  *prev = parent;
    rp_http_dav_loc_conf_t  *conf = child;

    rp_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (RP_CONF_BITMASK_SET|RP_HTTP_DAV_OFF));

    rp_conf_merge_uint_value(conf->min_delete_depth,
                         prev->min_delete_depth, 0);

    rp_conf_merge_uint_value(conf->access, prev->access, 0600);

    rp_conf_merge_value(conf->create_full_put_path,
                         prev->create_full_put_path, 0);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_dav_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_dav_handler;

    return RP_OK;
}
