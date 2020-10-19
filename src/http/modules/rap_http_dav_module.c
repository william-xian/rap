
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_DAV_OFF             2


#define RAP_HTTP_DAV_NO_DEPTH        -3
#define RAP_HTTP_DAV_INVALID_DEPTH   -2
#define RAP_HTTP_DAV_INFINITY_DEPTH  -1


typedef struct {
    rap_uint_t  methods;
    rap_uint_t  access;
    rap_uint_t  min_delete_depth;
    rap_flag_t  create_full_put_path;
} rap_http_dav_loc_conf_t;


typedef struct {
    rap_str_t   path;
    size_t      len;
} rap_http_dav_copy_ctx_t;


static rap_int_t rap_http_dav_handler(rap_http_request_t *r);

static void rap_http_dav_put_handler(rap_http_request_t *r);

static rap_int_t rap_http_dav_delete_handler(rap_http_request_t *r);
static rap_int_t rap_http_dav_delete_path(rap_http_request_t *r,
    rap_str_t *path, rap_uint_t dir);
static rap_int_t rap_http_dav_delete_dir(rap_tree_ctx_t *ctx, rap_str_t *path);
static rap_int_t rap_http_dav_delete_file(rap_tree_ctx_t *ctx, rap_str_t *path);
static rap_int_t rap_http_dav_noop(rap_tree_ctx_t *ctx, rap_str_t *path);

static rap_int_t rap_http_dav_mkcol_handler(rap_http_request_t *r,
    rap_http_dav_loc_conf_t *dlcf);

static rap_int_t rap_http_dav_copy_move_handler(rap_http_request_t *r);
static rap_int_t rap_http_dav_copy_dir(rap_tree_ctx_t *ctx, rap_str_t *path);
static rap_int_t rap_http_dav_copy_dir_time(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static rap_int_t rap_http_dav_copy_tree_file(rap_tree_ctx_t *ctx,
    rap_str_t *path);

static rap_int_t rap_http_dav_depth(rap_http_request_t *r, rap_int_t dflt);
static rap_int_t rap_http_dav_error(rap_log_t *log, rap_err_t err,
    rap_int_t not_found, char *failed, u_char *path);
static rap_int_t rap_http_dav_location(rap_http_request_t *r);
static void *rap_http_dav_create_loc_conf(rap_conf_t *cf);
static char *rap_http_dav_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_dav_init(rap_conf_t *cf);


static rap_conf_bitmask_t  rap_http_dav_methods_mask[] = {
    { rap_string("off"), RAP_HTTP_DAV_OFF },
    { rap_string("put"), RAP_HTTP_PUT },
    { rap_string("delete"), RAP_HTTP_DELETE },
    { rap_string("mkcol"), RAP_HTTP_MKCOL },
    { rap_string("copy"), RAP_HTTP_COPY },
    { rap_string("move"), RAP_HTTP_MOVE },
    { rap_null_string, 0 }
};


static rap_command_t  rap_http_dav_commands[] = {

    { rap_string("dav_methods"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_dav_loc_conf_t, methods),
      &rap_http_dav_methods_mask },

    { rap_string("create_full_put_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_dav_loc_conf_t, create_full_put_path),
      NULL },

    { rap_string("min_delete_depth"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_dav_loc_conf_t, min_delete_depth),
      NULL },

    { rap_string("dav_access"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_conf_set_access_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_dav_loc_conf_t, access),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_dav_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_dav_create_loc_conf,          /* create location configuration */
    rap_http_dav_merge_loc_conf            /* merge location configuration */
};


rap_module_t  rap_http_dav_module = {
    RAP_MODULE_V1,
    &rap_http_dav_module_ctx,              /* module context */
    rap_http_dav_commands,                 /* module directives */
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
rap_http_dav_handler(rap_http_request_t *r)
{
    rap_int_t                 rc;
    rap_http_dav_loc_conf_t  *dlcf;

    dlcf = rap_http_get_module_loc_conf(r, rap_http_dav_module);

    if (!(r->method & dlcf->methods)) {
        return RAP_DECLINED;
    }

    switch (r->method) {

    case RAP_HTTP_PUT:

        if (r->uri.data[r->uri.len - 1] == '/') {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "cannot PUT to a collection");
            return RAP_HTTP_CONFLICT;
        }

        if (r->headers_in.content_range) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "PUT with range is unsupported");
            return RAP_HTTP_NOT_IMPLEMENTED;
        }

        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;
        r->request_body_file_group_access = 1;
        r->request_body_file_log_level = 0;

        rc = rap_http_read_client_request_body(r, rap_http_dav_put_handler);

        if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return RAP_DONE;

    case RAP_HTTP_DELETE:

        return rap_http_dav_delete_handler(r);

    case RAP_HTTP_MKCOL:

        return rap_http_dav_mkcol_handler(r, dlcf);

    case RAP_HTTP_COPY:

        return rap_http_dav_copy_move_handler(r);

    case RAP_HTTP_MOVE:

        return rap_http_dav_copy_move_handler(r);
    }

    return RAP_DECLINED;
}


static void
rap_http_dav_put_handler(rap_http_request_t *r)
{
    size_t                    root;
    time_t                    date;
    rap_str_t                *temp, path;
    rap_uint_t                status;
    rap_file_info_t           fi;
    rap_ext_rename_file_t     ext;
    rap_http_dav_loc_conf_t  *dlcf;

    if (r->request_body == NULL) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "PUT request body is unavailable");
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body->temp_file == NULL) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "PUT request body must be in a file");
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    path.len--;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (rap_file_info(path.data, &fi) == RAP_FILE_ERROR) {
        status = RAP_HTTP_CREATED;

    } else {
        status = RAP_HTTP_NO_CONTENT;

        if (rap_is_dir(&fi)) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, RAP_EISDIR,
                          "\"%s\" could not be created", path.data);

            if (rap_delete_file(temp->data) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                              rap_delete_file_n " \"%s\" failed",
                              temp->data);
            }

            rap_http_finalize_request(r, RAP_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = rap_http_get_module_loc_conf(r, rap_http_dav_module);

    ext.access = dlcf->access;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = dlcf->create_full_put_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (r->headers_in.date) {
        date = rap_parse_http_time(r->headers_in.date->value.data,
                                   r->headers_in.date->value.len);

        if (date != RAP_ERROR) {
            ext.time = date;
            ext.fd = r->request_body->temp_file->file.fd;
        }
    }

    if (rap_ext_rename_file(temp, &path, &ext) != RAP_OK) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (status == RAP_HTTP_CREATED) {
        if (rap_http_dav_location(r) != RAP_OK) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    rap_http_finalize_request(r, rap_http_send_header(r));
    return;
}


static rap_int_t
rap_http_dav_delete_handler(rap_http_request_t *r)
{
    size_t                    root;
    rap_err_t                 err;
    rap_int_t                 rc, depth;
    rap_uint_t                i, d, dir;
    rap_str_t                 path;
    rap_file_info_t           fi;
    rap_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "DELETE with body is unsupported");
        return RAP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dlcf = rap_http_get_module_loc_conf(r, rap_http_dav_module);

    if (dlcf->min_delete_depth) {
        d = 0;

        for (i = 0; i < r->uri.len; /* void */) {
            if (r->uri.data[i++] == '/') {
                if (++d >= dlcf->min_delete_depth && i < r->uri.len) {
                    goto ok;
                }
            }
        }

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "insufficient URI depth:%i to DELETE", d);
        return RAP_HTTP_CONFLICT;
    }

ok:

    if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http delete filename: \"%s\"", path.data);

    if (rap_link_info(path.data, &fi) == RAP_FILE_ERROR) {
        err = rap_errno;

        rc = (err == RAP_ENOTDIR) ? RAP_HTTP_CONFLICT : RAP_HTTP_NOT_FOUND;

        return rap_http_dav_error(r->connection->log, err,
                                  rc, rap_link_info_n, path.data);
    }

    if (rap_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            rap_log_error(RAP_LOG_ERR, r->connection->log, RAP_EISDIR,
                          "DELETE \"%s\" failed", path.data);
            return RAP_HTTP_CONFLICT;
        }

        depth = rap_http_dav_depth(r, RAP_HTTP_DAV_INFINITY_DEPTH);

        if (depth != RAP_HTTP_DAV_INFINITY_DEPTH) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return RAP_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        dir = 1;

    } else {

        /*
         * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
         * because rap_link_info("/file/") returned RAP_ENOTDIR above
         */

        depth = rap_http_dav_depth(r, 0);

        if (depth != 0 && depth != RAP_HTTP_DAV_INFINITY_DEPTH) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be 0 or infinity");
            return RAP_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = rap_http_dav_delete_path(r, &path, dir);

    if (rc == RAP_OK) {
        return RAP_HTTP_NO_CONTENT;
    }

    return rc;
}


static rap_int_t
rap_http_dav_delete_path(rap_http_request_t *r, rap_str_t *path, rap_uint_t dir)
{
    char            *failed;
    rap_tree_ctx_t   tree;

    if (dir) {

        tree.init_handler = NULL;
        tree.file_handler = rap_http_dav_delete_file;
        tree.pre_tree_handler = rap_http_dav_noop;
        tree.post_tree_handler = rap_http_dav_delete_dir;
        tree.spec_handler = rap_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        /* TODO: 207 */

        if (rap_walk_tree(&tree, path) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rap_delete_dir(path->data) != RAP_FILE_ERROR) {
            return RAP_OK;
        }

        failed = rap_delete_dir_n;

    } else {

        if (rap_delete_file(path->data) != RAP_FILE_ERROR) {
            return RAP_OK;
        }

        failed = rap_delete_file_n;
    }

    return rap_http_dav_error(r->connection->log, rap_errno,
                              RAP_HTTP_NOT_FOUND, failed, path->data);
}


static rap_int_t
rap_http_dav_delete_dir(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete dir: \"%s\"", path->data);

    if (rap_delete_dir(path->data) == RAP_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) rap_http_dav_error(ctx->log, rap_errno, 0, rap_delete_dir_n,
                                  path->data);
    }

    return RAP_OK;
}


static rap_int_t
rap_http_dav_delete_file(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete file: \"%s\"", path->data);

    if (rap_delete_file(path->data) == RAP_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) rap_http_dav_error(ctx->log, rap_errno, 0, rap_delete_file_n,
                                  path->data);
    }

    return RAP_OK;
}


static rap_int_t
rap_http_dav_noop(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    return RAP_OK;
}


static rap_int_t
rap_http_dav_mkcol_handler(rap_http_request_t *r, rap_http_dav_loc_conf_t *dlcf)
{
    u_char    *p;
    size_t     root;
    rap_str_t  path;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "MKCOL with body is unsupported");
        return RAP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->uri.data[r->uri.len - 1] != '/') {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "MKCOL can create a collection only");
        return RAP_HTTP_CONFLICT;
    }

    p = rap_http_map_uri_to_path(r, &path, &root, 0);
    if (p == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *(p - 1) = '\0';

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http mkcol path: \"%s\"", path.data);

    if (rap_create_dir(path.data, rap_dir_access(dlcf->access))
        != RAP_FILE_ERROR)
    {
        if (rap_http_dav_location(r) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        return RAP_HTTP_CREATED;
    }

    return rap_http_dav_error(r->connection->log, rap_errno,
                              RAP_HTTP_CONFLICT, rap_create_dir_n, path.data);
}


static rap_int_t
rap_http_dav_copy_move_handler(rap_http_request_t *r)
{
    u_char                   *p, *host, *last, ch;
    size_t                    len, root;
    rap_err_t                 err;
    rap_int_t                 rc, depth;
    rap_uint_t                overwrite, slash, dir, flags;
    rap_str_t                 path, uri, duri, args;
    rap_tree_ctx_t            tree;
    rap_copy_file_t           cf;
    rap_file_info_t           fi;
    rap_table_elt_t          *dest, *over;
    rap_ext_rename_file_t     ext;
    rap_http_dav_copy_ctx_t   copy;
    rap_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "COPY and MOVE with body are unsupported");
        return RAP_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dest = r->headers_in.destination;

    if (dest == NULL) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return RAP_HTTP_BAD_REQUEST;
    }

    p = dest->value.data;
    /* there is always '\0' even after empty header value */
    if (p[0] == '/') {
        last = p + dest->value.len;
        goto destination_done;
    }

    len = r->headers_in.server.len;

    if (len == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Host\" header");
        return RAP_HTTP_BAD_REQUEST;
    }

#if (RAP_HTTP_SSL)

    if (r->connection->ssl) {
        if (rap_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("https://") - 1;

    } else
#endif
    {
        if (rap_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
            != 0)
        {
            goto invalid_destination;
        }

        host = dest->value.data + sizeof("http://") - 1;
    }

    if (rap_strncmp(host, r->headers_in.server.data, len) != 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "\"Destination\" URI \"%V\" is handled by "
                      "different repository than the source URI",
                      &dest->value);
        return RAP_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;

    for (p = host + len; p < last; p++) {
        if (*p == '/') {
            goto destination_done;
        }
    }

invalid_destination:

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Destination\" header: \"%V\"",
                  &dest->value);
    return RAP_HTTP_BAD_REQUEST;

destination_done:

    duri.len = last - p;
    duri.data = p;
    flags = RAP_HTTP_LOG_UNSAFE;

    if (rap_http_parse_unsafe_uri(r, &duri, &args, &flags) != RAP_OK) {
        goto invalid_destination;
    }

    if ((r->uri.data[r->uri.len - 1] == '/' && *(last - 1) != '/')
        || (r->uri.data[r->uri.len - 1] != '/' && *(last - 1) == '/'))
    {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "both URI \"%V\" and \"Destination\" URI \"%V\" "
                      "should be either collections or non-collections",
                      &r->uri, &dest->value);
        return RAP_HTTP_CONFLICT;
    }

    depth = rap_http_dav_depth(r, RAP_HTTP_DAV_INFINITY_DEPTH);

    if (depth != RAP_HTTP_DAV_INFINITY_DEPTH) {

        if (r->method == RAP_HTTP_COPY) {
            if (depth != 0) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "\"Depth\" header must be 0 or infinity");
                return RAP_HTTP_BAD_REQUEST;
            }

        } else {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return RAP_HTTP_BAD_REQUEST;
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

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Overwrite\" header: \"%V\"",
                      &over->value);
        return RAP_HTTP_BAD_REQUEST;
    }

    overwrite = 1;

overwrite_done:

    if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy from: \"%s\"", path.data);

    uri = r->uri;
    r->uri = duri;

    if (rap_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
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

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy to: \"%s\"", copy.path.data);

    if (rap_link_info(copy.path.data, &fi) == RAP_FILE_ERROR) {
        err = rap_errno;

        if (err != RAP_ENOENT) {
            return rap_http_dav_error(r->connection->log, err,
                                      RAP_HTTP_NOT_FOUND, rap_link_info_n,
                                      copy.path.data);
        }

        /* destination does not exist */

        overwrite = 0;
        dir = 0;

    } else {

        /* destination exists */

        if (rap_is_dir(&fi) && !slash) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "\"%V\" could not be %Ved to collection \"%V\"",
                          &r->uri, &r->method_name, &dest->value);
            return RAP_HTTP_CONFLICT;
        }

        if (!overwrite) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, RAP_EEXIST,
                          "\"%s\" could not be created", copy.path.data);
            return RAP_HTTP_PRECONDITION_FAILED;
        }

        dir = rap_is_dir(&fi);
    }

    if (rap_link_info(path.data, &fi) == RAP_FILE_ERROR) {
        return rap_http_dav_error(r->connection->log, rap_errno,
                                  RAP_HTTP_NOT_FOUND, rap_link_info_n,
                                  path.data);
    }

    if (rap_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "\"%V\" is collection", &r->uri);
            return RAP_HTTP_BAD_REQUEST;
        }

        if (overwrite) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http delete: \"%s\"", copy.path.data);

            rc = rap_http_dav_delete_path(r, &copy.path, dir);

            if (rc != RAP_OK) {
                return rc;
            }
        }
    }

    if (rap_is_dir(&fi)) {

        path.len -= 2;  /* omit "/\0" */

        if (r->method == RAP_HTTP_MOVE) {
            if (rap_rename_file(path.data, copy.path.data) != RAP_FILE_ERROR) {
                return RAP_HTTP_CREATED;
            }
        }

        if (rap_create_dir(copy.path.data, rap_file_access(&fi))
            == RAP_FILE_ERROR)
        {
            return rap_http_dav_error(r->connection->log, rap_errno,
                                      RAP_HTTP_NOT_FOUND,
                                      rap_create_dir_n, copy.path.data);
        }

        copy.len = path.len;

        tree.init_handler = NULL;
        tree.file_handler = rap_http_dav_copy_tree_file;
        tree.pre_tree_handler = rap_http_dav_copy_dir;
        tree.post_tree_handler = rap_http_dav_copy_dir_time;
        tree.spec_handler = rap_http_dav_noop;
        tree.data = &copy;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (rap_walk_tree(&tree, &path) == RAP_OK) {

            if (r->method == RAP_HTTP_MOVE) {
                rc = rap_http_dav_delete_path(r, &path, 1);

                if (rc != RAP_OK) {
                    return rc;
                }
            }

            return RAP_HTTP_CREATED;
        }

    } else {

        if (r->method == RAP_HTTP_MOVE) {

            dlcf = rap_http_get_module_loc_conf(r, rap_http_dav_module);

            ext.access = 0;
            ext.path_access = dlcf->access;
            ext.time = -1;
            ext.create_path = 1;
            ext.delete_file = 0;
            ext.log = r->connection->log;

            if (rap_ext_rename_file(&path, &copy.path, &ext) == RAP_OK) {
                return RAP_HTTP_NO_CONTENT;
            }

            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        cf.size = rap_file_size(&fi);
        cf.buf_size = 0;
        cf.access = rap_file_access(&fi);
        cf.time = rap_file_mtime(&fi);
        cf.log = r->connection->log;

        if (rap_copy_file(path.data, copy.path.data, &cf) == RAP_OK) {
            return RAP_HTTP_NO_CONTENT;
        }
    }

    return RAP_HTTP_INTERNAL_SERVER_ERROR;
}


static rap_int_t
rap_http_dav_copy_dir(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    rap_http_dav_copy_ctx_t  *copy;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = rap_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return RAP_ABORT;
    }

    p = rap_cpymem(dir, copy->path.data, copy->path.len);
    (void) rap_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir to: \"%s\"", dir);

    if (rap_create_dir(dir, rap_dir_access(ctx->access)) == RAP_FILE_ERROR) {
        (void) rap_http_dav_error(ctx->log, rap_errno, 0, rap_create_dir_n,
                                  dir);
    }

    rap_free(dir);

    return RAP_OK;
}


static rap_int_t
rap_http_dav_copy_dir_time(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    rap_http_dav_copy_ctx_t  *copy;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = rap_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return RAP_ABORT;
    }

    p = rap_cpymem(dir, copy->path.data, copy->path.len);
    (void) rap_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time to: \"%s\"", dir);

#if (RAP_WIN32)
    {
    rap_fd_t  fd;

    fd = rap_open_file(dir, RAP_FILE_RDWR, RAP_FILE_OPEN, 0);

    if (fd == RAP_INVALID_FILE) {
        (void) rap_http_dav_error(ctx->log, rap_errno, 0, rap_open_file_n, dir);
        goto failed;
    }

    if (rap_set_file_time(NULL, fd, ctx->mtime) != RAP_OK) {
        rap_log_error(RAP_LOG_ALERT, ctx->log, rap_errno,
                      rap_set_file_time_n " \"%s\" failed", dir);
    }

    if (rap_close_file(fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, ctx->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", dir);
    }
    }

failed:

#else

    if (rap_set_file_time(dir, 0, ctx->mtime) != RAP_OK) {
        rap_log_error(RAP_LOG_ALERT, ctx->log, rap_errno,
                      rap_set_file_time_n " \"%s\" failed", dir);
    }

#endif

    rap_free(dir);

    return RAP_OK;
}


static rap_int_t
rap_http_dav_copy_tree_file(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    rap_copy_file_t           cf;
    rap_http_dav_copy_ctx_t  *copy;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    file = rap_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return RAP_ABORT;
    }

    p = rap_cpymem(file, copy->path.data, copy->path.len);
    (void) rap_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file to: \"%s\"", file);

    cf.size = ctx->size;
    cf.buf_size = 0;
    cf.access = ctx->access;
    cf.time = ctx->mtime;
    cf.log = ctx->log;

    (void) rap_copy_file(path->data, file, &cf);

    rap_free(file);

    return RAP_OK;
}


static rap_int_t
rap_http_dav_depth(rap_http_request_t *r, rap_int_t dflt)
{
    rap_table_elt_t  *depth;

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
            && rap_strcmp(depth->value.data, "infinity") == 0)
        {
            return RAP_HTTP_DAV_INFINITY_DEPTH;
        }
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return RAP_HTTP_DAV_INVALID_DEPTH;
}


static rap_int_t
rap_http_dav_error(rap_log_t *log, rap_err_t err, rap_int_t not_found,
    char *failed, u_char *path)
{
    rap_int_t   rc;
    rap_uint_t  level;

    if (err == RAP_ENOENT || err == RAP_ENOTDIR || err == RAP_ENAMETOOLONG) {
        level = RAP_LOG_ERR;
        rc = not_found;

    } else if (err == RAP_EACCES || err == RAP_EPERM) {
        level = RAP_LOG_ERR;
        rc = RAP_HTTP_FORBIDDEN;

    } else if (err == RAP_EEXIST) {
        level = RAP_LOG_ERR;
        rc = RAP_HTTP_NOT_ALLOWED;

    } else if (err == RAP_ENOSPC) {
        level = RAP_LOG_CRIT;
        rc = RAP_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = RAP_LOG_CRIT;
        rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_log_error(level, log, err, "%s \"%s\" failed", failed, path);

    return rc;
}


static rap_int_t
rap_http_dav_location(rap_http_request_t *r)
{
    r->headers_out.location = rap_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return RAP_ERROR;
    }

    r->headers_out.location->hash = 1;
    rap_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = r->uri;

    return RAP_OK;
}


static void *
rap_http_dav_create_loc_conf(rap_conf_t *cf)
{
    rap_http_dav_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->methods = 0;
     */

    conf->min_delete_depth = RAP_CONF_UNSET_UINT;
    conf->access = RAP_CONF_UNSET_UINT;
    conf->create_full_put_path = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_dav_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_dav_loc_conf_t  *prev = parent;
    rap_http_dav_loc_conf_t  *conf = child;

    rap_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (RAP_CONF_BITMASK_SET|RAP_HTTP_DAV_OFF));

    rap_conf_merge_uint_value(conf->min_delete_depth,
                         prev->min_delete_depth, 0);

    rap_conf_merge_uint_value(conf->access, prev->access, 0600);

    rap_conf_merge_value(conf->create_full_put_path,
                         prev->create_full_put_path, 0);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_dav_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_dav_handler;

    return RAP_OK;
}
