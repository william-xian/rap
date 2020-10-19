
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


static rap_int_t rap_test_full_name(rap_str_t *name);


static rap_atomic_t   temp_number = 0;
rap_atomic_t         *rap_temp_number = &temp_number;
rap_atomic_int_t      rap_random_number = 123456;


rap_int_t
rap_get_full_name(rap_pool_t *pool, rap_str_t *prefix, rap_str_t *name)
{
    size_t      len;
    u_char     *p, *n;
    rap_int_t   rc;

    rc = rap_test_full_name(name);

    if (rc == RAP_OK) {
        return rc;
    }

    len = prefix->len;

#if (RAP_WIN32)

    if (rc == 2) {
        len = rc;
    }

#endif

    n = rap_pnalloc(pool, len + name->len + 1);
    if (n == NULL) {
        return RAP_ERROR;
    }

    p = rap_cpymem(n, prefix->data, len);
    rap_cpystrn(p, name->data, name->len + 1);

    name->len += len;
    name->data = n;

    return RAP_OK;
}


static rap_int_t
rap_test_full_name(rap_str_t *name)
{
#if (RAP_WIN32)
    u_char  c0, c1;

    c0 = name->data[0];

    if (name->len < 2) {
        if (c0 == '/') {
            return 2;
        }

        return RAP_DECLINED;
    }

    c1 = name->data[1];

    if (c1 == ':') {
        c0 |= 0x20;

        if ((c0 >= 'a' && c0 <= 'z')) {
            return RAP_OK;
        }

        return RAP_DECLINED;
    }

    if (c1 == '/') {
        return RAP_OK;
    }

    if (c0 == '/') {
        return 2;
    }

    return RAP_DECLINED;

#else

    if (name->data[0] == '/') {
        return RAP_OK;
    }

    return RAP_DECLINED;

#endif
}


ssize_t
rap_write_chain_to_temp_file(rap_temp_file_t *tf, rap_chain_t *chain)
{
    rap_int_t  rc;

    if (tf->file.fd == RAP_INVALID_FILE) {
        rc = rap_create_temp_file(&tf->file, tf->path, tf->pool,
                                  tf->persistent, tf->clean, tf->access);

        if (rc != RAP_OK) {
            return rc;
        }

        if (tf->log_level) {
            rap_log_error(tf->log_level, tf->file.log, 0, "%s %V",
                          tf->warn, &tf->file.name);
        }
    }

#if (RAP_THREADS && RAP_HAVE_PWRITEV)

    if (tf->thread_write) {
        return rap_thread_write_chain_to_file(&tf->file, chain, tf->offset,
                                              tf->pool);
    }

#endif

    return rap_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
}


rap_int_t
rap_create_temp_file(rap_file_t *file, rap_path_t *path, rap_pool_t *pool,
    rap_uint_t persistent, rap_uint_t clean, rap_uint_t access)
{
    size_t                    levels;
    u_char                   *p;
    uint32_t                  n;
    rap_err_t                 err;
    rap_str_t                 name;
    rap_uint_t                prefix;
    rap_pool_cleanup_t       *cln;
    rap_pool_cleanup_file_t  *clnf;

    if (file->name.len) {
        name = file->name;
        levels = 0;
        prefix = 1;

    } else {
        name = path->name;
        levels = path->len;
        prefix = 0;
    }

    file->name.len = name.len + 1 + levels + 10;

    file->name.data = rap_pnalloc(pool, file->name.len + 1);
    if (file->name.data == NULL) {
        return RAP_ERROR;
    }

#if 0
    for (i = 0; i < file->name.len; i++) {
        file->name.data[i] = 'X';
    }
#endif

    p = rap_cpymem(file->name.data, name.data, name.len);

    if (prefix) {
        *p = '.';
    }

    p += 1 + levels;

    n = (uint32_t) rap_next_temp_number(0);

    cln = rap_pool_cleanup_add(pool, sizeof(rap_pool_cleanup_file_t));
    if (cln == NULL) {
        return RAP_ERROR;
    }

    for ( ;; ) {
        (void) rap_sprintf(p, "%010uD%Z", n);

        if (!prefix) {
            rap_create_hashed_filename(path, file->name.data, file->name.len);
        }

        rap_log_debug1(RAP_LOG_DEBUG_CORE, file->log, 0,
                       "hashed path: %s", file->name.data);

        file->fd = rap_open_tempfile(file->name.data, persistent, access);

        rap_log_debug1(RAP_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

        if (file->fd != RAP_INVALID_FILE) {

            cln->handler = clean ? rap_pool_delete_file : rap_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return RAP_OK;
        }

        err = rap_errno;

        if (err == RAP_EEXIST_FILE) {
            n = (uint32_t) rap_next_temp_number(1);
            continue;
        }

        if ((path->level[0] == 0) || (err != RAP_ENOPATH)) {
            rap_log_error(RAP_LOG_CRIT, file->log, err,
                          rap_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return RAP_ERROR;
        }

        if (rap_create_path(file, path) == RAP_ERROR) {
            return RAP_ERROR;
        }
    }
}


void
rap_create_hashed_filename(rap_path_t *path, u_char *file, size_t len)
{
    size_t      i, level;
    rap_uint_t  n;

    i = path->name.len + 1;

    file[path->name.len + path->len]  = '/';

    for (n = 0; n < RAP_MAX_PATH_LEVEL; n++) {
        level = path->level[n];

        if (level == 0) {
            break;
        }

        len -= level;
        file[i - 1] = '/';
        rap_memcpy(&file[i], &file[len], level);
        i += level + 1;
    }
}


rap_int_t
rap_create_path(rap_file_t *file, rap_path_t *path)
{
    size_t      pos;
    rap_err_t   err;
    rap_uint_t  i;

    pos = path->name.len;

    for (i = 0; i < RAP_MAX_PATH_LEVEL; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        rap_log_debug1(RAP_LOG_DEBUG_CORE, file->log, 0,
                       "temp file: \"%s\"", file->name.data);

        if (rap_create_dir(file->name.data, 0700) == RAP_FILE_ERROR) {
            err = rap_errno;
            if (err != RAP_EEXIST) {
                rap_log_error(RAP_LOG_CRIT, file->log, err,
                              rap_create_dir_n " \"%s\" failed",
                              file->name.data);
                return RAP_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return RAP_OK;
}


rap_err_t
rap_create_full_path(u_char *dir, rap_uint_t access)
{
    u_char     *p, ch;
    rap_err_t   err;

    err = 0;

#if (RAP_WIN32)
    p = dir + 3;
#else
    p = dir + 1;
#endif

    for ( /* void */ ; *p; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (rap_create_dir(dir, access) == RAP_FILE_ERROR) {
            err = rap_errno;

            switch (err) {
            case RAP_EEXIST:
                err = 0;
            case RAP_EACCES:
                break;

            default:
                return err;
            }
        }

        *p = '/';
    }

    return err;
}


rap_atomic_uint_t
rap_next_temp_number(rap_uint_t collision)
{
    rap_atomic_uint_t  n, add;

    add = collision ? rap_random_number : 1;

    n = rap_atomic_fetch_add(rap_temp_number, add);

    return n + add;
}


char *
rap_conf_set_path_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t      level;
    rap_str_t   *value;
    rap_uint_t   i, n;
    rap_path_t  *path, **slot;

    slot = (rap_path_t **) (p + cmd->offset);

    if (*slot) {
        return "is duplicate";
    }

    path = rap_pcalloc(cf->pool, sizeof(rap_path_t));
    if (path == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (rap_conf_full_name(cf->cycle, &path->name, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
        level = rap_atoi(value[n].data, value[n].len);
        if (level == RAP_ERROR || level == 0) {
            return "invalid value";
        }

        path->level[i] = level;
        path->len += level + 1;
    }

    if (path->len > 10 + i) {
        return "invalid value";
    }

    *slot = path;

    if (rap_add_path(cf, slot) == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


char *
rap_conf_merge_path_value(rap_conf_t *cf, rap_path_t **path, rap_path_t *prev,
    rap_path_init_t *init)
{
    rap_uint_t  i;

    if (*path) {
        return RAP_CONF_OK;
    }

    if (prev) {
        *path = prev;
        return RAP_CONF_OK;
    }

    *path = rap_pcalloc(cf->pool, sizeof(rap_path_t));
    if (*path == NULL) {
        return RAP_CONF_ERROR;
    }

    (*path)->name = init->name;

    if (rap_conf_full_name(cf->cycle, &(*path)->name, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    for (i = 0; i < RAP_MAX_PATH_LEVEL; i++) {
        (*path)->level[i] = init->level[i];
        (*path)->len += init->level[i] + (init->level[i] ? 1 : 0);
    }

    if (rap_add_path(cf, path) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_access_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *confp = conf;

    u_char      *p;
    rap_str_t   *value;
    rap_uint_t   i, right, shift, *access, user;

    access = (rap_uint_t *) (confp + cmd->offset);

    if (*access != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *access = 0;
    user = 0600;

    for (i = 1; i < cf->args->nelts; i++) {

        p = value[i].data;

        if (rap_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
            shift = 6;
            p += sizeof("user:") - 1;
            user = 0;

        } else if (rap_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
            shift = 3;
            p += sizeof("group:") - 1;

        } else if (rap_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
            shift = 0;
            p += sizeof("all:") - 1;

        } else {
            goto invalid;
        }

        if (rap_strcmp(p, "rw") == 0) {
            right = 6;

        } else if (rap_strcmp(p, "r") == 0) {
            right = 4;

        } else {
            goto invalid;
        }

        *access |= right << shift;
    }

    *access |= user;

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[i]);

    return RAP_CONF_ERROR;
}


rap_int_t
rap_add_path(rap_conf_t *cf, rap_path_t **slot)
{
    rap_uint_t   i, n;
    rap_path_t  *path, **p;

    path = *slot;

    p = cf->cycle->paths.elts;
    for (i = 0; i < cf->cycle->paths.nelts; i++) {
        if (p[i]->name.len == path->name.len
            && rap_strcmp(p[i]->name.data, path->name.data) == 0)
        {
            if (p[i]->data != path->data) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "the same path name \"%V\" "
                                   "used in %s:%ui and",
                                   &p[i]->name, p[i]->conf_file, p[i]->line);
                return RAP_ERROR;
            }

            for (n = 0; n < RAP_MAX_PATH_LEVEL; n++) {
                if (p[i]->level[n] != path->level[n]) {
                    if (path->conf_file == NULL) {
                        if (p[i]->conf_file == NULL) {
                            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                                      "the default path name \"%V\" has "
                                      "the same name as another default path, "
                                      "but the different levels, you need to "
                                      "redefine one of them in http section",
                                      &p[i]->name);
                            return RAP_ERROR;
                        }

                        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                                      "the path name \"%V\" in %s:%ui has "
                                      "the same name as default path, but "
                                      "the different levels, you need to "
                                      "define default path in http section",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                        return RAP_ERROR;
                    }

                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                      "the same path name \"%V\" in %s:%ui "
                                      "has the different levels than",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                    return RAP_ERROR;
                }

                if (p[i]->level[n] == 0) {
                    break;
                }
            }

            *slot = p[i];

            return RAP_OK;
        }
    }

    p = rap_array_push(&cf->cycle->paths);
    if (p == NULL) {
        return RAP_ERROR;
    }

    *p = path;

    return RAP_OK;
}


rap_int_t
rap_create_paths(rap_cycle_t *cycle, rap_uid_t user)
{
    rap_err_t         err;
    rap_uint_t        i;
    rap_path_t      **path;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (rap_create_dir(path[i]->name.data, 0700) == RAP_FILE_ERROR) {
            err = rap_errno;
            if (err != RAP_EEXIST) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, err,
                              rap_create_dir_n " \"%s\" failed",
                              path[i]->name.data);
                return RAP_ERROR;
            }
        }

        if (user == (rap_uid_t) RAP_CONF_UNSET_UINT) {
            continue;
        }

#if !(RAP_WIN32)
        {
        rap_file_info_t   fi;

        if (rap_file_info(path[i]->name.data, &fi) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          rap_file_info_n " \"%s\" failed", path[i]->name.data);
            return RAP_ERROR;
        }

        if (fi.st_uid != user) {
            if (chown((const char *) path[i]->name.data, user, -1) == -1) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              "chown(\"%s\", %d) failed",
                              path[i]->name.data, user);
                return RAP_ERROR;
            }
        }

        if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))
                                                  != (S_IRUSR|S_IWUSR|S_IXUSR))
        {
            fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);

            if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              "chmod() \"%s\" failed", path[i]->name.data);
                return RAP_ERROR;
            }
        }
        }
#endif
    }

    return RAP_OK;
}


rap_int_t
rap_ext_rename_file(rap_str_t *src, rap_str_t *to, rap_ext_rename_file_t *ext)
{
    u_char           *name;
    rap_err_t         err;
    rap_copy_file_t   cf;

#if !(RAP_WIN32)

    if (ext->access) {
        if (rap_change_file_access(src->data, ext->access) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                          rap_change_file_access_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

#endif

    if (ext->time != -1) {
        if (rap_set_file_time(src->data, ext->fd, ext->time) != RAP_OK) {
            rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                          rap_set_file_time_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

    if (rap_rename_file(src->data, to->data) != RAP_FILE_ERROR) {
        return RAP_OK;
    }

    err = rap_errno;

    if (err == RAP_ENOPATH) {

        if (!ext->create_path) {
            goto failed;
        }

        err = rap_create_full_path(to->data, rap_dir_access(ext->path_access));

        if (err) {
            rap_log_error(RAP_LOG_CRIT, ext->log, err,
                          rap_create_dir_n " \"%s\" failed", to->data);
            err = 0;
            goto failed;
        }

        if (rap_rename_file(src->data, to->data) != RAP_FILE_ERROR) {
            return RAP_OK;
        }

        err = rap_errno;
    }

#if (RAP_WIN32)

    if (err == RAP_EEXIST || err == RAP_EEXIST_FILE) {
        err = rap_win32_rename_file(src, to, ext->log);

        if (err == 0) {
            return RAP_OK;
        }
    }

#endif

    if (err == RAP_EXDEV) {

        cf.size = -1;
        cf.buf_size = 0;
        cf.access = ext->access;
        cf.time = ext->time;
        cf.log = ext->log;

        name = rap_alloc(to->len + 1 + 10 + 1, ext->log);
        if (name == NULL) {
            return RAP_ERROR;
        }

        (void) rap_sprintf(name, "%*s.%010uD%Z", to->len, to->data,
                           (uint32_t) rap_next_temp_number(0));

        if (rap_copy_file(src->data, name, &cf) == RAP_OK) {

            if (rap_rename_file(name, to->data) != RAP_FILE_ERROR) {
                rap_free(name);

                if (rap_delete_file(src->data) == RAP_FILE_ERROR) {
                    rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                                  rap_delete_file_n " \"%s\" failed",
                                  src->data);
                    return RAP_ERROR;
                }

                return RAP_OK;
            }

            rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                          rap_rename_file_n " \"%s\" to \"%s\" failed",
                          name, to->data);

            if (rap_delete_file(name) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                              rap_delete_file_n " \"%s\" failed", name);

            }
        }

        rap_free(name);

        err = 0;
    }

failed:

    if (ext->delete_file) {
        if (rap_delete_file(src->data) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_CRIT, ext->log, rap_errno,
                          rap_delete_file_n " \"%s\" failed", src->data);
        }
    }

    if (err) {
        rap_log_error(RAP_LOG_CRIT, ext->log, err,
                      rap_rename_file_n " \"%s\" to \"%s\" failed",
                      src->data, to->data);
    }

    return RAP_ERROR;
}


rap_int_t
rap_copy_file(u_char *from, u_char *to, rap_copy_file_t *cf)
{
    char             *buf;
    off_t             size;
    time_t            time;
    size_t            len;
    ssize_t           n;
    rap_fd_t          fd, nfd;
    rap_int_t         rc;
    rap_uint_t        access;
    rap_file_info_t   fi;

    rc = RAP_ERROR;
    buf = NULL;
    nfd = RAP_INVALID_FILE;

    fd = rap_open_file(from, RAP_FILE_RDONLY, RAP_FILE_OPEN, 0);

    if (fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_CRIT, cf->log, rap_errno,
                      rap_open_file_n " \"%s\" failed", from);
        goto failed;
    }

    if (cf->size != -1 && cf->access != 0 && cf->time != -1) {
        size = cf->size;
        access = cf->access;
        time = cf->time;

    } else {
        if (rap_fd_info(fd, &fi) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_fd_info_n " \"%s\" failed", from);

            goto failed;
        }

        size = (cf->size != -1) ? cf->size : rap_file_size(&fi);
        access = cf->access ? cf->access : rap_file_access(&fi);
        time = (cf->time != -1) ? cf->time : rap_file_mtime(&fi);
    }

    len = cf->buf_size ? cf->buf_size : 65536;

    if ((off_t) len > size) {
        len = (size_t) size;
    }

    buf = rap_alloc(len, cf->log);
    if (buf == NULL) {
        goto failed;
    }

    nfd = rap_open_file(to, RAP_FILE_WRONLY, RAP_FILE_TRUNCATE, access);

    if (nfd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_CRIT, cf->log, rap_errno,
                      rap_open_file_n " \"%s\" failed", to);
        goto failed;
    }

    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = rap_read_fd(fd, buf, len);

        if (n == -1) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_read_fd_n " \"%s\" failed", from);
            goto failed;
        }

        if ((size_t) n != len) {
            rap_log_error(RAP_LOG_ALERT, cf->log, 0,
                          rap_read_fd_n " has read only %z of %O from %s",
                          n, size, from);
            goto failed;
        }

        n = rap_write_fd(nfd, buf, len);

        if (n == -1) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_write_fd_n " \"%s\" failed", to);
            goto failed;
        }

        if ((size_t) n != len) {
            rap_log_error(RAP_LOG_ALERT, cf->log, 0,
                          rap_write_fd_n " has written only %z of %O to %s",
                          n, size, to);
            goto failed;
        }

        size -= n;
    }

    if (rap_set_file_time(to, nfd, time) != RAP_OK) {
        rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                      rap_set_file_time_n " \"%s\" failed", to);
        goto failed;
    }

    rc = RAP_OK;

failed:

    if (nfd != RAP_INVALID_FILE) {
        if (rap_close_file(nfd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_close_file_n " \"%s\" failed", to);
        }
    }

    if (fd != RAP_INVALID_FILE) {
        if (rap_close_file(fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_close_file_n " \"%s\" failed", from);
        }
    }

    if (buf) {
        rap_free(buf);
    }

    return rc;
}


/*
 * ctx->init_handler() - see ctx->alloc
 * ctx->file_handler() - file handler
 * ctx->pre_tree_handler() - handler is called before entering directory
 * ctx->post_tree_handler() - handler is called after leaving directory
 * ctx->spec_handler() - special (socket, FIFO, etc.) file handler
 *
 * ctx->data - some data structure, it may be the same on all levels, or
 *     reallocated if ctx->alloc is nonzero
 *
 * ctx->alloc - a size of data structure that is allocated at every level
 *     and is initialized by ctx->init_handler()
 *
 * ctx->log - a log
 *
 * on fatal (memory) error handler must return RAP_ABORT to stop walking tree
 */

rap_int_t
rap_walk_tree(rap_tree_ctx_t *ctx, rap_str_t *tree)
{
    void       *data, *prev;
    u_char     *p, *name;
    size_t      len;
    rap_int_t   rc;
    rap_err_t   err;
    rap_str_t   file, buf;
    rap_dir_t   dir;

    rap_str_null(&buf);

    rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                   "walk tree \"%V\"", tree);

    if (rap_open_dir(tree, &dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_CRIT, ctx->log, rap_errno,
                      rap_open_dir_n " \"%s\" failed", tree->data);
        return RAP_ERROR;
    }

    prev = ctx->data;

    if (ctx->alloc) {
        data = rap_alloc(ctx->alloc, ctx->log);
        if (data == NULL) {
            goto failed;
        }

        if (ctx->init_handler(data, prev) == RAP_ABORT) {
            goto failed;
        }

        ctx->data = data;

    } else {
        data = NULL;
    }

    for ( ;; ) {

        rap_set_errno(0);

        if (rap_read_dir(&dir) == RAP_ERROR) {
            err = rap_errno;

            if (err == RAP_ENOMOREFILES) {
                rc = RAP_OK;

            } else {
                rap_log_error(RAP_LOG_CRIT, ctx->log, err,
                              rap_read_dir_n " \"%s\" failed", tree->data);
                rc = RAP_ERROR;
            }

            goto done;
        }

        len = rap_de_namelen(&dir);
        name = rap_de_name(&dir);

        rap_log_debug2(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                      "tree name %uz:\"%s\"", len, name);

        if (len == 1 && name[0] == '.') {
            continue;
        }

        if (len == 2 && name[0] == '.' && name[1] == '.') {
            continue;
        }

        file.len = tree->len + 1 + len;

        if (file.len > buf.len) {

            if (buf.len) {
                rap_free(buf.data);
            }

            buf.len = tree->len + 1 + len;

            buf.data = rap_alloc(buf.len + 1, ctx->log);
            if (buf.data == NULL) {
                goto failed;
            }
        }

        p = rap_cpymem(buf.data, tree->data, tree->len);
        *p++ = '/';
        rap_memcpy(p, name, len + 1);

        file.data = buf.data;

        rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                       "tree path \"%s\"", file.data);

        if (!dir.valid_info) {
            if (rap_de_info(file.data, &dir) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_CRIT, ctx->log, rap_errno,
                              rap_de_info_n " \"%s\" failed", file.data);
                continue;
            }
        }

        if (rap_de_is_file(&dir)) {

            rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree file \"%s\"", file.data);

            ctx->size = rap_de_size(&dir);
            ctx->fs_size = rap_de_fs_size(&dir);
            ctx->access = rap_de_access(&dir);
            ctx->mtime = rap_de_mtime(&dir);

            if (ctx->file_handler(ctx, &file) == RAP_ABORT) {
                goto failed;
            }

        } else if (rap_de_is_dir(&dir)) {

            rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree enter dir \"%s\"", file.data);

            ctx->access = rap_de_access(&dir);
            ctx->mtime = rap_de_mtime(&dir);

            rc = ctx->pre_tree_handler(ctx, &file);

            if (rc == RAP_ABORT) {
                goto failed;
            }

            if (rc == RAP_DECLINED) {
                rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                               "tree skip dir \"%s\"", file.data);
                continue;
            }

            if (rap_walk_tree(ctx, &file) == RAP_ABORT) {
                goto failed;
            }

            ctx->access = rap_de_access(&dir);
            ctx->mtime = rap_de_mtime(&dir);

            if (ctx->post_tree_handler(ctx, &file) == RAP_ABORT) {
                goto failed;
            }

        } else {

            rap_log_debug1(RAP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree special \"%s\"", file.data);

            if (ctx->spec_handler(ctx, &file) == RAP_ABORT) {
                goto failed;
            }
        }
    }

failed:

    rc = RAP_ABORT;

done:

    if (buf.len) {
        rap_free(buf.data);
    }

    if (data) {
        rap_free(data);
        ctx->data = prev;
    }

    if (rap_close_dir(&dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_CRIT, ctx->log, rap_errno,
                      rap_close_dir_n " \"%s\" failed", tree->data);
    }

    return rc;
}
