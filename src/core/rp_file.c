
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


static rp_int_t rp_test_full_name(rp_str_t *name);


static rp_atomic_t   temp_number = 0;
rp_atomic_t         *rp_temp_number = &temp_number;
rp_atomic_int_t      rp_random_number = 123456;


rp_int_t
rp_get_full_name(rp_pool_t *pool, rp_str_t *prefix, rp_str_t *name)
{
    size_t      len;
    u_char     *p, *n;
    rp_int_t   rc;

    rc = rp_test_full_name(name);

    if (rc == RP_OK) {
        return rc;
    }

    len = prefix->len;

#if (RP_WIN32)

    if (rc == 2) {
        len = rc;
    }

#endif

    n = rp_pnalloc(pool, len + name->len + 1);
    if (n == NULL) {
        return RP_ERROR;
    }

    p = rp_cpymem(n, prefix->data, len);
    rp_cpystrn(p, name->data, name->len + 1);

    name->len += len;
    name->data = n;

    return RP_OK;
}


static rp_int_t
rp_test_full_name(rp_str_t *name)
{
#if (RP_WIN32)
    u_char  c0, c1;

    c0 = name->data[0];

    if (name->len < 2) {
        if (c0 == '/') {
            return 2;
        }

        return RP_DECLINED;
    }

    c1 = name->data[1];

    if (c1 == ':') {
        c0 |= 0x20;

        if ((c0 >= 'a' && c0 <= 'z')) {
            return RP_OK;
        }

        return RP_DECLINED;
    }

    if (c1 == '/') {
        return RP_OK;
    }

    if (c0 == '/') {
        return 2;
    }

    return RP_DECLINED;

#else

    if (name->data[0] == '/') {
        return RP_OK;
    }

    return RP_DECLINED;

#endif
}


ssize_t
rp_write_chain_to_temp_file(rp_temp_file_t *tf, rp_chain_t *chain)
{
    rp_int_t  rc;

    if (tf->file.fd == RP_INVALID_FILE) {
        rc = rp_create_temp_file(&tf->file, tf->path, tf->pool,
                                  tf->persistent, tf->clean, tf->access);

        if (rc != RP_OK) {
            return rc;
        }

        if (tf->log_level) {
            rp_log_error(tf->log_level, tf->file.log, 0, "%s %V",
                          tf->warn, &tf->file.name);
        }
    }

#if (RP_THREADS && RP_HAVE_PWRITEV)

    if (tf->thread_write) {
        return rp_thread_write_chain_to_file(&tf->file, chain, tf->offset,
                                              tf->pool);
    }

#endif

    return rp_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
}


rp_int_t
rp_create_temp_file(rp_file_t *file, rp_path_t *path, rp_pool_t *pool,
    rp_uint_t persistent, rp_uint_t clean, rp_uint_t access)
{
    size_t                    levels;
    u_char                   *p;
    uint32_t                  n;
    rp_err_t                 err;
    rp_str_t                 name;
    rp_uint_t                prefix;
    rp_pool_cleanup_t       *cln;
    rp_pool_cleanup_file_t  *clnf;

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

    file->name.data = rp_pnalloc(pool, file->name.len + 1);
    if (file->name.data == NULL) {
        return RP_ERROR;
    }

#if 0
    for (i = 0; i < file->name.len; i++) {
        file->name.data[i] = 'X';
    }
#endif

    p = rp_cpymem(file->name.data, name.data, name.len);

    if (prefix) {
        *p = '.';
    }

    p += 1 + levels;

    n = (uint32_t) rp_next_temp_number(0);

    cln = rp_pool_cleanup_add(pool, sizeof(rp_pool_cleanup_file_t));
    if (cln == NULL) {
        return RP_ERROR;
    }

    for ( ;; ) {
        (void) rp_sprintf(p, "%010uD%Z", n);

        if (!prefix) {
            rp_create_hashed_filename(path, file->name.data, file->name.len);
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, file->log, 0,
                       "hashed path: %s", file->name.data);

        file->fd = rp_open_tempfile(file->name.data, persistent, access);

        rp_log_debug1(RP_LOG_DEBUG_CORE, file->log, 0,
                       "temp fd:%d", file->fd);

        if (file->fd != RP_INVALID_FILE) {

            cln->handler = clean ? rp_pool_delete_file : rp_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = file->fd;
            clnf->name = file->name.data;
            clnf->log = pool->log;

            return RP_OK;
        }

        err = rp_errno;

        if (err == RP_EEXIST_FILE) {
            n = (uint32_t) rp_next_temp_number(1);
            continue;
        }

        if ((path->level[0] == 0) || (err != RP_ENOPATH)) {
            rp_log_error(RP_LOG_CRIT, file->log, err,
                          rp_open_tempfile_n " \"%s\" failed",
                          file->name.data);
            return RP_ERROR;
        }

        if (rp_create_path(file, path) == RP_ERROR) {
            return RP_ERROR;
        }
    }
}


void
rp_create_hashed_filename(rp_path_t *path, u_char *file, size_t len)
{
    size_t      i, level;
    rp_uint_t  n;

    i = path->name.len + 1;

    file[path->name.len + path->len]  = '/';

    for (n = 0; n < RP_MAX_PATH_LEVEL; n++) {
        level = path->level[n];

        if (level == 0) {
            break;
        }

        len -= level;
        file[i - 1] = '/';
        rp_memcpy(&file[i], &file[len], level);
        i += level + 1;
    }
}


rp_int_t
rp_create_path(rp_file_t *file, rp_path_t *path)
{
    size_t      pos;
    rp_err_t   err;
    rp_uint_t  i;

    pos = path->name.len;

    for (i = 0; i < RP_MAX_PATH_LEVEL; i++) {
        if (path->level[i] == 0) {
            break;
        }

        pos += path->level[i] + 1;

        file->name.data[pos] = '\0';

        rp_log_debug1(RP_LOG_DEBUG_CORE, file->log, 0,
                       "temp file: \"%s\"", file->name.data);

        if (rp_create_dir(file->name.data, 0700) == RP_FILE_ERROR) {
            err = rp_errno;
            if (err != RP_EEXIST) {
                rp_log_error(RP_LOG_CRIT, file->log, err,
                              rp_create_dir_n " \"%s\" failed",
                              file->name.data);
                return RP_ERROR;
            }
        }

        file->name.data[pos] = '/';
    }

    return RP_OK;
}


rp_err_t
rp_create_full_path(u_char *dir, rp_uint_t access)
{
    u_char     *p, ch;
    rp_err_t   err;

    err = 0;

#if (RP_WIN32)
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

        if (rp_create_dir(dir, access) == RP_FILE_ERROR) {
            err = rp_errno;

            switch (err) {
            case RP_EEXIST:
                err = 0;
            case RP_EACCES:
                break;

            default:
                return err;
            }
        }

        *p = '/';
    }

    return err;
}


rp_atomic_uint_t
rp_next_temp_number(rp_uint_t collision)
{
    rp_atomic_uint_t  n, add;

    add = collision ? rp_random_number : 1;

    n = rp_atomic_fetch_add(rp_temp_number, add);

    return n + add;
}


char *
rp_conf_set_path_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t      level;
    rp_str_t   *value;
    rp_uint_t   i, n;
    rp_path_t  *path, **slot;

    slot = (rp_path_t **) (p + cmd->offset);

    if (*slot) {
        return "is duplicate";
    }

    path = rp_pcalloc(cf->pool, sizeof(rp_path_t));
    if (path == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    path->name = value[1];

    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }

    if (rp_conf_full_name(cf->cycle, &path->name, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;

    for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
        level = rp_atoi(value[n].data, value[n].len);
        if (level == RP_ERROR || level == 0) {
            return "invalid value";
        }

        path->level[i] = level;
        path->len += level + 1;
    }

    if (path->len > 10 + i) {
        return "invalid value";
    }

    *slot = path;

    if (rp_add_path(cf, slot) == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


char *
rp_conf_merge_path_value(rp_conf_t *cf, rp_path_t **path, rp_path_t *prev,
    rp_path_init_t *init)
{
    rp_uint_t  i;

    if (*path) {
        return RP_CONF_OK;
    }

    if (prev) {
        *path = prev;
        return RP_CONF_OK;
    }

    *path = rp_pcalloc(cf->pool, sizeof(rp_path_t));
    if (*path == NULL) {
        return RP_CONF_ERROR;
    }

    (*path)->name = init->name;

    if (rp_conf_full_name(cf->cycle, &(*path)->name, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    for (i = 0; i < RP_MAX_PATH_LEVEL; i++) {
        (*path)->level[i] = init->level[i];
        (*path)->len += init->level[i] + (init->level[i] ? 1 : 0);
    }

    if (rp_add_path(cf, path) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_access_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *confp = conf;

    u_char      *p;
    rp_str_t   *value;
    rp_uint_t   i, right, shift, *access, user;

    access = (rp_uint_t *) (confp + cmd->offset);

    if (*access != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *access = 0;
    user = 0600;

    for (i = 1; i < cf->args->nelts; i++) {

        p = value[i].data;

        if (rp_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
            shift = 6;
            p += sizeof("user:") - 1;
            user = 0;

        } else if (rp_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
            shift = 3;
            p += sizeof("group:") - 1;

        } else if (rp_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
            shift = 0;
            p += sizeof("all:") - 1;

        } else {
            goto invalid;
        }

        if (rp_strcmp(p, "rw") == 0) {
            right = 6;

        } else if (rp_strcmp(p, "r") == 0) {
            right = 4;

        } else {
            goto invalid;
        }

        *access |= right << shift;
    }

    *access |= user;

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[i]);

    return RP_CONF_ERROR;
}


rp_int_t
rp_add_path(rp_conf_t *cf, rp_path_t **slot)
{
    rp_uint_t   i, n;
    rp_path_t  *path, **p;

    path = *slot;

    p = cf->cycle->paths.elts;
    for (i = 0; i < cf->cycle->paths.nelts; i++) {
        if (p[i]->name.len == path->name.len
            && rp_strcmp(p[i]->name.data, path->name.data) == 0)
        {
            if (p[i]->data != path->data) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "the same path name \"%V\" "
                                   "used in %s:%ui and",
                                   &p[i]->name, p[i]->conf_file, p[i]->line);
                return RP_ERROR;
            }

            for (n = 0; n < RP_MAX_PATH_LEVEL; n++) {
                if (p[i]->level[n] != path->level[n]) {
                    if (path->conf_file == NULL) {
                        if (p[i]->conf_file == NULL) {
                            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                                      "the default path name \"%V\" has "
                                      "the same name as another default path, "
                                      "but the different levels, you need to "
                                      "redefine one of them in http section",
                                      &p[i]->name);
                            return RP_ERROR;
                        }

                        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                                      "the path name \"%V\" in %s:%ui has "
                                      "the same name as default path, but "
                                      "the different levels, you need to "
                                      "define default path in http section",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                        return RP_ERROR;
                    }

                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                      "the same path name \"%V\" in %s:%ui "
                                      "has the different levels than",
                                      &p[i]->name, p[i]->conf_file, p[i]->line);
                    return RP_ERROR;
                }

                if (p[i]->level[n] == 0) {
                    break;
                }
            }

            *slot = p[i];

            return RP_OK;
        }
    }

    p = rp_array_push(&cf->cycle->paths);
    if (p == NULL) {
        return RP_ERROR;
    }

    *p = path;

    return RP_OK;
}


rp_int_t
rp_create_paths(rp_cycle_t *cycle, rp_uid_t user)
{
    rp_err_t         err;
    rp_uint_t        i;
    rp_path_t      **path;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (rp_create_dir(path[i]->name.data, 0700) == RP_FILE_ERROR) {
            err = rp_errno;
            if (err != RP_EEXIST) {
                rp_log_error(RP_LOG_EMERG, cycle->log, err,
                              rp_create_dir_n " \"%s\" failed",
                              path[i]->name.data);
                return RP_ERROR;
            }
        }

        if (user == (rp_uid_t) RP_CONF_UNSET_UINT) {
            continue;
        }

#if !(RP_WIN32)
        {
        rp_file_info_t   fi;

        if (rp_file_info(path[i]->name.data, &fi) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          rp_file_info_n " \"%s\" failed", path[i]->name.data);
            return RP_ERROR;
        }

        if (fi.st_uid != user) {
            if (chown((const char *) path[i]->name.data, user, -1) == -1) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              "chown(\"%s\", %d) failed",
                              path[i]->name.data, user);
                return RP_ERROR;
            }
        }

        if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))
                                                  != (S_IRUSR|S_IWUSR|S_IXUSR))
        {
            fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);

            if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              "chmod() \"%s\" failed", path[i]->name.data);
                return RP_ERROR;
            }
        }
        }
#endif
    }

    return RP_OK;
}


rp_int_t
rp_ext_rename_file(rp_str_t *src, rp_str_t *to, rp_ext_rename_file_t *ext)
{
    u_char           *name;
    rp_err_t         err;
    rp_copy_file_t   cf;

#if !(RP_WIN32)

    if (ext->access) {
        if (rp_change_file_access(src->data, ext->access) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                          rp_change_file_access_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

#endif

    if (ext->time != -1) {
        if (rp_set_file_time(src->data, ext->fd, ext->time) != RP_OK) {
            rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                          rp_set_file_time_n " \"%s\" failed", src->data);
            err = 0;
            goto failed;
        }
    }

    if (rp_rename_file(src->data, to->data) != RP_FILE_ERROR) {
        return RP_OK;
    }

    err = rp_errno;

    if (err == RP_ENOPATH) {

        if (!ext->create_path) {
            goto failed;
        }

        err = rp_create_full_path(to->data, rp_dir_access(ext->path_access));

        if (err) {
            rp_log_error(RP_LOG_CRIT, ext->log, err,
                          rp_create_dir_n " \"%s\" failed", to->data);
            err = 0;
            goto failed;
        }

        if (rp_rename_file(src->data, to->data) != RP_FILE_ERROR) {
            return RP_OK;
        }

        err = rp_errno;
    }

#if (RP_WIN32)

    if (err == RP_EEXIST || err == RP_EEXIST_FILE) {
        err = rp_win32_rename_file(src, to, ext->log);

        if (err == 0) {
            return RP_OK;
        }
    }

#endif

    if (err == RP_EXDEV) {

        cf.size = -1;
        cf.buf_size = 0;
        cf.access = ext->access;
        cf.time = ext->time;
        cf.log = ext->log;

        name = rp_alloc(to->len + 1 + 10 + 1, ext->log);
        if (name == NULL) {
            return RP_ERROR;
        }

        (void) rp_sprintf(name, "%*s.%010uD%Z", to->len, to->data,
                           (uint32_t) rp_next_temp_number(0));

        if (rp_copy_file(src->data, name, &cf) == RP_OK) {

            if (rp_rename_file(name, to->data) != RP_FILE_ERROR) {
                rp_free(name);

                if (rp_delete_file(src->data) == RP_FILE_ERROR) {
                    rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                                  rp_delete_file_n " \"%s\" failed",
                                  src->data);
                    return RP_ERROR;
                }

                return RP_OK;
            }

            rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                          rp_rename_file_n " \"%s\" to \"%s\" failed",
                          name, to->data);

            if (rp_delete_file(name) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                              rp_delete_file_n " \"%s\" failed", name);

            }
        }

        rp_free(name);

        err = 0;
    }

failed:

    if (ext->delete_file) {
        if (rp_delete_file(src->data) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_CRIT, ext->log, rp_errno,
                          rp_delete_file_n " \"%s\" failed", src->data);
        }
    }

    if (err) {
        rp_log_error(RP_LOG_CRIT, ext->log, err,
                      rp_rename_file_n " \"%s\" to \"%s\" failed",
                      src->data, to->data);
    }

    return RP_ERROR;
}


rp_int_t
rp_copy_file(u_char *from, u_char *to, rp_copy_file_t *cf)
{
    char             *buf;
    off_t             size;
    time_t            time;
    size_t            len;
    ssize_t           n;
    rp_fd_t          fd, nfd;
    rp_int_t         rc;
    rp_uint_t        access;
    rp_file_info_t   fi;

    rc = RP_ERROR;
    buf = NULL;
    nfd = RP_INVALID_FILE;

    fd = rp_open_file(from, RP_FILE_RDONLY, RP_FILE_OPEN, 0);

    if (fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_CRIT, cf->log, rp_errno,
                      rp_open_file_n " \"%s\" failed", from);
        goto failed;
    }

    if (cf->size != -1 && cf->access != 0 && cf->time != -1) {
        size = cf->size;
        access = cf->access;
        time = cf->time;

    } else {
        if (rp_fd_info(fd, &fi) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_fd_info_n " \"%s\" failed", from);

            goto failed;
        }

        size = (cf->size != -1) ? cf->size : rp_file_size(&fi);
        access = cf->access ? cf->access : rp_file_access(&fi);
        time = (cf->time != -1) ? cf->time : rp_file_mtime(&fi);
    }

    len = cf->buf_size ? cf->buf_size : 65536;

    if ((off_t) len > size) {
        len = (size_t) size;
    }

    buf = rp_alloc(len, cf->log);
    if (buf == NULL) {
        goto failed;
    }

    nfd = rp_open_file(to, RP_FILE_WRONLY, RP_FILE_TRUNCATE, access);

    if (nfd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_CRIT, cf->log, rp_errno,
                      rp_open_file_n " \"%s\" failed", to);
        goto failed;
    }

    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = rp_read_fd(fd, buf, len);

        if (n == -1) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_read_fd_n " \"%s\" failed", from);
            goto failed;
        }

        if ((size_t) n != len) {
            rp_log_error(RP_LOG_ALERT, cf->log, 0,
                          rp_read_fd_n " has read only %z of %O from %s",
                          n, size, from);
            goto failed;
        }

        n = rp_write_fd(nfd, buf, len);

        if (n == -1) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_write_fd_n " \"%s\" failed", to);
            goto failed;
        }

        if ((size_t) n != len) {
            rp_log_error(RP_LOG_ALERT, cf->log, 0,
                          rp_write_fd_n " has written only %z of %O to %s",
                          n, size, to);
            goto failed;
        }

        size -= n;
    }

    if (rp_set_file_time(to, nfd, time) != RP_OK) {
        rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                      rp_set_file_time_n " \"%s\" failed", to);
        goto failed;
    }

    rc = RP_OK;

failed:

    if (nfd != RP_INVALID_FILE) {
        if (rp_close_file(nfd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_close_file_n " \"%s\" failed", to);
        }
    }

    if (fd != RP_INVALID_FILE) {
        if (rp_close_file(fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_close_file_n " \"%s\" failed", from);
        }
    }

    if (buf) {
        rp_free(buf);
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
 * on fatal (memory) error handler must return RP_ABORT to stop walking tree
 */

rp_int_t
rp_walk_tree(rp_tree_ctx_t *ctx, rp_str_t *tree)
{
    void       *data, *prev;
    u_char     *p, *name;
    size_t      len;
    rp_int_t   rc;
    rp_err_t   err;
    rp_str_t   file, buf;
    rp_dir_t   dir;

    rp_str_null(&buf);

    rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                   "walk tree \"%V\"", tree);

    if (rp_open_dir(tree, &dir) == RP_ERROR) {
        rp_log_error(RP_LOG_CRIT, ctx->log, rp_errno,
                      rp_open_dir_n " \"%s\" failed", tree->data);
        return RP_ERROR;
    }

    prev = ctx->data;

    if (ctx->alloc) {
        data = rp_alloc(ctx->alloc, ctx->log);
        if (data == NULL) {
            goto failed;
        }

        if (ctx->init_handler(data, prev) == RP_ABORT) {
            goto failed;
        }

        ctx->data = data;

    } else {
        data = NULL;
    }

    for ( ;; ) {

        rp_set_errno(0);

        if (rp_read_dir(&dir) == RP_ERROR) {
            err = rp_errno;

            if (err == RP_ENOMOREFILES) {
                rc = RP_OK;

            } else {
                rp_log_error(RP_LOG_CRIT, ctx->log, err,
                              rp_read_dir_n " \"%s\" failed", tree->data);
                rc = RP_ERROR;
            }

            goto done;
        }

        len = rp_de_namelen(&dir);
        name = rp_de_name(&dir);

        rp_log_debug2(RP_LOG_DEBUG_CORE, ctx->log, 0,
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
                rp_free(buf.data);
            }

            buf.len = tree->len + 1 + len;

            buf.data = rp_alloc(buf.len + 1, ctx->log);
            if (buf.data == NULL) {
                goto failed;
            }
        }

        p = rp_cpymem(buf.data, tree->data, tree->len);
        *p++ = '/';
        rp_memcpy(p, name, len + 1);

        file.data = buf.data;

        rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                       "tree path \"%s\"", file.data);

        if (!dir.valid_info) {
            if (rp_de_info(file.data, &dir) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_CRIT, ctx->log, rp_errno,
                              rp_de_info_n " \"%s\" failed", file.data);
                continue;
            }
        }

        if (rp_de_is_file(&dir)) {

            rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree file \"%s\"", file.data);

            ctx->size = rp_de_size(&dir);
            ctx->fs_size = rp_de_fs_size(&dir);
            ctx->access = rp_de_access(&dir);
            ctx->mtime = rp_de_mtime(&dir);

            if (ctx->file_handler(ctx, &file) == RP_ABORT) {
                goto failed;
            }

        } else if (rp_de_is_dir(&dir)) {

            rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree enter dir \"%s\"", file.data);

            ctx->access = rp_de_access(&dir);
            ctx->mtime = rp_de_mtime(&dir);

            rc = ctx->pre_tree_handler(ctx, &file);

            if (rc == RP_ABORT) {
                goto failed;
            }

            if (rc == RP_DECLINED) {
                rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                               "tree skip dir \"%s\"", file.data);
                continue;
            }

            if (rp_walk_tree(ctx, &file) == RP_ABORT) {
                goto failed;
            }

            ctx->access = rp_de_access(&dir);
            ctx->mtime = rp_de_mtime(&dir);

            if (ctx->post_tree_handler(ctx, &file) == RP_ABORT) {
                goto failed;
            }

        } else {

            rp_log_debug1(RP_LOG_DEBUG_CORE, ctx->log, 0,
                           "tree special \"%s\"", file.data);

            if (ctx->spec_handler(ctx, &file) == RP_ABORT) {
                goto failed;
            }
        }
    }

failed:

    rc = RP_ABORT;

done:

    if (buf.len) {
        rp_free(buf.data);
    }

    if (data) {
        rp_free(data);
        ctx->data = prev;
    }

    if (rp_close_dir(&dir) == RP_ERROR) {
        rp_log_error(RP_LOG_CRIT, ctx->log, rp_errno,
                      rp_close_dir_n " \"%s\" failed", tree->data);
    }

    return rc;
}
