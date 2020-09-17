
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>

#define RP_CONF_BUFFER  4096

static rp_int_t rp_conf_add_dump(rp_conf_t *cf, rp_str_t *filename);
static rp_int_t rp_conf_handler(rp_conf_t *cf, rp_int_t last);
static rp_int_t rp_conf_read_token(rp_conf_t *cf);
static void rp_conf_flush_files(rp_cycle_t *cycle);


static rp_command_t  rp_conf_commands[] = {

    { rp_string("include"),
      RP_ANY_CONF|RP_CONF_TAKE1,
      rp_conf_include,
      0,
      0,
      NULL },

      rp_null_command
};


rp_module_t  rp_conf_module = {
    RP_MODULE_V1,
    NULL,                                  /* module context */
    rp_conf_commands,                     /* module directives */
    RP_CONF_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rp_conf_flush_files,                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


/* The eight fixed arguments */

static rp_uint_t argument_number[] = {
    RP_CONF_NOARGS,
    RP_CONF_TAKE1,
    RP_CONF_TAKE2,
    RP_CONF_TAKE3,
    RP_CONF_TAKE4,
    RP_CONF_TAKE5,
    RP_CONF_TAKE6,
    RP_CONF_TAKE7
};


char *
rp_conf_param(rp_conf_t *cf)
{
    char             *rv;
    rp_str_t        *param;
    rp_buf_t         b;
    rp_conf_file_t   conf_file;

    param = &cf->cycle->conf_param;

    if (param->len == 0) {
        return RP_CONF_OK;
    }

    rp_memzero(&conf_file, sizeof(rp_conf_file_t));

    rp_memzero(&b, sizeof(rp_buf_t));

    b.start = param->data;
    b.pos = param->data;
    b.last = param->data + param->len;
    b.end = b.last;
    b.temporary = 1;

    conf_file.file.fd = RP_INVALID_FILE;
    conf_file.file.name.data = NULL;
    conf_file.line = 0;

    cf->conf_file = &conf_file;
    cf->conf_file->buffer = &b;

    rv = rp_conf_parse(cf, NULL);

    cf->conf_file = NULL;

    return rv;
}


static rp_int_t
rp_conf_add_dump(rp_conf_t *cf, rp_str_t *filename)
{
    off_t             size;
    u_char           *p;
    uint32_t          hash;
    rp_buf_t        *buf;
    rp_str_node_t   *sn;
    rp_conf_dump_t  *cd;

    hash = rp_crc32_long(filename->data, filename->len);

    sn = rp_str_rbtree_lookup(&cf->cycle->config_dump_rbtree, filename, hash);

    if (sn) {
        cf->conf_file->dump = NULL;
        return RP_OK;
    }

    p = rp_pstrdup(cf->cycle->pool, filename);
    if (p == NULL) {
        return RP_ERROR;
    }

    cd = rp_array_push(&cf->cycle->config_dump);
    if (cd == NULL) {
        return RP_ERROR;
    }

    size = rp_file_size(&cf->conf_file->file.info);

    buf = rp_create_temp_buf(cf->cycle->pool, (size_t) size);
    if (buf == NULL) {
        return RP_ERROR;
    }

    cd->name.data = p;
    cd->name.len = filename->len;
    cd->buffer = buf;

    cf->conf_file->dump = buf;

    sn = rp_palloc(cf->temp_pool, sizeof(rp_str_node_t));
    if (sn == NULL) {
        return RP_ERROR;
    }

    sn->node.key = hash;
    sn->str = cd->name;

    rp_rbtree_insert(&cf->cycle->config_dump_rbtree, &sn->node);

    return RP_OK;
}


char *
rp_conf_parse(rp_conf_t *cf, rp_str_t *filename)
{
    char             *rv;
    rp_fd_t          fd;
    rp_int_t         rc;
    rp_buf_t         buf;
    rp_conf_file_t  *prev, conf_file;
    enum {
        parse_file = 0,
        parse_block,
        parse_param
    } type;

#if (RP_SUPPRESS_WARN)
    fd = RP_INVALID_FILE;
    prev = NULL;
#endif

    if (filename) {

        /* open configuration file */

        fd = rp_open_file(filename->data, RP_FILE_RDONLY, RP_FILE_OPEN, 0);

        if (fd == RP_INVALID_FILE) {
            rp_conf_log_error(RP_LOG_EMERG, cf, rp_errno,
                               rp_open_file_n " \"%s\" failed",
                               filename->data);
            return RP_CONF_ERROR;
        }

        prev = cf->conf_file;

        cf->conf_file = &conf_file;

        if (rp_fd_info(fd, &cf->conf_file->file.info) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_EMERG, cf->log, rp_errno,
                          rp_fd_info_n " \"%s\" failed", filename->data);
        }

        cf->conf_file->buffer = &buf;

        buf.start = rp_alloc(RP_CONF_BUFFER, cf->log);
        if (buf.start == NULL) {
            goto failed;
        }

        buf.pos = buf.start;
        buf.last = buf.start;
        buf.end = buf.last + RP_CONF_BUFFER;
        buf.temporary = 1;

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.offset = 0;
        cf->conf_file->file.log = cf->log;
        cf->conf_file->line = 1;

        type = parse_file;

        if (rp_dump_config
#if (RP_DEBUG)
            || 1
#endif
           )
        {
            if (rp_conf_add_dump(cf, filename) != RP_OK) {
                goto failed;
            }

        } else {
            cf->conf_file->dump = NULL;
        }

    } else if (cf->conf_file->file.fd != RP_INVALID_FILE) {

        type = parse_block;

    } else {
        type = parse_param;
    }


    for ( ;; ) {
        rc = rp_conf_read_token(cf);

        /*
         * rp_conf_read_token() may return
         *
         *    RP_ERROR             there is error
         *    RP_OK                the token terminated by ";" was found
         *    RP_CONF_BLOCK_START  the token terminated by "{" was found
         *    RP_CONF_BLOCK_DONE   the "}" was found
         *    RP_CONF_FILE_DONE    the configuration file is done
         */

        if (rc == RP_ERROR) {
            goto done;
        }

        if (rc == RP_CONF_BLOCK_DONE) {

            if (type != parse_block) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0, "unexpected \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == RP_CONF_FILE_DONE) {

            if (type == parse_block) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == RP_CONF_BLOCK_START) {

            if (type == parse_param) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "block directives are not supported "
                                   "in -g option");
                goto failed;
            }
        }

        /* rc == RP_OK || rc == RP_CONF_BLOCK_START */

        if (cf->handler) {

            /*
             * the custom handler, i.e., that is used in the http's
             * "types { ... }" directive
             */

            if (rc == RP_CONF_BLOCK_START) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0, "unexpected \"{\"");
                goto failed;
            }

            rv = (*cf->handler)(cf, NULL, cf->handler_conf);
            if (rv == RP_CONF_OK) {
                continue;
            }

            if (rv == RP_CONF_ERROR) {
                goto failed;
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0, "%s", rv);

            goto failed;
        }


        rc = rp_conf_handler(cf, rc);

        if (rc == RP_ERROR) {
            goto failed;
        }
    }

failed:

    rc = RP_ERROR;

done:

    if (filename) {
        if (cf->conf_file->buffer->start) {
            rp_free(cf->conf_file->buffer->start);
        }

        if (rp_close_file(fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cf->log, rp_errno,
                          rp_close_file_n " %s failed",
                          filename->data);
            rc = RP_ERROR;
        }

        cf->conf_file = prev;
    }

    if (rc == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_conf_handler(rp_conf_t *cf, rp_int_t last)
{
    char           *rv;
    void           *conf, **confp;
    rp_uint_t      i, found;
    rp_str_t      *name;
    rp_command_t  *cmd;

    name = cf->args->elts;

    found = 0;

    for (i = 0; cf->cycle->modules[i]; i++) {

        cmd = cf->cycle->modules[i]->commands;
        if (cmd == NULL) {
            continue;
        }

        for ( /* void */ ; cmd->name.len; cmd++) {

            if (name->len != cmd->name.len) {
                continue;
            }

            if (rp_strcmp(name->data, cmd->name.data) != 0) {
                continue;
            }

            found = 1;

            if (cf->cycle->modules[i]->type != RP_CONF_MODULE
                && cf->cycle->modules[i]->type != cf->module_type)
            {
                continue;
            }

            /* is the directive's location right ? */

            if (!(cmd->type & cf->cmd_type)) {
                continue;
            }

            if (!(cmd->type & RP_CONF_BLOCK) && last != RP_OK) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                  "directive \"%s\" is not terminated by \";\"",
                                  name->data);
                return RP_ERROR;
            }

            if ((cmd->type & RP_CONF_BLOCK) && last != RP_CONF_BLOCK_START) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "directive \"%s\" has no opening \"{\"",
                                   name->data);
                return RP_ERROR;
            }

            /* is the directive's argument count right ? */

            if (!(cmd->type & RP_CONF_ANY)) {

                if (cmd->type & RP_CONF_FLAG) {

                    if (cf->args->nelts != 2) {
                        goto invalid;
                    }

                } else if (cmd->type & RP_CONF_1MORE) {

                    if (cf->args->nelts < 2) {
                        goto invalid;
                    }

                } else if (cmd->type & RP_CONF_2MORE) {

                    if (cf->args->nelts < 3) {
                        goto invalid;
                    }

                } else if (cf->args->nelts > RP_CONF_MAX_ARGS) {

                    goto invalid;

                } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
                {
                    goto invalid;
                }
            }

            /* set up the directive's configuration context */

            conf = NULL;

            if (cmd->type & RP_DIRECT_CONF) {
                conf = ((void **) cf->ctx)[cf->cycle->modules[i]->index];

            } else if (cmd->type & RP_MAIN_CONF) {
                conf = &(((void **) cf->ctx)[cf->cycle->modules[i]->index]);

            } else if (cf->ctx) {
                confp = *(void **) ((char *) cf->ctx + cmd->conf);

                if (confp) {
                    conf = confp[cf->cycle->modules[i]->ctx_index];
                }
            }

            rv = cmd->set(cf, cmd, conf);

            if (rv == RP_CONF_OK) {
                return RP_OK;
            }

            if (rv == RP_CONF_ERROR) {
                return RP_ERROR;
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "\"%s\" directive %s", name->data, rv);

            return RP_ERROR;
        }
    }

    if (found) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%s\" directive is not allowed here", name->data);

        return RP_ERROR;
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "unknown directive \"%s\"", name->data);

    return RP_ERROR;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid number of arguments in \"%s\" directive",
                       name->data);

    return RP_ERROR;
}


static rp_int_t
rp_conf_read_token(rp_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    rp_uint_t   found, need_space, last_space, sharp_comment, variable;
    rp_uint_t   quoted, s_quoted, d_quoted, start_line;
    rp_str_t   *word;
    rp_buf_t   *b, *dump;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buffer;
    dump = cf->conf_file->dump;
    start = b->pos;
    start_line = cf->conf_file->line;

    file_size = rp_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last) {

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == RP_INVALID_FILE) {
                        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                           "unexpected end of parameter, "
                                           "expecting \";\"");
                        return RP_ERROR;
                    }

                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                  "unexpected end of file, "
                                  "expecting \";\" or \"}\"");
                    return RP_ERROR;
                }

                return RP_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == RP_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return RP_ERROR;
                }

                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return RP_ERROR;
            }

            if (len) {
                rp_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = rp_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == RP_ERROR) {
                return RP_ERROR;
            }

            if (n != size) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   rp_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return RP_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;

            if (dump) {
                dump->last = rp_cpymem(dump->last, b->pos, size);
            }
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return RP_OK;
            }

            if (ch == '{') {
                return RP_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "unexpected \"%c\"", ch);
                return RP_ERROR;
            }
        }

        if (last_space) {

            start = b->pos - 1;
            start_line = cf->conf_file->line;

            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            switch (ch) {

            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return RP_ERROR;
                }

                if (ch == '{') {
                    return RP_CONF_BLOCK_START;
                }

                return RP_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return RP_ERROR;
                }

                return RP_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            case '$':
                variable = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {
            if (ch == '{' && variable) {
                continue;
            }

            variable = 0;

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (ch == '$') {
                variable = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = rp_array_push(cf->args);
                if (word == NULL) {
                    return RP_ERROR;
                }

                word->data = rp_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return RP_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < b->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return RP_OK;
                }

                if (ch == '{') {
                    return RP_CONF_BLOCK_START;
                }

                found = 0;
            }
        }
    }
}


char *
rp_conf_include(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char        *rv;
    rp_int_t    n;
    rp_str_t   *value, file, name;
    rp_glob_t   gl;

    value = cf->args->elts;
    file = value[1];

    rp_log_debug1(RP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    if (rp_conf_full_name(cf->cycle, &file, 1) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") == NULL) {

        rp_log_debug1(RP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return rp_conf_parse(cf, &file);
    }

    rp_memzero(&gl, sizeof(rp_glob_t));

    gl.pattern = file.data;
    gl.log = cf->log;
    gl.test = 1;

    if (rp_open_glob(&gl) != RP_OK) {
        rp_conf_log_error(RP_LOG_EMERG, cf, rp_errno,
                           rp_open_glob_n " \"%s\" failed", file.data);
        return RP_CONF_ERROR;
    }

    rv = RP_CONF_OK;

    for ( ;; ) {
        n = rp_read_glob(&gl, &name);

        if (n != RP_OK) {
            break;
        }

        file.len = name.len++;
        file.data = rp_pstrdup(cf->pool, &name);
        if (file.data == NULL) {
            return RP_CONF_ERROR;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        rv = rp_conf_parse(cf, &file);

        if (rv != RP_CONF_OK) {
            break;
        }
    }

    rp_close_glob(&gl);

    return rv;
}


rp_int_t
rp_conf_full_name(rp_cycle_t *cycle, rp_str_t *name, rp_uint_t conf_prefix)
{
    rp_str_t  *prefix;

    prefix = conf_prefix ? &cycle->conf_prefix : &cycle->prefix;

    return rp_get_full_name(cycle->pool, prefix, name);
}


rp_open_file_t *
rp_conf_open_file(rp_cycle_t *cycle, rp_str_t *name)
{
    rp_str_t         full;
    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_open_file_t  *file;

#if (RP_SUPPRESS_WARN)
    rp_str_null(&full);
#endif

    if (name->len) {
        full = *name;

        if (rp_conf_full_name(cycle, &full, 0) != RP_OK) {
            return NULL;
        }

        part = &cycle->open_files.part;
        file = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                file = part->elts;
                i = 0;
            }

            if (full.len != file[i].name.len) {
                continue;
            }

            if (rp_strcmp(full.data, file[i].name.data) == 0) {
                return &file[i];
            }
        }
    }

    file = rp_list_push(&cycle->open_files);
    if (file == NULL) {
        return NULL;
    }

    if (name->len) {
        file->fd = RP_INVALID_FILE;
        file->name = full;

    } else {
        file->fd = rp_stderr;
        file->name = *name;
    }

    file->flush = NULL;
    file->data = NULL;

    return file;
}


static void
rp_conf_flush_files(rp_cycle_t *cycle)
{
    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_open_file_t  *file;

    rp_log_debug0(RP_LOG_DEBUG_CORE, cycle->log, 0, "flush files");

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], cycle->log);
        }
    }
}


void rp_cdecl
rp_conf_log_error(rp_uint_t level, rp_conf_t *cf, rp_err_t err,
    const char *fmt, ...)
{
    u_char   errstr[RP_MAX_CONF_ERRSTR], *p, *last;
    va_list  args;

    last = errstr + RP_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = rp_vslprintf(errstr, last, fmt, args);
    va_end(args);

    if (err) {
        p = rp_log_errno(p, last, err);
    }

    if (cf->conf_file == NULL) {
        rp_log_error(level, cf->log, 0, "%*s", p - errstr, errstr);
        return;
    }

    if (cf->conf_file->file.fd == RP_INVALID_FILE) {
        rp_log_error(level, cf->log, 0, "%*s in command line",
                      p - errstr, errstr);
        return;
    }

    rp_log_error(level, cf->log, 0, "%*s in %s:%ui",
                  p - errstr, errstr,
                  cf->conf_file->file.name.data, cf->conf_file->line);
}


char *
rp_conf_set_flag_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t        *value;
    rp_flag_t       *fp;
    rp_conf_post_t  *post;

    fp = (rp_flag_t *) (p + cmd->offset);

    if (*fp != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        *fp = 1;

    } else if (rp_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        *fp = 0;

    } else {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return RP_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_str_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t        *field, *value;
    rp_conf_post_t  *post;

    field = (rp_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_str_array_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t         *value, *s;
    rp_array_t      **a;
    rp_conf_post_t   *post;

    a = (rp_array_t **) (p + cmd->offset);

    if (*a == RP_CONF_UNSET_PTR) {
        *a = rp_array_create(cf->pool, 4, sizeof(rp_str_t));
        if (*a == NULL) {
            return RP_CONF_ERROR;
        }
    }

    s = rp_array_push(*a);
    if (s == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    *s = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, s);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_keyval_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t         *value;
    rp_array_t      **a;
    rp_keyval_t      *kv;
    rp_conf_post_t   *post;

    a = (rp_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = rp_array_create(cf->pool, 4, sizeof(rp_keyval_t));
        if (*a == NULL) {
            return RP_CONF_ERROR;
        }
    }

    kv = rp_array_push(*a);
    if (kv == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    kv->key = value[1];
    kv->value = value[2];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, kv);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_num_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_int_t        *np;
    rp_str_t        *value;
    rp_conf_post_t  *post;


    np = (rp_int_t *) (p + cmd->offset);

    if (*np != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    *np = rp_atoi(value[1].data, value[1].len);
    if (*np == RP_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_size_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    size_t           *sp;
    rp_str_t        *value;
    rp_conf_post_t  *post;


    sp = (size_t *) (p + cmd->offset);
    if (*sp != RP_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = rp_parse_size(&value[1]);
    if (*sp == (size_t) RP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_off_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    off_t            *op;
    rp_str_t        *value;
    rp_conf_post_t  *post;


    op = (off_t *) (p + cmd->offset);
    if (*op != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *op = rp_parse_offset(&value[1]);
    if (*op == (off_t) RP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, op);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_msec_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_msec_t       *msp;
    rp_str_t        *value;
    rp_conf_post_t  *post;


    msp = (rp_msec_t *) (p + cmd->offset);
    if (*msp != RP_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *msp = rp_parse_time(&value[1], 0);
    if (*msp == (rp_msec_t) RP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, msp);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_sec_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t           *sp;
    rp_str_t        *value;
    rp_conf_post_t  *post;


    sp = (time_t *) (p + cmd->offset);
    if (*sp != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = rp_parse_time(&value[1], 1);
    if (*sp == (time_t) RP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_bufs_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char *p = conf;

    rp_str_t   *value;
    rp_bufs_t  *bufs;


    bufs = (rp_bufs_t *) (p + cmd->offset);
    if (bufs->num) {
        return "is duplicate";
    }

    value = cf->args->elts;

    bufs->num = rp_atoi(value[1].data, value[1].len);
    if (bufs->num == RP_ERROR || bufs->num == 0) {
        return "invalid value";
    }

    bufs->size = rp_parse_size(&value[2]);
    if (bufs->size == (size_t) RP_ERROR || bufs->size == 0) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


char *
rp_conf_set_enum_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_uint_t       *np, i;
    rp_str_t        *value;
    rp_conf_enum_t  *e;

    np = (rp_uint_t *) (p + cmd->offset);

    if (*np != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    e = cmd->post;

    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len != value[1].len
            || rp_strcasecmp(e[i].name.data, value[1].data) != 0)
        {
            continue;
        }

        *np = e[i].value;

        return RP_CONF_OK;
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid value \"%s\"", value[1].data);

    return RP_CONF_ERROR;
}


char *
rp_conf_set_bitmask_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_uint_t          *np, i, m;
    rp_str_t           *value;
    rp_conf_bitmask_t  *mask;


    np = (rp_uint_t *) (p + cmd->offset);
    value = cf->args->elts;
    mask = cmd->post;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || rp_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                rp_conf_log_error(RP_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


#if 0

char *
rp_conf_unsupported(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    return "unsupported on this platform";
}

#endif


char *
rp_conf_deprecated(rp_conf_t *cf, void *post, void *data)
{
    rp_conf_deprecated_t  *d = post;

    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "the \"%s\" directive is deprecated, "
                       "use the \"%s\" directive instead",
                       d->old_name, d->new_name);

    return RP_CONF_OK;
}


char *
rp_conf_check_num_bounds(rp_conf_t *cf, void *post, void *data)
{
    rp_conf_num_bounds_t  *bounds = post;
    rp_int_t  *np = data;

    if (bounds->high == -1) {
        if (*np >= bounds->low) {
            return RP_CONF_OK;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "value must be equal to or greater than %i",
                           bounds->low);

        return RP_CONF_ERROR;
    }

    if (*np >= bounds->low && *np <= bounds->high) {
        return RP_CONF_OK;
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "value must be between %i and %i",
                       bounds->low, bounds->high);

    return RP_CONF_ERROR;
}
