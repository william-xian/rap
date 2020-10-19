
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>

#define RAP_CONF_BUFFER  4096

static rap_int_t rap_conf_add_dump(rap_conf_t *cf, rap_str_t *filename);
static rap_int_t rap_conf_handler(rap_conf_t *cf, rap_int_t last);
static rap_int_t rap_conf_read_token(rap_conf_t *cf);
static void rap_conf_flush_files(rap_cycle_t *cycle);


static rap_command_t  rap_conf_commands[] = {

    { rap_string("include"),
      RAP_ANY_CONF|RAP_CONF_TAKE1,
      rap_conf_include,
      0,
      0,
      NULL },

      rap_null_command
};


rap_module_t  rap_conf_module = {
    RAP_MODULE_V1,
    NULL,                                  /* module context */
    rap_conf_commands,                     /* module directives */
    RAP_CONF_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    rap_conf_flush_files,                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


/* The eight fixed arguments */

static rap_uint_t argument_number[] = {
    RAP_CONF_NOARGS,
    RAP_CONF_TAKE1,
    RAP_CONF_TAKE2,
    RAP_CONF_TAKE3,
    RAP_CONF_TAKE4,
    RAP_CONF_TAKE5,
    RAP_CONF_TAKE6,
    RAP_CONF_TAKE7
};


char *
rap_conf_param(rap_conf_t *cf)
{
    char             *rv;
    rap_str_t        *param;
    rap_buf_t         b;
    rap_conf_file_t   conf_file;

    param = &cf->cycle->conf_param;

    if (param->len == 0) {
        return RAP_CONF_OK;
    }

    rap_memzero(&conf_file, sizeof(rap_conf_file_t));

    rap_memzero(&b, sizeof(rap_buf_t));

    b.start = param->data;
    b.pos = param->data;
    b.last = param->data + param->len;
    b.end = b.last;
    b.temporary = 1;

    conf_file.file.fd = RAP_INVALID_FILE;
    conf_file.file.name.data = NULL;
    conf_file.line = 0;

    cf->conf_file = &conf_file;
    cf->conf_file->buffer = &b;

    rv = rap_conf_parse(cf, NULL);

    cf->conf_file = NULL;

    return rv;
}


static rap_int_t
rap_conf_add_dump(rap_conf_t *cf, rap_str_t *filename)
{
    off_t             size;
    u_char           *p;
    uint32_t          hash;
    rap_buf_t        *buf;
    rap_str_node_t   *sn;
    rap_conf_dump_t  *cd;

    hash = rap_crc32_long(filename->data, filename->len);

    sn = rap_str_rbtree_lookup(&cf->cycle->config_dump_rbtree, filename, hash);

    if (sn) {
        cf->conf_file->dump = NULL;
        return RAP_OK;
    }

    p = rap_pstrdup(cf->cycle->pool, filename);
    if (p == NULL) {
        return RAP_ERROR;
    }

    cd = rap_array_push(&cf->cycle->config_dump);
    if (cd == NULL) {
        return RAP_ERROR;
    }

    size = rap_file_size(&cf->conf_file->file.info);

    buf = rap_create_temp_buf(cf->cycle->pool, (size_t) size);
    if (buf == NULL) {
        return RAP_ERROR;
    }

    cd->name.data = p;
    cd->name.len = filename->len;
    cd->buffer = buf;

    cf->conf_file->dump = buf;

    sn = rap_palloc(cf->temp_pool, sizeof(rap_str_node_t));
    if (sn == NULL) {
        return RAP_ERROR;
    }

    sn->node.key = hash;
    sn->str = cd->name;

    rap_rbtree_insert(&cf->cycle->config_dump_rbtree, &sn->node);

    return RAP_OK;
}


char *
rap_conf_parse(rap_conf_t *cf, rap_str_t *filename)
{
    char             *rv;
    rap_fd_t          fd;
    rap_int_t         rc;
    rap_buf_t         buf;
    rap_conf_file_t  *prev, conf_file;
    enum {
        parse_file = 0,
        parse_block,
        parse_param
    } type;

#if (RAP_SUPPRESS_WARN)
    fd = RAP_INVALID_FILE;
    prev = NULL;
#endif

    if (filename) {

        /* open configuration file */

        fd = rap_open_file(filename->data, RAP_FILE_RDONLY, RAP_FILE_OPEN, 0);

        if (fd == RAP_INVALID_FILE) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                               rap_open_file_n " \"%s\" failed",
                               filename->data);
            return RAP_CONF_ERROR;
        }

        prev = cf->conf_file;

        cf->conf_file = &conf_file;

        if (rap_fd_info(fd, &cf->conf_file->file.info) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_EMERG, cf->log, rap_errno,
                          rap_fd_info_n " \"%s\" failed", filename->data);
        }

        cf->conf_file->buffer = &buf;

        buf.start = rap_alloc(RAP_CONF_BUFFER, cf->log);
        if (buf.start == NULL) {
            goto failed;
        }

        buf.pos = buf.start;
        buf.last = buf.start;
        buf.end = buf.last + RAP_CONF_BUFFER;
        buf.temporary = 1;

        cf->conf_file->file.fd = fd;
        cf->conf_file->file.name.len = filename->len;
        cf->conf_file->file.name.data = filename->data;
        cf->conf_file->file.offset = 0;
        cf->conf_file->file.log = cf->log;
        cf->conf_file->line = 1;

        type = parse_file;

        if (rap_dump_config
#if (RAP_DEBUG)
            || 1
#endif
           )
        {
            if (rap_conf_add_dump(cf, filename) != RAP_OK) {
                goto failed;
            }

        } else {
            cf->conf_file->dump = NULL;
        }

    } else if (cf->conf_file->file.fd != RAP_INVALID_FILE) {

        type = parse_block;

    } else {
        type = parse_param;
    }


    for ( ;; ) {
        rc = rap_conf_read_token(cf);

        /*
         * rap_conf_read_token() may return
         *
         *    RAP_ERROR             there is error
         *    RAP_OK                the token terminated by ";" was found
         *    RAP_CONF_BLOCK_START  the token terminated by "{" was found
         *    RAP_CONF_BLOCK_DONE   the "}" was found
         *    RAP_CONF_FILE_DONE    the configuration file is done
         */

        if (rc == RAP_ERROR) {
            goto done;
        }

        if (rc == RAP_CONF_BLOCK_DONE) {

            if (type != parse_block) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "unexpected \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == RAP_CONF_FILE_DONE) {

            if (type == parse_block) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "unexpected end of file, expecting \"}\"");
                goto failed;
            }

            goto done;
        }

        if (rc == RAP_CONF_BLOCK_START) {

            if (type == parse_param) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "block directives are not supported "
                                   "in -g option");
                goto failed;
            }
        }

        /* rc == RAP_OK || rc == RAP_CONF_BLOCK_START */

        if (cf->handler) {

            /*
             * the custom handler, i.e., that is used in the http's
             * "types { ... }" directive
             */

            if (rc == RAP_CONF_BLOCK_START) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "unexpected \"{\"");
                goto failed;
            }

            rv = (*cf->handler)(cf, NULL, cf->handler_conf);
            if (rv == RAP_CONF_OK) {
                continue;
            }

            if (rv == RAP_CONF_ERROR) {
                goto failed;
            }

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%s", rv);

            goto failed;
        }


        rc = rap_conf_handler(cf, rc);

        if (rc == RAP_ERROR) {
            goto failed;
        }
    }

failed:

    rc = RAP_ERROR;

done:

    if (filename) {
        if (cf->conf_file->buffer->start) {
            rap_free(cf->conf_file->buffer->start);
        }

        if (rap_close_file(fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cf->log, rap_errno,
                          rap_close_file_n " %s failed",
                          filename->data);
            rc = RAP_ERROR;
        }

        cf->conf_file = prev;
    }

    if (rc == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_conf_handler(rap_conf_t *cf, rap_int_t last)
{
    char           *rv;
    void           *conf, **confp;
    rap_uint_t      i, found;
    rap_str_t      *name;
    rap_command_t  *cmd;

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

            if (rap_strcmp(name->data, cmd->name.data) != 0) {
                continue;
            }

            found = 1;

            if (cf->cycle->modules[i]->type != RAP_CONF_MODULE
                && cf->cycle->modules[i]->type != cf->module_type)
            {
                continue;
            }

            /* is the directive's location right ? */

            if (!(cmd->type & cf->cmd_type)) {
                continue;
            }

            if (!(cmd->type & RAP_CONF_BLOCK) && last != RAP_OK) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                  "directive \"%s\" is not terminated by \";\"",
                                  name->data);
                return RAP_ERROR;
            }

            if ((cmd->type & RAP_CONF_BLOCK) && last != RAP_CONF_BLOCK_START) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "directive \"%s\" has no opening \"{\"",
                                   name->data);
                return RAP_ERROR;
            }

            /* is the directive's argument count right ? */

            if (!(cmd->type & RAP_CONF_ANY)) {

                if (cmd->type & RAP_CONF_FLAG) {

                    if (cf->args->nelts != 2) {
                        goto invalid;
                    }

                } else if (cmd->type & RAP_CONF_1MORE) {

                    if (cf->args->nelts < 2) {
                        goto invalid;
                    }

                } else if (cmd->type & RAP_CONF_2MORE) {

                    if (cf->args->nelts < 3) {
                        goto invalid;
                    }

                } else if (cf->args->nelts > RAP_CONF_MAX_ARGS) {

                    goto invalid;

                } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
                {
                    goto invalid;
                }
            }

            /* set up the directive's configuration context */

            conf = NULL;

            if (cmd->type & RAP_DIRECT_CONF) {
                conf = ((void **) cf->ctx)[cf->cycle->modules[i]->index];

            } else if (cmd->type & RAP_MAIN_CONF) {
                conf = &(((void **) cf->ctx)[cf->cycle->modules[i]->index]);

            } else if (cf->ctx) {
                confp = *(void **) ((char *) cf->ctx + cmd->conf);

                if (confp) {
                    conf = confp[cf->cycle->modules[i]->ctx_index];
                }
            }

            rv = cmd->set(cf, cmd, conf);

            if (rv == RAP_CONF_OK) {
                return RAP_OK;
            }

            if (rv == RAP_CONF_ERROR) {
                return RAP_ERROR;
            }

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"%s\" directive %s", name->data, rv);

            return RAP_ERROR;
        }
    }

    if (found) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%s\" directive is not allowed here", name->data);

        return RAP_ERROR;
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "unknown directive \"%s\"", name->data);

    return RAP_ERROR;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid number of arguments in \"%s\" directive",
                       name->data);

    return RAP_ERROR;
}


static rap_int_t
rap_conf_read_token(rap_conf_t *cf)
{
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    rap_uint_t   found, need_space, last_space, sharap_comment, variable;
    rap_uint_t   quoted, s_quoted, d_quoted, start_line;
    rap_str_t   *word;
    rap_buf_t   *b, *dump;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharap_comment = 0;
    variable = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buffer;
    dump = cf->conf_file->dump;
    start = b->pos;
    start_line = cf->conf_file->line;

    file_size = rap_file_size(&cf->conf_file->file.info);

    for ( ;; ) {

        if (b->pos >= b->last) {

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == RAP_INVALID_FILE) {
                        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                           "unexpected end of parameter, "
                                           "expecting \";\"");
                        return RAP_ERROR;
                    }

                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                  "unexpected end of file, "
                                  "expecting \";\" or \"}\"");
                    return RAP_ERROR;
                }

                return RAP_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == RAP_CONF_BUFFER) {
                cf->conf_file->line = start_line;

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "too long parameter \"%*s...\" started",
                                       10, start);
                    return RAP_ERROR;
                }

                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "too long parameter, probably "
                                   "missing terminating \"%c\" character", ch);
                return RAP_ERROR;
            }

            if (len) {
                rap_memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = rap_read_file(&cf->conf_file->file, b->start + len, size,
                              cf->conf_file->file.offset);

            if (n == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (n != size) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   rap_read_file_n " returned "
                                   "only %z bytes instead of %z",
                                   n, size);
                return RAP_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;

            if (dump) {
                dump->last = rap_cpymem(dump->last, b->pos, size);
            }
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharap_comment) {
                sharap_comment = 0;
            }
        }

        if (sharap_comment) {
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
                return RAP_OK;
            }

            if (ch == '{') {
                return RAP_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "unexpected \"%c\"", ch);
                return RAP_ERROR;
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
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "unexpected \"%c\"", ch);
                    return RAP_ERROR;
                }

                if (ch == '{') {
                    return RAP_CONF_BLOCK_START;
                }

                return RAP_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "unexpected \"}\"");
                    return RAP_ERROR;
                }

                return RAP_CONF_BLOCK_DONE;

            case '#':
                sharap_comment = 1;
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
                word = rap_array_push(cf->args);
                if (word == NULL) {
                    return RAP_ERROR;
                }

                word->data = rap_pnalloc(cf->pool, b->pos - 1 - start + 1);
                if (word->data == NULL) {
                    return RAP_ERROR;
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
                    return RAP_OK;
                }

                if (ch == '{') {
                    return RAP_CONF_BLOCK_START;
                }

                found = 0;
            }
        }
    }
}


char *
rap_conf_include(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char        *rv;
    rap_int_t    n;
    rap_str_t   *value, file, name;
    rap_glob_t   gl;

    value = cf->args->elts;
    file = value[1];

    rap_log_debug1(RAP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

    if (rap_conf_full_name(cf->cycle, &file, 1) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") == NULL) {

        rap_log_debug1(RAP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        return rap_conf_parse(cf, &file);
    }

    rap_memzero(&gl, sizeof(rap_glob_t));

    gl.pattern = file.data;
    gl.log = cf->log;
    gl.test = 1;

    if (rap_open_glob(&gl) != RAP_OK) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                           rap_open_glob_n " \"%s\" failed", file.data);
        return RAP_CONF_ERROR;
    }

    rv = RAP_CONF_OK;

    for ( ;; ) {
        n = rap_read_glob(&gl, &name);

        if (n != RAP_OK) {
            break;
        }

        file.len = name.len++;
        file.data = rap_pstrdup(cf->pool, &name);
        if (file.data == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_log_debug1(RAP_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);

        rv = rap_conf_parse(cf, &file);

        if (rv != RAP_CONF_OK) {
            break;
        }
    }

    rap_close_glob(&gl);

    return rv;
}


rap_int_t
rap_conf_full_name(rap_cycle_t *cycle, rap_str_t *name, rap_uint_t conf_prefix)
{
    rap_str_t  *prefix;

    prefix = conf_prefix ? &cycle->conf_prefix : &cycle->prefix;

    return rap_get_full_name(cycle->pool, prefix, name);
}


rap_open_file_t *
rap_conf_open_file(rap_cycle_t *cycle, rap_str_t *name)
{
    rap_str_t         full;
    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_open_file_t  *file;

#if (RAP_SUPPRESS_WARN)
    rap_str_null(&full);
#endif

    if (name->len) {
        full = *name;

        if (rap_conf_full_name(cycle, &full, 0) != RAP_OK) {
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

            if (rap_strcmp(full.data, file[i].name.data) == 0) {
                return &file[i];
            }
        }
    }

    file = rap_list_push(&cycle->open_files);
    if (file == NULL) {
        return NULL;
    }

    if (name->len) {
        file->fd = RAP_INVALID_FILE;
        file->name = full;

    } else {
        file->fd = rap_stderr;
        file->name = *name;
    }

    file->flush = NULL;
    file->data = NULL;

    return file;
}


static void
rap_conf_flush_files(rap_cycle_t *cycle)
{
    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_open_file_t  *file;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, cycle->log, 0, "flush files");

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


void rap_cdecl
rap_conf_log_error(rap_uint_t level, rap_conf_t *cf, rap_err_t err,
    const char *fmt, ...)
{
    u_char   errstr[RAP_MAX_CONF_ERRSTR], *p, *last;
    va_list  args;

    last = errstr + RAP_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = rap_vslprintf(errstr, last, fmt, args);
    va_end(args);

    if (err) {
        p = rap_log_errno(p, last, err);
    }

    if (cf->conf_file == NULL) {
        rap_log_error(level, cf->log, 0, "%*s", p - errstr, errstr);
        return;
    }

    if (cf->conf_file->file.fd == RAP_INVALID_FILE) {
        rap_log_error(level, cf->log, 0, "%*s in command line",
                      p - errstr, errstr);
        return;
    }

    rap_log_error(level, cf->log, 0, "%*s in %s:%ui",
                  p - errstr, errstr,
                  cf->conf_file->file.name.data, cf->conf_file->line);
}


char *
rap_conf_set_flag_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t        *value;
    rap_flag_t       *fp;
    rap_conf_post_t  *post;

    fp = (rap_flag_t *) (p + cmd->offset);

    if (*fp != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        *fp = 1;

    } else if (rap_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        *fp = 0;

    } else {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return RAP_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, fp);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_str_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t        *field, *value;
    rap_conf_post_t  *post;

    field = (rap_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_str_array_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t         *value, *s;
    rap_array_t      **a;
    rap_conf_post_t   *post;

    a = (rap_array_t **) (p + cmd->offset);

    if (*a == RAP_CONF_UNSET_PTR) {
        *a = rap_array_create(cf->pool, 4, sizeof(rap_str_t));
        if (*a == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    s = rap_array_push(*a);
    if (s == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    *s = value[1];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, s);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_keyval_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t         *value;
    rap_array_t      **a;
    rap_keyval_t      *kv;
    rap_conf_post_t   *post;

    a = (rap_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = rap_array_create(cf->pool, 4, sizeof(rap_keyval_t));
        if (*a == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    kv = rap_array_push(*a);
    if (kv == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    kv->key = value[1];
    kv->value = value[2];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, kv);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_num_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_int_t        *np;
    rap_str_t        *value;
    rap_conf_post_t  *post;


    np = (rap_int_t *) (p + cmd->offset);

    if (*np != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    *np = rap_atoi(value[1].data, value[1].len);
    if (*np == RAP_ERROR) {
        return "invalid number";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_size_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    size_t           *sp;
    rap_str_t        *value;
    rap_conf_post_t  *post;


    sp = (size_t *) (p + cmd->offset);
    if (*sp != RAP_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = rap_parse_size(&value[1]);
    if (*sp == (size_t) RAP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_off_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    off_t            *op;
    rap_str_t        *value;
    rap_conf_post_t  *post;


    op = (off_t *) (p + cmd->offset);
    if (*op != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *op = rap_parse_offset(&value[1]);
    if (*op == (off_t) RAP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, op);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_msec_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_msec_t       *msp;
    rap_str_t        *value;
    rap_conf_post_t  *post;


    msp = (rap_msec_t *) (p + cmd->offset);
    if (*msp != RAP_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *msp = rap_parse_time(&value[1], 0);
    if (*msp == (rap_msec_t) RAP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, msp);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_sec_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    time_t           *sp;
    rap_str_t        *value;
    rap_conf_post_t  *post;


    sp = (time_t *) (p + cmd->offset);
    if (*sp != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *sp = rap_parse_time(&value[1], 1);
    if (*sp == (time_t) RAP_ERROR) {
        return "invalid value";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, sp);
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_bufs_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char *p = conf;

    rap_str_t   *value;
    rap_bufs_t  *bufs;


    bufs = (rap_bufs_t *) (p + cmd->offset);
    if (bufs->num) {
        return "is duplicate";
    }

    value = cf->args->elts;

    bufs->num = rap_atoi(value[1].data, value[1].len);
    if (bufs->num == RAP_ERROR || bufs->num == 0) {
        return "invalid value";
    }

    bufs->size = rap_parse_size(&value[2]);
    if (bufs->size == (size_t) RAP_ERROR || bufs->size == 0) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


char *
rap_conf_set_enum_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_uint_t       *np, i;
    rap_str_t        *value;
    rap_conf_enum_t  *e;

    np = (rap_uint_t *) (p + cmd->offset);

    if (*np != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    e = cmd->post;

    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len != value[1].len
            || rap_strcasecmp(e[i].name.data, value[1].data) != 0)
        {
            continue;
        }

        *np = e[i].value;

        return RAP_CONF_OK;
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid value \"%s\"", value[1].data);

    return RAP_CONF_ERROR;
}


char *
rap_conf_set_bitmask_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_uint_t          *np, i, m;
    rap_str_t           *value;
    rap_conf_bitmask_t  *mask;


    np = (rap_uint_t *) (p + cmd->offset);
    value = cf->args->elts;
    mask = cmd->post;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || rap_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (*np & mask[m].mask) {
                rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                *np |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


#if 0

char *
rap_conf_unsupported(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    return "unsupported on this platform";
}

#endif


char *
rap_conf_deprecated(rap_conf_t *cf, void *post, void *data)
{
    rap_conf_deprecated_t  *d = post;

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "the \"%s\" directive is deprecated, "
                       "use the \"%s\" directive instead",
                       d->old_name, d->new_name);

    return RAP_CONF_OK;
}


char *
rap_conf_check_num_bounds(rap_conf_t *cf, void *post, void *data)
{
    rap_conf_num_bounds_t  *bounds = post;
    rap_int_t  *np = data;

    if (bounds->high == -1) {
        if (*np >= bounds->low) {
            return RAP_CONF_OK;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "value must be equal to or greater than %i",
                           bounds->low);

        return RAP_CONF_ERROR;
    }

    if (*np >= bounds->low && *np <= bounds->high) {
        return RAP_CONF_OK;
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "value must be between %i and %i",
                       bounds->low, bounds->high);

    return RAP_CONF_ERROR;
}
