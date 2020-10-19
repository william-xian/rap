
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#if 0

typedef struct {
    rap_buf_t     *buf;
    size_t         size;
    rap_pool_t    *pool;
    size_t         alloc_size;
    rap_chain_t  **last_out;
} rap_http_autoindex_ctx_t;

#endif


typedef struct {
    rap_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;
    unsigned       file:1;

    time_t         mtime;
    off_t          size;
} rap_http_autoindex_entry_t;


typedef struct {
    rap_flag_t     enable;
    rap_uint_t     format;
    rap_flag_t     localtime;
    rap_flag_t     exact_size;
} rap_http_autoindex_loc_conf_t;


#define RAP_HTTP_AUTOINDEX_HTML         0
#define RAP_HTTP_AUTOINDEX_JSON         1
#define RAP_HTTP_AUTOINDEX_JSONP        2
#define RAP_HTTP_AUTOINDEX_XML          3

#define RAP_HTTP_AUTOINDEX_PREALLOCATE  50

#define RAP_HTTP_AUTOINDEX_NAME_LEN     50


static rap_buf_t *rap_http_autoindex_html(rap_http_request_t *r,
    rap_array_t *entries);
static rap_buf_t *rap_http_autoindex_json(rap_http_request_t *r,
    rap_array_t *entries, rap_str_t *callback);
static rap_int_t rap_http_autoindex_jsonp_callback(rap_http_request_t *r,
    rap_str_t *callback);
static rap_buf_t *rap_http_autoindex_xml(rap_http_request_t *r,
    rap_array_t *entries);

static int rap_libc_cdecl rap_http_autoindex_cmp_entries(const void *one,
    const void *two);
static rap_int_t rap_http_autoindex_error(rap_http_request_t *r,
    rap_dir_t *dir, rap_str_t *name);

static rap_int_t rap_http_autoindex_init(rap_conf_t *cf);
static void *rap_http_autoindex_create_loc_conf(rap_conf_t *cf);
static char *rap_http_autoindex_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);


static rap_conf_enum_t  rap_http_autoindex_format[] = {
    { rap_string("html"), RAP_HTTP_AUTOINDEX_HTML },
    { rap_string("json"), RAP_HTTP_AUTOINDEX_JSON },
    { rap_string("jsonp"), RAP_HTTP_AUTOINDEX_JSONP },
    { rap_string("xml"), RAP_HTTP_AUTOINDEX_XML },
    { rap_null_string, 0 }
};


static rap_command_t  rap_http_autoindex_commands[] = {

    { rap_string("autoindex"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_autoindex_loc_conf_t, enable),
      NULL },

    { rap_string("autoindex_format"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_autoindex_loc_conf_t, format),
      &rap_http_autoindex_format },

    { rap_string("autoindex_localtime"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_autoindex_loc_conf_t, localtime),
      NULL },

    { rap_string("autoindex_exact_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_autoindex_loc_conf_t, exact_size),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_autoindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_autoindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_autoindex_create_loc_conf,    /* create location configuration */
    rap_http_autoindex_merge_loc_conf      /* merge location configuration */
};


rap_module_t  rap_http_autoindex_module = {
    RAP_MODULE_V1,
    &rap_http_autoindex_module_ctx,        /* module context */
    rap_http_autoindex_commands,           /* module directives */
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
rap_http_autoindex_handler(rap_http_request_t *r)
{
    u_char                         *last, *filename;
    size_t                          len, allocated, root;
    rap_err_t                       err;
    rap_buf_t                      *b;
    rap_int_t                       rc;
    rap_str_t                       path, callback;
    rap_dir_t                       dir;
    rap_uint_t                      level, format;
    rap_pool_t                     *pool;
    rap_chain_t                     out;
    rap_array_t                     entries;
    rap_http_autoindex_entry_t     *entry;
    rap_http_autoindex_loc_conf_t  *alcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RAP_DECLINED;
    }

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_DECLINED;
    }

    alcf = rap_http_get_module_loc_conf(r, rap_http_autoindex_module);

    if (!alcf->enable) {
        return RAP_DECLINED;
    }

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    last = rap_http_map_uri_to_path(r, &path, &root,
                                    RAP_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", path.data);

    format = alcf->format;

    if (format == RAP_HTTP_AUTOINDEX_JSONP) {
        if (rap_http_autoindex_jsonp_callback(r, &callback) != RAP_OK) {
            return RAP_HTTP_BAD_REQUEST;
        }

        if (callback.len == 0) {
            format = RAP_HTTP_AUTOINDEX_JSON;
        }
    }

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

#if (RAP_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    rap_memzero(&entries, sizeof(rap_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    if (rap_array_init(&entries, pool, 40, sizeof(rap_http_autoindex_entry_t))
        != RAP_OK)
    {
        return rap_http_autoindex_error(r, &dir, &path);
    }

    r->headers_out.status = RAP_HTTP_OK;

    switch (format) {

    case RAP_HTTP_AUTOINDEX_JSON:
        rap_str_set(&r->headers_out.content_type, "application/json");
        break;

    case RAP_HTTP_AUTOINDEX_JSONP:
        rap_str_set(&r->headers_out.content_type, "application/javascript");
        break;

    case RAP_HTTP_AUTOINDEX_XML:
        rap_str_set(&r->headers_out.content_type, "text/xml");
        rap_str_set(&r->headers_out.charset, "utf-8");
        break;

    default: /* RAP_HTTP_AUTOINDEX_HTML */
        rap_str_set(&r->headers_out.content_type, "text/html");
        break;
    }

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        if (rap_close_dir(&dir) == RAP_ERROR) {
            rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                          rap_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
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
                return rap_http_autoindex_error(r, &dir, &path);
            }

            break;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", rap_de_name(&dir));

        len = rap_de_namelen(&dir);

        if (rap_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + RAP_HTTP_AUTOINDEX_PREALLOCATE;

                filename = rap_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return rap_http_autoindex_error(r, &dir, &path);
                }

                last = rap_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            rap_cpystrn(last, rap_de_name(&dir), len + 1);

            if (rap_de_info(filename, &dir) == RAP_FILE_ERROR) {
                err = rap_errno;

                if (err != RAP_ENOENT && err != RAP_ELOOP) {
                    rap_log_error(RAP_LOG_CRIT, r->connection->log, err,
                                  rap_de_info_n " \"%s\" failed", filename);

                    if (err == RAP_EACCES) {
                        continue;
                    }

                    return rap_http_autoindex_error(r, &dir, &path);
                }

                if (rap_de_link_info(filename, &dir) == RAP_FILE_ERROR) {
                    rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                                  rap_de_link_info_n " \"%s\" failed",
                                  filename);
                    return rap_http_autoindex_error(r, &dir, &path);
                }
            }
        }

        entry = rap_array_push(&entries);
        if (entry == NULL) {
            return rap_http_autoindex_error(r, &dir, &path);
        }

        entry->name.len = len;

        entry->name.data = rap_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return rap_http_autoindex_error(r, &dir, &path);
        }

        rap_cpystrn(entry->name.data, rap_de_name(&dir), len + 1);

        entry->dir = rap_de_is_dir(&dir);
        entry->file = rap_de_is_file(&dir);
        entry->mtime = rap_de_mtime(&dir);
        entry->size = rap_de_size(&dir);
    }

    if (rap_close_dir(&dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_dir_n " \"%V\" failed", &path);
    }

    if (entries.nelts > 1) {
        rap_qsort(entries.elts, (size_t) entries.nelts,
                  sizeof(rap_http_autoindex_entry_t),
                  rap_http_autoindex_cmp_entries);
    }

    switch (format) {

    case RAP_HTTP_AUTOINDEX_JSON:
        b = rap_http_autoindex_json(r, &entries, NULL);
        break;

    case RAP_HTTP_AUTOINDEX_JSONP:
        b = rap_http_autoindex_json(r, &entries, &callback);
        break;

    case RAP_HTTP_AUTOINDEX_XML:
        b = rap_http_autoindex_xml(r, &entries);
        break;

    default: /* RAP_HTTP_AUTOINDEX_HTML */
        b = rap_http_autoindex_html(r, &entries);
        break;
    }

    if (b == NULL) {
        return RAP_ERROR;
    }

    /* TODO: free temporary pool */

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}


static rap_buf_t *
rap_http_autoindex_html(rap_http_request_t *r, rap_array_t *entries)
{
    u_char                         *last, scale;
    off_t                           length;
    size_t                          len, entry_len, char_len, escape_html;
    rap_tm_t                        tm;
    rap_buf_t                      *b;
    rap_int_t                       size;
    rap_uint_t                      i, utf8;
    rap_time_t                     *tp;
    rap_http_autoindex_entry_t     *entry;
    rap_http_autoindex_loc_conf_t  *alcf;

    static u_char  title[] =
        "<html>" CRLF
        "<head><title>Index of "
    ;

    static u_char  header[] =
        "</title></head>" CRLF
        "<body>" CRLF
        "<h1>Index of "
    ;

    static u_char  tail[] =
        "</body>" CRLF
        "</html>" CRLF
    ;

    static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (r->headers_out.charset.len == 5
        && rap_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    escape_html = rap_escape_html(NULL, r->uri.data, r->uri.len);

    len = sizeof(title) - 1
          + r->uri.len + escape_html
          + sizeof(header) - 1
          + r->uri.len + escape_html
          + sizeof("</h1>") - 1
          + sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1
          + sizeof("</pre><hr>") - 1
          + sizeof(tail) - 1;

    entry = entries->elts;
    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = 2 * rap_escape_uri(NULL, entry[i].name.data,
                                             entry[i].name.len,
                                             RAP_ESCAPE_URI_COMPONENT);

        entry[i].escape_html = rap_escape_html(NULL, entry[i].name.data,
                                               entry[i].name.len);

        if (utf8) {
            entry[i].utf_len = rap_utf8_length(entry[i].name.data,
                                               entry[i].name.len);
        } else {
            entry[i].utf_len = entry[i].name.len;
        }

        entry_len = sizeof("<a href=\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + 1                                    /* 1 is for "/" */
                  + sizeof("\">") - 1
                  + entry[i].name.len - entry[i].utf_len
                  + entry[i].escape_html
                  + RAP_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
                  + sizeof("</a>") - 1
                  + sizeof(" 28-Sep-1970 12:00 ") - 1
                  + 20                                   /* the file size */
                  + 2;

        if (len > RAP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rap_cpymem(b->last, title, sizeof(title) - 1);

    if (escape_html) {
        b->last = (u_char *) rap_escape_html(b->last, r->uri.data, r->uri.len);
        b->last = rap_cpymem(b->last, header, sizeof(header) - 1);
        b->last = (u_char *) rap_escape_html(b->last, r->uri.data, r->uri.len);

    } else {
        b->last = rap_cpymem(b->last, r->uri.data, r->uri.len);
        b->last = rap_cpymem(b->last, header, sizeof(header) - 1);
        b->last = rap_cpymem(b->last, r->uri.data, r->uri.len);
    }

    b->last = rap_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);

    b->last = rap_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
                         sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);

    alcf = rap_http_get_module_loc_conf(r, rap_http_autoindex_module);
    tp = rap_timeofday();

    for (i = 0; i < entries->nelts; i++) {
        b->last = rap_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);

        if (entry[i].escape) {
            rap_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           RAP_ESCAPE_URI_COMPONENT);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = rap_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        len = entry[i].utf_len;

        if (entry[i].name.len != len) {
            if (len > RAP_HTTP_AUTOINDEX_NAME_LEN) {
                char_len = RAP_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;

            } else {
                char_len = RAP_HTTP_AUTOINDEX_NAME_LEN + 1;
            }

            last = b->last;
            b->last = rap_utf8_cpystrn(b->last, entry[i].name.data,
                                       char_len, entry[i].name.len + 1);

            if (entry[i].escape_html) {
                b->last = (u_char *) rap_escape_html(last, entry[i].name.data,
                                                     b->last - last);
            }

            last = b->last;

        } else {
            if (entry[i].escape_html) {
                if (len > RAP_HTTP_AUTOINDEX_NAME_LEN) {
                    char_len = RAP_HTTP_AUTOINDEX_NAME_LEN - 3;

                } else {
                    char_len = len;
                }

                b->last = (u_char *) rap_escape_html(b->last,
                                                  entry[i].name.data, char_len);
                last = b->last;

            } else {
                b->last = rap_cpystrn(b->last, entry[i].name.data,
                                      RAP_HTTP_AUTOINDEX_NAME_LEN + 1);
                last = b->last - 3;
            }
        }

        if (len > RAP_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = rap_cpymem(last, "..&gt;</a>", sizeof("..&gt;</a>") - 1);

        } else {
            if (entry[i].dir && RAP_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = rap_cpymem(b->last, "</a>", sizeof("</a>") - 1);

            if (RAP_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                rap_memset(b->last, ' ', RAP_HTTP_AUTOINDEX_NAME_LEN - len);
                b->last += RAP_HTTP_AUTOINDEX_NAME_LEN - len;
            }
        }

        *b->last++ = ' ';

        rap_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);

        b->last = rap_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
                              tm.rap_tm_mday,
                              months[tm.rap_tm_mon - 1],
                              tm.rap_tm_year,
                              tm.rap_tm_hour,
                              tm.rap_tm_min);

        if (alcf->exact_size) {
            if (entry[i].dir) {
                b->last = rap_cpymem(b->last,  "                  -",
                                     sizeof("                  -") - 1);
            } else {
                b->last = rap_sprintf(b->last, "%19O", entry[i].size);
            }

        } else {
            if (entry[i].dir) {
                b->last = rap_cpymem(b->last,  "      -",
                                     sizeof("      -") - 1);

            } else {
                length = entry[i].size;

                if (length > 1024 * 1024 * 1024 - 1) {
                    size = (rap_int_t) (length / (1024 * 1024 * 1024));
                    if ((length % (1024 * 1024 * 1024))
                                                > (1024 * 1024 * 1024 / 2 - 1))
                    {
                        size++;
                    }
                    scale = 'G';

                } else if (length > 1024 * 1024 - 1) {
                    size = (rap_int_t) (length / (1024 * 1024));
                    if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
                        size++;
                    }
                    scale = 'M';

                } else if (length > 9999) {
                    size = (rap_int_t) (length / 1024);
                    if (length % 1024 > 511) {
                        size++;
                    }
                    scale = 'K';

                } else {
                    size = (rap_int_t) length;
                    scale = '\0';
                }

                if (scale) {
                    b->last = rap_sprintf(b->last, "%6i%c", size, scale);

                } else {
                    b->last = rap_sprintf(b->last, " %6i", size);
                }
            }
        }

        *b->last++ = CR;
        *b->last++ = LF;
    }

    b->last = rap_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);

    b->last = rap_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static rap_buf_t *
rap_http_autoindex_json(rap_http_request_t *r, rap_array_t *entries,
    rap_str_t *callback)
{
    size_t                       len, entry_len;
    rap_buf_t                   *b;
    rap_uint_t                   i;
    rap_http_autoindex_entry_t  *entry;

    len = sizeof("[" CRLF CRLF "]") - 1;

    if (callback) {
        len += sizeof("/* callback */" CRLF "();") - 1 + callback->len;
    }

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = rap_escape_json(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("{  }," CRLF) - 1
                  + sizeof("\"name\":\"\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(", \"type\":\"directory\"") - 1
                  + sizeof(", \"mtime\":\"Wed, 31 Dec 1986 10:00:00 GMT\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(", \"size\":") - 1 + RAP_OFF_T_LEN;
        }

        if (len > RAP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    if (callback) {
        b->last = rap_cpymem(b->last, "/* callback */" CRLF,
                             sizeof("/* callback */" CRLF) - 1);

        b->last = rap_cpymem(b->last, callback->data, callback->len);

        *b->last++ = '(';
    }

    *b->last++ = '[';

    for (i = 0; i < entries->nelts; i++) {
        b->last = rap_cpymem(b->last, CRLF "{ \"name\":\"",
                             sizeof(CRLF "{ \"name\":\"") - 1);

        if (entry[i].escape) {
            b->last = (u_char *) rap_escape_json(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = rap_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        b->last = rap_cpymem(b->last, "\", \"type\":\"",
                             sizeof("\", \"type\":\"") - 1);

        if (entry[i].dir) {
            b->last = rap_cpymem(b->last, "directory", sizeof("directory") - 1);

        } else if (entry[i].file) {
            b->last = rap_cpymem(b->last, "file", sizeof("file") - 1);

        } else {
            b->last = rap_cpymem(b->last, "other", sizeof("other") - 1);
        }

        b->last = rap_cpymem(b->last, "\", \"mtime\":\"",
                             sizeof("\", \"mtime\":\"") - 1);

        b->last = rap_http_time(b->last, entry[i].mtime);

        if (entry[i].file) {
            b->last = rap_cpymem(b->last, "\", \"size\":",
                                 sizeof("\", \"size\":") - 1);
            b->last = rap_sprintf(b->last, "%O", entry[i].size);

        } else {
            *b->last++ = '"';
        }

        b->last = rap_cpymem(b->last, " },", sizeof(" },") - 1);
    }

    if (i > 0) {
        b->last--;  /* strip last comma */
    }

    b->last = rap_cpymem(b->last, CRLF "]", sizeof(CRLF "]") - 1);

    if (callback) {
        *b->last++ = ')'; *b->last++ = ';';
    }

    return b;
}


static rap_int_t
rap_http_autoindex_jsonp_callback(rap_http_request_t *r, rap_str_t *callback)
{
    u_char      *p, c, ch;
    rap_uint_t   i;

    if (rap_http_arg(r, (u_char *) "callback", 8, callback) != RAP_OK) {
        callback->len = 0;
        return RAP_OK;
    }

    if (callback->len > 128) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent too long callback name: \"%V\"", callback);
        return RAP_DECLINED;
    }

    p = callback->data;

    for (i = 0; i < callback->len; i++) {
        ch = p[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if ((ch >= '0' && ch <= '9') || ch == '_' || ch == '.') {
            continue;
        }

        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid callback name: \"%V\"", callback);

        return RAP_DECLINED;
    }

    return RAP_OK;
}


static rap_buf_t *
rap_http_autoindex_xml(rap_http_request_t *r, rap_array_t *entries)
{
    size_t                          len, entry_len;
    rap_tm_t                        tm;
    rap_buf_t                      *b;
    rap_str_t                       type;
    rap_uint_t                      i;
    rap_http_autoindex_entry_t     *entry;

    static u_char  head[] = "<?xml version=\"1.0\"?>" CRLF "<list>" CRLF;
    static u_char  tail[] = "</list>" CRLF;

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = rap_escape_html(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("<directory></directory>" CRLF) - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(" mtime=\"1986-12-31T10:00:00Z\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(" size=\"\"") - 1 + RAP_OFF_T_LEN;
        }

        if (len > RAP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rap_cpymem(b->last, head, sizeof(head) - 1);

    for (i = 0; i < entries->nelts; i++) {
        *b->last++ = '<';

        if (entry[i].dir) {
            rap_str_set(&type, "directory");

        } else if (entry[i].file) {
            rap_str_set(&type, "file");

        } else {
            rap_str_set(&type, "other");
        }

        b->last = rap_cpymem(b->last, type.data, type.len);

        b->last = rap_cpymem(b->last, " mtime=\"", sizeof(" mtime=\"") - 1);

        rap_gmtime(entry[i].mtime, &tm);

        b->last = rap_sprintf(b->last, "%4d-%02d-%02dT%02d:%02d:%02dZ",
                              tm.rap_tm_year, tm.rap_tm_mon,
                              tm.rap_tm_mday, tm.rap_tm_hour,
                              tm.rap_tm_min, tm.rap_tm_sec);

        if (entry[i].file) {
            b->last = rap_cpymem(b->last, "\" size=\"",
                                 sizeof("\" size=\"") - 1);
            b->last = rap_sprintf(b->last, "%O", entry[i].size);
        }

        *b->last++ = '"'; *b->last++ = '>';

        if (entry[i].escape) {
            b->last = (u_char *) rap_escape_html(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = rap_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        *b->last++ = '<'; *b->last++ = '/';

        b->last = rap_cpymem(b->last, type.data, type.len);

        *b->last++ = '>';

        *b->last++ = CR; *b->last++ = LF;
    }

    b->last = rap_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static int rap_libc_cdecl
rap_http_autoindex_cmp_entries(const void *one, const void *two)
{
    rap_http_autoindex_entry_t *first = (rap_http_autoindex_entry_t *) one;
    rap_http_autoindex_entry_t *second = (rap_http_autoindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) rap_strcmp(first->name.data, second->name.data);
}


#if 0

static rap_buf_t *
rap_http_autoindex_alloc(rap_http_autoindex_ctx_t *ctx, size_t size)
{
    rap_chain_t  *cl;

    if (ctx->buf) {

        if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
            return ctx->buf;
        }

        ctx->size += ctx->buf->last - ctx->buf->pos;
    }

    ctx->buf = rap_create_temp_buf(ctx->pool, ctx->alloc_size);
    if (ctx->buf == NULL) {
        return NULL;
    }

    cl = rap_alloc_chain_link(ctx->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ctx->buf;
    cl->next = NULL;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    return ctx->buf;
}

#endif


static rap_int_t
rap_http_autoindex_error(rap_http_request_t *r, rap_dir_t *dir, rap_str_t *name)
{
    if (rap_close_dir(dir) == RAP_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_dir_n " \"%V\" failed", name);
    }

    return r->header_sent ? RAP_ERROR : RAP_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
rap_http_autoindex_create_loc_conf(rap_conf_t *cf)
{
    rap_http_autoindex_loc_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RAP_CONF_UNSET;
    conf->format = RAP_CONF_UNSET_UINT;
    conf->localtime = RAP_CONF_UNSET;
    conf->exact_size = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_autoindex_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_autoindex_loc_conf_t *prev = parent;
    rap_http_autoindex_loc_conf_t *conf = child;

    rap_conf_merge_value(conf->enable, prev->enable, 0);
    rap_conf_merge_uint_value(conf->format, prev->format,
                              RAP_HTTP_AUTOINDEX_HTML);
    rap_conf_merge_value(conf->localtime, prev->localtime, 0);
    rap_conf_merge_value(conf->exact_size, prev->exact_size, 1);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_autoindex_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_autoindex_handler;

    return RAP_OK;
}
