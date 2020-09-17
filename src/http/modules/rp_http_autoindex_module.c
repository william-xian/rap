
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#if 0

typedef struct {
    rp_buf_t     *buf;
    size_t         size;
    rp_pool_t    *pool;
    size_t         alloc_size;
    rp_chain_t  **last_out;
} rp_http_autoindex_ctx_t;

#endif


typedef struct {
    rp_str_t      name;
    size_t         utf_len;
    size_t         escape;
    size_t         escape_html;

    unsigned       dir:1;
    unsigned       file:1;

    time_t         mtime;
    off_t          size;
} rp_http_autoindex_entry_t;


typedef struct {
    rp_flag_t     enable;
    rp_uint_t     format;
    rp_flag_t     localtime;
    rp_flag_t     exact_size;
} rp_http_autoindex_loc_conf_t;


#define RP_HTTP_AUTOINDEX_HTML         0
#define RP_HTTP_AUTOINDEX_JSON         1
#define RP_HTTP_AUTOINDEX_JSONP        2
#define RP_HTTP_AUTOINDEX_XML          3

#define RP_HTTP_AUTOINDEX_PREALLOCATE  50

#define RP_HTTP_AUTOINDEX_NAME_LEN     50


static rp_buf_t *rp_http_autoindex_html(rp_http_request_t *r,
    rp_array_t *entries);
static rp_buf_t *rp_http_autoindex_json(rp_http_request_t *r,
    rp_array_t *entries, rp_str_t *callback);
static rp_int_t rp_http_autoindex_jsonp_callback(rp_http_request_t *r,
    rp_str_t *callback);
static rp_buf_t *rp_http_autoindex_xml(rp_http_request_t *r,
    rp_array_t *entries);

static int rp_libc_cdecl rp_http_autoindex_cmp_entries(const void *one,
    const void *two);
static rp_int_t rp_http_autoindex_error(rp_http_request_t *r,
    rp_dir_t *dir, rp_str_t *name);

static rp_int_t rp_http_autoindex_init(rp_conf_t *cf);
static void *rp_http_autoindex_create_loc_conf(rp_conf_t *cf);
static char *rp_http_autoindex_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);


static rp_conf_enum_t  rp_http_autoindex_format[] = {
    { rp_string("html"), RP_HTTP_AUTOINDEX_HTML },
    { rp_string("json"), RP_HTTP_AUTOINDEX_JSON },
    { rp_string("jsonp"), RP_HTTP_AUTOINDEX_JSONP },
    { rp_string("xml"), RP_HTTP_AUTOINDEX_XML },
    { rp_null_string, 0 }
};


static rp_command_t  rp_http_autoindex_commands[] = {

    { rp_string("autoindex"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_autoindex_loc_conf_t, enable),
      NULL },

    { rp_string("autoindex_format"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_autoindex_loc_conf_t, format),
      &rp_http_autoindex_format },

    { rp_string("autoindex_localtime"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_autoindex_loc_conf_t, localtime),
      NULL },

    { rp_string("autoindex_exact_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_autoindex_loc_conf_t, exact_size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_autoindex_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_autoindex_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_autoindex_create_loc_conf,    /* create location configuration */
    rp_http_autoindex_merge_loc_conf      /* merge location configuration */
};


rp_module_t  rp_http_autoindex_module = {
    RP_MODULE_V1,
    &rp_http_autoindex_module_ctx,        /* module context */
    rp_http_autoindex_commands,           /* module directives */
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
rp_http_autoindex_handler(rp_http_request_t *r)
{
    u_char                         *last, *filename;
    size_t                          len, allocated, root;
    rp_err_t                       err;
    rp_buf_t                      *b;
    rp_int_t                       rc;
    rp_str_t                       path, callback;
    rp_dir_t                       dir;
    rp_uint_t                      level, format;
    rp_pool_t                     *pool;
    rp_chain_t                     out;
    rp_array_t                     entries;
    rp_http_autoindex_entry_t     *entry;
    rp_http_autoindex_loc_conf_t  *alcf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return RP_DECLINED;
    }

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_DECLINED;
    }

    alcf = rp_http_get_module_loc_conf(r, rp_http_autoindex_module);

    if (!alcf->enable) {
        return RP_DECLINED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    last = rp_http_map_uri_to_path(r, &path, &root,
                                    RP_HTTP_AUTOINDEX_PREALLOCATE);
    if (last == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    allocated = path.len;
    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http autoindex: \"%s\"", path.data);

    format = alcf->format;

    if (format == RP_HTTP_AUTOINDEX_JSONP) {
        if (rp_http_autoindex_jsonp_callback(r, &callback) != RP_OK) {
            return RP_HTTP_BAD_REQUEST;
        }

        if (callback.len == 0) {
            format = RP_HTTP_AUTOINDEX_JSON;
        }
    }

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

#if (RP_SUPPRESS_WARN)

    /* MSVC thinks 'entries' may be used without having been initialized */
    rp_memzero(&entries, sizeof(rp_array_t));

#endif

    /* TODO: pool should be temporary pool */
    pool = r->pool;

    if (rp_array_init(&entries, pool, 40, sizeof(rp_http_autoindex_entry_t))
        != RP_OK)
    {
        return rp_http_autoindex_error(r, &dir, &path);
    }

    r->headers_out.status = RP_HTTP_OK;

    switch (format) {

    case RP_HTTP_AUTOINDEX_JSON:
        rp_str_set(&r->headers_out.content_type, "application/json");
        break;

    case RP_HTTP_AUTOINDEX_JSONP:
        rp_str_set(&r->headers_out.content_type, "application/javascript");
        break;

    case RP_HTTP_AUTOINDEX_XML:
        rp_str_set(&r->headers_out.content_type, "text/xml");
        rp_str_set(&r->headers_out.charset, "utf-8");
        break;

    default: /* RP_HTTP_AUTOINDEX_HTML */
        rp_str_set(&r->headers_out.content_type, "text/html");
        break;
    }

    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        if (rp_close_dir(&dir) == RP_ERROR) {
            rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                          rp_close_dir_n " \"%V\" failed", &path);
        }

        return rc;
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
                return rp_http_autoindex_error(r, &dir, &path);
            }

            break;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http autoindex file: \"%s\"", rp_de_name(&dir));

        len = rp_de_namelen(&dir);

        if (rp_de_name(&dir)[0] == '.') {
            continue;
        }

        if (!dir.valid_info) {

            /* 1 byte for '/' and 1 byte for terminating '\0' */

            if (path.len + 1 + len + 1 > allocated) {
                allocated = path.len + 1 + len + 1
                                     + RP_HTTP_AUTOINDEX_PREALLOCATE;

                filename = rp_pnalloc(pool, allocated);
                if (filename == NULL) {
                    return rp_http_autoindex_error(r, &dir, &path);
                }

                last = rp_cpystrn(filename, path.data, path.len + 1);
                *last++ = '/';
            }

            rp_cpystrn(last, rp_de_name(&dir), len + 1);

            if (rp_de_info(filename, &dir) == RP_FILE_ERROR) {
                err = rp_errno;

                if (err != RP_ENOENT && err != RP_ELOOP) {
                    rp_log_error(RP_LOG_CRIT, r->connection->log, err,
                                  rp_de_info_n " \"%s\" failed", filename);

                    if (err == RP_EACCES) {
                        continue;
                    }

                    return rp_http_autoindex_error(r, &dir, &path);
                }

                if (rp_de_link_info(filename, &dir) == RP_FILE_ERROR) {
                    rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                                  rp_de_link_info_n " \"%s\" failed",
                                  filename);
                    return rp_http_autoindex_error(r, &dir, &path);
                }
            }
        }

        entry = rp_array_push(&entries);
        if (entry == NULL) {
            return rp_http_autoindex_error(r, &dir, &path);
        }

        entry->name.len = len;

        entry->name.data = rp_pnalloc(pool, len + 1);
        if (entry->name.data == NULL) {
            return rp_http_autoindex_error(r, &dir, &path);
        }

        rp_cpystrn(entry->name.data, rp_de_name(&dir), len + 1);

        entry->dir = rp_de_is_dir(&dir);
        entry->file = rp_de_is_file(&dir);
        entry->mtime = rp_de_mtime(&dir);
        entry->size = rp_de_size(&dir);
    }

    if (rp_close_dir(&dir) == RP_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_dir_n " \"%V\" failed", &path);
    }

    if (entries.nelts > 1) {
        rp_qsort(entries.elts, (size_t) entries.nelts,
                  sizeof(rp_http_autoindex_entry_t),
                  rp_http_autoindex_cmp_entries);
    }

    switch (format) {

    case RP_HTTP_AUTOINDEX_JSON:
        b = rp_http_autoindex_json(r, &entries, NULL);
        break;

    case RP_HTTP_AUTOINDEX_JSONP:
        b = rp_http_autoindex_json(r, &entries, &callback);
        break;

    case RP_HTTP_AUTOINDEX_XML:
        b = rp_http_autoindex_xml(r, &entries);
        break;

    default: /* RP_HTTP_AUTOINDEX_HTML */
        b = rp_http_autoindex_html(r, &entries);
        break;
    }

    if (b == NULL) {
        return RP_ERROR;
    }

    /* TODO: free temporary pool */

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return rp_http_output_filter(r, &out);
}


static rp_buf_t *
rp_http_autoindex_html(rp_http_request_t *r, rp_array_t *entries)
{
    u_char                         *last, scale;
    off_t                           length;
    size_t                          len, entry_len, char_len, escape_html;
    rp_tm_t                        tm;
    rp_buf_t                      *b;
    rp_int_t                       size;
    rp_uint_t                      i, utf8;
    rp_time_t                     *tp;
    rp_http_autoindex_entry_t     *entry;
    rp_http_autoindex_loc_conf_t  *alcf;

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
        && rp_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
           == 0)
    {
        utf8 = 1;

    } else {
        utf8 = 0;
    }

    escape_html = rp_escape_html(NULL, r->uri.data, r->uri.len);

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
        entry[i].escape = 2 * rp_escape_uri(NULL, entry[i].name.data,
                                             entry[i].name.len,
                                             RP_ESCAPE_URI_COMPONENT);

        entry[i].escape_html = rp_escape_html(NULL, entry[i].name.data,
                                               entry[i].name.len);

        if (utf8) {
            entry[i].utf_len = rp_utf8_length(entry[i].name.data,
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
                  + RP_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
                  + sizeof("</a>") - 1
                  + sizeof(" 28-Sep-1970 12:00 ") - 1
                  + 20                                   /* the file size */
                  + 2;

        if (len > RP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rp_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rp_cpymem(b->last, title, sizeof(title) - 1);

    if (escape_html) {
        b->last = (u_char *) rp_escape_html(b->last, r->uri.data, r->uri.len);
        b->last = rp_cpymem(b->last, header, sizeof(header) - 1);
        b->last = (u_char *) rp_escape_html(b->last, r->uri.data, r->uri.len);

    } else {
        b->last = rp_cpymem(b->last, r->uri.data, r->uri.len);
        b->last = rp_cpymem(b->last, header, sizeof(header) - 1);
        b->last = rp_cpymem(b->last, r->uri.data, r->uri.len);
    }

    b->last = rp_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);

    b->last = rp_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
                         sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);

    alcf = rp_http_get_module_loc_conf(r, rp_http_autoindex_module);
    tp = rp_timeofday();

    for (i = 0; i < entries->nelts; i++) {
        b->last = rp_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);

        if (entry[i].escape) {
            rp_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
                           RP_ESCAPE_URI_COMPONENT);

            b->last += entry[i].name.len + entry[i].escape;

        } else {
            b->last = rp_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        if (entry[i].dir) {
            *b->last++ = '/';
        }

        *b->last++ = '"';
        *b->last++ = '>';

        len = entry[i].utf_len;

        if (entry[i].name.len != len) {
            if (len > RP_HTTP_AUTOINDEX_NAME_LEN) {
                char_len = RP_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;

            } else {
                char_len = RP_HTTP_AUTOINDEX_NAME_LEN + 1;
            }

            last = b->last;
            b->last = rp_utf8_cpystrn(b->last, entry[i].name.data,
                                       char_len, entry[i].name.len + 1);

            if (entry[i].escape_html) {
                b->last = (u_char *) rp_escape_html(last, entry[i].name.data,
                                                     b->last - last);
            }

            last = b->last;

        } else {
            if (entry[i].escape_html) {
                if (len > RP_HTTP_AUTOINDEX_NAME_LEN) {
                    char_len = RP_HTTP_AUTOINDEX_NAME_LEN - 3;

                } else {
                    char_len = len;
                }

                b->last = (u_char *) rp_escape_html(b->last,
                                                  entry[i].name.data, char_len);
                last = b->last;

            } else {
                b->last = rp_cpystrn(b->last, entry[i].name.data,
                                      RP_HTTP_AUTOINDEX_NAME_LEN + 1);
                last = b->last - 3;
            }
        }

        if (len > RP_HTTP_AUTOINDEX_NAME_LEN) {
            b->last = rp_cpymem(last, "..&gt;</a>", sizeof("..&gt;</a>") - 1);

        } else {
            if (entry[i].dir && RP_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                *b->last++ = '/';
                len++;
            }

            b->last = rp_cpymem(b->last, "</a>", sizeof("</a>") - 1);

            if (RP_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
                rp_memset(b->last, ' ', RP_HTTP_AUTOINDEX_NAME_LEN - len);
                b->last += RP_HTTP_AUTOINDEX_NAME_LEN - len;
            }
        }

        *b->last++ = ' ';

        rp_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);

        b->last = rp_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
                              tm.rp_tm_mday,
                              months[tm.rp_tm_mon - 1],
                              tm.rp_tm_year,
                              tm.rp_tm_hour,
                              tm.rp_tm_min);

        if (alcf->exact_size) {
            if (entry[i].dir) {
                b->last = rp_cpymem(b->last,  "                  -",
                                     sizeof("                  -") - 1);
            } else {
                b->last = rp_sprintf(b->last, "%19O", entry[i].size);
            }

        } else {
            if (entry[i].dir) {
                b->last = rp_cpymem(b->last,  "      -",
                                     sizeof("      -") - 1);

            } else {
                length = entry[i].size;

                if (length > 1024 * 1024 * 1024 - 1) {
                    size = (rp_int_t) (length / (1024 * 1024 * 1024));
                    if ((length % (1024 * 1024 * 1024))
                                                > (1024 * 1024 * 1024 / 2 - 1))
                    {
                        size++;
                    }
                    scale = 'G';

                } else if (length > 1024 * 1024 - 1) {
                    size = (rp_int_t) (length / (1024 * 1024));
                    if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
                        size++;
                    }
                    scale = 'M';

                } else if (length > 9999) {
                    size = (rp_int_t) (length / 1024);
                    if (length % 1024 > 511) {
                        size++;
                    }
                    scale = 'K';

                } else {
                    size = (rp_int_t) length;
                    scale = '\0';
                }

                if (scale) {
                    b->last = rp_sprintf(b->last, "%6i%c", size, scale);

                } else {
                    b->last = rp_sprintf(b->last, " %6i", size);
                }
            }
        }

        *b->last++ = CR;
        *b->last++ = LF;
    }

    b->last = rp_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);

    b->last = rp_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static rp_buf_t *
rp_http_autoindex_json(rp_http_request_t *r, rp_array_t *entries,
    rp_str_t *callback)
{
    size_t                       len, entry_len;
    rp_buf_t                   *b;
    rp_uint_t                   i;
    rp_http_autoindex_entry_t  *entry;

    len = sizeof("[" CRLF CRLF "]") - 1;

    if (callback) {
        len += sizeof("/* callback */" CRLF "();") - 1 + callback->len;
    }

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = rp_escape_json(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("{  }," CRLF) - 1
                  + sizeof("\"name\":\"\"") - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(", \"type\":\"directory\"") - 1
                  + sizeof(", \"mtime\":\"Wed, 31 Dec 1986 10:00:00 GMT\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(", \"size\":") - 1 + RP_OFF_T_LEN;
        }

        if (len > RP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rp_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    if (callback) {
        b->last = rp_cpymem(b->last, "/* callback */" CRLF,
                             sizeof("/* callback */" CRLF) - 1);

        b->last = rp_cpymem(b->last, callback->data, callback->len);

        *b->last++ = '(';
    }

    *b->last++ = '[';

    for (i = 0; i < entries->nelts; i++) {
        b->last = rp_cpymem(b->last, CRLF "{ \"name\":\"",
                             sizeof(CRLF "{ \"name\":\"") - 1);

        if (entry[i].escape) {
            b->last = (u_char *) rp_escape_json(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = rp_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        b->last = rp_cpymem(b->last, "\", \"type\":\"",
                             sizeof("\", \"type\":\"") - 1);

        if (entry[i].dir) {
            b->last = rp_cpymem(b->last, "directory", sizeof("directory") - 1);

        } else if (entry[i].file) {
            b->last = rp_cpymem(b->last, "file", sizeof("file") - 1);

        } else {
            b->last = rp_cpymem(b->last, "other", sizeof("other") - 1);
        }

        b->last = rp_cpymem(b->last, "\", \"mtime\":\"",
                             sizeof("\", \"mtime\":\"") - 1);

        b->last = rp_http_time(b->last, entry[i].mtime);

        if (entry[i].file) {
            b->last = rp_cpymem(b->last, "\", \"size\":",
                                 sizeof("\", \"size\":") - 1);
            b->last = rp_sprintf(b->last, "%O", entry[i].size);

        } else {
            *b->last++ = '"';
        }

        b->last = rp_cpymem(b->last, " },", sizeof(" },") - 1);
    }

    if (i > 0) {
        b->last--;  /* strip last comma */
    }

    b->last = rp_cpymem(b->last, CRLF "]", sizeof(CRLF "]") - 1);

    if (callback) {
        *b->last++ = ')'; *b->last++ = ';';
    }

    return b;
}


static rp_int_t
rp_http_autoindex_jsonp_callback(rp_http_request_t *r, rp_str_t *callback)
{
    u_char      *p, c, ch;
    rp_uint_t   i;

    if (rp_http_arg(r, (u_char *) "callback", 8, callback) != RP_OK) {
        callback->len = 0;
        return RP_OK;
    }

    if (callback->len > 128) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent too long callback name: \"%V\"", callback);
        return RP_DECLINED;
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

        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid callback name: \"%V\"", callback);

        return RP_DECLINED;
    }

    return RP_OK;
}


static rp_buf_t *
rp_http_autoindex_xml(rp_http_request_t *r, rp_array_t *entries)
{
    size_t                          len, entry_len;
    rp_tm_t                        tm;
    rp_buf_t                      *b;
    rp_str_t                       type;
    rp_uint_t                      i;
    rp_http_autoindex_entry_t     *entry;

    static u_char  head[] = "<?xml version=\"1.0\"?>" CRLF "<list>" CRLF;
    static u_char  tail[] = "</list>" CRLF;

    len = sizeof(head) - 1 + sizeof(tail) - 1;

    entry = entries->elts;

    for (i = 0; i < entries->nelts; i++) {
        entry[i].escape = rp_escape_html(NULL, entry[i].name.data,
                                          entry[i].name.len);

        entry_len = sizeof("<directory></directory>" CRLF) - 1
                  + entry[i].name.len + entry[i].escape
                  + sizeof(" mtime=\"1986-12-31T10:00:00Z\"") - 1;

        if (entry[i].file) {
            entry_len += sizeof(" size=\"\"") - 1 + RP_OFF_T_LEN;
        }

        if (len > RP_MAX_SIZE_T_VALUE - entry_len) {
            return NULL;
        }

        len += entry_len;
    }

    b = rp_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rp_cpymem(b->last, head, sizeof(head) - 1);

    for (i = 0; i < entries->nelts; i++) {
        *b->last++ = '<';

        if (entry[i].dir) {
            rp_str_set(&type, "directory");

        } else if (entry[i].file) {
            rp_str_set(&type, "file");

        } else {
            rp_str_set(&type, "other");
        }

        b->last = rp_cpymem(b->last, type.data, type.len);

        b->last = rp_cpymem(b->last, " mtime=\"", sizeof(" mtime=\"") - 1);

        rp_gmtime(entry[i].mtime, &tm);

        b->last = rp_sprintf(b->last, "%4d-%02d-%02dT%02d:%02d:%02dZ",
                              tm.rp_tm_year, tm.rp_tm_mon,
                              tm.rp_tm_mday, tm.rp_tm_hour,
                              tm.rp_tm_min, tm.rp_tm_sec);

        if (entry[i].file) {
            b->last = rp_cpymem(b->last, "\" size=\"",
                                 sizeof("\" size=\"") - 1);
            b->last = rp_sprintf(b->last, "%O", entry[i].size);
        }

        *b->last++ = '"'; *b->last++ = '>';

        if (entry[i].escape) {
            b->last = (u_char *) rp_escape_html(b->last, entry[i].name.data,
                                                 entry[i].name.len);
        } else {
            b->last = rp_cpymem(b->last, entry[i].name.data,
                                 entry[i].name.len);
        }

        *b->last++ = '<'; *b->last++ = '/';

        b->last = rp_cpymem(b->last, type.data, type.len);

        *b->last++ = '>';

        *b->last++ = CR; *b->last++ = LF;
    }

    b->last = rp_cpymem(b->last, tail, sizeof(tail) - 1);

    return b;
}


static int rp_libc_cdecl
rp_http_autoindex_cmp_entries(const void *one, const void *two)
{
    rp_http_autoindex_entry_t *first = (rp_http_autoindex_entry_t *) one;
    rp_http_autoindex_entry_t *second = (rp_http_autoindex_entry_t *) two;

    if (first->dir && !second->dir) {
        /* move the directories to the start */
        return -1;
    }

    if (!first->dir && second->dir) {
        /* move the directories to the start */
        return 1;
    }

    return (int) rp_strcmp(first->name.data, second->name.data);
}


#if 0

static rp_buf_t *
rp_http_autoindex_alloc(rp_http_autoindex_ctx_t *ctx, size_t size)
{
    rp_chain_t  *cl;

    if (ctx->buf) {

        if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
            return ctx->buf;
        }

        ctx->size += ctx->buf->last - ctx->buf->pos;
    }

    ctx->buf = rp_create_temp_buf(ctx->pool, ctx->alloc_size);
    if (ctx->buf == NULL) {
        return NULL;
    }

    cl = rp_alloc_chain_link(ctx->pool);
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


static rp_int_t
rp_http_autoindex_error(rp_http_request_t *r, rp_dir_t *dir, rp_str_t *name)
{
    if (rp_close_dir(dir) == RP_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_dir_n " \"%V\" failed", name);
    }

    return r->header_sent ? RP_ERROR : RP_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
rp_http_autoindex_create_loc_conf(rp_conf_t *cf)
{
    rp_http_autoindex_loc_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_autoindex_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RP_CONF_UNSET;
    conf->format = RP_CONF_UNSET_UINT;
    conf->localtime = RP_CONF_UNSET;
    conf->exact_size = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_autoindex_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_autoindex_loc_conf_t *prev = parent;
    rp_http_autoindex_loc_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);
    rp_conf_merge_uint_value(conf->format, prev->format,
                              RP_HTTP_AUTOINDEX_HTML);
    rp_conf_merge_value(conf->localtime, prev->localtime, 0);
    rp_conf_merge_value(conf->exact_size, prev->exact_size, 1);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_autoindex_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_autoindex_handler;

    return RP_OK;
}
