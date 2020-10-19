
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_V2_TABLE_SIZE  4096


static rap_int_t rap_http_v2_table_account(rap_http_v2_connection_t *h2c,
    size_t size);


static rap_http_v2_header_t  rap_http_v2_static_table[] = {
    { rap_string(":authority"), rap_string("") },
    { rap_string(":method"), rap_string("GET") },
    { rap_string(":method"), rap_string("POST") },
    { rap_string(":path"), rap_string("/") },
    { rap_string(":path"), rap_string("/index.html") },
    { rap_string(":scheme"), rap_string("http") },
    { rap_string(":scheme"), rap_string("https") },
    { rap_string(":status"), rap_string("200") },
    { rap_string(":status"), rap_string("204") },
    { rap_string(":status"), rap_string("206") },
    { rap_string(":status"), rap_string("304") },
    { rap_string(":status"), rap_string("400") },
    { rap_string(":status"), rap_string("404") },
    { rap_string(":status"), rap_string("500") },
    { rap_string("accept-charset"), rap_string("") },
    { rap_string("accept-encoding"), rap_string("gzip, deflate") },
    { rap_string("accept-language"), rap_string("") },
    { rap_string("accept-ranges"), rap_string("") },
    { rap_string("accept"), rap_string("") },
    { rap_string("access-control-allow-origin"), rap_string("") },
    { rap_string("age"), rap_string("") },
    { rap_string("allow"), rap_string("") },
    { rap_string("authorization"), rap_string("") },
    { rap_string("cache-control"), rap_string("") },
    { rap_string("content-disposition"), rap_string("") },
    { rap_string("content-encoding"), rap_string("") },
    { rap_string("content-language"), rap_string("") },
    { rap_string("content-length"), rap_string("") },
    { rap_string("content-location"), rap_string("") },
    { rap_string("content-range"), rap_string("") },
    { rap_string("content-type"), rap_string("") },
    { rap_string("cookie"), rap_string("") },
    { rap_string("date"), rap_string("") },
    { rap_string("etag"), rap_string("") },
    { rap_string("expect"), rap_string("") },
    { rap_string("expires"), rap_string("") },
    { rap_string("from"), rap_string("") },
    { rap_string("host"), rap_string("") },
    { rap_string("if-match"), rap_string("") },
    { rap_string("if-modified-since"), rap_string("") },
    { rap_string("if-none-match"), rap_string("") },
    { rap_string("if-range"), rap_string("") },
    { rap_string("if-unmodified-since"), rap_string("") },
    { rap_string("last-modified"), rap_string("") },
    { rap_string("link"), rap_string("") },
    { rap_string("location"), rap_string("") },
    { rap_string("max-forwards"), rap_string("") },
    { rap_string("proxy-authenticate"), rap_string("") },
    { rap_string("proxy-authorization"), rap_string("") },
    { rap_string("range"), rap_string("") },
    { rap_string("referer"), rap_string("") },
    { rap_string("refresh"), rap_string("") },
    { rap_string("retry-after"), rap_string("") },
    { rap_string("server"), rap_string("") },
    { rap_string("set-cookie"), rap_string("") },
    { rap_string("strict-transport-security"), rap_string("") },
    { rap_string("transfer-encoding"), rap_string("") },
    { rap_string("user-agent"), rap_string("") },
    { rap_string("vary"), rap_string("") },
    { rap_string("via"), rap_string("") },
    { rap_string("www-authenticate"), rap_string("") },
};

#define RAP_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(rap_http_v2_static_table)                                         \
     / sizeof(rap_http_v2_header_t))


rap_str_t *
rap_http_v2_get_static_name(rap_uint_t index)
{
    return &rap_http_v2_static_table[index - 1].name;
}


rap_str_t *
rap_http_v2_get_static_value(rap_uint_t index)
{
    return &rap_http_v2_static_table[index - 1].value;
}


rap_int_t
rap_http_v2_get_indexed_header(rap_http_v2_connection_t *h2c, rap_uint_t index,
    rap_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    rap_http_v2_header_t  *entry;

    if (index == 0) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return RAP_ERROR;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < RAP_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = rap_http_v2_static_table[index];
        return RAP_OK;
    }

    index -= RAP_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack.added - h2c->hpack.deleted) {
        index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
        entry = h2c->hpack.entries[index];

        p = rap_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return RAP_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack.storage + RAP_HTTP_V2_TABLE_SIZE - entry->name.data;

        if (entry->name.len > rest) {
            p = rap_cpymem(p, entry->name.data, rest);
            p = rap_cpymem(p, h2c->hpack.storage, entry->name.len - rest);

        } else {
            p = rap_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return RAP_OK;
        }

        p = rap_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return RAP_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack.storage + RAP_HTTP_V2_TABLE_SIZE - entry->value.data;

        if (entry->value.len > rest) {
            p = rap_cpymem(p, entry->value.data, rest);
            p = rap_cpymem(p, h2c->hpack.storage, entry->value.len - rest);

        } else {
            p = rap_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return RAP_OK;
    }

    rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return RAP_ERROR;
}


rap_int_t
rap_http_v2_add_header(rap_http_v2_connection_t *h2c,
    rap_http_v2_header_t *header)
{
    size_t                 avail;
    rap_uint_t             index;
    rap_http_v2_header_t  *entry, **entries;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table add: \"%V: %V\"",
                   &header->name, &header->value);

    if (h2c->hpack.entries == NULL) {
        h2c->hpack.allocated = 64;
        h2c->hpack.size = RAP_HTTP_V2_TABLE_SIZE;
        h2c->hpack.free = RAP_HTTP_V2_TABLE_SIZE;

        h2c->hpack.entries = rap_palloc(h2c->connection->pool,
                                        sizeof(rap_http_v2_header_t *)
                                        * h2c->hpack.allocated);
        if (h2c->hpack.entries == NULL) {
            return RAP_ERROR;
        }

        h2c->hpack.storage = rap_palloc(h2c->connection->pool,
                                        h2c->hpack.free);
        if (h2c->hpack.storage == NULL) {
            return RAP_ERROR;
        }

        h2c->hpack.pos = h2c->hpack.storage;
    }

    if (rap_http_v2_table_account(h2c, header->name.len + header->value.len)
        != RAP_OK)
    {
        return RAP_OK;
    }

    if (h2c->hpack.reused == h2c->hpack.deleted) {
        entry = rap_palloc(h2c->connection->pool, sizeof(rap_http_v2_header_t));
        if (entry == NULL) {
            return RAP_ERROR;
        }

    } else {
        entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
    }

    avail = h2c->hpack.storage + RAP_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;

    entry->name.len = header->name.len;
    entry->name.data = h2c->hpack.pos;

    if (avail >= header->name.len) {
        h2c->hpack.pos = rap_cpymem(h2c->hpack.pos, header->name.data,
                                    header->name.len);
    } else {
        rap_memcpy(h2c->hpack.pos, header->name.data, avail);
        h2c->hpack.pos = rap_cpymem(h2c->hpack.storage,
                                    header->name.data + avail,
                                    header->name.len - avail);
        avail = RAP_HTTP_V2_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = h2c->hpack.pos;

    if (avail >= header->value.len) {
        h2c->hpack.pos = rap_cpymem(h2c->hpack.pos, header->value.data,
                                    header->value.len);
    } else {
        rap_memcpy(h2c->hpack.pos, header->value.data, avail);
        h2c->hpack.pos = rap_cpymem(h2c->hpack.storage,
                                    header->value.data + avail,
                                    header->value.len - avail);
    }

    if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {

        entries = rap_palloc(h2c->connection->pool,
                             sizeof(rap_http_v2_header_t *)
                             * (h2c->hpack.allocated + 64));
        if (entries == NULL) {
            return RAP_ERROR;
        }

        index = h2c->hpack.deleted % h2c->hpack.allocated;

        rap_memcpy(entries, &h2c->hpack.entries[index],
                   (h2c->hpack.allocated - index)
                   * sizeof(rap_http_v2_header_t *));

        rap_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
                   index * sizeof(rap_http_v2_header_t *));

        (void) rap_pfree(h2c->connection->pool, h2c->hpack.entries);

        h2c->hpack.entries = entries;

        h2c->hpack.added = h2c->hpack.allocated;
        h2c->hpack.deleted = 0;
        h2c->hpack.reused = 0;
        h2c->hpack.allocated += 64;
    }

    h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;

    return RAP_OK;
}


static rap_int_t
rap_http_v2_table_account(rap_http_v2_connection_t *h2c, size_t size)
{
    rap_http_v2_header_t  *entry;

    size += 32;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table account: %uz free:%uz",
                   size, h2c->hpack.free);

    if (size <= h2c->hpack.free) {
        h2c->hpack.free -= size;
        return RAP_OK;
    }

    if (size > h2c->hpack.size) {
        h2c->hpack.deleted = h2c->hpack.added;
        h2c->hpack.free = h2c->hpack.size;
        return RAP_DECLINED;
    }

    do {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    } while (size > h2c->hpack.free);

    h2c->hpack.free -= size;

    return RAP_OK;
}


rap_int_t
rap_http_v2_table_size(rap_http_v2_connection_t *h2c, size_t size)
{
    ssize_t                needed;
    rap_http_v2_header_t  *entry;

    if (size > RAP_HTTP_V2_TABLE_SIZE) {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return RAP_ERROR;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack table size: %uz was:%uz",
                   size, h2c->hpack.size);

    needed = h2c->hpack.size - size;

    while (needed > (ssize_t) h2c->hpack.free) {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    }

    h2c->hpack.size = size;
    h2c->hpack.free -= needed;

    return RAP_OK;
}
