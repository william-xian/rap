
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_V2_TABLE_SIZE  4096


static rp_int_t rp_http_v2_table_account(rp_http_v2_connection_t *h2c,
    size_t size);


static rp_http_v2_header_t  rp_http_v2_static_table[] = {
    { rp_string(":authority"), rp_string("") },
    { rp_string(":method"), rp_string("GET") },
    { rp_string(":method"), rp_string("POST") },
    { rp_string(":path"), rp_string("/") },
    { rp_string(":path"), rp_string("/index.html") },
    { rp_string(":scheme"), rp_string("http") },
    { rp_string(":scheme"), rp_string("https") },
    { rp_string(":status"), rp_string("200") },
    { rp_string(":status"), rp_string("204") },
    { rp_string(":status"), rp_string("206") },
    { rp_string(":status"), rp_string("304") },
    { rp_string(":status"), rp_string("400") },
    { rp_string(":status"), rp_string("404") },
    { rp_string(":status"), rp_string("500") },
    { rp_string("accept-charset"), rp_string("") },
    { rp_string("accept-encoding"), rp_string("gzip, deflate") },
    { rp_string("accept-language"), rp_string("") },
    { rp_string("accept-ranges"), rp_string("") },
    { rp_string("accept"), rp_string("") },
    { rp_string("access-control-allow-origin"), rp_string("") },
    { rp_string("age"), rp_string("") },
    { rp_string("allow"), rp_string("") },
    { rp_string("authorization"), rp_string("") },
    { rp_string("cache-control"), rp_string("") },
    { rp_string("content-disposition"), rp_string("") },
    { rp_string("content-encoding"), rp_string("") },
    { rp_string("content-language"), rp_string("") },
    { rp_string("content-length"), rp_string("") },
    { rp_string("content-location"), rp_string("") },
    { rp_string("content-range"), rp_string("") },
    { rp_string("content-type"), rp_string("") },
    { rp_string("cookie"), rp_string("") },
    { rp_string("date"), rp_string("") },
    { rp_string("etag"), rp_string("") },
    { rp_string("expect"), rp_string("") },
    { rp_string("expires"), rp_string("") },
    { rp_string("from"), rp_string("") },
    { rp_string("host"), rp_string("") },
    { rp_string("if-match"), rp_string("") },
    { rp_string("if-modified-since"), rp_string("") },
    { rp_string("if-none-match"), rp_string("") },
    { rp_string("if-range"), rp_string("") },
    { rp_string("if-unmodified-since"), rp_string("") },
    { rp_string("last-modified"), rp_string("") },
    { rp_string("link"), rp_string("") },
    { rp_string("location"), rp_string("") },
    { rp_string("max-forwards"), rp_string("") },
    { rp_string("proxy-authenticate"), rp_string("") },
    { rp_string("proxy-authorization"), rp_string("") },
    { rp_string("range"), rp_string("") },
    { rp_string("referer"), rp_string("") },
    { rp_string("refresh"), rp_string("") },
    { rp_string("retry-after"), rp_string("") },
    { rp_string("server"), rp_string("") },
    { rp_string("set-cookie"), rp_string("") },
    { rp_string("strict-transport-security"), rp_string("") },
    { rp_string("transfer-encoding"), rp_string("") },
    { rp_string("user-agent"), rp_string("") },
    { rp_string("vary"), rp_string("") },
    { rp_string("via"), rp_string("") },
    { rp_string("www-authenticate"), rp_string("") },
};

#define RP_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(rp_http_v2_static_table)                                         \
     / sizeof(rp_http_v2_header_t))


rp_str_t *
rp_http_v2_get_static_name(rp_uint_t index)
{
    return &rp_http_v2_static_table[index - 1].name;
}


rp_str_t *
rp_http_v2_get_static_value(rp_uint_t index)
{
    return &rp_http_v2_static_table[index - 1].value;
}


rp_int_t
rp_http_v2_get_indexed_header(rp_http_v2_connection_t *h2c, rp_uint_t index,
    rp_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    rp_http_v2_header_t  *entry;

    if (index == 0) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return RP_ERROR;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < RP_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = rp_http_v2_static_table[index];
        return RP_OK;
    }

    index -= RP_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack.added - h2c->hpack.deleted) {
        index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
        entry = h2c->hpack.entries[index];

        p = rp_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return RP_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack.storage + RP_HTTP_V2_TABLE_SIZE - entry->name.data;

        if (entry->name.len > rest) {
            p = rp_cpymem(p, entry->name.data, rest);
            p = rp_cpymem(p, h2c->hpack.storage, entry->name.len - rest);

        } else {
            p = rp_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return RP_OK;
        }

        p = rp_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return RP_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack.storage + RP_HTTP_V2_TABLE_SIZE - entry->value.data;

        if (entry->value.len > rest) {
            p = rp_cpymem(p, entry->value.data, rest);
            p = rp_cpymem(p, h2c->hpack.storage, entry->value.len - rest);

        } else {
            p = rp_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return RP_OK;
    }

    rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return RP_ERROR;
}


rp_int_t
rp_http_v2_add_header(rp_http_v2_connection_t *h2c,
    rp_http_v2_header_t *header)
{
    size_t                 avail;
    rp_uint_t             index;
    rp_http_v2_header_t  *entry, **entries;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table add: \"%V: %V\"",
                   &header->name, &header->value);

    if (h2c->hpack.entries == NULL) {
        h2c->hpack.allocated = 64;
        h2c->hpack.size = RP_HTTP_V2_TABLE_SIZE;
        h2c->hpack.free = RP_HTTP_V2_TABLE_SIZE;

        h2c->hpack.entries = rp_palloc(h2c->connection->pool,
                                        sizeof(rp_http_v2_header_t *)
                                        * h2c->hpack.allocated);
        if (h2c->hpack.entries == NULL) {
            return RP_ERROR;
        }

        h2c->hpack.storage = rp_palloc(h2c->connection->pool,
                                        h2c->hpack.free);
        if (h2c->hpack.storage == NULL) {
            return RP_ERROR;
        }

        h2c->hpack.pos = h2c->hpack.storage;
    }

    if (rp_http_v2_table_account(h2c, header->name.len + header->value.len)
        != RP_OK)
    {
        return RP_OK;
    }

    if (h2c->hpack.reused == h2c->hpack.deleted) {
        entry = rp_palloc(h2c->connection->pool, sizeof(rp_http_v2_header_t));
        if (entry == NULL) {
            return RP_ERROR;
        }

    } else {
        entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
    }

    avail = h2c->hpack.storage + RP_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;

    entry->name.len = header->name.len;
    entry->name.data = h2c->hpack.pos;

    if (avail >= header->name.len) {
        h2c->hpack.pos = rp_cpymem(h2c->hpack.pos, header->name.data,
                                    header->name.len);
    } else {
        rp_memcpy(h2c->hpack.pos, header->name.data, avail);
        h2c->hpack.pos = rp_cpymem(h2c->hpack.storage,
                                    header->name.data + avail,
                                    header->name.len - avail);
        avail = RP_HTTP_V2_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = h2c->hpack.pos;

    if (avail >= header->value.len) {
        h2c->hpack.pos = rp_cpymem(h2c->hpack.pos, header->value.data,
                                    header->value.len);
    } else {
        rp_memcpy(h2c->hpack.pos, header->value.data, avail);
        h2c->hpack.pos = rp_cpymem(h2c->hpack.storage,
                                    header->value.data + avail,
                                    header->value.len - avail);
    }

    if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {

        entries = rp_palloc(h2c->connection->pool,
                             sizeof(rp_http_v2_header_t *)
                             * (h2c->hpack.allocated + 64));
        if (entries == NULL) {
            return RP_ERROR;
        }

        index = h2c->hpack.deleted % h2c->hpack.allocated;

        rp_memcpy(entries, &h2c->hpack.entries[index],
                   (h2c->hpack.allocated - index)
                   * sizeof(rp_http_v2_header_t *));

        rp_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
                   index * sizeof(rp_http_v2_header_t *));

        (void) rp_pfree(h2c->connection->pool, h2c->hpack.entries);

        h2c->hpack.entries = entries;

        h2c->hpack.added = h2c->hpack.allocated;
        h2c->hpack.deleted = 0;
        h2c->hpack.reused = 0;
        h2c->hpack.allocated += 64;
    }

    h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;

    return RP_OK;
}


static rp_int_t
rp_http_v2_table_account(rp_http_v2_connection_t *h2c, size_t size)
{
    rp_http_v2_header_t  *entry;

    size += 32;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table account: %uz free:%uz",
                   size, h2c->hpack.free);

    if (size <= h2c->hpack.free) {
        h2c->hpack.free -= size;
        return RP_OK;
    }

    if (size > h2c->hpack.size) {
        h2c->hpack.deleted = h2c->hpack.added;
        h2c->hpack.free = h2c->hpack.size;
        return RP_DECLINED;
    }

    do {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    } while (size > h2c->hpack.free);

    h2c->hpack.free -= size;

    return RP_OK;
}


rp_int_t
rp_http_v2_table_size(rp_http_v2_connection_t *h2c, size_t size)
{
    ssize_t                needed;
    rp_http_v2_header_t  *entry;

    if (size > RP_HTTP_V2_TABLE_SIZE) {
        rp_log_error(RP_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return RP_ERROR;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack table size: %uz was:%uz",
                   size, h2c->hpack.size);

    needed = h2c->hpack.size - size;

    while (needed > (ssize_t) h2c->hpack.free) {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    }

    h2c->hpack.size = size;
    h2c->hpack.free -= needed;

    return RP_OK;
}
