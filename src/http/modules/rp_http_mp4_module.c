
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_MP4_TRAK_ATOM     0
#define RP_HTTP_MP4_TKHD_ATOM     1
#define RP_HTTP_MP4_MDIA_ATOM     2
#define RP_HTTP_MP4_MDHD_ATOM     3
#define RP_HTTP_MP4_HDLR_ATOM     4
#define RP_HTTP_MP4_MINF_ATOM     5
#define RP_HTTP_MP4_VMHD_ATOM     6
#define RP_HTTP_MP4_SMHD_ATOM     7
#define RP_HTTP_MP4_DINF_ATOM     8
#define RP_HTTP_MP4_STBL_ATOM     9
#define RP_HTTP_MP4_STSD_ATOM    10
#define RP_HTTP_MP4_STTS_ATOM    11
#define RP_HTTP_MP4_STTS_DATA    12
#define RP_HTTP_MP4_STSS_ATOM    13
#define RP_HTTP_MP4_STSS_DATA    14
#define RP_HTTP_MP4_CTTS_ATOM    15
#define RP_HTTP_MP4_CTTS_DATA    16
#define RP_HTTP_MP4_STSC_ATOM    17
#define RP_HTTP_MP4_STSC_START   18
#define RP_HTTP_MP4_STSC_DATA    19
#define RP_HTTP_MP4_STSC_END     20
#define RP_HTTP_MP4_STSZ_ATOM    21
#define RP_HTTP_MP4_STSZ_DATA    22
#define RP_HTTP_MP4_STCO_ATOM    23
#define RP_HTTP_MP4_STCO_DATA    24
#define RP_HTTP_MP4_CO64_ATOM    25
#define RP_HTTP_MP4_CO64_DATA    26

#define RP_HTTP_MP4_LAST_ATOM    RP_HTTP_MP4_CO64_DATA


typedef struct {
    size_t                buffer_size;
    size_t                max_buffer_size;
} rp_http_mp4_conf_t;


typedef struct {
    u_char                chunk[4];
    u_char                samples[4];
    u_char                id[4];
} rp_mp4_stsc_entry_t;


typedef struct {
    uint32_t              timescale;
    uint32_t              time_to_sample_entries;
    uint32_t              sample_to_chunk_entries;
    uint32_t              sync_samples_entries;
    uint32_t              composition_offset_entries;
    uint32_t              sample_sizes_entries;
    uint32_t              chunks;

    rp_uint_t            start_sample;
    rp_uint_t            end_sample;
    rp_uint_t            start_chunk;
    rp_uint_t            end_chunk;
    rp_uint_t            start_chunk_samples;
    rp_uint_t            end_chunk_samples;
    uint64_t              start_chunk_samples_size;
    uint64_t              end_chunk_samples_size;
    off_t                 start_offset;
    off_t                 end_offset;

    size_t                tkhd_size;
    size_t                mdhd_size;
    size_t                hdlr_size;
    size_t                vmhd_size;
    size_t                smhd_size;
    size_t                dinf_size;
    size_t                size;

    rp_chain_t           out[RP_HTTP_MP4_LAST_ATOM + 1];

    rp_buf_t             trak_atom_buf;
    rp_buf_t             tkhd_atom_buf;
    rp_buf_t             mdia_atom_buf;
    rp_buf_t             mdhd_atom_buf;
    rp_buf_t             hdlr_atom_buf;
    rp_buf_t             minf_atom_buf;
    rp_buf_t             vmhd_atom_buf;
    rp_buf_t             smhd_atom_buf;
    rp_buf_t             dinf_atom_buf;
    rp_buf_t             stbl_atom_buf;
    rp_buf_t             stsd_atom_buf;
    rp_buf_t             stts_atom_buf;
    rp_buf_t             stts_data_buf;
    rp_buf_t             stss_atom_buf;
    rp_buf_t             stss_data_buf;
    rp_buf_t             ctts_atom_buf;
    rp_buf_t             ctts_data_buf;
    rp_buf_t             stsc_atom_buf;
    rp_buf_t             stsc_start_chunk_buf;
    rp_buf_t             stsc_end_chunk_buf;
    rp_buf_t             stsc_data_buf;
    rp_buf_t             stsz_atom_buf;
    rp_buf_t             stsz_data_buf;
    rp_buf_t             stco_atom_buf;
    rp_buf_t             stco_data_buf;
    rp_buf_t             co64_atom_buf;
    rp_buf_t             co64_data_buf;

    rp_mp4_stsc_entry_t  stsc_start_chunk_entry;
    rp_mp4_stsc_entry_t  stsc_end_chunk_entry;
} rp_http_mp4_trak_t;


typedef struct {
    rp_file_t            file;

    u_char               *buffer;
    u_char               *buffer_start;
    u_char               *buffer_pos;
    u_char               *buffer_end;
    size_t                buffer_size;

    off_t                 offset;
    off_t                 end;
    off_t                 content_length;
    rp_uint_t            start;
    rp_uint_t            length;
    uint32_t              timescale;
    rp_http_request_t   *request;
    rp_array_t           trak;
    rp_http_mp4_trak_t   traks[2];

    size_t                ftyp_size;
    size_t                moov_size;

    rp_chain_t          *out;
    rp_chain_t           ftyp_atom;
    rp_chain_t           moov_atom;
    rp_chain_t           mvhd_atom;
    rp_chain_t           mdat_atom;
    rp_chain_t           mdat_data;

    rp_buf_t             ftyp_atom_buf;
    rp_buf_t             moov_atom_buf;
    rp_buf_t             mvhd_atom_buf;
    rp_buf_t             mdat_atom_buf;
    rp_buf_t             mdat_data_buf;

    u_char                moov_atom_header[8];
    u_char                mdat_atom_header[16];
} rp_http_mp4_file_t;


typedef struct {
    char                 *name;
    rp_int_t           (*handler)(rp_http_mp4_file_t *mp4,
                                   uint64_t atom_data_size);
} rp_http_mp4_atom_handler_t;


#define rp_mp4_atom_header(mp4)   (mp4->buffer_pos - 8)
#define rp_mp4_atom_data(mp4)     mp4->buffer_pos
#define rp_mp4_atom_data_size(t)  (uint64_t) (sizeof(t) - 8)


#define rp_mp4_atom_next(mp4, n)                                             \
                                                                              \
    if (n > (size_t) (mp4->buffer_end - mp4->buffer_pos)) {                   \
        mp4->buffer_pos = mp4->buffer_end;                                    \
                                                                              \
    } else {                                                                  \
        mp4->buffer_pos += (size_t) n;                                        \
    }                                                                         \
                                                                              \
    mp4->offset += n


#define rp_mp4_set_atom_name(p, n1, n2, n3, n4)                              \
    ((u_char *) (p))[4] = n1;                                                 \
    ((u_char *) (p))[5] = n2;                                                 \
    ((u_char *) (p))[6] = n3;                                                 \
    ((u_char *) (p))[7] = n4

#define rp_mp4_get_32value(p)                                                \
    ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
    + (           ((u_char *) (p))[1] << 16)                                  \
    + (           ((u_char *) (p))[2] << 8)                                   \
    + (           ((u_char *) (p))[3]) )

#define rp_mp4_set_32value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((n) >> 24);                               \
    ((u_char *) (p))[1] = (u_char) ((n) >> 16);                               \
    ((u_char *) (p))[2] = (u_char) ((n) >> 8);                                \
    ((u_char *) (p))[3] = (u_char)  (n)

#define rp_mp4_get_64value(p)                                                \
    ( ((uint64_t) ((u_char *) (p))[0] << 56)                                  \
    + ((uint64_t) ((u_char *) (p))[1] << 48)                                  \
    + ((uint64_t) ((u_char *) (p))[2] << 40)                                  \
    + ((uint64_t) ((u_char *) (p))[3] << 32)                                  \
    + ((uint64_t) ((u_char *) (p))[4] << 24)                                  \
    + (           ((u_char *) (p))[5] << 16)                                  \
    + (           ((u_char *) (p))[6] << 8)                                   \
    + (           ((u_char *) (p))[7]) )

#define rp_mp4_set_64value(p, n)                                             \
    ((u_char *) (p))[0] = (u_char) ((uint64_t) (n) >> 56);                    \
    ((u_char *) (p))[1] = (u_char) ((uint64_t) (n) >> 48);                    \
    ((u_char *) (p))[2] = (u_char) ((uint64_t) (n) >> 40);                    \
    ((u_char *) (p))[3] = (u_char) ((uint64_t) (n) >> 32);                    \
    ((u_char *) (p))[4] = (u_char) (           (n) >> 24);                    \
    ((u_char *) (p))[5] = (u_char) (           (n) >> 16);                    \
    ((u_char *) (p))[6] = (u_char) (           (n) >> 8);                     \
    ((u_char *) (p))[7] = (u_char)             (n)

#define rp_mp4_last_trak(mp4)                                                \
    &((rp_http_mp4_trak_t *) mp4->trak.elts)[mp4->trak.nelts - 1]


static rp_int_t rp_http_mp4_handler(rp_http_request_t *r);
static rp_int_t rp_http_mp4_atofp(u_char *line, size_t n, size_t point);

static rp_int_t rp_http_mp4_process(rp_http_mp4_file_t *mp4);
static rp_int_t rp_http_mp4_read_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_atom_handler_t *atom, uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read(rp_http_mp4_file_t *mp4, size_t size);
static rp_int_t rp_http_mp4_read_ftyp_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_moov_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_mdat_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static size_t rp_http_mp4_update_mdat_atom(rp_http_mp4_file_t *mp4,
    off_t start_offset, off_t end_offset);
static rp_int_t rp_http_mp4_read_mvhd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_trak_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void rp_http_mp4_update_trak_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_read_cmov_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_tkhd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_mdia_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void rp_http_mp4_update_mdia_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_read_mdhd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_hdlr_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_minf_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void rp_http_mp4_update_minf_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_read_dinf_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_vmhd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_smhd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_stbl_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void rp_http_mp4_update_stbl_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_read_stsd_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_read_stts_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_stts_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_crop_stts_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start);
static rp_int_t rp_http_mp4_read_stss_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_stss_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static void rp_http_mp4_crop_stss_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start);
static rp_int_t rp_http_mp4_read_ctts_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static void rp_http_mp4_update_ctts_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static void rp_http_mp4_crop_ctts_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start);
static rp_int_t rp_http_mp4_read_stsc_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_stsc_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_crop_stsc_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start);
static rp_int_t rp_http_mp4_read_stsz_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_stsz_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static rp_int_t rp_http_mp4_read_stco_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_stco_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static void rp_http_mp4_adjust_stco_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, int32_t adjustment);
static rp_int_t rp_http_mp4_read_co64_atom(rp_http_mp4_file_t *mp4,
    uint64_t atom_data_size);
static rp_int_t rp_http_mp4_update_co64_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak);
static void rp_http_mp4_adjust_co64_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, off_t adjustment);

static char *rp_http_mp4(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static void *rp_http_mp4_create_conf(rp_conf_t *cf);
static char *rp_http_mp4_merge_conf(rp_conf_t *cf, void *parent, void *child);


static rp_command_t  rp_http_mp4_commands[] = {

    { rp_string("mp4"),
      RP_HTTP_LOC_CONF|RP_CONF_NOARGS,
      rp_http_mp4,
      0,
      0,
      NULL },

    { rp_string("mp4_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_mp4_conf_t, buffer_size),
      NULL },

    { rp_string("mp4_max_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_mp4_conf_t, max_buffer_size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_mp4_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    rp_http_mp4_create_conf,      /* create location configuration */
    rp_http_mp4_merge_conf        /* merge location configuration */
};


rp_module_t  rp_http_mp4_module = {
    RP_MODULE_V1,
    &rp_http_mp4_module_ctx,      /* module context */
    rp_http_mp4_commands,         /* module directives */
    RP_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_mp4_atom_handler_t  rp_http_mp4_atoms[] = {
    { "ftyp", rp_http_mp4_read_ftyp_atom },
    { "moov", rp_http_mp4_read_moov_atom },
    { "mdat", rp_http_mp4_read_mdat_atom },
    { NULL, NULL }
};

static rp_http_mp4_atom_handler_t  rp_http_mp4_moov_atoms[] = {
    { "mvhd", rp_http_mp4_read_mvhd_atom },
    { "trak", rp_http_mp4_read_trak_atom },
    { "cmov", rp_http_mp4_read_cmov_atom },
    { NULL, NULL }
};

static rp_http_mp4_atom_handler_t  rp_http_mp4_trak_atoms[] = {
    { "tkhd", rp_http_mp4_read_tkhd_atom },
    { "mdia", rp_http_mp4_read_mdia_atom },
    { NULL, NULL }
};

static rp_http_mp4_atom_handler_t  rp_http_mp4_mdia_atoms[] = {
    { "mdhd", rp_http_mp4_read_mdhd_atom },
    { "hdlr", rp_http_mp4_read_hdlr_atom },
    { "minf", rp_http_mp4_read_minf_atom },
    { NULL, NULL }
};

static rp_http_mp4_atom_handler_t  rp_http_mp4_minf_atoms[] = {
    { "vmhd", rp_http_mp4_read_vmhd_atom },
    { "smhd", rp_http_mp4_read_smhd_atom },
    { "dinf", rp_http_mp4_read_dinf_atom },
    { "stbl", rp_http_mp4_read_stbl_atom },
    { NULL, NULL }
};

static rp_http_mp4_atom_handler_t  rp_http_mp4_stbl_atoms[] = {
    { "stsd", rp_http_mp4_read_stsd_atom },
    { "stts", rp_http_mp4_read_stts_atom },
    { "stss", rp_http_mp4_read_stss_atom },
    { "ctts", rp_http_mp4_read_ctts_atom },
    { "stsc", rp_http_mp4_read_stsc_atom },
    { "stsz", rp_http_mp4_read_stsz_atom },
    { "stco", rp_http_mp4_read_stco_atom },
    { "co64", rp_http_mp4_read_co64_atom },
    { NULL, NULL }
};


static rp_int_t
rp_http_mp4_handler(rp_http_request_t *r)
{
    u_char                    *last;
    size_t                     root;
    rp_int_t                  rc, start, end;
    rp_uint_t                 level, length;
    rp_str_t                  path, value;
    rp_log_t                 *log;
    rp_buf_t                 *b;
    rp_chain_t                out;
    rp_http_mp4_file_t       *mp4;
    rp_open_file_info_t       of;
    rp_http_core_loc_conf_t  *clcf;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RP_DECLINED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    last = rp_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0,
                   "http mp4 filename: \"%V\"", &path);

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = RP_MAX_OFF_T_VALUE;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (rp_http_set_disable_symlinks(r, clcf, &path, &of) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != RP_OK)
    {
        switch (of.err) {

        case 0:
            return RP_HTTP_INTERNAL_SERVER_ERROR;

        case RP_ENOENT:
        case RP_ENOTDIR:
        case RP_ENAMETOOLONG:

            level = RP_LOG_ERR;
            rc = RP_HTTP_NOT_FOUND;
            break;

        case RP_EACCES:
#if (RP_HAVE_OPENAT)
        case RP_EMLINK:
        case RP_ELOOP:
#endif

            level = RP_LOG_ERR;
            rc = RP_HTTP_FORBIDDEN;
            break;

        default:

            level = RP_LOG_CRIT;
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != RP_HTTP_NOT_FOUND || clcf->log_not_found) {
            rp_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (rp_close_file(of.fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%s\" failed", path.data);
        }

        return RP_DECLINED;
    }

    r->root_tested = !r->error_page;
    r->allow_ranges = 1;

    start = -1;
    length = 0;
    r->headers_out.content_length_n = of.size;
    mp4 = NULL;
    b = NULL;

    if (r->args.len) {

        if (rp_http_arg(r, (u_char *) "start", 5, &value) == RP_OK) {

            /*
             * A Flash player may send start value with a lot of digits
             * after dot so a custom function is used instead of rp_atofp().
             */

            start = rp_http_mp4_atofp(value.data, value.len, 3);
        }

        if (rp_http_arg(r, (u_char *) "end", 3, &value) == RP_OK) {

            end = rp_http_mp4_atofp(value.data, value.len, 3);

            if (end > 0) {
                if (start < 0) {
                    start = 0;
                }

                if (end > start) {
                    length = end - start;
                }
            }
        }
    }

    if (start >= 0) {
        r->single_range = 1;

        mp4 = rp_pcalloc(r->pool, sizeof(rp_http_mp4_file_t));
        if (mp4 == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        mp4->file.fd = of.fd;
        mp4->file.name = path;
        mp4->file.log = r->connection->log;
        mp4->end = of.size;
        mp4->start = (rp_uint_t) start;
        mp4->length = length;
        mp4->request = r;

        switch (rp_http_mp4_process(mp4)) {

        case RP_DECLINED:
            if (mp4->buffer) {
                rp_pfree(r->pool, mp4->buffer);
            }

            rp_pfree(r->pool, mp4);
            mp4 = NULL;

            break;

        case RP_OK:
            r->headers_out.content_length_n = mp4->content_length;
            break;

        default: /* RP_ERROR */
            if (mp4->buffer) {
                rp_pfree(r->pool, mp4->buffer);
            }

            rp_pfree(r->pool, mp4);

            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    log->action = "sending mp4 to client";

    if (clcf->directio <= of.size) {

        /*
         * DIRECTIO is set on transfer only
         * to allow kernel to cache "moov" atom
         */

        if (rp_directio_on(of.fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_directio_on_n " \"%s\" failed", path.data);
        }

        of.is_directio = 1;

        if (mp4) {
            mp4->file.directio = 1;
        }
    }

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.last_modified_time = of.mtime;

    if (rp_http_set_etag(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_set_content_type(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (mp4 == NULL) {
        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->file = rp_pcalloc(r->pool, sizeof(rp_file_t));
        if (b->file == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        return rc;
    }

    if (mp4) {
        return rp_http_output_filter(r, mp4->out);
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return rp_http_output_filter(r, &out);
}


static rp_int_t
rp_http_mp4_atofp(u_char *line, size_t n, size_t point)
{
    rp_int_t   value, cutoff, cutlim;
    rp_uint_t  dot;

    /* same as rp_atofp(), but allows additional digits */

    if (n == 0) {
        return RP_ERROR;
    }

    cutoff = RP_MAX_INT_T_VALUE / 10;
    cutlim = RP_MAX_INT_T_VALUE % 10;

    dot = 0;

    for (value = 0; n--; line++) {

        if (*line == '.') {
            if (dot) {
                return RP_ERROR;
            }

            dot = 1;
            continue;
        }

        if (*line < '0' || *line > '9') {
            return RP_ERROR;
        }

        if (point == 0) {
            continue;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return RP_ERROR;
        }

        value = value * 10 + (*line - '0');
        point -= dot;
    }

    while (point--) {
        if (value > cutoff) {
            return RP_ERROR;
        }

        value = value * 10;
    }

    return value;
}


static rp_int_t
rp_http_mp4_process(rp_http_mp4_file_t *mp4)
{
    off_t                  start_offset, end_offset, adjustment;
    rp_int_t              rc;
    rp_uint_t             i, j;
    rp_chain_t          **prev;
    rp_http_mp4_trak_t   *trak;
    rp_http_mp4_conf_t   *conf;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 start:%ui, length:%ui", mp4->start, mp4->length);

    conf = rp_http_get_module_loc_conf(mp4->request, rp_http_mp4_module);

    mp4->buffer_size = conf->buffer_size;

    rc = rp_http_mp4_read_atom(mp4, rp_http_mp4_atoms, mp4->end);
    if (rc != RP_OK) {
        return rc;
    }

    if (mp4->trak.nelts == 0) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 trak atoms were found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (mp4->mdat_atom.buf == NULL) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 mdat atom was found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    prev = &mp4->out;

    if (mp4->ftyp_atom.buf) {
        *prev = &mp4->ftyp_atom;
        prev = &mp4->ftyp_atom.next;
    }

    *prev = &mp4->moov_atom;
    prev = &mp4->moov_atom.next;

    if (mp4->mvhd_atom.buf) {
        mp4->moov_size += mp4->mvhd_atom_buf.last - mp4->mvhd_atom_buf.pos;
        *prev = &mp4->mvhd_atom;
        prev = &mp4->mvhd_atom.next;
    }

    start_offset = mp4->end;
    end_offset = 0;
    trak = mp4->trak.elts;

    for (i = 0; i < mp4->trak.nelts; i++) {

        if (rp_http_mp4_update_stts_atom(mp4, &trak[i]) != RP_OK) {
            return RP_ERROR;
        }

        if (rp_http_mp4_update_stss_atom(mp4, &trak[i]) != RP_OK) {
            return RP_ERROR;
        }

        rp_http_mp4_update_ctts_atom(mp4, &trak[i]);

        if (rp_http_mp4_update_stsc_atom(mp4, &trak[i]) != RP_OK) {
            return RP_ERROR;
        }

        if (rp_http_mp4_update_stsz_atom(mp4, &trak[i]) != RP_OK) {
            return RP_ERROR;
        }

        if (trak[i].out[RP_HTTP_MP4_CO64_DATA].buf) {
            if (rp_http_mp4_update_co64_atom(mp4, &trak[i]) != RP_OK) {
                return RP_ERROR;
            }

        } else {
            if (rp_http_mp4_update_stco_atom(mp4, &trak[i]) != RP_OK) {
                return RP_ERROR;
            }
        }

        rp_http_mp4_update_stbl_atom(mp4, &trak[i]);
        rp_http_mp4_update_minf_atom(mp4, &trak[i]);
        trak[i].size += trak[i].mdhd_size;
        trak[i].size += trak[i].hdlr_size;
        rp_http_mp4_update_mdia_atom(mp4, &trak[i]);
        trak[i].size += trak[i].tkhd_size;
        rp_http_mp4_update_trak_atom(mp4, &trak[i]);

        mp4->moov_size += trak[i].size;

        if (start_offset > trak[i].start_offset) {
            start_offset = trak[i].start_offset;
        }

        if (end_offset < trak[i].end_offset) {
            end_offset = trak[i].end_offset;
        }

        *prev = &trak[i].out[RP_HTTP_MP4_TRAK_ATOM];
        prev = &trak[i].out[RP_HTTP_MP4_TRAK_ATOM].next;

        for (j = 0; j < RP_HTTP_MP4_LAST_ATOM + 1; j++) {
            if (trak[i].out[j].buf) {
                *prev = &trak[i].out[j];
                prev = &trak[i].out[j].next;
            }
        }
    }

    if (end_offset < start_offset) {
        end_offset = start_offset;
    }

    mp4->moov_size += 8;

    rp_mp4_set_32value(mp4->moov_atom_header, mp4->moov_size);
    rp_mp4_set_atom_name(mp4->moov_atom_header, 'm', 'o', 'o', 'v');
    mp4->content_length += mp4->moov_size;

    *prev = &mp4->mdat_atom;

    if (start_offset > mp4->mdat_data.buf->file_last) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 mdat atom in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    adjustment = mp4->ftyp_size + mp4->moov_size
                 + rp_http_mp4_update_mdat_atom(mp4, start_offset, end_offset)
                 - start_offset;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 adjustment:%O", adjustment);

    for (i = 0; i < mp4->trak.nelts; i++) {
        if (trak[i].out[RP_HTTP_MP4_CO64_DATA].buf) {
            rp_http_mp4_adjust_co64_atom(mp4, &trak[i], adjustment);
        } else {
            rp_http_mp4_adjust_stco_atom(mp4, &trak[i], (int32_t) adjustment);
        }
    }

    return RP_OK;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
} rp_mp4_atom_header_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    size64[8];
} rp_mp4_atom_header64_t;


static rp_int_t
rp_http_mp4_read_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_atom_handler_t *atom, uint64_t atom_data_size)
{
    off_t        end;
    size_t       atom_header_size;
    u_char      *atom_header, *atom_name;
    uint64_t     atom_size;
    rp_int_t    rc;
    rp_uint_t   n;

    end = mp4->offset + atom_data_size;

    while (mp4->offset < end) {

        if (rp_http_mp4_read(mp4, sizeof(uint32_t)) != RP_OK) {
            return RP_ERROR;
        }

        atom_header = mp4->buffer_pos;
        atom_size = rp_mp4_get_32value(atom_header);
        atom_header_size = sizeof(rp_mp4_atom_header_t);

        if (atom_size == 0) {
            rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "mp4 atom end");
            return RP_OK;
        }

        if (atom_size < sizeof(rp_mp4_atom_header_t)) {

            if (atom_size == 1) {

                if (rp_http_mp4_read(mp4, sizeof(rp_mp4_atom_header64_t))
                    != RP_OK)
                {
                    return RP_ERROR;
                }

                /* 64-bit atom size */
                atom_header = mp4->buffer_pos;
                atom_size = rp_mp4_get_64value(atom_header + 8);
                atom_header_size = sizeof(rp_mp4_atom_header64_t);

                if (atom_size < sizeof(rp_mp4_atom_header64_t)) {
                    rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                                  "\"%s\" mp4 atom is too small:%uL",
                                  mp4->file.name.data, atom_size);
                    return RP_ERROR;
                }

            } else {
                rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                              "\"%s\" mp4 atom is too small:%uL",
                              mp4->file.name.data, atom_size);
                return RP_ERROR;
            }
        }

        if (rp_http_mp4_read(mp4, sizeof(rp_mp4_atom_header_t)) != RP_OK) {
            return RP_ERROR;
        }

        atom_header = mp4->buffer_pos;
        atom_name = atom_header + sizeof(uint32_t);

        rp_log_debug4(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 atom: %*s @%O:%uL",
                       (size_t) 4, atom_name, mp4->offset, atom_size);

        if (atom_size > (uint64_t) (RP_MAX_OFF_T_VALUE - mp4->offset)
            || mp4->offset + (off_t) atom_size > end)
        {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 atom too large:%uL",
                          mp4->file.name.data, atom_size);
            return RP_ERROR;
        }

        for (n = 0; atom[n].name; n++) {

            if (rp_strncmp(atom_name, atom[n].name, 4) == 0) {

                rp_mp4_atom_next(mp4, atom_header_size);

                rc = atom[n].handler(mp4, atom_size - atom_header_size);
                if (rc != RP_OK) {
                    return rc;
                }

                goto next;
            }
        }

        rp_mp4_atom_next(mp4, atom_size);

    next:
        continue;
    }

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read(rp_http_mp4_file_t *mp4, size_t size)
{
    ssize_t  n;

    if (mp4->buffer_pos + size <= mp4->buffer_end) {
        return RP_OK;
    }

    if (mp4->offset + (off_t) mp4->buffer_size > mp4->end) {
        mp4->buffer_size = (size_t) (mp4->end - mp4->offset);
    }

    if (mp4->buffer_size < size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 file truncated", mp4->file.name.data);
        return RP_ERROR;
    }

    if (mp4->buffer == NULL) {
        mp4->buffer = rp_palloc(mp4->request->pool, mp4->buffer_size);
        if (mp4->buffer == NULL) {
            return RP_ERROR;
        }

        mp4->buffer_start = mp4->buffer;
    }

    n = rp_read_file(&mp4->file, mp4->buffer_start, mp4->buffer_size,
                      mp4->offset);

    if (n == RP_ERROR) {
        return RP_ERROR;
    }

    if ((size_t) n != mp4->buffer_size) {
        rp_log_error(RP_LOG_CRIT, mp4->file.log, 0,
                      rp_read_file_n " read only %z of %z from \"%s\"",
                      n, mp4->buffer_size, mp4->file.name.data);
        return RP_ERROR;
    }

    mp4->buffer_pos = mp4->buffer_start;
    mp4->buffer_end = mp4->buffer_start + mp4->buffer_size;

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_ftyp_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char     *ftyp_atom;
    size_t      atom_size;
    rp_buf_t  *atom;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ftyp atom");

    if (atom_data_size > 1024
        || rp_mp4_atom_data(mp4) + (size_t) atom_data_size > mp4->buffer_end)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ftyp atom is too large:%uL",
                      mp4->file.name.data, atom_data_size);
        return RP_ERROR;
    }

    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;

    ftyp_atom = rp_palloc(mp4->request->pool, atom_size);
    if (ftyp_atom == NULL) {
        return RP_ERROR;
    }

    rp_mp4_set_32value(ftyp_atom, atom_size);
    rp_mp4_set_atom_name(ftyp_atom, 'f', 't', 'y', 'p');

    /*
     * only moov atom content is guaranteed to be in mp4->buffer
     * during sending response, so ftyp atom content should be copied
     */
    rp_memcpy(ftyp_atom + sizeof(rp_mp4_atom_header_t),
               rp_mp4_atom_data(mp4), (size_t) atom_data_size);

    atom = &mp4->ftyp_atom_buf;
    atom->temporary = 1;
    atom->pos = ftyp_atom;
    atom->last = ftyp_atom + atom_size;

    mp4->ftyp_atom.buf = atom;
    mp4->ftyp_size = atom_size;
    mp4->content_length = atom_size;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


/*
 * Small excess buffer to process atoms after moov atom, mp4->buffer_start
 * will be set to this buffer part after moov atom processing.
 */
#define RP_HTTP_MP4_MOOV_BUFFER_EXCESS  (4 * 1024)

static rp_int_t
rp_http_mp4_read_moov_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    rp_int_t             rc;
    rp_uint_t            no_mdat;
    rp_buf_t            *atom;
    rp_http_mp4_conf_t  *conf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom");

    no_mdat = (mp4->mdat_atom.buf == NULL);

    if (no_mdat && mp4->start == 0 && mp4->length == 0) {
        /*
         * send original file if moov atom resides before
         * mdat atom and client requests integral file
         */
        return RP_DECLINED;
    }

    conf = rp_http_get_module_loc_conf(mp4->request, rp_http_mp4_module);

    if (atom_data_size > mp4->buffer_size) {

        if (atom_data_size > conf->max_buffer_size) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 moov atom is too large:%uL, "
                          "you may want to increase mp4_max_buffer_size",
                          mp4->file.name.data, atom_data_size);
            return RP_ERROR;
        }

        rp_pfree(mp4->request->pool, mp4->buffer);
        mp4->buffer = NULL;
        mp4->buffer_pos = NULL;
        mp4->buffer_end = NULL;

        mp4->buffer_size = (size_t) atom_data_size
                         + RP_HTTP_MP4_MOOV_BUFFER_EXCESS * no_mdat;
    }

    if (rp_http_mp4_read(mp4, (size_t) atom_data_size) != RP_OK) {
        return RP_ERROR;
    }

    mp4->trak.elts = &mp4->traks;
    mp4->trak.size = sizeof(rp_http_mp4_trak_t);
    mp4->trak.nalloc = 2;
    mp4->trak.pool = mp4->request->pool;

    atom = &mp4->moov_atom_buf;
    atom->temporary = 1;
    atom->pos = mp4->moov_atom_header;
    atom->last = mp4->moov_atom_header + 8;

    mp4->moov_atom.buf = &mp4->moov_atom_buf;

    rc = rp_http_mp4_read_atom(mp4, rp_http_mp4_moov_atoms, atom_data_size);

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom done");

    if (no_mdat) {
        mp4->buffer_start = mp4->buffer_pos;
        mp4->buffer_size = RP_HTTP_MP4_MOOV_BUFFER_EXCESS;

        if (mp4->buffer_start + mp4->buffer_size > mp4->buffer_end) {
            mp4->buffer = NULL;
            mp4->buffer_pos = NULL;
            mp4->buffer_end = NULL;
        }

    } else {
        /* skip atoms after moov atom */
        mp4->offset = mp4->end;
    }

    return rc;
}


static rp_int_t
rp_http_mp4_read_mdat_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    rp_buf_t  *data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdat atom");

    data = &mp4->mdat_data_buf;
    data->file = &mp4->file;
    data->in_file = 1;
    data->last_buf = (mp4->request == mp4->request->main) ? 1 : 0;
    data->last_in_chain = 1;
    data->file_last = mp4->offset + atom_data_size;

    mp4->mdat_atom.buf = &mp4->mdat_atom_buf;
    mp4->mdat_atom.next = &mp4->mdat_data;
    mp4->mdat_data.buf = data;

    if (mp4->trak.nelts) {
        /* skip atoms after mdat atom */
        mp4->offset = mp4->end;

    } else {
        rp_mp4_atom_next(mp4, atom_data_size);
    }

    return RP_OK;
}


static size_t
rp_http_mp4_update_mdat_atom(rp_http_mp4_file_t *mp4, off_t start_offset,
    off_t end_offset)
{
    off_t       atom_data_size;
    u_char     *atom_header;
    uint32_t    atom_header_size;
    uint64_t    atom_size;
    rp_buf_t  *atom;

    atom_data_size = end_offset - start_offset;
    mp4->mdat_data.buf->file_pos = start_offset;
    mp4->mdat_data.buf->file_last = end_offset;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdat new offset @%O:%O", start_offset, atom_data_size);

    atom_header = mp4->mdat_atom_header;

    if ((uint64_t) atom_data_size
        > (uint64_t) 0xffffffff - sizeof(rp_mp4_atom_header_t))
    {
        atom_size = 1;
        atom_header_size = sizeof(rp_mp4_atom_header64_t);
        rp_mp4_set_64value(atom_header + sizeof(rp_mp4_atom_header_t),
                            sizeof(rp_mp4_atom_header64_t) + atom_data_size);
    } else {
        atom_size = sizeof(rp_mp4_atom_header_t) + atom_data_size;
        atom_header_size = sizeof(rp_mp4_atom_header_t);
    }

    mp4->content_length += atom_header_size + atom_data_size;

    rp_mp4_set_32value(atom_header, atom_size);
    rp_mp4_set_atom_name(atom_header, 'm', 'd', 'a', 't');

    atom = &mp4->mdat_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_header_size;

    return atom_header_size;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    timescale[4];
    u_char    duration[4];
    u_char    rate[4];
    u_char    volume[2];
    u_char    reserved[10];
    u_char    matrix[36];
    u_char    preview_time[4];
    u_char    preview_duration[4];
    u_char    poster_time[4];
    u_char    selection_time[4];
    u_char    selection_duration[4];
    u_char    current_time[4];
    u_char    next_track_id[4];
} rp_mp4_mvhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    timescale[4];
    u_char    duration[8];
    u_char    rate[4];
    u_char    volume[2];
    u_char    reserved[10];
    u_char    matrix[36];
    u_char    preview_time[4];
    u_char    preview_duration[4];
    u_char    poster_time[4];
    u_char    selection_time[4];
    u_char    selection_duration[4];
    u_char    current_time[4];
    u_char    next_track_id[4];
} rp_mp4_mvhd64_atom_t;


static rp_int_t
rp_http_mp4_read_mvhd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint32_t                timescale;
    uint64_t                duration, start_time, length_time;
    rp_buf_t              *atom;
    rp_mp4_mvhd_atom_t    *mvhd_atom;
    rp_mp4_mvhd64_atom_t  *mvhd64_atom;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mvhd atom");

    atom_header = rp_mp4_atom_header(mp4);
    mvhd_atom = (rp_mp4_mvhd_atom_t *) atom_header;
    mvhd64_atom = (rp_mp4_mvhd64_atom_t *) atom_header;
    rp_mp4_set_atom_name(atom_header, 'm', 'v', 'h', 'd');

    if (rp_mp4_atom_data_size(rp_mp4_mvhd_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 mvhd atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    if (mvhd_atom->version[0] == 0) {
        /* version 0: 32-bit duration */
        timescale = rp_mp4_get_32value(mvhd_atom->timescale);
        duration = rp_mp4_get_32value(mvhd_atom->duration);

    } else {
        /* version 1: 64-bit duration */

        if (rp_mp4_atom_data_size(rp_mp4_mvhd64_atom_t) > atom_data_size) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 mvhd atom too small",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        timescale = rp_mp4_get_32value(mvhd64_atom->timescale);
        duration = rp_mp4_get_64value(mvhd64_atom->duration);
    }

    mp4->timescale = timescale;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mvhd timescale:%uD, duration:%uL, time:%.3fs",
                   timescale, duration, (double) duration / timescale);

    start_time = (uint64_t) mp4->start * timescale / 1000;

    if (duration < start_time) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 start time exceeds file duration",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mvhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / timescale);

    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    rp_mp4_set_32value(mvhd_atom->size, atom_size);

    if (mvhd_atom->version[0] == 0) {
        rp_mp4_set_32value(mvhd_atom->duration, duration);

    } else {
        rp_mp4_set_64value(mvhd64_atom->duration, duration);
    }

    atom = &mp4->mvhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    mp4->mvhd_atom.buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_trak_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_end;
    off_t                 atom_file_end;
    rp_int_t             rc;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 trak atom");

    trak = rp_array_push(&mp4->trak);
    if (trak == NULL) {
        return RP_ERROR;
    }

    rp_memzero(trak, sizeof(rp_http_mp4_trak_t));

    atom_header = rp_mp4_atom_header(mp4);
    rp_mp4_set_atom_name(atom_header, 't', 'r', 'a', 'k');

    atom = &trak->trak_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(rp_mp4_atom_header_t);

    trak->out[RP_HTTP_MP4_TRAK_ATOM].buf = atom;

    atom_end = mp4->buffer_pos + (size_t) atom_data_size;
    atom_file_end = mp4->offset + atom_data_size;

    rc = rp_http_mp4_read_atom(mp4, rp_http_mp4_trak_atoms, atom_data_size);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 trak atom: %i", rc);

    if (rc == RP_DECLINED) {
        /* skip this trak */
        rp_memzero(trak, sizeof(rp_http_mp4_trak_t));
        mp4->trak.nelts--;
        mp4->buffer_pos = atom_end;
        mp4->offset = atom_file_end;
        return RP_OK;
    }

    return rc;
}


static void
rp_http_mp4_update_trak_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    rp_buf_t  *atom;

    trak->size += sizeof(rp_mp4_atom_header_t);
    atom = &trak->trak_atom_buf;
    rp_mp4_set_32value(atom->pos, trak->size);
}


static rp_int_t
rp_http_mp4_read_cmov_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                  "\"%s\" mp4 compressed moov atom (cmov) is not supported",
                  mp4->file.name.data);

    return RP_ERROR;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    track_id[4];
    u_char    reserved1[4];
    u_char    duration[4];
    u_char    reserved2[8];
    u_char    layer[2];
    u_char    group[2];
    u_char    volume[2];
    u_char    reserved3[2];
    u_char    matrix[36];
    u_char    width[4];
    u_char    height[4];
} rp_mp4_tkhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    track_id[4];
    u_char    reserved1[4];
    u_char    duration[8];
    u_char    reserved2[8];
    u_char    layer[2];
    u_char    group[2];
    u_char    volume[2];
    u_char    reserved3[2];
    u_char    matrix[36];
    u_char    width[4];
    u_char    height[4];
} rp_mp4_tkhd64_atom_t;


static rp_int_t
rp_http_mp4_read_tkhd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint64_t                duration, start_time, length_time;
    rp_buf_t              *atom;
    rp_http_mp4_trak_t    *trak;
    rp_mp4_tkhd_atom_t    *tkhd_atom;
    rp_mp4_tkhd64_atom_t  *tkhd64_atom;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 tkhd atom");

    atom_header = rp_mp4_atom_header(mp4);
    tkhd_atom = (rp_mp4_tkhd_atom_t *) atom_header;
    tkhd64_atom = (rp_mp4_tkhd64_atom_t *) atom_header;
    rp_mp4_set_atom_name(tkhd_atom, 't', 'k', 'h', 'd');

    if (rp_mp4_atom_data_size(rp_mp4_tkhd_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 tkhd atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    if (tkhd_atom->version[0] == 0) {
        /* version 0: 32-bit duration */
        duration = rp_mp4_get_32value(tkhd_atom->duration);

    } else {
        /* version 1: 64-bit duration */

        if (rp_mp4_atom_data_size(rp_mp4_tkhd64_atom_t) > atom_data_size) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 tkhd atom too small",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        duration = rp_mp4_get_64value(tkhd64_atom->duration);
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "tkhd duration:%uL, time:%.3fs",
                   duration, (double) duration / mp4->timescale);

    start_time = (uint64_t) mp4->start * mp4->timescale / 1000;

    if (duration <= start_time) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "tkhd duration is less than start time");
        return RP_DECLINED;
    }

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * mp4->timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "tkhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / mp4->timescale);

    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;

    trak = rp_mp4_last_trak(mp4);
    trak->tkhd_size = atom_size;

    rp_mp4_set_32value(tkhd_atom->size, atom_size);

    if (tkhd_atom->version[0] == 0) {
        rp_mp4_set_32value(tkhd_atom->duration, duration);

    } else {
        rp_mp4_set_64value(tkhd64_atom->duration, duration);
    }

    atom = &trak->tkhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->out[RP_HTTP_MP4_TKHD_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_mdia_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "process mdia atom");

    atom_header = rp_mp4_atom_header(mp4);
    rp_mp4_set_atom_name(atom_header, 'm', 'd', 'i', 'a');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->mdia_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(rp_mp4_atom_header_t);

    trak->out[RP_HTTP_MP4_MDIA_ATOM].buf = atom;

    return rp_http_mp4_read_atom(mp4, rp_http_mp4_mdia_atoms, atom_data_size);
}


static void
rp_http_mp4_update_mdia_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    rp_buf_t  *atom;

    trak->size += sizeof(rp_mp4_atom_header_t);
    atom = &trak->mdia_atom_buf;
    rp_mp4_set_32value(atom->pos, trak->size);
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[4];
    u_char    modification_time[4];
    u_char    timescale[4];
    u_char    duration[4];
    u_char    language[2];
    u_char    quality[2];
} rp_mp4_mdhd_atom_t;

typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    creation_time[8];
    u_char    modification_time[8];
    u_char    timescale[4];
    u_char    duration[8];
    u_char    language[2];
    u_char    quality[2];
} rp_mp4_mdhd64_atom_t;


static rp_int_t
rp_http_mp4_read_mdhd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                 *atom_header;
    size_t                  atom_size;
    uint32_t                timescale;
    uint64_t                duration, start_time, length_time;
    rp_buf_t              *atom;
    rp_http_mp4_trak_t    *trak;
    rp_mp4_mdhd_atom_t    *mdhd_atom;
    rp_mp4_mdhd64_atom_t  *mdhd64_atom;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdhd atom");

    atom_header = rp_mp4_atom_header(mp4);
    mdhd_atom = (rp_mp4_mdhd_atom_t *) atom_header;
    mdhd64_atom = (rp_mp4_mdhd64_atom_t *) atom_header;
    rp_mp4_set_atom_name(mdhd_atom, 'm', 'd', 'h', 'd');

    if (rp_mp4_atom_data_size(rp_mp4_mdhd_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 mdhd atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    if (mdhd_atom->version[0] == 0) {
        /* version 0: everything is 32-bit */
        timescale = rp_mp4_get_32value(mdhd_atom->timescale);
        duration = rp_mp4_get_32value(mdhd_atom->duration);

    } else {
        /* version 1: 64-bit duration and 32-bit timescale */

        if (rp_mp4_atom_data_size(rp_mp4_mdhd64_atom_t) > atom_data_size) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 mdhd atom too small",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        timescale = rp_mp4_get_32value(mdhd64_atom->timescale);
        duration = rp_mp4_get_64value(mdhd64_atom->duration);
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdhd timescale:%uD, duration:%uL, time:%.3fs",
                   timescale, duration, (double) duration / timescale);

    start_time = (uint64_t) mp4->start * timescale / 1000;

    if (duration <= start_time) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mdhd duration is less than start time");
        return RP_DECLINED;
    }

    duration -= start_time;

    if (mp4->length) {
        length_time = (uint64_t) mp4->length * timescale / 1000;

        if (duration > length_time) {
            duration = length_time;
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mdhd new duration:%uL, time:%.3fs",
                   duration, (double) duration / timescale);

    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;

    trak = rp_mp4_last_trak(mp4);
    trak->mdhd_size = atom_size;
    trak->timescale = timescale;

    rp_mp4_set_32value(mdhd_atom->size, atom_size);

    if (mdhd_atom->version[0] == 0) {
        rp_mp4_set_32value(mdhd_atom->duration, duration);

    } else {
        rp_mp4_set_64value(mdhd64_atom->duration, duration);
    }

    atom = &trak->mdhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->out[RP_HTTP_MP4_MDHD_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_hdlr_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 hdlr atom");

    atom_header = rp_mp4_atom_header(mp4);
    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    rp_mp4_set_32value(atom_header, atom_size);
    rp_mp4_set_atom_name(atom_header, 'h', 'd', 'l', 'r');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->hdlr_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->hdlr_size = atom_size;
    trak->out[RP_HTTP_MP4_HDLR_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_minf_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "process minf atom");

    atom_header = rp_mp4_atom_header(mp4);
    rp_mp4_set_atom_name(atom_header, 'm', 'i', 'n', 'f');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->minf_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(rp_mp4_atom_header_t);

    trak->out[RP_HTTP_MP4_MINF_ATOM].buf = atom;

    return rp_http_mp4_read_atom(mp4, rp_http_mp4_minf_atoms, atom_data_size);
}


static void
rp_http_mp4_update_minf_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    rp_buf_t  *atom;

    trak->size += sizeof(rp_mp4_atom_header_t)
               + trak->vmhd_size
               + trak->smhd_size
               + trak->dinf_size;
    atom = &trak->minf_atom_buf;
    rp_mp4_set_32value(atom->pos, trak->size);
}


static rp_int_t
rp_http_mp4_read_vmhd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 vmhd atom");

    atom_header = rp_mp4_atom_header(mp4);
    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    rp_mp4_set_32value(atom_header, atom_size);
    rp_mp4_set_atom_name(atom_header, 'v', 'm', 'h', 'd');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->vmhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->vmhd_size += atom_size;
    trak->out[RP_HTTP_MP4_VMHD_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_smhd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 smhd atom");

    atom_header = rp_mp4_atom_header(mp4);
    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    rp_mp4_set_32value(atom_header, atom_size);
    rp_mp4_set_atom_name(atom_header, 's', 'm', 'h', 'd');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->smhd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->smhd_size += atom_size;
    trak->out[RP_HTTP_MP4_SMHD_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_dinf_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char              *atom_header;
    size_t               atom_size;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 dinf atom");

    atom_header = rp_mp4_atom_header(mp4);
    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    rp_mp4_set_32value(atom_header, atom_size);
    rp_mp4_set_atom_name(atom_header, 'd', 'i', 'n', 'f');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->dinf_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + atom_size;

    trak->dinf_size += atom_size;
    trak->out[RP_HTTP_MP4_DINF_ATOM].buf = atom;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_read_stbl_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header;
    rp_buf_t            *atom;
    rp_http_mp4_trak_t  *trak;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "process stbl atom");

    atom_header = rp_mp4_atom_header(mp4);
    rp_mp4_set_atom_name(atom_header, 's', 't', 'b', 'l');

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->stbl_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_header + sizeof(rp_mp4_atom_header_t);

    trak->out[RP_HTTP_MP4_STBL_ATOM].buf = atom;

    return rp_http_mp4_read_atom(mp4, rp_http_mp4_stbl_atoms, atom_data_size);
}


static void
rp_http_mp4_update_stbl_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    rp_buf_t  *atom;

    trak->size += sizeof(rp_mp4_atom_header_t);
    atom = &trak->stbl_atom_buf;
    rp_mp4_set_32value(atom->pos, trak->size);
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];

    u_char    media_size[4];
    u_char    media_name[4];
} rp_mp4_stsd_atom_t;


static rp_int_t
rp_http_mp4_read_stsd_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table;
    size_t                atom_size;
    rp_buf_t            *atom;
    rp_mp4_stsd_atom_t  *stsd_atom;
    rp_http_mp4_trak_t  *trak;

    /* sample description atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsd atom");

    atom_header = rp_mp4_atom_header(mp4);
    stsd_atom = (rp_mp4_stsd_atom_t *) atom_header;
    atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
    atom_table = atom_header + atom_size;
    rp_mp4_set_32value(stsd_atom->size, atom_size);
    rp_mp4_set_atom_name(stsd_atom, 's', 't', 's', 'd');

    if (rp_mp4_atom_data_size(rp_mp4_stsd_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsd atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "stsd entries:%uD, media:%*s",
                   rp_mp4_get_32value(stsd_atom->entries),
                   (size_t) 4, stsd_atom->media_name);

    trak = rp_mp4_last_trak(mp4);

    atom = &trak->stsd_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    trak->out[RP_HTTP_MP4_STSD_ATOM].buf = atom;
    trak->size += atom_size;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_mp4_stts_atom_t;

typedef struct {
    u_char    count[4];
    u_char    duration[4];
} rp_mp4_stts_entry_t;


static rp_int_t
rp_http_mp4_read_stts_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    rp_buf_t            *atom, *data;
    rp_mp4_stts_atom_t  *stts_atom;
    rp_http_mp4_trak_t  *trak;

    /* time-to-sample atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stts atom");

    atom_header = rp_mp4_atom_header(mp4);
    stts_atom = (rp_mp4_stts_atom_t *) atom_header;
    rp_mp4_set_atom_name(stts_atom, 's', 't', 't', 's');

    if (rp_mp4_atom_data_size(rp_mp4_stts_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stts atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(stts_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 time-to-sample entries:%uD", entries);

    if (rp_mp4_atom_data_size(rp_mp4_stts_atom_t)
        + entries * sizeof(rp_mp4_stts_entry_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stts atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_table = atom_header + sizeof(rp_mp4_stts_atom_t);
    atom_end = atom_table + entries * sizeof(rp_mp4_stts_entry_t);

    trak = rp_mp4_last_trak(mp4);
    trak->time_to_sample_entries = entries;

    atom = &trak->stts_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stts_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_STTS_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_STTS_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_stts_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                atom_size;
    rp_buf_t            *atom, *data;
    rp_mp4_stts_atom_t  *stts_atom;

    /*
     * mdia.minf.stbl.stts updating requires trak->timescale
     * from mdia.mdhd atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stts atom update");

    data = trak->out[RP_HTTP_MP4_STTS_DATA].buf;

    if (data == NULL) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stts atoms were found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (rp_http_mp4_crop_stts_data(mp4, trak, 1) != RP_OK) {
        return RP_ERROR;
    }

    if (rp_http_mp4_crop_stts_data(mp4, trak, 0) != RP_OK) {
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "time-to-sample entries:%uD", trak->time_to_sample_entries);

    atom_size = sizeof(rp_mp4_stts_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_STTS_ATOM].buf;
    stts_atom = (rp_mp4_stts_atom_t *) atom->pos;
    rp_mp4_set_32value(stts_atom->size, atom_size);
    rp_mp4_set_32value(stts_atom->entries, trak->time_to_sample_entries);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_crop_stts_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start)
{
    uint32_t               count, duration, rest;
    uint64_t               start_time;
    rp_buf_t             *data;
    rp_uint_t             start_sample, entries, start_sec;
    rp_mp4_stts_entry_t  *entry, *end;

    if (start) {
        start_sec = mp4->start;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stts crop start_time:%ui", start_sec);

    } else if (mp4->length) {
        start_sec = mp4->length;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stts crop end_time:%ui", start_sec);

    } else {
        return RP_OK;
    }

    data = trak->out[RP_HTTP_MP4_STTS_DATA].buf;

    start_time = (uint64_t) start_sec * trak->timescale / 1000;

    entries = trak->time_to_sample_entries;
    start_sample = 0;
    entry = (rp_mp4_stts_entry_t *) data->pos;
    end = (rp_mp4_stts_entry_t *) data->last;

    while (entry < end) {
        count = rp_mp4_get_32value(entry->count);
        duration = rp_mp4_get_32value(entry->duration);

        rp_log_debug3(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "time:%uL, count:%uD, duration:%uD",
                       start_time, count, duration);

        if (start_time < (uint64_t) count * duration) {
            start_sample += (rp_uint_t) (start_time / duration);
            rest = (uint32_t) (start_time / duration);
            goto found;
        }

        start_sample += count;
        start_time -= count * duration;
        entries--;
        entry++;
    }

    if (start) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 stts samples in \"%s\"",
                      mp4->file.name.data);

        return RP_ERROR;

    } else {
        trak->end_sample = trak->start_sample + start_sample;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_sample:%ui", trak->end_sample);

        return RP_OK;
    }

found:

    if (start) {
        rp_mp4_set_32value(entry->count, count - rest);
        data->pos = (u_char *) entry;
        trak->time_to_sample_entries = entries;
        trak->start_sample = start_sample;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "start_sample:%ui, new count:%uD",
                       trak->start_sample, count - rest);

    } else {
        rp_mp4_set_32value(entry->count, rest);
        data->last = (u_char *) (entry + 1);
        trak->time_to_sample_entries -= entries - 1;
        trak->end_sample = trak->start_sample + start_sample;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_sample:%ui, new count:%uD",
                       trak->end_sample, rest);
    }

    return RP_OK;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_http_mp4_stss_atom_t;


static rp_int_t
rp_http_mp4_read_stss_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char                    *atom_header, *atom_table, *atom_end;
    uint32_t                   entries;
    rp_buf_t                 *atom, *data;
    rp_http_mp4_trak_t       *trak;
    rp_http_mp4_stss_atom_t  *stss_atom;

    /* sync samples atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stss atom");

    atom_header = rp_mp4_atom_header(mp4);
    stss_atom = (rp_http_mp4_stss_atom_t *) atom_header;
    rp_mp4_set_atom_name(stss_atom, 's', 't', 's', 's');

    if (rp_mp4_atom_data_size(rp_http_mp4_stss_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stss atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(stss_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sync sample entries:%uD", entries);

    trak = rp_mp4_last_trak(mp4);
    trak->sync_samples_entries = entries;

    atom_table = atom_header + sizeof(rp_http_mp4_stss_atom_t);

    atom = &trak->stss_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    if (rp_mp4_atom_data_size(rp_http_mp4_stss_atom_t)
        + entries * sizeof(uint32_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stss atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_end = atom_table + entries * sizeof(uint32_t);

    data = &trak->stss_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_STSS_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_STSS_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_stss_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                     atom_size;
    uint32_t                   sample, start_sample, *entry, *end;
    rp_buf_t                 *atom, *data;
    rp_http_mp4_stss_atom_t  *stss_atom;

    /*
     * mdia.minf.stbl.stss updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stss atom update");

    data = trak->out[RP_HTTP_MP4_STSS_DATA].buf;

    if (data == NULL) {
        return RP_OK;
    }

    rp_http_mp4_crop_stss_data(mp4, trak, 1);
    rp_http_mp4_crop_stss_data(mp4, trak, 0);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sync sample entries:%uD", trak->sync_samples_entries);

    if (trak->sync_samples_entries) {
        entry = (uint32_t *) data->pos;
        end = (uint32_t *) data->last;

        start_sample = trak->start_sample;

        while (entry < end) {
            sample = rp_mp4_get_32value(entry);
            sample -= start_sample;
            rp_mp4_set_32value(entry, sample);
            entry++;
        }

    } else {
        trak->out[RP_HTTP_MP4_STSS_DATA].buf = NULL;
    }

    atom_size = sizeof(rp_http_mp4_stss_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_STSS_ATOM].buf;
    stss_atom = (rp_http_mp4_stss_atom_t *) atom->pos;

    rp_mp4_set_32value(stss_atom->size, atom_size);
    rp_mp4_set_32value(stss_atom->entries, trak->sync_samples_entries);

    return RP_OK;
}


static void
rp_http_mp4_crop_stss_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start)
{
    uint32_t     sample, start_sample, *entry, *end;
    rp_buf_t   *data;
    rp_uint_t   entries;

    /* sync samples starts from 1 */

    if (start) {
        start_sample = trak->start_sample + 1;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stss crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = trak->end_sample + 1;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stss crop end_sample:%uD", start_sample);

    } else {
        return;
    }

    data = trak->out[RP_HTTP_MP4_STSS_DATA].buf;

    entries = trak->sync_samples_entries;
    entry = (uint32_t *) data->pos;
    end = (uint32_t *) data->last;

    while (entry < end) {
        sample = rp_mp4_get_32value(entry);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sync:%uD", sample);

        if (sample >= start_sample) {
            goto found;
        }

        entries--;
        entry++;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample is out of mp4 stss atom");

found:

    if (start) {
        data->pos = (u_char *) entry;
        trak->sync_samples_entries = entries;

    } else {
        data->last = (u_char *) entry;
        trak->sync_samples_entries -= entries;
    }
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_mp4_ctts_atom_t;

typedef struct {
    u_char    count[4];
    u_char    offset[4];
} rp_mp4_ctts_entry_t;


static rp_int_t
rp_http_mp4_read_ctts_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    rp_buf_t            *atom, *data;
    rp_mp4_ctts_atom_t  *ctts_atom;
    rp_http_mp4_trak_t  *trak;

    /* composition offsets atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ctts atom");

    atom_header = rp_mp4_atom_header(mp4);
    ctts_atom = (rp_mp4_ctts_atom_t *) atom_header;
    rp_mp4_set_atom_name(ctts_atom, 'c', 't', 't', 's');

    if (rp_mp4_atom_data_size(rp_mp4_ctts_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(ctts_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "composition offset entries:%uD", entries);

    trak = rp_mp4_last_trak(mp4);
    trak->composition_offset_entries = entries;

    atom_table = atom_header + sizeof(rp_mp4_ctts_atom_t);

    atom = &trak->ctts_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    if (rp_mp4_atom_data_size(rp_mp4_ctts_atom_t)
        + entries * sizeof(rp_mp4_ctts_entry_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_end = atom_table + entries * sizeof(rp_mp4_ctts_entry_t);

    data = &trak->ctts_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_CTTS_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_CTTS_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static void
rp_http_mp4_update_ctts_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                atom_size;
    rp_buf_t            *atom, *data;
    rp_mp4_ctts_atom_t  *ctts_atom;

    /*
     * mdia.minf.stbl.ctts updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 ctts atom update");

    data = trak->out[RP_HTTP_MP4_CTTS_DATA].buf;

    if (data == NULL) {
        return;
    }

    rp_http_mp4_crop_ctts_data(mp4, trak, 1);
    rp_http_mp4_crop_ctts_data(mp4, trak, 0);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "composition offset entries:%uD",
                   trak->composition_offset_entries);

    if (trak->composition_offset_entries == 0) {
        trak->out[RP_HTTP_MP4_CTTS_ATOM].buf = NULL;
        trak->out[RP_HTTP_MP4_CTTS_DATA].buf = NULL;
        return;
    }

    atom_size = sizeof(rp_mp4_ctts_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_CTTS_ATOM].buf;
    ctts_atom = (rp_mp4_ctts_atom_t *) atom->pos;

    rp_mp4_set_32value(ctts_atom->size, atom_size);
    rp_mp4_set_32value(ctts_atom->entries, trak->composition_offset_entries);

    return;
}


static void
rp_http_mp4_crop_ctts_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start)
{
    uint32_t               count, start_sample, rest;
    rp_buf_t             *data;
    rp_uint_t             entries;
    rp_mp4_ctts_entry_t  *entry, *end;

    /* sync samples starts from 1 */

    if (start) {
        start_sample = trak->start_sample + 1;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 ctts crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = trak->end_sample - trak->start_sample + 1;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 ctts crop end_sample:%uD", start_sample);

    } else {
        return;
    }

    data = trak->out[RP_HTTP_MP4_CTTS_DATA].buf;

    entries = trak->composition_offset_entries;
    entry = (rp_mp4_ctts_entry_t *) data->pos;
    end = (rp_mp4_ctts_entry_t *) data->last;

    while (entry < end) {
        count = rp_mp4_get_32value(entry->count);

        rp_log_debug3(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sample:%uD, count:%uD, offset:%uD",
                       start_sample, count, rp_mp4_get_32value(entry->offset));

        if (start_sample <= count) {
            rest = start_sample - 1;
            goto found;
        }

        start_sample -= count;
        entries--;
        entry++;
    }

    if (start) {
        data->pos = (u_char *) end;
        trak->composition_offset_entries = 0;
    }

    return;

found:

    if (start) {
        rp_mp4_set_32value(entry->count, count - rest);
        data->pos = (u_char *) entry;
        trak->composition_offset_entries = entries;

    } else {
        rp_mp4_set_32value(entry->count, rest);
        data->last = (u_char *) (entry + 1);
        trak->composition_offset_entries -= entries - 1;
    }
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_mp4_stsc_atom_t;


static rp_int_t
rp_http_mp4_read_stsc_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    rp_buf_t            *atom, *data;
    rp_mp4_stsc_atom_t  *stsc_atom;
    rp_http_mp4_trak_t  *trak;

    /* sample-to-chunk atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsc atom");

    atom_header = rp_mp4_atom_header(mp4);
    stsc_atom = (rp_mp4_stsc_atom_t *) atom_header;
    rp_mp4_set_atom_name(stsc_atom, 's', 't', 's', 'c');

    if (rp_mp4_atom_data_size(rp_mp4_stsc_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(stsc_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample-to-chunk entries:%uD", entries);

    if (rp_mp4_atom_data_size(rp_mp4_stsc_atom_t)
        + entries * sizeof(rp_mp4_stsc_entry_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_table = atom_header + sizeof(rp_mp4_stsc_atom_t);
    atom_end = atom_table + entries * sizeof(rp_mp4_stsc_entry_t);

    trak = rp_mp4_last_trak(mp4);
    trak->sample_to_chunk_entries = entries;

    atom = &trak->stsc_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stsc_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_STSC_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_STSC_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_stsc_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                 atom_size;
    uint32_t               chunk;
    rp_buf_t             *atom, *data;
    rp_mp4_stsc_atom_t   *stsc_atom;
    rp_mp4_stsc_entry_t  *entry, *end;

    /*
     * mdia.minf.stbl.stsc updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stsc atom update");

    data = trak->out[RP_HTTP_MP4_STSC_DATA].buf;

    if (data == NULL) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stsc atoms were found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (trak->sample_to_chunk_entries == 0) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "zero number of entries in stsc atom in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (rp_http_mp4_crop_stsc_data(mp4, trak, 1) != RP_OK) {
        return RP_ERROR;
    }

    if (rp_http_mp4_crop_stsc_data(mp4, trak, 0) != RP_OK) {
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample-to-chunk entries:%uD",
                   trak->sample_to_chunk_entries);

    entry = (rp_mp4_stsc_entry_t *) data->pos;
    end = (rp_mp4_stsc_entry_t *) data->last;

    while (entry < end) {
        chunk = rp_mp4_get_32value(entry->chunk);
        chunk -= trak->start_chunk;
        rp_mp4_set_32value(entry->chunk, chunk);
        entry++;
    }

    atom_size = sizeof(rp_mp4_stsc_atom_t)
                + trak->sample_to_chunk_entries * sizeof(rp_mp4_stsc_entry_t);

    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_STSC_ATOM].buf;
    stsc_atom = (rp_mp4_stsc_atom_t *) atom->pos;

    rp_mp4_set_32value(stsc_atom->size, atom_size);
    rp_mp4_set_32value(stsc_atom->entries, trak->sample_to_chunk_entries);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_crop_stsc_data(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, rp_uint_t start)
{
    uint32_t               start_sample, chunk, samples, id, next_chunk, n,
                           prev_samples;
    rp_buf_t             *data, *buf;
    rp_uint_t             entries, target_chunk, chunk_samples;
    rp_mp4_stsc_entry_t  *entry, *end, *first;

    entries = trak->sample_to_chunk_entries - 1;

    if (start) {
        start_sample = (uint32_t) trak->start_sample;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stsc crop start_sample:%uD", start_sample);

    } else if (mp4->length) {
        start_sample = (uint32_t) (trak->end_sample - trak->start_sample);
        samples = 0;

        data = trak->out[RP_HTTP_MP4_STSC_START].buf;

        if (data) {
            entry = (rp_mp4_stsc_entry_t *) data->pos;
            samples = rp_mp4_get_32value(entry->samples);
            entries--;

            if (samples > start_sample) {
                samples = start_sample;
                rp_mp4_set_32value(entry->samples, samples);
            }

            start_sample -= samples;
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "mp4 stsc crop end_sample:%uD, ext_samples:%uD",
                       start_sample, samples);

    } else {
        return RP_OK;
    }

    data = trak->out[RP_HTTP_MP4_STSC_DATA].buf;

    entry = (rp_mp4_stsc_entry_t *) data->pos;
    end = (rp_mp4_stsc_entry_t *) data->last;

    chunk = rp_mp4_get_32value(entry->chunk);
    samples = rp_mp4_get_32value(entry->samples);
    id = rp_mp4_get_32value(entry->id);
    prev_samples = 0;
    entry++;

    while (entry < end) {

        next_chunk = rp_mp4_get_32value(entry->chunk);

        rp_log_debug5(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "sample:%uD, chunk:%uD, chunks:%uD, "
                       "samples:%uD, id:%uD",
                       start_sample, chunk, next_chunk - chunk, samples, id);

        n = (next_chunk - chunk) * samples;

        if (start_sample < n) {
            goto found;
        }

        start_sample -= n;

        prev_samples = samples;
        chunk = next_chunk;
        samples = rp_mp4_get_32value(entry->samples);
        id = rp_mp4_get_32value(entry->id);
        entries--;
        entry++;
    }

    next_chunk = trak->chunks + 1;

    rp_log_debug4(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample:%uD, chunk:%uD, chunks:%uD, samples:%uD",
                   start_sample, chunk, next_chunk - chunk, samples);

    n = (next_chunk - chunk) * samples;

    if (start_sample > n) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "%s time is out mp4 stsc chunks in \"%s\"",
                      start ? "start" : "end", mp4->file.name.data);
        return RP_ERROR;
    }

found:

    entries++;
    entry--;

    if (samples == 0) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "zero number of samples in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    target_chunk = chunk - 1;
    target_chunk += start_sample / samples;
    chunk_samples = start_sample % samples;

    if (start) {
        data->pos = (u_char *) entry;

        trak->sample_to_chunk_entries = entries;
        trak->start_chunk = target_chunk;
        trak->start_chunk_samples = chunk_samples;

        rp_mp4_set_32value(entry->chunk, trak->start_chunk + 1);

        samples -= chunk_samples;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "start_chunk:%ui, start_chunk_samples:%ui",
                       trak->start_chunk, trak->start_chunk_samples);

    } else {
        if (start_sample) {
            data->last = (u_char *) (entry + 1);
            trak->sample_to_chunk_entries -= entries - 1;
            trak->end_chunk_samples = samples;

        } else {
            data->last = (u_char *) entry;
            trak->sample_to_chunk_entries -= entries;
            trak->end_chunk_samples = prev_samples;
        }

        if (chunk_samples) {
            trak->end_chunk = target_chunk + 1;
            trak->end_chunk_samples = chunk_samples;

        } else {
            trak->end_chunk = target_chunk;
        }

        samples = chunk_samples;
        next_chunk = chunk + 1;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "end_chunk:%ui, end_chunk_samples:%ui",
                       trak->end_chunk, trak->end_chunk_samples);
    }

    if (chunk_samples && next_chunk - target_chunk == 2) {

        rp_mp4_set_32value(entry->samples, samples);

    } else if (chunk_samples && start) {

        first = &trak->stsc_start_chunk_entry;
        rp_mp4_set_32value(first->chunk, 1);
        rp_mp4_set_32value(first->samples, samples);
        rp_mp4_set_32value(first->id, id);

        buf = &trak->stsc_start_chunk_buf;
        buf->temporary = 1;
        buf->pos = (u_char *) first;
        buf->last = (u_char *) first + sizeof(rp_mp4_stsc_entry_t);

        trak->out[RP_HTTP_MP4_STSC_START].buf = buf;

        rp_mp4_set_32value(entry->chunk, trak->start_chunk + 2);

        trak->sample_to_chunk_entries++;

    } else if (chunk_samples) {

        first = &trak->stsc_end_chunk_entry;
        rp_mp4_set_32value(first->chunk, trak->end_chunk - trak->start_chunk);
        rp_mp4_set_32value(first->samples, samples);
        rp_mp4_set_32value(first->id, id);

        buf = &trak->stsc_end_chunk_buf;
        buf->temporary = 1;
        buf->pos = (u_char *) first;
        buf->last = (u_char *) first + sizeof(rp_mp4_stsc_entry_t);

        trak->out[RP_HTTP_MP4_STSC_END].buf = buf;

        trak->sample_to_chunk_entries++;
    }

    return RP_OK;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    uniform_size[4];
    u_char    entries[4];
} rp_mp4_stsz_atom_t;


static rp_int_t
rp_http_mp4_read_stsz_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    size_t                atom_size;
    uint32_t              entries, size;
    rp_buf_t            *atom, *data;
    rp_mp4_stsz_atom_t  *stsz_atom;
    rp_http_mp4_trak_t  *trak;

    /* sample sizes atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsz atom");

    atom_header = rp_mp4_atom_header(mp4);
    stsz_atom = (rp_mp4_stsz_atom_t *) atom_header;
    rp_mp4_set_atom_name(stsz_atom, 's', 't', 's', 'z');

    if (rp_mp4_atom_data_size(rp_mp4_stsz_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stsz atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    size = rp_mp4_get_32value(stsz_atom->uniform_size);
    entries = rp_mp4_get_32value(stsz_atom->entries);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "sample uniform size:%uD, entries:%uD", size, entries);

    trak = rp_mp4_last_trak(mp4);
    trak->sample_sizes_entries = entries;

    atom_table = atom_header + sizeof(rp_mp4_stsz_atom_t);

    atom = &trak->stsz_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    trak->out[RP_HTTP_MP4_STSZ_ATOM].buf = atom;

    if (size == 0) {
        if (rp_mp4_atom_data_size(rp_mp4_stsz_atom_t)
            + entries * sizeof(uint32_t) > atom_data_size)
        {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "\"%s\" mp4 stsz atom too small",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        atom_end = atom_table + entries * sizeof(uint32_t);

        data = &trak->stsz_data_buf;
        data->temporary = 1;
        data->pos = atom_table;
        data->last = atom_end;

        trak->out[RP_HTTP_MP4_STSZ_DATA].buf = data;

    } else {
        /* if size != 0 then all samples are the same size */
        /* TODO : chunk samples */
        atom_size = sizeof(rp_mp4_atom_header_t) + (size_t) atom_data_size;
        rp_mp4_set_32value(atom_header, atom_size);
        trak->size += atom_size;
    }

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_stsz_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint32_t             *pos, *end, entries;
    rp_buf_t            *atom, *data;
    rp_mp4_stsz_atom_t  *stsz_atom;

    /*
     * mdia.minf.stbl.stsz updating requires trak->start_sample
     * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stsz atom update");

    data = trak->out[RP_HTTP_MP4_STSZ_DATA].buf;

    if (data) {
        entries = trak->sample_sizes_entries;

        if (trak->start_sample > entries) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "start time is out mp4 stsz samples in \"%s\"",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        entries -= trak->start_sample;
        data->pos += trak->start_sample * sizeof(uint32_t);
        end = (uint32_t *) data->pos;

        for (pos = end - trak->start_chunk_samples; pos < end; pos++) {
            trak->start_chunk_samples_size += rp_mp4_get_32value(pos);
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                       "chunk samples sizes:%uL",
                       trak->start_chunk_samples_size);

        if (trak->start_chunk_samples_size > (uint64_t) mp4->end) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "too large mp4 start samples size in \"%s\"",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        if (mp4->length) {
            if (trak->end_sample - trak->start_sample > entries) {
                rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                              "end time is out mp4 stsz samples in \"%s\"",
                              mp4->file.name.data);
                return RP_ERROR;
            }

            entries = trak->end_sample - trak->start_sample;
            data->last = data->pos + entries * sizeof(uint32_t);
            end = (uint32_t *) data->last;

            for (pos = end - trak->end_chunk_samples; pos < end; pos++) {
                trak->end_chunk_samples_size += rp_mp4_get_32value(pos);
            }

            rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "mp4 stsz end_chunk_samples_size:%uL",
                           trak->end_chunk_samples_size);

            if (trak->end_chunk_samples_size > (uint64_t) mp4->end) {
                rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                              "too large mp4 end samples size in \"%s\"",
                              mp4->file.name.data);
                return RP_ERROR;
            }
        }

        atom_size = sizeof(rp_mp4_stsz_atom_t) + (data->last - data->pos);
        trak->size += atom_size;

        atom = trak->out[RP_HTTP_MP4_STSZ_ATOM].buf;
        stsz_atom = (rp_mp4_stsz_atom_t *) atom->pos;

        rp_mp4_set_32value(stsz_atom->size, atom_size);
        rp_mp4_set_32value(stsz_atom->entries, entries);
    }

    return RP_OK;
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_mp4_stco_atom_t;


static rp_int_t
rp_http_mp4_read_stco_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    rp_buf_t            *atom, *data;
    rp_mp4_stco_atom_t  *stco_atom;
    rp_http_mp4_trak_t  *trak;

    /* chunk offsets atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stco atom");

    atom_header = rp_mp4_atom_header(mp4);
    stco_atom = (rp_mp4_stco_atom_t *) atom_header;
    rp_mp4_set_atom_name(stco_atom, 's', 't', 'c', 'o');

    if (rp_mp4_atom_data_size(rp_mp4_stco_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stco atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(stco_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);

    if (rp_mp4_atom_data_size(rp_mp4_stco_atom_t)
        + entries * sizeof(uint32_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 stco atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_table = atom_header + sizeof(rp_mp4_stco_atom_t);
    atom_end = atom_table + entries * sizeof(uint32_t);

    trak = rp_mp4_last_trak(mp4);
    trak->chunks = entries;

    atom = &trak->stco_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->stco_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_STCO_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_STCO_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_stco_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint32_t              entries;
    uint64_t              chunk_offset, samples_size;
    rp_buf_t            *atom, *data;
    rp_mp4_stco_atom_t  *stco_atom;

    /*
     * mdia.minf.stbl.stco updating requires trak->start_chunk
     * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stco atom update");

    data = trak->out[RP_HTTP_MP4_STCO_DATA].buf;

    if (data == NULL) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 stco atoms were found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (trak->start_chunk > trak->chunks) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 stco chunks in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    data->pos += trak->start_chunk * sizeof(uint32_t);

    chunk_offset = rp_mp4_get_32value(data->pos);
    samples_size = trak->start_chunk_samples_size;

    if (chunk_offset > (uint64_t) mp4->end - samples_size
        || chunk_offset + samples_size > RP_MAX_UINT32_VALUE)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "too large chunk offset in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    trak->start_offset = chunk_offset + samples_size;
    rp_mp4_set_32value(data->pos, trak->start_offset);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "start chunk offset:%O", trak->start_offset);

    if (mp4->length) {

        if (trak->end_chunk > trak->chunks) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "end time is out mp4 stco chunks in \"%s\"",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        entries = trak->end_chunk - trak->start_chunk;
        data->last = data->pos + entries * sizeof(uint32_t);

        if (entries) {
            chunk_offset = rp_mp4_get_32value(data->last - sizeof(uint32_t));
            samples_size = trak->end_chunk_samples_size;

            if (chunk_offset > (uint64_t) mp4->end - samples_size
                || chunk_offset + samples_size > RP_MAX_UINT32_VALUE)
            {
                rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                              "too large chunk offset in \"%s\"",
                              mp4->file.name.data);
                return RP_ERROR;
            }

            trak->end_offset = chunk_offset + samples_size;

            rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "end chunk offset:%O", trak->end_offset);
        }

    } else {
        entries = trak->chunks - trak->start_chunk;
        trak->end_offset = mp4->mdat_data.buf->file_last;
    }

    if (entries == 0) {
        trak->start_offset = mp4->end;
        trak->end_offset = 0;
    }

    atom_size = sizeof(rp_mp4_stco_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_STCO_ATOM].buf;
    stco_atom = (rp_mp4_stco_atom_t *) atom->pos;

    rp_mp4_set_32value(stco_atom->size, atom_size);
    rp_mp4_set_32value(stco_atom->entries, entries);

    return RP_OK;
}


static void
rp_http_mp4_adjust_stco_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, int32_t adjustment)
{
    uint32_t    offset, *entry, *end;
    rp_buf_t  *data;

    /*
     * moov.trak.mdia.minf.stbl.stco adjustment requires
     * minimal start offset of all traks and new moov atom size
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 stco atom adjustment");

    data = trak->out[RP_HTTP_MP4_STCO_DATA].buf;
    entry = (uint32_t *) data->pos;
    end = (uint32_t *) data->last;

    while (entry < end) {
        offset = rp_mp4_get_32value(entry);
        offset += adjustment;
        rp_mp4_set_32value(entry, offset);
        entry++;
    }
}


typedef struct {
    u_char    size[4];
    u_char    name[4];
    u_char    version[1];
    u_char    flags[3];
    u_char    entries[4];
} rp_mp4_co64_atom_t;


static rp_int_t
rp_http_mp4_read_co64_atom(rp_http_mp4_file_t *mp4, uint64_t atom_data_size)
{
    u_char               *atom_header, *atom_table, *atom_end;
    uint32_t              entries;
    rp_buf_t            *atom, *data;
    rp_mp4_co64_atom_t  *co64_atom;
    rp_http_mp4_trak_t  *trak;

    /* chunk offsets atom */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 co64 atom");

    atom_header = rp_mp4_atom_header(mp4);
    co64_atom = (rp_mp4_co64_atom_t *) atom_header;
    rp_mp4_set_atom_name(co64_atom, 'c', 'o', '6', '4');

    if (rp_mp4_atom_data_size(rp_mp4_co64_atom_t) > atom_data_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    entries = rp_mp4_get_32value(co64_atom->entries);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);

    if (rp_mp4_atom_data_size(rp_mp4_co64_atom_t)
        + entries * sizeof(uint64_t) > atom_data_size)
    {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
        return RP_ERROR;
    }

    atom_table = atom_header + sizeof(rp_mp4_co64_atom_t);
    atom_end = atom_table + entries * sizeof(uint64_t);

    trak = rp_mp4_last_trak(mp4);
    trak->chunks = entries;

    atom = &trak->co64_atom_buf;
    atom->temporary = 1;
    atom->pos = atom_header;
    atom->last = atom_table;

    data = &trak->co64_data_buf;
    data->temporary = 1;
    data->pos = atom_table;
    data->last = atom_end;

    trak->out[RP_HTTP_MP4_CO64_ATOM].buf = atom;
    trak->out[RP_HTTP_MP4_CO64_DATA].buf = data;

    rp_mp4_atom_next(mp4, atom_data_size);

    return RP_OK;
}


static rp_int_t
rp_http_mp4_update_co64_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak)
{
    size_t                atom_size;
    uint64_t              entries, chunk_offset, samples_size;
    rp_buf_t            *atom, *data;
    rp_mp4_co64_atom_t  *co64_atom;

    /*
     * mdia.minf.stbl.co64 updating requires trak->start_chunk
     * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
     * atom which may reside after mdia.minf
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 co64 atom update");

    data = trak->out[RP_HTTP_MP4_CO64_DATA].buf;

    if (data == NULL) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "no mp4 co64 atoms were found in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    if (trak->start_chunk > trak->chunks) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "start time is out mp4 co64 chunks in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    data->pos += trak->start_chunk * sizeof(uint64_t);

    chunk_offset = rp_mp4_get_64value(data->pos);
    samples_size = trak->start_chunk_samples_size;

    if (chunk_offset > (uint64_t) mp4->end - samples_size) {
        rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                      "too large chunk offset in \"%s\"",
                      mp4->file.name.data);
        return RP_ERROR;
    }

    trak->start_offset = chunk_offset + samples_size;
    rp_mp4_set_64value(data->pos, trak->start_offset);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "start chunk offset:%O", trak->start_offset);

    if (mp4->length) {

        if (trak->end_chunk > trak->chunks) {
            rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                          "end time is out mp4 co64 chunks in \"%s\"",
                          mp4->file.name.data);
            return RP_ERROR;
        }

        entries = trak->end_chunk - trak->start_chunk;
        data->last = data->pos + entries * sizeof(uint64_t);

        if (entries) {
            chunk_offset = rp_mp4_get_64value(data->last - sizeof(uint64_t));
            samples_size = trak->end_chunk_samples_size;

            if (chunk_offset > (uint64_t) mp4->end - samples_size) {
                rp_log_error(RP_LOG_ERR, mp4->file.log, 0,
                              "too large chunk offset in \"%s\"",
                              mp4->file.name.data);
                return RP_ERROR;
            }

            trak->end_offset = chunk_offset + samples_size;

            rp_log_debug1(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                           "end chunk offset:%O", trak->end_offset);
        }

    } else {
        entries = trak->chunks - trak->start_chunk;
        trak->end_offset = mp4->mdat_data.buf->file_last;
    }

    if (entries == 0) {
        trak->start_offset = mp4->end;
        trak->end_offset = 0;
    }

    atom_size = sizeof(rp_mp4_co64_atom_t) + (data->last - data->pos);
    trak->size += atom_size;

    atom = trak->out[RP_HTTP_MP4_CO64_ATOM].buf;
    co64_atom = (rp_mp4_co64_atom_t *) atom->pos;

    rp_mp4_set_32value(co64_atom->size, atom_size);
    rp_mp4_set_32value(co64_atom->entries, entries);

    return RP_OK;
}


static void
rp_http_mp4_adjust_co64_atom(rp_http_mp4_file_t *mp4,
    rp_http_mp4_trak_t *trak, off_t adjustment)
{
    uint64_t    offset, *entry, *end;
    rp_buf_t  *data;

    /*
     * moov.trak.mdia.minf.stbl.co64 adjustment requires
     * minimal start offset of all traks and new moov atom size
     */

    rp_log_debug0(RP_LOG_DEBUG_HTTP, mp4->file.log, 0,
                   "mp4 co64 atom adjustment");

    data = trak->out[RP_HTTP_MP4_CO64_DATA].buf;
    entry = (uint64_t *) data->pos;
    end = (uint64_t *) data->last;

    while (entry < end) {
        offset = rp_mp4_get_64value(entry);
        offset += adjustment;
        rp_mp4_set_64value(entry, offset);
        entry++;
    }
}


static char *
rp_http_mp4(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_mp4_handler;

    return RP_CONF_OK;
}


static void *
rp_http_mp4_create_conf(rp_conf_t *cf)
{
    rp_http_mp4_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_mp4_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->buffer_size = RP_CONF_UNSET_SIZE;
    conf->max_buffer_size = RP_CONF_UNSET_SIZE;

    return conf;
}


static char *
rp_http_mp4_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_mp4_conf_t *prev = parent;
    rp_http_mp4_conf_t *conf = child;

    rp_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 512 * 1024);
    rp_conf_merge_size_value(conf->max_buffer_size, prev->max_buffer_size,
                              10 * 1024 * 1024);

    return RP_CONF_OK;
}
