
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_int_t rp_http_stub_status_handler(rp_http_request_t *r);
static rp_int_t rp_http_stub_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_stub_status_add_variables(rp_conf_t *cf);
static char *rp_http_set_stub_status(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_status_commands[] = {

    { rp_string("stub_status"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_NOARGS|RP_CONF_TAKE1,
      rp_http_set_stub_status,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_stub_status_module_ctx = {
    rp_http_stub_status_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_stub_status_module = {
    RP_MODULE_V1,
    &rp_http_stub_status_module_ctx,      /* module context */
    rp_http_status_commands,              /* module directives */
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


static rp_http_variable_t  rp_http_stub_status_vars[] = {

    { rp_string("connections_active"), NULL, rp_http_stub_status_variable,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("connections_reading"), NULL, rp_http_stub_status_variable,
      1, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("connections_writing"), NULL, rp_http_stub_status_variable,
      2, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("connections_waiting"), NULL, rp_http_stub_status_variable,
      3, RP_HTTP_VAR_NOCACHEABLE, 0 },

      rp_http_null_variable
};


static rp_int_t
rp_http_stub_status_handler(rp_http_request_t *r)
{
    size_t             size;
    rp_int_t          rc;
    rp_buf_t         *b;
    rp_chain_t        out;
    rp_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    rp_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == RP_HTTP_HEAD) {
        r->headers_out.status = RP_HTTP_OK;

        rc = rp_http_send_header(r);

        if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
            return rc;
        }
    }

    size = sizeof("Active connections:  \n") + RP_ATOMIC_T_LEN
           + sizeof("server accepts handled requests\n") - 1
           + 6 + 3 * RP_ATOMIC_T_LEN
           + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * RP_ATOMIC_T_LEN;

    b = rp_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *rp_stat_accepted;
    hn = *rp_stat_handled;
    ac = *rp_stat_active;
    rq = *rp_stat_requests;
    rd = *rp_stat_reading;
    wr = *rp_stat_writing;
    wa = *rp_stat_waiting;

    b->last = rp_sprintf(b->last, "Active connections: %uA \n", ac);

    b->last = rp_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = rp_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = rp_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, wa);

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
        return rc;
    }

    return rp_http_output_filter(r, &out);
}


static rp_int_t
rp_http_stub_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    rp_atomic_int_t   value;

    p = rp_pnalloc(r->pool, RP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    switch (data) {
    case 0:
        value = *rp_stat_active;
        break;

    case 1:
        value = *rp_stat_reading;
        break;

    case 2:
        value = *rp_stat_writing;
        break;

    case 3:
        value = *rp_stat_waiting;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = rp_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_stub_status_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_stub_status_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static char *
rp_http_set_stub_status(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_stub_status_handler;

    return RP_CONF_OK;
}
