
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_stub_status_handler(rap_http_request_t *r);
static rap_int_t rap_http_stub_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_stub_status_add_variables(rap_conf_t *cf);
static char *rap_http_set_stub_status(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_status_commands[] = {

    { rap_string("stub_status"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_NOARGS|RAP_CONF_TAKE1,
      rap_http_set_stub_status,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_stub_status_module_ctx = {
    rap_http_stub_status_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_stub_status_module = {
    RAP_MODULE_V1,
    &rap_http_stub_status_module_ctx,      /* module context */
    rap_http_status_commands,              /* module directives */
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


static rap_http_variable_t  rap_http_stub_status_vars[] = {

    { rap_string("connections_active"), NULL, rap_http_stub_status_variable,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("connections_reading"), NULL, rap_http_stub_status_variable,
      1, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("connections_writing"), NULL, rap_http_stub_status_variable,
      2, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("connections_waiting"), NULL, rap_http_stub_status_variable,
      3, RAP_HTTP_VAR_NOCACHEABLE, 0 },

      rap_http_null_variable
};


static rap_int_t
rap_http_stub_status_handler(rap_http_request_t *r)
{
    size_t             size;
    rap_int_t          rc;
    rap_buf_t         *b;
    rap_chain_t        out;
    rap_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    rap_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == RAP_HTTP_HEAD) {
        r->headers_out.status = RAP_HTTP_OK;

        rc = rap_http_send_header(r);

        if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
            return rc;
        }
    }

    size = sizeof("Active connections:  \n") + RAP_ATOMIC_T_LEN
           + sizeof("server accepts handled requests\n") - 1
           + 6 + 3 * RAP_ATOMIC_T_LEN
           + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * RAP_ATOMIC_T_LEN;

    b = rap_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ap = *rap_stat_accepted;
    hn = *rap_stat_handled;
    ac = *rap_stat_active;
    rq = *rap_stat_requests;
    rd = *rap_stat_reading;
    wr = *rap_stat_writing;
    wa = *rap_stat_waiting;

    b->last = rap_sprintf(b->last, "Active connections: %uA \n", ac);

    b->last = rap_cpymem(b->last, "server accepts handled requests\n",
                         sizeof("server accepts handled requests\n") - 1);

    b->last = rap_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);

    b->last = rap_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
                          rd, wr, wa);

    r->headers_out.status = RAP_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return rc;
    }

    return rap_http_output_filter(r, &out);
}


static rap_int_t
rap_http_stub_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    rap_atomic_int_t   value;

    p = rap_pnalloc(r->pool, RAP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    switch (data) {
    case 0:
        value = *rap_stat_active;
        break;

    case 1:
        value = *rap_stat_reading;
        break;

    case 2:
        value = *rap_stat_writing;
        break;

    case 3:
        value = *rap_stat_waiting;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = rap_sprintf(p, "%uA", value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_stub_status_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_stub_status_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static char *
rap_http_set_stub_status(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);
    clcf->handler = rap_http_stub_status_handler;

    return RAP_CONF_OK;
}
