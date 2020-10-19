
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


static rap_int_t rap_stream_script_init_arrays(
    rap_stream_script_compile_t *sc);
static rap_int_t rap_stream_script_done(rap_stream_script_compile_t *sc);
static rap_int_t rap_stream_script_add_copy_code(
    rap_stream_script_compile_t *sc, rap_str_t *value, rap_uint_t last);
static rap_int_t rap_stream_script_add_var_code(
    rap_stream_script_compile_t *sc, rap_str_t *name);
#if (RAP_PCRE)
static rap_int_t rap_stream_script_add_capture_code(
    rap_stream_script_compile_t *sc, rap_uint_t n);
#endif
static rap_int_t rap_stream_script_add_full_name_code(
    rap_stream_script_compile_t *sc);
static size_t rap_stream_script_full_name_len_code(
    rap_stream_script_engine_t *e);
static void rap_stream_script_full_name_code(rap_stream_script_engine_t *e);


#define rap_stream_script_exit  (u_char *) &rap_stream_script_exit_code

static uintptr_t rap_stream_script_exit_code = (uintptr_t) NULL;


void
rap_stream_script_flush_complex_value(rap_stream_session_t *s,
    rap_stream_complex_value_t *val)
{
    rap_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (rap_uint_t) -1) {

            if (s->variables[*index].no_cacheable) {
                s->variables[*index].valid = 0;
                s->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


rap_int_t
rap_stream_complex_value(rap_stream_session_t *s,
    rap_stream_complex_value_t *val, rap_str_t *value)
{
    size_t                         len;
    rap_stream_script_code_pt      code;
    rap_stream_script_engine_t     e;
    rap_stream_script_len_code_pt  lcode;

    if (val->lengths == NULL) {
        *value = val->value;
        return RAP_OK;
    }

    rap_stream_script_flush_complex_value(s, val);

    rap_memzero(&e, sizeof(rap_stream_script_engine_t));

    e.ip = val->lengths;
    e.session = s;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rap_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = rap_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return RAP_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(rap_stream_script_code_pt *) e.ip;
        code((rap_stream_script_engine_t *) &e);
    }

    *value = e.buf;

    return RAP_OK;
}


size_t
rap_stream_complex_value_size(rap_stream_session_t *s,
    rap_stream_complex_value_t *val, size_t default_value)
{
    size_t     size;
    rap_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (rap_stream_complex_value(s, val, &value) != RAP_OK) {
        return default_value;
    }

    size = rap_parse_size(&value);

    if (size == (size_t) RAP_ERROR) {
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


rap_int_t
rap_stream_compile_complex_value(rap_stream_compile_complex_value_t *ccv)
{
    rap_str_t                    *v;
    rap_uint_t                    i, n, nv, nc;
    rap_array_t                   flushes, lengths, values, *pf, *pl, *pv;
    rap_stream_script_compile_t   sc;

    v = ccv->value;

    nv = 0;
    nc = 0;

    for (i = 0; i < v->len; i++) {
        if (v->data[i] == '$') {
            if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
                nc++;

            } else {
                nv++;
            }
        }
    }

    if ((v->len == 0 || v->data[0] != '$')
        && (ccv->conf_prefix || ccv->root_prefix))
    {
        if (rap_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != RAP_OK) {
            return RAP_ERROR;
        }

        ccv->conf_prefix = 0;
        ccv->root_prefix = 0;
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->flushes = NULL;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (nv == 0 && nc == 0) {
        return RAP_OK;
    }

    n = nv + 1;

    if (rap_array_init(&flushes, ccv->cf->pool, n, sizeof(rap_uint_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    n = nv * (2 * sizeof(rap_stream_script_copy_code_t)
                  + sizeof(rap_stream_script_var_code_t))
        + sizeof(uintptr_t);

    if (rap_array_init(&lengths, ccv->cf->pool, n, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    n = (nv * (2 * sizeof(rap_stream_script_copy_code_t)
                   + sizeof(rap_stream_script_var_code_t))
                + sizeof(uintptr_t)
                + v->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (rap_array_init(&values, ccv->cf->pool, n, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    pf = &flushes;
    pl = &lengths;
    pv = &values;

    rap_memzero(&sc, sizeof(rap_stream_script_compile_t));

    sc.cf = ccv->cf;
    sc.source = v;
    sc.flushes = &pf;
    sc.lengths = &pl;
    sc.values = &pv;
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    sc.zero = ccv->zero;
    sc.conf_prefix = ccv->conf_prefix;
    sc.root_prefix = ccv->root_prefix;

    if (rap_stream_script_compile(&sc) != RAP_OK) {
        return RAP_ERROR;
    }

    if (flushes.nelts) {
        ccv->complex_value->flushes = flushes.elts;
        ccv->complex_value->flushes[flushes.nelts] = (rap_uint_t) -1;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return RAP_OK;
}


char *
rap_stream_set_complex_value_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rap_str_t                            *value;
    rap_stream_complex_value_t          **cv;
    rap_stream_compile_complex_value_t    ccv;

    cv = (rap_stream_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = rap_palloc(cf->pool, sizeof(rap_stream_complex_value_t));
    if (*cv == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


char *
rap_stream_set_complex_value_size_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                        *rv;
    rap_stream_complex_value_t  *cv;

    rv = rap_stream_set_complex_value_slot(cf, cmd, conf);

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    cv = *(rap_stream_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return RAP_CONF_OK;
    }

    cv->u.size = rap_parse_size(&cv->value);
    if (cv->u.size == (size_t) RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


rap_uint_t
rap_stream_script_variables_count(rap_str_t *value)
{
    rap_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


rap_int_t
rap_stream_script_compile(rap_stream_script_compile_t *sc)
{
    u_char       ch;
    rap_str_t    name;
    rap_uint_t   i, bracket;

    if (rap_stream_script_init_arrays(sc) != RAP_OK) {
        return RAP_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
#if (RAP_PCRE)
                rap_uint_t  n;

                n = sc->source->data[i] - '0';

                if (rap_stream_script_add_capture_code(sc, n) != RAP_OK) {
                    return RAP_ERROR;
                }

                i++;

                continue;
#else
                rap_conf_log_error(RAP_LOG_EMERG, sc->cf, 0,
                                   "using variable \"$%c\" requires "
                                   "PCRE library", sc->source->data[i]);
                return RAP_ERROR;
#endif
            }

            if (sc->source->data[i] == '{') {
                bracket = 1;

                if (++i == sc->source->len) {
                    goto invalid_variable;
                }

                name.data = &sc->source->data[i];

            } else {
                bracket = 0;
                name.data = &sc->source->data[i];
            }

            for ( /* void */ ; i < sc->source->len; i++, name.len++) {
                ch = sc->source->data[i];

                if (ch == '}' && bracket) {
                    i++;
                    bracket = 0;
                    break;
                }

                if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_')
                {
                    continue;
                }

                break;
            }

            if (bracket) {
                rap_conf_log_error(RAP_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return RAP_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            if (rap_stream_script_add_var_code(sc, &name) != RAP_OK) {
                return RAP_ERROR;
            }

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (rap_stream_script_add_copy_code(sc, &name, (i == sc->source->len))
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    return rap_stream_script_done(sc);

invalid_variable:

    rap_conf_log_error(RAP_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return RAP_ERROR;
}


u_char *
rap_stream_script_run(rap_stream_session_t *s, rap_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    rap_uint_t                      i;
    rap_stream_script_code_pt       code;
    rap_stream_script_engine_t      e;
    rap_stream_core_main_conf_t    *cmcf;
    rap_stream_script_len_code_pt   lcode;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (s->variables[i].no_cacheable) {
            s->variables[i].valid = 0;
            s->variables[i].not_found = 0;
        }
    }

    rap_memzero(&e, sizeof(rap_stream_script_engine_t));

    e.ip = code_lengths;
    e.session = s;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rap_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = rap_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(rap_stream_script_code_pt *) e.ip;
        code((rap_stream_script_engine_t *) &e);
    }

    return e.pos;
}


void
rap_stream_script_flush_no_cacheable_variables(rap_stream_session_t *s,
    rap_array_t *indices)
{
    rap_uint_t  n, *index;

    if (indices) {
        index = indices->elts;
        for (n = 0; n < indices->nelts; n++) {
            if (s->variables[index[n]].no_cacheable) {
                s->variables[index[n]].valid = 0;
                s->variables[index[n]].not_found = 0;
            }
        }
    }
}


static rap_int_t
rap_stream_script_init_arrays(rap_stream_script_compile_t *sc)
{
    rap_uint_t   n;

    if (sc->flushes && *sc->flushes == NULL) {
        n = sc->variables ? sc->variables : 1;
        *sc->flushes = rap_array_create(sc->cf->pool, n, sizeof(rap_uint_t));
        if (*sc->flushes == NULL) {
            return RAP_ERROR;
        }
    }

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(rap_stream_script_copy_code_t)
                             + sizeof(rap_stream_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = rap_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return RAP_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(rap_stream_script_copy_code_t)
                              + sizeof(rap_stream_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = rap_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return RAP_ERROR;
        }
    }

    sc->variables = 0;

    return RAP_OK;
}


static rap_int_t
rap_stream_script_done(rap_stream_script_compile_t *sc)
{
    rap_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (rap_stream_script_add_copy_code(sc, &zero, 0) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (rap_stream_script_add_full_name_code(sc) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = rap_stream_script_add_code(*sc->lengths, sizeof(uintptr_t),
                                          NULL);
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = rap_stream_script_add_code(*sc->values, sizeof(uintptr_t),
                                          &sc->main);
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return RAP_OK;
}


void *
rap_stream_script_add_code(rap_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = rap_array_push_n(codes, size);
    if (new == NULL) {
        return NULL;
    }

    if (code) {
        if (elts != codes->elts) {
            p = code;
            *p += (u_char *) codes->elts - elts;
        }
    }

    return new;
}


static rap_int_t
rap_stream_script_add_copy_code(rap_stream_script_compile_t *sc,
    rap_str_t *value, rap_uint_t last)
{
    u_char                         *p;
    size_t                          size, len, zero;
    rap_stream_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = rap_stream_script_add_code(*sc->lengths,
                                      sizeof(rap_stream_script_copy_code_t),
                                      NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_stream_script_code_pt) (void *)
                                               rap_stream_script_copy_len_code;
    code->len = len;

    size = (sizeof(rap_stream_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = rap_stream_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_stream_script_copy_code;
    code->len = len;

    p = rap_cpymem((u_char *) code + sizeof(rap_stream_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return RAP_OK;
}


size_t
rap_stream_script_copy_len_code(rap_stream_script_engine_t *e)
{
    rap_stream_script_copy_code_t  *code;

    code = (rap_stream_script_copy_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_copy_code_t);

    return code->len;
}


void
rap_stream_script_copy_code(rap_stream_script_engine_t *e)
{
    u_char                         *p;
    rap_stream_script_copy_code_t  *code;

    code = (rap_stream_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = rap_copy(p, e->ip + sizeof(rap_stream_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(rap_stream_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    rap_log_debug2(RAP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script copy: \"%*s\"", e->pos - p, p);
}


static rap_int_t
rap_stream_script_add_var_code(rap_stream_script_compile_t *sc, rap_str_t *name)
{
    rap_int_t                      index, *p;
    rap_stream_script_var_code_t  *code;

    index = rap_stream_get_variable_index(sc->cf, name);

    if (index == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (sc->flushes) {
        p = rap_array_push(*sc->flushes);
        if (p == NULL) {
            return RAP_ERROR;
        }

        *p = index;
    }

    code = rap_stream_script_add_code(*sc->lengths,
                                      sizeof(rap_stream_script_var_code_t),
                                      NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_stream_script_code_pt) (void *)
                                           rap_stream_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = rap_stream_script_add_code(*sc->values,
                                      sizeof(rap_stream_script_var_code_t),
                                      &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_stream_script_copy_var_code;
    code->index = (uintptr_t) index;

    return RAP_OK;
}


size_t
rap_stream_script_copy_var_len_code(rap_stream_script_engine_t *e)
{
    rap_stream_variable_value_t   *value;
    rap_stream_script_var_code_t  *code;

    code = (rap_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_var_code_t);

    if (e->flushed) {
        value = rap_stream_get_indexed_variable(e->session, code->index);

    } else {
        value = rap_stream_get_flushed_variable(e->session, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
rap_stream_script_copy_var_code(rap_stream_script_engine_t *e)
{
    u_char                        *p;
    rap_stream_variable_value_t   *value;
    rap_stream_script_var_code_t  *code;

    code = (rap_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = rap_stream_get_indexed_variable(e->session, code->index);

        } else {
            value = rap_stream_get_flushed_variable(e->session, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = rap_copy(p, value->data, value->len);

            rap_log_debug2(RAP_LOG_DEBUG_STREAM,
                           e->session->connection->log, 0,
                           "stream script var: \"%*s\"", e->pos - p, p);
        }
    }
}


#if (RAP_PCRE)

static rap_int_t
rap_stream_script_add_capture_code(rap_stream_script_compile_t *sc,
    rap_uint_t n)
{
    rap_stream_script_copy_capture_code_t  *code;

    code = rap_stream_script_add_code(*sc->lengths,
                                  sizeof(rap_stream_script_copy_capture_code_t),
                                  NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_stream_script_code_pt) (void *)
                                       rap_stream_script_copy_capture_len_code;
    code->n = 2 * n;


    code = rap_stream_script_add_code(*sc->values,
                                  sizeof(rap_stream_script_copy_capture_code_t),
                                  &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_stream_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return RAP_OK;
}


size_t
rap_stream_script_copy_capture_len_code(rap_stream_script_engine_t *e)
{
    int                                    *cap;
    rap_uint_t                              n;
    rap_stream_session_t                   *s;
    rap_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (rap_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_copy_capture_code_t);

    n = code->n;

    if (n < s->ncaptures) {
        cap = s->captures;
        return cap[n + 1] - cap[n];
    }

    return 0;
}


void
rap_stream_script_copy_capture_code(rap_stream_script_engine_t *e)
{
    int                                    *cap;
    u_char                                 *p, *pos;
    rap_uint_t                              n;
    rap_stream_session_t                   *s;
    rap_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (rap_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < s->ncaptures) {
        cap = s->captures;
        p = s->captures_data;
        e->pos = rap_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
    }

    rap_log_debug2(RAP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static rap_int_t
rap_stream_script_add_full_name_code(rap_stream_script_compile_t *sc)
{
    rap_stream_script_full_name_code_t  *code;

    code = rap_stream_script_add_code(*sc->lengths,
                                    sizeof(rap_stream_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_stream_script_code_pt) (void *)
                                          rap_stream_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = rap_stream_script_add_code(*sc->values,
                        sizeof(rap_stream_script_full_name_code_t), &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_stream_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return RAP_OK;
}


static size_t
rap_stream_script_full_name_len_code(rap_stream_script_engine_t *e)
{
    rap_stream_script_full_name_code_t  *code;

    code = (rap_stream_script_full_name_code_t *) e->ip;

    e->ip += sizeof(rap_stream_script_full_name_code_t);

    return code->conf_prefix ? rap_cycle->conf_prefix.len:
                               rap_cycle->prefix.len;
}


static void
rap_stream_script_full_name_code(rap_stream_script_engine_t *e)
{
    rap_stream_script_full_name_code_t  *code;

    rap_str_t  value, *prefix;

    code = (rap_stream_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (rap_str_t *) &rap_cycle->conf_prefix:
                                 (rap_str_t *) &rap_cycle->prefix;

    if (rap_get_full_name(e->session->connection->pool, prefix, &value)
        != RAP_OK)
    {
        e->ip = rap_stream_script_exit;
        return;
    }

    e->buf = value;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script fullname: \"%V\"", &value);

    e->ip += sizeof(rap_stream_script_full_name_code_t);
}
