
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


static rp_int_t rp_stream_script_init_arrays(
    rp_stream_script_compile_t *sc);
static rp_int_t rp_stream_script_done(rp_stream_script_compile_t *sc);
static rp_int_t rp_stream_script_add_copy_code(
    rp_stream_script_compile_t *sc, rp_str_t *value, rp_uint_t last);
static rp_int_t rp_stream_script_add_var_code(
    rp_stream_script_compile_t *sc, rp_str_t *name);
#if (RP_PCRE)
static rp_int_t rp_stream_script_add_capture_code(
    rp_stream_script_compile_t *sc, rp_uint_t n);
#endif
static rp_int_t rp_stream_script_add_full_name_code(
    rp_stream_script_compile_t *sc);
static size_t rp_stream_script_full_name_len_code(
    rp_stream_script_engine_t *e);
static void rp_stream_script_full_name_code(rp_stream_script_engine_t *e);


#define rp_stream_script_exit  (u_char *) &rp_stream_script_exit_code

static uintptr_t rp_stream_script_exit_code = (uintptr_t) NULL;


void
rp_stream_script_flush_complex_value(rp_stream_session_t *s,
    rp_stream_complex_value_t *val)
{
    rp_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (rp_uint_t) -1) {

            if (s->variables[*index].no_cacheable) {
                s->variables[*index].valid = 0;
                s->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


rp_int_t
rp_stream_complex_value(rp_stream_session_t *s,
    rp_stream_complex_value_t *val, rp_str_t *value)
{
    size_t                         len;
    rp_stream_script_code_pt      code;
    rp_stream_script_engine_t     e;
    rp_stream_script_len_code_pt  lcode;

    if (val->lengths == NULL) {
        *value = val->value;
        return RP_OK;
    }

    rp_stream_script_flush_complex_value(s, val);

    rp_memzero(&e, sizeof(rp_stream_script_engine_t));

    e.ip = val->lengths;
    e.session = s;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rp_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = rp_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return RP_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(rp_stream_script_code_pt *) e.ip;
        code((rp_stream_script_engine_t *) &e);
    }

    *value = e.buf;

    return RP_OK;
}


size_t
rp_stream_complex_value_size(rp_stream_session_t *s,
    rp_stream_complex_value_t *val, size_t default_value)
{
    size_t     size;
    rp_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (rp_stream_complex_value(s, val, &value) != RP_OK) {
        return default_value;
    }

    size = rp_parse_size(&value);

    if (size == (size_t) RP_ERROR) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


rp_int_t
rp_stream_compile_complex_value(rp_stream_compile_complex_value_t *ccv)
{
    rp_str_t                    *v;
    rp_uint_t                    i, n, nv, nc;
    rp_array_t                   flushes, lengths, values, *pf, *pl, *pv;
    rp_stream_script_compile_t   sc;

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
        if (rp_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != RP_OK) {
            return RP_ERROR;
        }

        ccv->conf_prefix = 0;
        ccv->root_prefix = 0;
    }

    ccv->complex_value->value = *v;
    ccv->complex_value->flushes = NULL;
    ccv->complex_value->lengths = NULL;
    ccv->complex_value->values = NULL;

    if (nv == 0 && nc == 0) {
        return RP_OK;
    }

    n = nv + 1;

    if (rp_array_init(&flushes, ccv->cf->pool, n, sizeof(rp_uint_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    n = nv * (2 * sizeof(rp_stream_script_copy_code_t)
                  + sizeof(rp_stream_script_var_code_t))
        + sizeof(uintptr_t);

    if (rp_array_init(&lengths, ccv->cf->pool, n, 1) != RP_OK) {
        return RP_ERROR;
    }

    n = (nv * (2 * sizeof(rp_stream_script_copy_code_t)
                   + sizeof(rp_stream_script_var_code_t))
                + sizeof(uintptr_t)
                + v->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    if (rp_array_init(&values, ccv->cf->pool, n, 1) != RP_OK) {
        return RP_ERROR;
    }

    pf = &flushes;
    pl = &lengths;
    pv = &values;

    rp_memzero(&sc, sizeof(rp_stream_script_compile_t));

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

    if (rp_stream_script_compile(&sc) != RP_OK) {
        return RP_ERROR;
    }

    if (flushes.nelts) {
        ccv->complex_value->flushes = flushes.elts;
        ccv->complex_value->flushes[flushes.nelts] = (rp_uint_t) -1;
    }

    ccv->complex_value->lengths = lengths.elts;
    ccv->complex_value->values = values.elts;

    return RP_OK;
}


char *
rp_stream_set_complex_value_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rp_str_t                            *value;
    rp_stream_complex_value_t          **cv;
    rp_stream_compile_complex_value_t    ccv;

    cv = (rp_stream_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = rp_palloc(cf->pool, sizeof(rp_stream_complex_value_t));
    if (*cv == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


char *
rp_stream_set_complex_value_size_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                        *rv;
    rp_stream_complex_value_t  *cv;

    rv = rp_stream_set_complex_value_slot(cf, cmd, conf);

    if (rv != RP_CONF_OK) {
        return rv;
    }

    cv = *(rp_stream_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return RP_CONF_OK;
    }

    cv->u.size = rp_parse_size(&cv->value);
    if (cv->u.size == (size_t) RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


rp_uint_t
rp_stream_script_variables_count(rp_str_t *value)
{
    rp_uint_t  i, n;

    for (n = 0, i = 0; i < value->len; i++) {
        if (value->data[i] == '$') {
            n++;
        }
    }

    return n;
}


rp_int_t
rp_stream_script_compile(rp_stream_script_compile_t *sc)
{
    u_char       ch;
    rp_str_t    name;
    rp_uint_t   i, bracket;

    if (rp_stream_script_init_arrays(sc) != RP_OK) {
        return RP_ERROR;
    }

    for (i = 0; i < sc->source->len; /* void */ ) {

        name.len = 0;

        if (sc->source->data[i] == '$') {

            if (++i == sc->source->len) {
                goto invalid_variable;
            }

            if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
#if (RP_PCRE)
                rp_uint_t  n;

                n = sc->source->data[i] - '0';

                if (rp_stream_script_add_capture_code(sc, n) != RP_OK) {
                    return RP_ERROR;
                }

                i++;

                continue;
#else
                rp_conf_log_error(RP_LOG_EMERG, sc->cf, 0,
                                   "using variable \"$%c\" requires "
                                   "PCRE library", sc->source->data[i]);
                return RP_ERROR;
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
                rp_conf_log_error(RP_LOG_EMERG, sc->cf, 0,
                                   "the closing bracket in \"%V\" "
                                   "variable is missing", &name);
                return RP_ERROR;
            }

            if (name.len == 0) {
                goto invalid_variable;
            }

            sc->variables++;

            if (rp_stream_script_add_var_code(sc, &name) != RP_OK) {
                return RP_ERROR;
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

        if (rp_stream_script_add_copy_code(sc, &name, (i == sc->source->len))
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    return rp_stream_script_done(sc);

invalid_variable:

    rp_conf_log_error(RP_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return RP_ERROR;
}


u_char *
rp_stream_script_run(rp_stream_session_t *s, rp_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    rp_uint_t                      i;
    rp_stream_script_code_pt       code;
    rp_stream_script_engine_t      e;
    rp_stream_core_main_conf_t    *cmcf;
    rp_stream_script_len_code_pt   lcode;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (s->variables[i].no_cacheable) {
            s->variables[i].valid = 0;
            s->variables[i].not_found = 0;
        }
    }

    rp_memzero(&e, sizeof(rp_stream_script_engine_t));

    e.ip = code_lengths;
    e.session = s;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rp_stream_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = rp_pnalloc(s->connection->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(rp_stream_script_code_pt *) e.ip;
        code((rp_stream_script_engine_t *) &e);
    }

    return e.pos;
}


void
rp_stream_script_flush_no_cacheable_variables(rp_stream_session_t *s,
    rp_array_t *indices)
{
    rp_uint_t  n, *index;

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


static rp_int_t
rp_stream_script_init_arrays(rp_stream_script_compile_t *sc)
{
    rp_uint_t   n;

    if (sc->flushes && *sc->flushes == NULL) {
        n = sc->variables ? sc->variables : 1;
        *sc->flushes = rp_array_create(sc->cf->pool, n, sizeof(rp_uint_t));
        if (*sc->flushes == NULL) {
            return RP_ERROR;
        }
    }

    if (*sc->lengths == NULL) {
        n = sc->variables * (2 * sizeof(rp_stream_script_copy_code_t)
                             + sizeof(rp_stream_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = rp_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return RP_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(rp_stream_script_copy_code_t)
                              + sizeof(rp_stream_script_var_code_t))
                + sizeof(uintptr_t)
                + sc->source->len
                + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

        *sc->values = rp_array_create(sc->cf->pool, n, 1);
        if (*sc->values == NULL) {
            return RP_ERROR;
        }
    }

    sc->variables = 0;

    return RP_OK;
}


static rp_int_t
rp_stream_script_done(rp_stream_script_compile_t *sc)
{
    rp_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (rp_stream_script_add_copy_code(sc, &zero, 0) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (rp_stream_script_add_full_name_code(sc) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = rp_stream_script_add_code(*sc->lengths, sizeof(uintptr_t),
                                          NULL);
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = rp_stream_script_add_code(*sc->values, sizeof(uintptr_t),
                                          &sc->main);
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return RP_OK;
}


void *
rp_stream_script_add_code(rp_array_t *codes, size_t size, void *code)
{
    u_char  *elts, **p;
    void    *new;

    elts = codes->elts;

    new = rp_array_push_n(codes, size);
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


static rp_int_t
rp_stream_script_add_copy_code(rp_stream_script_compile_t *sc,
    rp_str_t *value, rp_uint_t last)
{
    u_char                         *p;
    size_t                          size, len, zero;
    rp_stream_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = rp_stream_script_add_code(*sc->lengths,
                                      sizeof(rp_stream_script_copy_code_t),
                                      NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_stream_script_code_pt) (void *)
                                               rp_stream_script_copy_len_code;
    code->len = len;

    size = (sizeof(rp_stream_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = rp_stream_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_stream_script_copy_code;
    code->len = len;

    p = rp_cpymem((u_char *) code + sizeof(rp_stream_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return RP_OK;
}


size_t
rp_stream_script_copy_len_code(rp_stream_script_engine_t *e)
{
    rp_stream_script_copy_code_t  *code;

    code = (rp_stream_script_copy_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_copy_code_t);

    return code->len;
}


void
rp_stream_script_copy_code(rp_stream_script_engine_t *e)
{
    u_char                         *p;
    rp_stream_script_copy_code_t  *code;

    code = (rp_stream_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = rp_copy(p, e->ip + sizeof(rp_stream_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(rp_stream_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    rp_log_debug2(RP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script copy: \"%*s\"", e->pos - p, p);
}


static rp_int_t
rp_stream_script_add_var_code(rp_stream_script_compile_t *sc, rp_str_t *name)
{
    rp_int_t                      index, *p;
    rp_stream_script_var_code_t  *code;

    index = rp_stream_get_variable_index(sc->cf, name);

    if (index == RP_ERROR) {
        return RP_ERROR;
    }

    if (sc->flushes) {
        p = rp_array_push(*sc->flushes);
        if (p == NULL) {
            return RP_ERROR;
        }

        *p = index;
    }

    code = rp_stream_script_add_code(*sc->lengths,
                                      sizeof(rp_stream_script_var_code_t),
                                      NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_stream_script_code_pt) (void *)
                                           rp_stream_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = rp_stream_script_add_code(*sc->values,
                                      sizeof(rp_stream_script_var_code_t),
                                      &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_stream_script_copy_var_code;
    code->index = (uintptr_t) index;

    return RP_OK;
}


size_t
rp_stream_script_copy_var_len_code(rp_stream_script_engine_t *e)
{
    rp_stream_variable_value_t   *value;
    rp_stream_script_var_code_t  *code;

    code = (rp_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_var_code_t);

    if (e->flushed) {
        value = rp_stream_get_indexed_variable(e->session, code->index);

    } else {
        value = rp_stream_get_flushed_variable(e->session, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
rp_stream_script_copy_var_code(rp_stream_script_engine_t *e)
{
    u_char                        *p;
    rp_stream_variable_value_t   *value;
    rp_stream_script_var_code_t  *code;

    code = (rp_stream_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = rp_stream_get_indexed_variable(e->session, code->index);

        } else {
            value = rp_stream_get_flushed_variable(e->session, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = rp_copy(p, value->data, value->len);

            rp_log_debug2(RP_LOG_DEBUG_STREAM,
                           e->session->connection->log, 0,
                           "stream script var: \"%*s\"", e->pos - p, p);
        }
    }
}


#if (RP_PCRE)

static rp_int_t
rp_stream_script_add_capture_code(rp_stream_script_compile_t *sc,
    rp_uint_t n)
{
    rp_stream_script_copy_capture_code_t  *code;

    code = rp_stream_script_add_code(*sc->lengths,
                                  sizeof(rp_stream_script_copy_capture_code_t),
                                  NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_stream_script_code_pt) (void *)
                                       rp_stream_script_copy_capture_len_code;
    code->n = 2 * n;


    code = rp_stream_script_add_code(*sc->values,
                                  sizeof(rp_stream_script_copy_capture_code_t),
                                  &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_stream_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return RP_OK;
}


size_t
rp_stream_script_copy_capture_len_code(rp_stream_script_engine_t *e)
{
    int                                    *cap;
    rp_uint_t                              n;
    rp_stream_session_t                   *s;
    rp_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (rp_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_copy_capture_code_t);

    n = code->n;

    if (n < s->ncaptures) {
        cap = s->captures;
        return cap[n + 1] - cap[n];
    }

    return 0;
}


void
rp_stream_script_copy_capture_code(rp_stream_script_engine_t *e)
{
    int                                    *cap;
    u_char                                 *p, *pos;
    rp_uint_t                              n;
    rp_stream_session_t                   *s;
    rp_stream_script_copy_capture_code_t  *code;

    s = e->session;

    code = (rp_stream_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < s->ncaptures) {
        cap = s->captures;
        p = s->captures_data;
        e->pos = rp_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
    }

    rp_log_debug2(RP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static rp_int_t
rp_stream_script_add_full_name_code(rp_stream_script_compile_t *sc)
{
    rp_stream_script_full_name_code_t  *code;

    code = rp_stream_script_add_code(*sc->lengths,
                                    sizeof(rp_stream_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_stream_script_code_pt) (void *)
                                          rp_stream_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = rp_stream_script_add_code(*sc->values,
                        sizeof(rp_stream_script_full_name_code_t), &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_stream_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return RP_OK;
}


static size_t
rp_stream_script_full_name_len_code(rp_stream_script_engine_t *e)
{
    rp_stream_script_full_name_code_t  *code;

    code = (rp_stream_script_full_name_code_t *) e->ip;

    e->ip += sizeof(rp_stream_script_full_name_code_t);

    return code->conf_prefix ? rp_cycle->conf_prefix.len:
                               rp_cycle->prefix.len;
}


static void
rp_stream_script_full_name_code(rp_stream_script_engine_t *e)
{
    rp_stream_script_full_name_code_t  *code;

    rp_str_t  value, *prefix;

    code = (rp_stream_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (rp_str_t *) &rp_cycle->conf_prefix:
                                 (rp_str_t *) &rp_cycle->prefix;

    if (rp_get_full_name(e->session->connection->pool, prefix, &value)
        != RP_OK)
    {
        e->ip = rp_stream_script_exit;
        return;
    }

    e->buf = value;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, e->session->connection->log, 0,
                   "stream script fullname: \"%V\"", &value);

    e->ip += sizeof(rp_stream_script_full_name_code_t);
}
