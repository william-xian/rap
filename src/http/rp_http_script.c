
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_int_t rp_http_script_init_arrays(rp_http_script_compile_t *sc);
static rp_int_t rp_http_script_done(rp_http_script_compile_t *sc);
static rp_int_t rp_http_script_add_copy_code(rp_http_script_compile_t *sc,
    rp_str_t *value, rp_uint_t last);
static rp_int_t rp_http_script_add_var_code(rp_http_script_compile_t *sc,
    rp_str_t *name);
static rp_int_t rp_http_script_add_args_code(rp_http_script_compile_t *sc);
#if (RP_PCRE)
static rp_int_t rp_http_script_add_capture_code(rp_http_script_compile_t *sc,
    rp_uint_t n);
#endif
static rp_int_t
    rp_http_script_add_full_name_code(rp_http_script_compile_t *sc);
static size_t rp_http_script_full_name_len_code(rp_http_script_engine_t *e);
static void rp_http_script_full_name_code(rp_http_script_engine_t *e);


#define rp_http_script_exit  (u_char *) &rp_http_script_exit_code

static uintptr_t rp_http_script_exit_code = (uintptr_t) NULL;


void
rp_http_script_flush_complex_value(rp_http_request_t *r,
    rp_http_complex_value_t *val)
{
    rp_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (rp_uint_t) -1) {

            if (r->variables[*index].no_cacheable) {
                r->variables[*index].valid = 0;
                r->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


rp_int_t
rp_http_complex_value(rp_http_request_t *r, rp_http_complex_value_t *val,
    rp_str_t *value)
{
    size_t                        len;
    rp_http_script_code_pt       code;
    rp_http_script_len_code_pt   lcode;
    rp_http_script_engine_t      e;

    if (val->lengths == NULL) {
        *value = val->value;
        return RP_OK;
    }

    rp_http_script_flush_complex_value(r, val);

    rp_memzero(&e, sizeof(rp_http_script_engine_t));

    e.ip = val->lengths;
    e.request = r;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rp_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = rp_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return RP_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(rp_http_script_code_pt *) e.ip;
        code((rp_http_script_engine_t *) &e);
    }

    *value = e.buf;

    return RP_OK;
}


size_t
rp_http_complex_value_size(rp_http_request_t *r,
    rp_http_complex_value_t *val, size_t default_value)
{
    size_t     size;
    rp_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (rp_http_complex_value(r, val, &value) != RP_OK) {
        return default_value;
    }

    size = rp_parse_size(&value);

    if (size == (size_t) RP_ERROR) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


rp_int_t
rp_http_compile_complex_value(rp_http_compile_complex_value_t *ccv)
{
    rp_str_t                  *v;
    rp_uint_t                  i, n, nv, nc;
    rp_array_t                 flushes, lengths, values, *pf, *pl, *pv;
    rp_http_script_compile_t   sc;

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

    n = nv * (2 * sizeof(rp_http_script_copy_code_t)
                  + sizeof(rp_http_script_var_code_t))
        + sizeof(uintptr_t);

    if (rp_array_init(&lengths, ccv->cf->pool, n, 1) != RP_OK) {
        return RP_ERROR;
    }

    n = (nv * (2 * sizeof(rp_http_script_copy_code_t)
                   + sizeof(rp_http_script_var_code_t))
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

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));

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

    if (rp_http_script_compile(&sc) != RP_OK) {
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
rp_http_set_complex_value_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t                          *value;
    rp_http_complex_value_t          **cv;
    rp_http_compile_complex_value_t    ccv;

    cv = (rp_http_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
    if (*cv == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


char *
rp_http_set_complex_value_size_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                      *rv;
    rp_http_complex_value_t  *cv;

    rv = rp_http_set_complex_value_slot(cf, cmd, conf);

    if (rv != RP_CONF_OK) {
        return rv;
    }

    cv = *(rp_http_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return RP_CONF_OK;
    }

    cv->u.size = rp_parse_size(&cv->value);
    if (cv->u.size == (size_t) RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


rp_int_t
rp_http_test_predicates(rp_http_request_t *r, rp_array_t *predicates)
{
    rp_str_t                  val;
    rp_uint_t                 i;
    rp_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return RP_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (rp_http_complex_value(r, &cv[i], &val) != RP_OK) {
            return RP_ERROR;
        }

        if (val.len && (val.len != 1 || val.data[0] != '0')) {
            return RP_DECLINED;
        }
    }

    return RP_OK;
}


rp_int_t
rp_http_test_required_predicates(rp_http_request_t *r,
    rp_array_t *predicates)
{
    rp_str_t                  val;
    rp_uint_t                 i;
    rp_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return RP_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (rp_http_complex_value(r, &cv[i], &val) != RP_OK) {
            return RP_ERROR;
        }

        if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
            return RP_DECLINED;
        }
    }

    return RP_OK;
}


char *
rp_http_set_predicate_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t                          *value;
    rp_uint_t                          i;
    rp_array_t                       **a;
    rp_http_complex_value_t           *cv;
    rp_http_compile_complex_value_t    ccv;

    a = (rp_array_t **) (p + cmd->offset);

    if (*a == RP_CONF_UNSET_PTR) {
        *a = rp_array_create(cf->pool, 1, sizeof(rp_http_complex_value_t));
        if (*a == NULL) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        cv = rp_array_push(*a);
        if (cv == NULL) {
            return RP_CONF_ERROR;
        }

        rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (rp_http_compile_complex_value(&ccv) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


rp_uint_t
rp_http_script_variables_count(rp_str_t *value)
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
rp_http_script_compile(rp_http_script_compile_t *sc)
{
    u_char       ch;
    rp_str_t    name;
    rp_uint_t   i, bracket;

    if (rp_http_script_init_arrays(sc) != RP_OK) {
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

                if (sc->captures_mask & ((rp_uint_t) 1 << n)) {
                    sc->dup_capture = 1;
                }

                sc->captures_mask |= (rp_uint_t) 1 << n;

                if (rp_http_script_add_capture_code(sc, n) != RP_OK) {
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

            if (rp_http_script_add_var_code(sc, &name) != RP_OK) {
                return RP_ERROR;
            }

            continue;
        }

        if (sc->source->data[i] == '?' && sc->compile_args) {
            sc->args = 1;
            sc->compile_args = 0;

            if (rp_http_script_add_args_code(sc) != RP_OK) {
                return RP_ERROR;
            }

            i++;

            continue;
        }

        name.data = &sc->source->data[i];

        while (i < sc->source->len) {

            if (sc->source->data[i] == '$') {
                break;
            }

            if (sc->source->data[i] == '?') {

                sc->args = 1;

                if (sc->compile_args) {
                    break;
                }
            }

            i++;
            name.len++;
        }

        sc->size += name.len;

        if (rp_http_script_add_copy_code(sc, &name, (i == sc->source->len))
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    return rp_http_script_done(sc);

invalid_variable:

    rp_conf_log_error(RP_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return RP_ERROR;
}


u_char *
rp_http_script_run(rp_http_request_t *r, rp_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    rp_uint_t                    i;
    rp_http_script_code_pt       code;
    rp_http_script_len_code_pt   lcode;
    rp_http_script_engine_t      e;
    rp_http_core_main_conf_t    *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (r->variables[i].no_cacheable) {
            r->variables[i].valid = 0;
            r->variables[i].not_found = 0;
        }
    }

    rp_memzero(&e, sizeof(rp_http_script_engine_t));

    e.ip = code_lengths;
    e.request = r;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rp_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = rp_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(rp_http_script_code_pt *) e.ip;
        code((rp_http_script_engine_t *) &e);
    }

    return e.pos;
}


void
rp_http_script_flush_no_cacheable_variables(rp_http_request_t *r,
    rp_array_t *indices)
{
    rp_uint_t  n, *index;

    if (indices) {
        index = indices->elts;
        for (n = 0; n < indices->nelts; n++) {
            if (r->variables[index[n]].no_cacheable) {
                r->variables[index[n]].valid = 0;
                r->variables[index[n]].not_found = 0;
            }
        }
    }
}


static rp_int_t
rp_http_script_init_arrays(rp_http_script_compile_t *sc)
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
        n = sc->variables * (2 * sizeof(rp_http_script_copy_code_t)
                             + sizeof(rp_http_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = rp_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return RP_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(rp_http_script_copy_code_t)
                              + sizeof(rp_http_script_var_code_t))
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
rp_http_script_done(rp_http_script_compile_t *sc)
{
    rp_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (rp_http_script_add_copy_code(sc, &zero, 0) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (rp_http_script_add_full_name_code(sc) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = rp_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = rp_http_script_add_code(*sc->values, sizeof(uintptr_t),
                                        &sc->main);
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return RP_OK;
}


void *
rp_http_script_start_code(rp_pool_t *pool, rp_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        *codes = rp_array_create(pool, 256, 1);
        if (*codes == NULL) {
            return NULL;
        }
    }

    return rp_array_push_n(*codes, size);
}


void *
rp_http_script_add_code(rp_array_t *codes, size_t size, void *code)
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
rp_http_script_add_copy_code(rp_http_script_compile_t *sc, rp_str_t *value,
    rp_uint_t last)
{
    u_char                       *p;
    size_t                        size, len, zero;
    rp_http_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = rp_http_script_add_code(*sc->lengths,
                                    sizeof(rp_http_script_copy_code_t), NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_http_script_code_pt) (void *)
                                                 rp_http_script_copy_len_code;
    code->len = len;

    size = (sizeof(rp_http_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = rp_http_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_http_script_copy_code;
    code->len = len;

    p = rp_cpymem((u_char *) code + sizeof(rp_http_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return RP_OK;
}


size_t
rp_http_script_copy_len_code(rp_http_script_engine_t *e)
{
    rp_http_script_copy_code_t  *code;

    code = (rp_http_script_copy_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_copy_code_t);

    return code->len;
}


void
rp_http_script_copy_code(rp_http_script_engine_t *e)
{
    u_char                       *p;
    rp_http_script_copy_code_t  *code;

    code = (rp_http_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = rp_copy(p, e->ip + sizeof(rp_http_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(rp_http_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    rp_log_debug2(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script copy: \"%*s\"", e->pos - p, p);
}


static rp_int_t
rp_http_script_add_var_code(rp_http_script_compile_t *sc, rp_str_t *name)
{
    rp_int_t                    index, *p;
    rp_http_script_var_code_t  *code;

    index = rp_http_get_variable_index(sc->cf, name);

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

    code = rp_http_script_add_code(*sc->lengths,
                                    sizeof(rp_http_script_var_code_t), NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_http_script_code_pt) (void *)
                                             rp_http_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = rp_http_script_add_code(*sc->values,
                                    sizeof(rp_http_script_var_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_http_script_copy_var_code;
    code->index = (uintptr_t) index;

    return RP_OK;
}


size_t
rp_http_script_copy_var_len_code(rp_http_script_engine_t *e)
{
    rp_http_variable_value_t   *value;
    rp_http_script_var_code_t  *code;

    code = (rp_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_var_code_t);

    if (e->flushed) {
        value = rp_http_get_indexed_variable(e->request, code->index);

    } else {
        value = rp_http_get_flushed_variable(e->request, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
rp_http_script_copy_var_code(rp_http_script_engine_t *e)
{
    u_char                      *p;
    rp_http_variable_value_t   *value;
    rp_http_script_var_code_t  *code;

    code = (rp_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = rp_http_get_indexed_variable(e->request, code->index);

        } else {
            value = rp_http_get_flushed_variable(e->request, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = rp_copy(p, value->data, value->len);

            rp_log_debug2(RP_LOG_DEBUG_HTTP,
                           e->request->connection->log, 0,
                           "http script var: \"%*s\"", e->pos - p, p);
        }
    }
}


static rp_int_t
rp_http_script_add_args_code(rp_http_script_compile_t *sc)
{
    uintptr_t   *code;

    code = rp_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    *code = (uintptr_t) rp_http_script_mark_args_code;

    code = rp_http_script_add_code(*sc->values, sizeof(uintptr_t), &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    *code = (uintptr_t) rp_http_script_start_args_code;

    return RP_OK;
}


size_t
rp_http_script_mark_args_code(rp_http_script_engine_t *e)
{
    e->is_args = 1;
    e->ip += sizeof(uintptr_t);

    return 1;
}


void
rp_http_script_start_args_code(rp_http_script_engine_t *e)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script args");

    e->is_args = 1;
    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}


#if (RP_PCRE)

void
rp_http_script_regex_start_code(rp_http_script_engine_t *e)
{
    size_t                         len;
    rp_int_t                      rc;
    rp_uint_t                     n;
    rp_http_request_t            *r;
    rp_http_script_engine_t       le;
    rp_http_script_len_code_pt    lcode;
    rp_http_script_regex_code_t  *code;

    code = (rp_http_script_regex_code_t *) e->ip;

    r = e->request;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex: \"%V\"", &code->name);

    if (code->uri) {
        e->line = r->uri;
    } else {
        e->sp--;
        e->line.len = e->sp->len;
        e->line.data = e->sp->data;
    }

    rc = rp_http_regex_exec(r, code->regex, &e->line);

    if (rc == RP_DECLINED) {
        if (e->log || (r->connection->log->log_level & RP_LOG_DEBUG_HTTP)) {
            rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
                          "\"%V\" does not match \"%V\"",
                          &code->name, &e->line);
        }

        r->ncaptures = 0;

        if (code->test) {
            if (code->negative_test) {
                e->sp->len = 1;
                e->sp->data = (u_char *) "1";

            } else {
                e->sp->len = 0;
                e->sp->data = (u_char *) "";
            }

            e->sp++;

            e->ip += sizeof(rp_http_script_regex_code_t);
            return;
        }

        e->ip += code->next;
        return;
    }

    if (rc == RP_ERROR) {
        e->ip = rp_http_script_exit;
        e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->log || (r->connection->log->log_level & RP_LOG_DEBUG_HTTP)) {
        rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
                      "\"%V\" matches \"%V\"", &code->name, &e->line);
    }

    if (code->test) {
        if (code->negative_test) {
            e->sp->len = 0;
            e->sp->data = (u_char *) "";

        } else {
            e->sp->len = 1;
            e->sp->data = (u_char *) "1";
        }

        e->sp++;

        e->ip += sizeof(rp_http_script_regex_code_t);
        return;
    }

    if (code->status) {
        e->status = code->status;

        if (!code->redirect) {
            e->ip = rp_http_script_exit;
            return;
        }
    }

    if (code->uri) {
        r->internal = 1;
        r->valid_unparsed_uri = 0;

        if (code->break_cycle) {
            r->valid_location = 0;
            r->uri_changed = 0;

        } else {
            r->uri_changed = 1;
        }
    }

    if (code->lengths == NULL) {
        e->buf.len = code->size;

        if (code->uri) {
            if (r->ncaptures && (r->quoted_uri || r->plus_in_uri)) {
                e->buf.len += 2 * rp_escape_uri(NULL, r->uri.data, r->uri.len,
                                                 RP_ESCAPE_ARGS);
            }
        }

        for (n = 2; n < r->ncaptures; n += 2) {
            e->buf.len += r->captures[n + 1] - r->captures[n];
        }

    } else {
        rp_memzero(&le, sizeof(rp_http_script_engine_t));

        le.ip = code->lengths->elts;
        le.line = e->line;
        le.request = r;
        le.quote = code->redirect;

        len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(rp_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }

        e->buf.len = len;
    }

    if (code->add_args && r->args.len) {
        e->buf.len += r->args.len + 1;
    }

    e->buf.data = rp_pnalloc(r->pool, e->buf.len);
    if (e->buf.data == NULL) {
        e->ip = rp_http_script_exit;
        e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->quote = code->redirect;

    e->pos = e->buf.data;

    e->ip += sizeof(rp_http_script_regex_code_t);
}


void
rp_http_script_regex_end_code(rp_http_script_engine_t *e)
{
    u_char                            *dst, *src;
    rp_http_request_t                *r;
    rp_http_script_regex_end_code_t  *code;

    code = (rp_http_script_regex_end_code_t *) e->ip;

    r = e->request;

    e->quote = 0;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex end");

    if (code->redirect) {

        dst = e->buf.data;
        src = e->buf.data;

        rp_unescape_uri(&dst, &src, e->pos - e->buf.data,
                         RP_UNESCAPE_REDIRECT);

        if (src < e->pos) {
            dst = rp_movemem(dst, src, e->pos - src);
        }

        e->pos = dst;

        if (code->add_args && r->args.len) {
            *e->pos++ = (u_char) (code->args ? '&' : '?');
            e->pos = rp_copy(e->pos, r->args.data, r->args.len);
        }

        e->buf.len = e->pos - e->buf.data;

        if (e->log || (r->connection->log->log_level & RP_LOG_DEBUG_HTTP)) {
            rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
                          "rewritten redirect: \"%V\"", &e->buf);
        }

        rp_http_clear_location(r);

        r->headers_out.location = rp_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            e->ip = rp_http_script_exit;
            e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        r->headers_out.location->hash = 1;
        rp_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = e->buf;

        e->ip += sizeof(rp_http_script_regex_end_code_t);
        return;
    }

    if (e->args) {
        e->buf.len = e->args - e->buf.data;

        if (code->add_args && r->args.len) {
            *e->pos++ = '&';
            e->pos = rp_copy(e->pos, r->args.data, r->args.len);
        }

        r->args.len = e->pos - e->args;
        r->args.data = e->args;

        e->args = NULL;

    } else {
        e->buf.len = e->pos - e->buf.data;

        if (!code->add_args) {
            r->args.len = 0;
        }
    }

    if (e->log || (r->connection->log->log_level & RP_LOG_DEBUG_HTTP)) {
        rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
                      "rewritten data: \"%V\", args: \"%V\"",
                      &e->buf, &r->args);
    }

    if (code->uri) {
        r->uri = e->buf;

        if (r->uri.len == 0) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "the rewritten URI has a zero length");
            e->ip = rp_http_script_exit;
            e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        rp_http_set_exten(r);
    }

    e->ip += sizeof(rp_http_script_regex_end_code_t);
}


static rp_int_t
rp_http_script_add_capture_code(rp_http_script_compile_t *sc, rp_uint_t n)
{
    rp_http_script_copy_capture_code_t  *code;

    code = rp_http_script_add_code(*sc->lengths,
                                    sizeof(rp_http_script_copy_capture_code_t),
                                    NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_http_script_code_pt) (void *)
                                         rp_http_script_copy_capture_len_code;
    code->n = 2 * n;


    code = rp_http_script_add_code(*sc->values,
                                    sizeof(rp_http_script_copy_capture_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_http_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return RP_OK;
}


size_t
rp_http_script_copy_capture_len_code(rp_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p;
    rp_uint_t                            n;
    rp_http_request_t                   *r;
    rp_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (rp_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_copy_capture_code_t);

    n = code->n;

    if (n < r->ncaptures) {

        cap = r->captures;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            p = r->captures_data;

            return cap[n + 1] - cap[n]
                   + 2 * rp_escape_uri(NULL, &p[cap[n]], cap[n + 1] - cap[n],
                                        RP_ESCAPE_ARGS);
        } else {
            return cap[n + 1] - cap[n];
        }
    }

    return 0;
}


void
rp_http_script_copy_capture_code(rp_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p, *pos;
    rp_uint_t                            n;
    rp_http_request_t                   *r;
    rp_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (rp_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < r->ncaptures) {

        cap = r->captures;
        p = r->captures_data;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            e->pos = (u_char *) rp_escape_uri(pos, &p[cap[n]],
                                               cap[n + 1] - cap[n],
                                               RP_ESCAPE_ARGS);
        } else {
            e->pos = rp_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
        }
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static rp_int_t
rp_http_script_add_full_name_code(rp_http_script_compile_t *sc)
{
    rp_http_script_full_name_code_t  *code;

    code = rp_http_script_add_code(*sc->lengths,
                                    sizeof(rp_http_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = (rp_http_script_code_pt) (void *)
                                            rp_http_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = rp_http_script_add_code(*sc->values,
                                    sizeof(rp_http_script_full_name_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RP_ERROR;
    }

    code->code = rp_http_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return RP_OK;
}


static size_t
rp_http_script_full_name_len_code(rp_http_script_engine_t *e)
{
    rp_http_script_full_name_code_t  *code;

    code = (rp_http_script_full_name_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_full_name_code_t);

    return code->conf_prefix ? rp_cycle->conf_prefix.len:
                               rp_cycle->prefix.len;
}


static void
rp_http_script_full_name_code(rp_http_script_engine_t *e)
{
    rp_http_script_full_name_code_t  *code;

    rp_str_t  value, *prefix;

    code = (rp_http_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (rp_str_t *) &rp_cycle->conf_prefix:
                                 (rp_str_t *) &rp_cycle->prefix;

    if (rp_get_full_name(e->request->pool, prefix, &value) != RP_OK) {
        e->ip = rp_http_script_exit;
        e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->buf = value;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script fullname: \"%V\"", &value);

    e->ip += sizeof(rp_http_script_full_name_code_t);
}


void
rp_http_script_return_code(rp_http_script_engine_t *e)
{
    rp_http_script_return_code_t  *code;

    code = (rp_http_script_return_code_t *) e->ip;

    if (code->status < RP_HTTP_BAD_REQUEST
        || code->text.value.len
        || code->text.lengths)
    {
        e->status = rp_http_send_response(e->request, code->status, NULL,
                                           &code->text);
    } else {
        e->status = code->status;
    }

    e->ip = rp_http_script_exit;
}


void
rp_http_script_break_code(rp_http_script_engine_t *e)
{
    rp_http_request_t  *r;

    r = e->request;

    if (r->uri_changed) {
        r->valid_location = 0;
        r->uri_changed = 0;
    }

    e->ip = rp_http_script_exit;
}


void
rp_http_script_if_code(rp_http_script_engine_t *e)
{
    rp_http_script_if_code_t  *code;

    code = (rp_http_script_if_code_t *) e->ip;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if");

    e->sp--;

    if (e->sp->len && (e->sp->len != 1 || e->sp->data[0] != '0')) {
        if (code->loc_conf) {
            e->request->loc_conf = code->loc_conf;
            rp_http_update_location_config(e->request);
        }

        e->ip += sizeof(rp_http_script_if_code_t);
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if: false");

    e->ip += code->next;
}


void
rp_http_script_equal_code(rp_http_script_engine_t *e)
{
    rp_http_variable_value_t  *val, *res;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && rp_strncmp(val->data, res->data, res->len) == 0)
    {
        *res = rp_http_variable_true_value;
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal: no");

    *res = rp_http_variable_null_value;
}


void
rp_http_script_not_equal_code(rp_http_script_engine_t *e)
{
    rp_http_variable_value_t  *val, *res;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script not equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && rp_strncmp(val->data, res->data, res->len) == 0)
    {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script not equal: no");

        *res = rp_http_variable_null_value;
        return;
    }

    *res = rp_http_variable_true_value;
}


void
rp_http_script_file_code(rp_http_script_engine_t *e)
{
    rp_str_t                     path;
    rp_http_request_t           *r;
    rp_open_file_info_t          of;
    rp_http_core_loc_conf_t     *clcf;
    rp_http_variable_value_t    *value;
    rp_http_script_file_code_t  *code;

    value = e->sp - 1;

    code = (rp_http_script_file_code_t *) e->ip;
    e->ip += sizeof(rp_http_script_file_code_t);

    path.len = value->len - 1;
    path.data = value->data;

    r = e->request;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op %p \"%V\"", (void *) code->op, &path);

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.test_only = 1;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (rp_http_set_disable_symlinks(r, clcf, &path, &of) != RP_OK) {
        e->ip = rp_http_script_exit;
        e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (rp_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != RP_OK)
    {
        if (of.err == 0) {
            e->ip = rp_http_script_exit;
            e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        if (of.err != RP_ENOENT
            && of.err != RP_ENOTDIR
            && of.err != RP_ENAMETOOLONG)
        {
            rp_log_error(RP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, value->data);
        }

        switch (code->op) {

        case rp_http_script_file_plain:
        case rp_http_script_file_dir:
        case rp_http_script_file_exists:
        case rp_http_script_file_exec:
             goto false_value;

        case rp_http_script_file_not_plain:
        case rp_http_script_file_not_dir:
        case rp_http_script_file_not_exists:
        case rp_http_script_file_not_exec:
             goto true_value;
        }

        goto false_value;
    }

    switch (code->op) {
    case rp_http_script_file_plain:
        if (of.is_file) {
             goto true_value;
        }
        goto false_value;

    case rp_http_script_file_not_plain:
        if (of.is_file) {
            goto false_value;
        }
        goto true_value;

    case rp_http_script_file_dir:
        if (of.is_dir) {
             goto true_value;
        }
        goto false_value;

    case rp_http_script_file_not_dir:
        if (of.is_dir) {
            goto false_value;
        }
        goto true_value;

    case rp_http_script_file_exists:
        if (of.is_file || of.is_dir || of.is_link) {
             goto true_value;
        }
        goto false_value;

    case rp_http_script_file_not_exists:
        if (of.is_file || of.is_dir || of.is_link) {
            goto false_value;
        }
        goto true_value;

    case rp_http_script_file_exec:
        if (of.is_exec) {
             goto true_value;
        }
        goto false_value;

    case rp_http_script_file_not_exec:
        if (of.is_exec) {
            goto false_value;
        }
        goto true_value;
    }

false_value:

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op false");

    *value = rp_http_variable_null_value;
    return;

true_value:

    *value = rp_http_variable_true_value;
    return;
}


void
rp_http_script_complex_value_code(rp_http_script_engine_t *e)
{
    size_t                                 len;
    rp_http_script_engine_t               le;
    rp_http_script_len_code_pt            lcode;
    rp_http_script_complex_value_code_t  *code;

    code = (rp_http_script_complex_value_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_complex_value_code_t);

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script complex value");

    rp_memzero(&le, sizeof(rp_http_script_engine_t));

    le.ip = code->lengths->elts;
    le.line = e->line;
    le.request = e->request;
    le.quote = e->quote;

    for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
        lcode = *(rp_http_script_len_code_pt *) le.ip;
    }

    e->buf.len = len;
    e->buf.data = rp_pnalloc(e->request->pool, len);
    if (e->buf.data == NULL) {
        e->ip = rp_http_script_exit;
        e->status = RP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->pos = e->buf.data;

    e->sp->len = e->buf.len;
    e->sp->data = e->buf.data;
    e->sp++;
}


void
rp_http_script_value_code(rp_http_script_engine_t *e)
{
    rp_http_script_value_code_t  *code;

    code = (rp_http_script_value_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_value_code_t);

    e->sp->len = code->text_len;
    e->sp->data = (u_char *) code->text_data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script value: \"%v\"", e->sp);

    e->sp++;
}


void
rp_http_script_set_var_code(rp_http_script_engine_t *e)
{
    rp_http_request_t          *r;
    rp_http_script_var_code_t  *code;

    code = (rp_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_var_code_t);

    r = e->request;

    e->sp--;

    r->variables[code->index].len = e->sp->len;
    r->variables[code->index].valid = 1;
    r->variables[code->index].no_cacheable = 0;
    r->variables[code->index].not_found = 0;
    r->variables[code->index].data = e->sp->data;

#if (RP_DEBUG)
    {
    rp_http_variable_t        *v;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    v = cmcf->variables.elts;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set $%V", &v[code->index].name);
    }
#endif
}


void
rp_http_script_var_set_handler_code(rp_http_script_engine_t *e)
{
    rp_http_script_var_handler_code_t  *code;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set var handler");

    code = (rp_http_script_var_handler_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_var_handler_code_t);

    e->sp--;

    code->handler(e->request, e->sp, code->data);
}


void
rp_http_script_var_code(rp_http_script_engine_t *e)
{
    rp_http_variable_value_t   *value;
    rp_http_script_var_code_t  *code;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script var");

    code = (rp_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rp_http_script_var_code_t);

    value = rp_http_get_flushed_variable(e->request, code->index);

    if (value && !value->not_found) {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script var: \"%v\"", value);

        *e->sp = *value;
        e->sp++;

        return;
    }

    *e->sp = rp_http_variable_null_value;
    e->sp++;
}


void
rp_http_script_nop_code(rp_http_script_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}
