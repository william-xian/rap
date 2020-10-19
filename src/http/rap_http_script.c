
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_script_init_arrays(rap_http_script_compile_t *sc);
static rap_int_t rap_http_script_done(rap_http_script_compile_t *sc);
static rap_int_t rap_http_script_add_copy_code(rap_http_script_compile_t *sc,
    rap_str_t *value, rap_uint_t last);
static rap_int_t rap_http_script_add_var_code(rap_http_script_compile_t *sc,
    rap_str_t *name);
static rap_int_t rap_http_script_add_args_code(rap_http_script_compile_t *sc);
#if (RAP_PCRE)
static rap_int_t rap_http_script_add_capture_code(rap_http_script_compile_t *sc,
    rap_uint_t n);
#endif
static rap_int_t
    rap_http_script_add_full_name_code(rap_http_script_compile_t *sc);
static size_t rap_http_script_full_name_len_code(rap_http_script_engine_t *e);
static void rap_http_script_full_name_code(rap_http_script_engine_t *e);


#define rap_http_script_exit  (u_char *) &rap_http_script_exit_code

static uintptr_t rap_http_script_exit_code = (uintptr_t) NULL;


void
rap_http_script_flush_complex_value(rap_http_request_t *r,
    rap_http_complex_value_t *val)
{
    rap_uint_t *index;

    index = val->flushes;

    if (index) {
        while (*index != (rap_uint_t) -1) {

            if (r->variables[*index].no_cacheable) {
                r->variables[*index].valid = 0;
                r->variables[*index].not_found = 0;
            }

            index++;
        }
    }
}


rap_int_t
rap_http_complex_value(rap_http_request_t *r, rap_http_complex_value_t *val,
    rap_str_t *value)
{
    size_t                        len;
    rap_http_script_code_pt       code;
    rap_http_script_len_code_pt   lcode;
    rap_http_script_engine_t      e;

    if (val->lengths == NULL) {
        *value = val->value;
        return RAP_OK;
    }

    rap_http_script_flush_complex_value(r, val);

    rap_memzero(&e, sizeof(rap_http_script_engine_t));

    e.ip = val->lengths;
    e.request = r;
    e.flushed = 1;

    len = 0;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rap_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }

    value->len = len;
    value->data = rap_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return RAP_ERROR;
    }

    e.ip = val->values;
    e.pos = value->data;
    e.buf = *value;

    while (*(uintptr_t *) e.ip) {
        code = *(rap_http_script_code_pt *) e.ip;
        code((rap_http_script_engine_t *) &e);
    }

    *value = e.buf;

    return RAP_OK;
}


size_t
rap_http_complex_value_size(rap_http_request_t *r,
    rap_http_complex_value_t *val, size_t default_value)
{
    size_t     size;
    rap_str_t  value;

    if (val == NULL) {
        return default_value;
    }

    if (val->lengths == NULL) {
        return val->u.size;
    }

    if (rap_http_complex_value(r, val, &value) != RAP_OK) {
        return default_value;
    }

    size = rap_parse_size(&value);

    if (size == (size_t) RAP_ERROR) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "invalid size \"%V\"", &value);
        return default_value;
    }

    return size;
}


rap_int_t
rap_http_compile_complex_value(rap_http_compile_complex_value_t *ccv)
{
    rap_str_t                  *v;
    rap_uint_t                  i, n, nv, nc;
    rap_array_t                 flushes, lengths, values, *pf, *pl, *pv;
    rap_http_script_compile_t   sc;

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

    n = nv * (2 * sizeof(rap_http_script_copy_code_t)
                  + sizeof(rap_http_script_var_code_t))
        + sizeof(uintptr_t);

    if (rap_array_init(&lengths, ccv->cf->pool, n, 1) != RAP_OK) {
        return RAP_ERROR;
    }

    n = (nv * (2 * sizeof(rap_http_script_copy_code_t)
                   + sizeof(rap_http_script_var_code_t))
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

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

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

    if (rap_http_script_compile(&sc) != RAP_OK) {
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
rap_http_set_complex_value_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t                          *value;
    rap_http_complex_value_t          **cv;
    rap_http_compile_complex_value_t    ccv;

    cv = (rap_http_complex_value_t **) (p + cmd->offset);

    if (*cv != NULL) {
        return "is duplicate";
    }

    *cv = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
    if (*cv == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = *cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


char *
rap_http_set_complex_value_size_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    char                      *rv;
    rap_http_complex_value_t  *cv;

    rv = rap_http_set_complex_value_slot(cf, cmd, conf);

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    cv = *(rap_http_complex_value_t **) (p + cmd->offset);

    if (cv->lengths) {
        return RAP_CONF_OK;
    }

    cv->u.size = rap_parse_size(&cv->value);
    if (cv->u.size == (size_t) RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


rap_int_t
rap_http_test_predicates(rap_http_request_t *r, rap_array_t *predicates)
{
    rap_str_t                  val;
    rap_uint_t                 i;
    rap_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return RAP_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (rap_http_complex_value(r, &cv[i], &val) != RAP_OK) {
            return RAP_ERROR;
        }

        if (val.len && (val.len != 1 || val.data[0] != '0')) {
            return RAP_DECLINED;
        }
    }

    return RAP_OK;
}


rap_int_t
rap_http_test_required_predicates(rap_http_request_t *r,
    rap_array_t *predicates)
{
    rap_str_t                  val;
    rap_uint_t                 i;
    rap_http_complex_value_t  *cv;

    if (predicates == NULL) {
        return RAP_OK;
    }

    cv = predicates->elts;

    for (i = 0; i < predicates->nelts; i++) {
        if (rap_http_complex_value(r, &cv[i], &val) != RAP_OK) {
            return RAP_ERROR;
        }

        if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
            return RAP_DECLINED;
        }
    }

    return RAP_OK;
}


char *
rap_http_set_predicate_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t                          *value;
    rap_uint_t                          i;
    rap_array_t                       **a;
    rap_http_complex_value_t           *cv;
    rap_http_compile_complex_value_t    ccv;

    a = (rap_array_t **) (p + cmd->offset);

    if (*a == RAP_CONF_UNSET_PTR) {
        *a = rap_array_create(cf->pool, 1, sizeof(rap_http_complex_value_t));
        if (*a == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        cv = rap_array_push(*a);
        if (cv == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


rap_uint_t
rap_http_script_variables_count(rap_str_t *value)
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
rap_http_script_compile(rap_http_script_compile_t *sc)
{
    u_char       ch;
    rap_str_t    name;
    rap_uint_t   i, bracket;

    if (rap_http_script_init_arrays(sc) != RAP_OK) {
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

                if (sc->captures_mask & ((rap_uint_t) 1 << n)) {
                    sc->dup_capture = 1;
                }

                sc->captures_mask |= (rap_uint_t) 1 << n;

                if (rap_http_script_add_capture_code(sc, n) != RAP_OK) {
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

            if (rap_http_script_add_var_code(sc, &name) != RAP_OK) {
                return RAP_ERROR;
            }

            continue;
        }

        if (sc->source->data[i] == '?' && sc->compile_args) {
            sc->args = 1;
            sc->compile_args = 0;

            if (rap_http_script_add_args_code(sc) != RAP_OK) {
                return RAP_ERROR;
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

        if (rap_http_script_add_copy_code(sc, &name, (i == sc->source->len))
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    return rap_http_script_done(sc);

invalid_variable:

    rap_conf_log_error(RAP_LOG_EMERG, sc->cf, 0, "invalid variable name");

    return RAP_ERROR;
}


u_char *
rap_http_script_run(rap_http_request_t *r, rap_str_t *value,
    void *code_lengths, size_t len, void *code_values)
{
    rap_uint_t                    i;
    rap_http_script_code_pt       code;
    rap_http_script_len_code_pt   lcode;
    rap_http_script_engine_t      e;
    rap_http_core_main_conf_t    *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    for (i = 0; i < cmcf->variables.nelts; i++) {
        if (r->variables[i].no_cacheable) {
            r->variables[i].valid = 0;
            r->variables[i].not_found = 0;
        }
    }

    rap_memzero(&e, sizeof(rap_http_script_engine_t));

    e.ip = code_lengths;
    e.request = r;
    e.flushed = 1;

    while (*(uintptr_t *) e.ip) {
        lcode = *(rap_http_script_len_code_pt *) e.ip;
        len += lcode(&e);
    }


    value->len = len;
    value->data = rap_pnalloc(r->pool, len);
    if (value->data == NULL) {
        return NULL;
    }

    e.ip = code_values;
    e.pos = value->data;

    while (*(uintptr_t *) e.ip) {
        code = *(rap_http_script_code_pt *) e.ip;
        code((rap_http_script_engine_t *) &e);
    }

    return e.pos;
}


void
rap_http_script_flush_no_cacheable_variables(rap_http_request_t *r,
    rap_array_t *indices)
{
    rap_uint_t  n, *index;

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


static rap_int_t
rap_http_script_init_arrays(rap_http_script_compile_t *sc)
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
        n = sc->variables * (2 * sizeof(rap_http_script_copy_code_t)
                             + sizeof(rap_http_script_var_code_t))
            + sizeof(uintptr_t);

        *sc->lengths = rap_array_create(sc->cf->pool, n, 1);
        if (*sc->lengths == NULL) {
            return RAP_ERROR;
        }
    }

    if (*sc->values == NULL) {
        n = (sc->variables * (2 * sizeof(rap_http_script_copy_code_t)
                              + sizeof(rap_http_script_var_code_t))
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
rap_http_script_done(rap_http_script_compile_t *sc)
{
    rap_str_t    zero;
    uintptr_t   *code;

    if (sc->zero) {

        zero.len = 1;
        zero.data = (u_char *) "\0";

        if (rap_http_script_add_copy_code(sc, &zero, 0) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (sc->conf_prefix || sc->root_prefix) {
        if (rap_http_script_add_full_name_code(sc) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (sc->complete_lengths) {
        code = rap_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    if (sc->complete_values) {
        code = rap_http_script_add_code(*sc->values, sizeof(uintptr_t),
                                        &sc->main);
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    return RAP_OK;
}


void *
rap_http_script_start_code(rap_pool_t *pool, rap_array_t **codes, size_t size)
{
    if (*codes == NULL) {
        *codes = rap_array_create(pool, 256, 1);
        if (*codes == NULL) {
            return NULL;
        }
    }

    return rap_array_push_n(*codes, size);
}


void *
rap_http_script_add_code(rap_array_t *codes, size_t size, void *code)
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
rap_http_script_add_copy_code(rap_http_script_compile_t *sc, rap_str_t *value,
    rap_uint_t last)
{
    u_char                       *p;
    size_t                        size, len, zero;
    rap_http_script_copy_code_t  *code;

    zero = (sc->zero && last);
    len = value->len + zero;

    code = rap_http_script_add_code(*sc->lengths,
                                    sizeof(rap_http_script_copy_code_t), NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
    code->len = len;

    size = (sizeof(rap_http_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
            & ~(sizeof(uintptr_t) - 1);

    code = rap_http_script_add_code(*sc->values, size, &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_http_script_copy_code;
    code->len = len;

    p = rap_cpymem((u_char *) code + sizeof(rap_http_script_copy_code_t),
                   value->data, value->len);

    if (zero) {
        *p = '\0';
        sc->zero = 0;
    }

    return RAP_OK;
}


size_t
rap_http_script_copy_len_code(rap_http_script_engine_t *e)
{
    rap_http_script_copy_code_t  *code;

    code = (rap_http_script_copy_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_copy_code_t);

    return code->len;
}


void
rap_http_script_copy_code(rap_http_script_engine_t *e)
{
    u_char                       *p;
    rap_http_script_copy_code_t  *code;

    code = (rap_http_script_copy_code_t *) e->ip;

    p = e->pos;

    if (!e->skip) {
        e->pos = rap_copy(p, e->ip + sizeof(rap_http_script_copy_code_t),
                          code->len);
    }

    e->ip += sizeof(rap_http_script_copy_code_t)
          + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script copy: \"%*s\"", e->pos - p, p);
}


static rap_int_t
rap_http_script_add_var_code(rap_http_script_compile_t *sc, rap_str_t *name)
{
    rap_int_t                    index, *p;
    rap_http_script_var_code_t  *code;

    index = rap_http_get_variable_index(sc->cf, name);

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

    code = rap_http_script_add_code(*sc->lengths,
                                    sizeof(rap_http_script_var_code_t), NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_http_script_code_pt) (void *)
                                             rap_http_script_copy_var_len_code;
    code->index = (uintptr_t) index;

    code = rap_http_script_add_code(*sc->values,
                                    sizeof(rap_http_script_var_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_http_script_copy_var_code;
    code->index = (uintptr_t) index;

    return RAP_OK;
}


size_t
rap_http_script_copy_var_len_code(rap_http_script_engine_t *e)
{
    rap_http_variable_value_t   *value;
    rap_http_script_var_code_t  *code;

    code = (rap_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_var_code_t);

    if (e->flushed) {
        value = rap_http_get_indexed_variable(e->request, code->index);

    } else {
        value = rap_http_get_flushed_variable(e->request, code->index);
    }

    if (value && !value->not_found) {
        return value->len;
    }

    return 0;
}


void
rap_http_script_copy_var_code(rap_http_script_engine_t *e)
{
    u_char                      *p;
    rap_http_variable_value_t   *value;
    rap_http_script_var_code_t  *code;

    code = (rap_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_var_code_t);

    if (!e->skip) {

        if (e->flushed) {
            value = rap_http_get_indexed_variable(e->request, code->index);

        } else {
            value = rap_http_get_flushed_variable(e->request, code->index);
        }

        if (value && !value->not_found) {
            p = e->pos;
            e->pos = rap_copy(p, value->data, value->len);

            rap_log_debug2(RAP_LOG_DEBUG_HTTP,
                           e->request->connection->log, 0,
                           "http script var: \"%*s\"", e->pos - p, p);
        }
    }
}


static rap_int_t
rap_http_script_add_args_code(rap_http_script_compile_t *sc)
{
    uintptr_t   *code;

    code = rap_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) rap_http_script_mark_args_code;

    code = rap_http_script_add_code(*sc->values, sizeof(uintptr_t), &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) rap_http_script_start_args_code;

    return RAP_OK;
}


size_t
rap_http_script_mark_args_code(rap_http_script_engine_t *e)
{
    e->is_args = 1;
    e->ip += sizeof(uintptr_t);

    return 1;
}


void
rap_http_script_start_args_code(rap_http_script_engine_t *e)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script args");

    e->is_args = 1;
    e->args = e->pos;
    e->ip += sizeof(uintptr_t);
}


#if (RAP_PCRE)

void
rap_http_script_regex_start_code(rap_http_script_engine_t *e)
{
    size_t                         len;
    rap_int_t                      rc;
    rap_uint_t                     n;
    rap_http_request_t            *r;
    rap_http_script_engine_t       le;
    rap_http_script_len_code_pt    lcode;
    rap_http_script_regex_code_t  *code;

    code = (rap_http_script_regex_code_t *) e->ip;

    r = e->request;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex: \"%V\"", &code->name);

    if (code->uri) {
        e->line = r->uri;
    } else {
        e->sp--;
        e->line.len = e->sp->len;
        e->line.data = e->sp->data;
    }

    rc = rap_http_regex_exec(r, code->regex, &e->line);

    if (rc == RAP_DECLINED) {
        if (e->log || (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP)) {
            rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
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

            e->ip += sizeof(rap_http_script_regex_code_t);
            return;
        }

        e->ip += code->next;
        return;
    }

    if (rc == RAP_ERROR) {
        e->ip = rap_http_script_exit;
        e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (e->log || (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP)) {
        rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
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

        e->ip += sizeof(rap_http_script_regex_code_t);
        return;
    }

    if (code->status) {
        e->status = code->status;

        if (!code->redirect) {
            e->ip = rap_http_script_exit;
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
                e->buf.len += 2 * rap_escape_uri(NULL, r->uri.data, r->uri.len,
                                                 RAP_ESCAPE_ARGS);
            }
        }

        for (n = 2; n < r->ncaptures; n += 2) {
            e->buf.len += r->captures[n + 1] - r->captures[n];
        }

    } else {
        rap_memzero(&le, sizeof(rap_http_script_engine_t));

        le.ip = code->lengths->elts;
        le.line = e->line;
        le.request = r;
        le.quote = code->redirect;

        len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
            len += lcode(&le);
        }

        e->buf.len = len;
    }

    if (code->add_args && r->args.len) {
        e->buf.len += r->args.len + 1;
    }

    e->buf.data = rap_pnalloc(r->pool, e->buf.len);
    if (e->buf.data == NULL) {
        e->ip = rap_http_script_exit;
        e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->quote = code->redirect;

    e->pos = e->buf.data;

    e->ip += sizeof(rap_http_script_regex_code_t);
}


void
rap_http_script_regex_end_code(rap_http_script_engine_t *e)
{
    u_char                            *dst, *src;
    rap_http_request_t                *r;
    rap_http_script_regex_end_code_t  *code;

    code = (rap_http_script_regex_end_code_t *) e->ip;

    r = e->request;

    e->quote = 0;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex end");

    if (code->redirect) {

        dst = e->buf.data;
        src = e->buf.data;

        rap_unescape_uri(&dst, &src, e->pos - e->buf.data,
                         RAP_UNESCAPE_REDIRECT);

        if (src < e->pos) {
            dst = rap_movemem(dst, src, e->pos - src);
        }

        e->pos = dst;

        if (code->add_args && r->args.len) {
            *e->pos++ = (u_char) (code->args ? '&' : '?');
            e->pos = rap_copy(e->pos, r->args.data, r->args.len);
        }

        e->buf.len = e->pos - e->buf.data;

        if (e->log || (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP)) {
            rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
                          "rewritten redirect: \"%V\"", &e->buf);
        }

        rap_http_clear_location(r);

        r->headers_out.location = rap_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            e->ip = rap_http_script_exit;
            e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        r->headers_out.location->hash = 1;
        rap_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = e->buf;

        e->ip += sizeof(rap_http_script_regex_end_code_t);
        return;
    }

    if (e->args) {
        e->buf.len = e->args - e->buf.data;

        if (code->add_args && r->args.len) {
            *e->pos++ = '&';
            e->pos = rap_copy(e->pos, r->args.data, r->args.len);
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

    if (e->log || (r->connection->log->log_level & RAP_LOG_DEBUG_HTTP)) {
        rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
                      "rewritten data: \"%V\", args: \"%V\"",
                      &e->buf, &r->args);
    }

    if (code->uri) {
        r->uri = e->buf;

        if (r->uri.len == 0) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "the rewritten URI has a zero length");
            e->ip = rap_http_script_exit;
            e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        rap_http_set_exten(r);
    }

    e->ip += sizeof(rap_http_script_regex_end_code_t);
}


static rap_int_t
rap_http_script_add_capture_code(rap_http_script_compile_t *sc, rap_uint_t n)
{
    rap_http_script_copy_capture_code_t  *code;

    code = rap_http_script_add_code(*sc->lengths,
                                    sizeof(rap_http_script_copy_capture_code_t),
                                    NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_http_script_code_pt) (void *)
                                         rap_http_script_copy_capture_len_code;
    code->n = 2 * n;


    code = rap_http_script_add_code(*sc->values,
                                    sizeof(rap_http_script_copy_capture_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_http_script_copy_capture_code;
    code->n = 2 * n;

    if (sc->ncaptures < n) {
        sc->ncaptures = n;
    }

    return RAP_OK;
}


size_t
rap_http_script_copy_capture_len_code(rap_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p;
    rap_uint_t                            n;
    rap_http_request_t                   *r;
    rap_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (rap_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_copy_capture_code_t);

    n = code->n;

    if (n < r->ncaptures) {

        cap = r->captures;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            p = r->captures_data;

            return cap[n + 1] - cap[n]
                   + 2 * rap_escape_uri(NULL, &p[cap[n]], cap[n + 1] - cap[n],
                                        RAP_ESCAPE_ARGS);
        } else {
            return cap[n + 1] - cap[n];
        }
    }

    return 0;
}


void
rap_http_script_copy_capture_code(rap_http_script_engine_t *e)
{
    int                                  *cap;
    u_char                               *p, *pos;
    rap_uint_t                            n;
    rap_http_request_t                   *r;
    rap_http_script_copy_capture_code_t  *code;

    r = e->request;

    code = (rap_http_script_copy_capture_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_copy_capture_code_t);

    n = code->n;

    pos = e->pos;

    if (n < r->ncaptures) {

        cap = r->captures;
        p = r->captures_data;

        if ((e->is_args || e->quote)
            && (e->request->quoted_uri || e->request->plus_in_uri))
        {
            e->pos = (u_char *) rap_escape_uri(pos, &p[cap[n]],
                                               cap[n + 1] - cap[n],
                                               RAP_ESCAPE_ARGS);
        } else {
            e->pos = rap_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
        }
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script capture: \"%*s\"", e->pos - pos, pos);
}

#endif


static rap_int_t
rap_http_script_add_full_name_code(rap_http_script_compile_t *sc)
{
    rap_http_script_full_name_code_t  *code;

    code = rap_http_script_add_code(*sc->lengths,
                                    sizeof(rap_http_script_full_name_code_t),
                                    NULL);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = (rap_http_script_code_pt) (void *)
                                            rap_http_script_full_name_len_code;
    code->conf_prefix = sc->conf_prefix;

    code = rap_http_script_add_code(*sc->values,
                                    sizeof(rap_http_script_full_name_code_t),
                                    &sc->main);
    if (code == NULL) {
        return RAP_ERROR;
    }

    code->code = rap_http_script_full_name_code;
    code->conf_prefix = sc->conf_prefix;

    return RAP_OK;
}


static size_t
rap_http_script_full_name_len_code(rap_http_script_engine_t *e)
{
    rap_http_script_full_name_code_t  *code;

    code = (rap_http_script_full_name_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_full_name_code_t);

    return code->conf_prefix ? rap_cycle->conf_prefix.len:
                               rap_cycle->prefix.len;
}


static void
rap_http_script_full_name_code(rap_http_script_engine_t *e)
{
    rap_http_script_full_name_code_t  *code;

    rap_str_t  value, *prefix;

    code = (rap_http_script_full_name_code_t *) e->ip;

    value.data = e->buf.data;
    value.len = e->pos - e->buf.data;

    prefix = code->conf_prefix ? (rap_str_t *) &rap_cycle->conf_prefix:
                                 (rap_str_t *) &rap_cycle->prefix;

    if (rap_get_full_name(e->request->pool, prefix, &value) != RAP_OK) {
        e->ip = rap_http_script_exit;
        e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->buf = value;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script fullname: \"%V\"", &value);

    e->ip += sizeof(rap_http_script_full_name_code_t);
}


void
rap_http_script_return_code(rap_http_script_engine_t *e)
{
    rap_http_script_return_code_t  *code;

    code = (rap_http_script_return_code_t *) e->ip;

    if (code->status < RAP_HTTP_BAD_REQUEST
        || code->text.value.len
        || code->text.lengths)
    {
        e->status = rap_http_send_response(e->request, code->status, NULL,
                                           &code->text);
    } else {
        e->status = code->status;
    }

    e->ip = rap_http_script_exit;
}


void
rap_http_script_break_code(rap_http_script_engine_t *e)
{
    rap_http_request_t  *r;

    r = e->request;

    if (r->uri_changed) {
        r->valid_location = 0;
        r->uri_changed = 0;
    }

    e->ip = rap_http_script_exit;
}


void
rap_http_script_if_code(rap_http_script_engine_t *e)
{
    rap_http_script_if_code_t  *code;

    code = (rap_http_script_if_code_t *) e->ip;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if");

    e->sp--;

    if (e->sp->len && (e->sp->len != 1 || e->sp->data[0] != '0')) {
        if (code->loc_conf) {
            e->request->loc_conf = code->loc_conf;
            rap_http_update_location_config(e->request);
        }

        e->ip += sizeof(rap_http_script_if_code_t);
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script if: false");

    e->ip += code->next;
}


void
rap_http_script_equal_code(rap_http_script_engine_t *e)
{
    rap_http_variable_value_t  *val, *res;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && rap_strncmp(val->data, res->data, res->len) == 0)
    {
        *res = rap_http_variable_true_value;
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script equal: no");

    *res = rap_http_variable_null_value;
}


void
rap_http_script_not_equal_code(rap_http_script_engine_t *e)
{
    rap_http_variable_value_t  *val, *res;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script not equal");

    e->sp--;
    val = e->sp;
    res = e->sp - 1;

    e->ip += sizeof(uintptr_t);

    if (val->len == res->len
        && rap_strncmp(val->data, res->data, res->len) == 0)
    {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script not equal: no");

        *res = rap_http_variable_null_value;
        return;
    }

    *res = rap_http_variable_true_value;
}


void
rap_http_script_file_code(rap_http_script_engine_t *e)
{
    rap_str_t                     path;
    rap_http_request_t           *r;
    rap_open_file_info_t          of;
    rap_http_core_loc_conf_t     *clcf;
    rap_http_variable_value_t    *value;
    rap_http_script_file_code_t  *code;

    value = e->sp - 1;

    code = (rap_http_script_file_code_t *) e->ip;
    e->ip += sizeof(rap_http_script_file_code_t);

    path.len = value->len - 1;
    path.data = value->data;

    r = e->request;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op %p \"%V\"", (void *) code->op, &path);

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_memzero(&of, sizeof(rap_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.test_only = 1;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (rap_http_set_disable_symlinks(r, clcf, &path, &of) != RAP_OK) {
        e->ip = rap_http_script_exit;
        e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    if (rap_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != RAP_OK)
    {
        if (of.err == 0) {
            e->ip = rap_http_script_exit;
            e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        if (of.err != RAP_ENOENT
            && of.err != RAP_ENOTDIR
            && of.err != RAP_ENAMETOOLONG)
        {
            rap_log_error(RAP_LOG_CRIT, r->connection->log, of.err,
                          "%s \"%s\" failed", of.failed, value->data);
        }

        switch (code->op) {

        case rap_http_script_file_plain:
        case rap_http_script_file_dir:
        case rap_http_script_file_exists:
        case rap_http_script_file_exec:
             goto false_value;

        case rap_http_script_file_not_plain:
        case rap_http_script_file_not_dir:
        case rap_http_script_file_not_exists:
        case rap_http_script_file_not_exec:
             goto true_value;
        }

        goto false_value;
    }

    switch (code->op) {
    case rap_http_script_file_plain:
        if (of.is_file) {
             goto true_value;
        }
        goto false_value;

    case rap_http_script_file_not_plain:
        if (of.is_file) {
            goto false_value;
        }
        goto true_value;

    case rap_http_script_file_dir:
        if (of.is_dir) {
             goto true_value;
        }
        goto false_value;

    case rap_http_script_file_not_dir:
        if (of.is_dir) {
            goto false_value;
        }
        goto true_value;

    case rap_http_script_file_exists:
        if (of.is_file || of.is_dir || of.is_link) {
             goto true_value;
        }
        goto false_value;

    case rap_http_script_file_not_exists:
        if (of.is_file || of.is_dir || of.is_link) {
            goto false_value;
        }
        goto true_value;

    case rap_http_script_file_exec:
        if (of.is_exec) {
             goto true_value;
        }
        goto false_value;

    case rap_http_script_file_not_exec:
        if (of.is_exec) {
            goto false_value;
        }
        goto true_value;
    }

false_value:

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script file op false");

    *value = rap_http_variable_null_value;
    return;

true_value:

    *value = rap_http_variable_true_value;
    return;
}


void
rap_http_script_complex_value_code(rap_http_script_engine_t *e)
{
    size_t                                 len;
    rap_http_script_engine_t               le;
    rap_http_script_len_code_pt            lcode;
    rap_http_script_complex_value_code_t  *code;

    code = (rap_http_script_complex_value_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_complex_value_code_t);

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script complex value");

    rap_memzero(&le, sizeof(rap_http_script_engine_t));

    le.ip = code->lengths->elts;
    le.line = e->line;
    le.request = e->request;
    le.quote = e->quote;

    for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
        lcode = *(rap_http_script_len_code_pt *) le.ip;
    }

    e->buf.len = len;
    e->buf.data = rap_pnalloc(e->request->pool, len);
    if (e->buf.data == NULL) {
        e->ip = rap_http_script_exit;
        e->status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        return;
    }

    e->pos = e->buf.data;

    e->sp->len = e->buf.len;
    e->sp->data = e->buf.data;
    e->sp++;
}


void
rap_http_script_value_code(rap_http_script_engine_t *e)
{
    rap_http_script_value_code_t  *code;

    code = (rap_http_script_value_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_value_code_t);

    e->sp->len = code->text_len;
    e->sp->data = (u_char *) code->text_data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script value: \"%v\"", e->sp);

    e->sp++;
}


void
rap_http_script_set_var_code(rap_http_script_engine_t *e)
{
    rap_http_request_t          *r;
    rap_http_script_var_code_t  *code;

    code = (rap_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_var_code_t);

    r = e->request;

    e->sp--;

    r->variables[code->index].len = e->sp->len;
    r->variables[code->index].valid = 1;
    r->variables[code->index].no_cacheable = 0;
    r->variables[code->index].not_found = 0;
    r->variables[code->index].data = e->sp->data;

#if (RAP_DEBUG)
    {
    rap_http_variable_t        *v;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    v = cmcf->variables.elts;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set $%V", &v[code->index].name);
    }
#endif
}


void
rap_http_script_var_set_handler_code(rap_http_script_engine_t *e)
{
    rap_http_script_var_handler_code_t  *code;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script set var handler");

    code = (rap_http_script_var_handler_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_var_handler_code_t);

    e->sp--;

    code->handler(e->request, e->sp, code->data);
}


void
rap_http_script_var_code(rap_http_script_engine_t *e)
{
    rap_http_variable_value_t   *value;
    rap_http_script_var_code_t  *code;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                   "http script var");

    code = (rap_http_script_var_code_t *) e->ip;

    e->ip += sizeof(rap_http_script_var_code_t);

    value = rap_http_get_flushed_variable(e->request, code->index);

    if (value && !value->not_found) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, e->request->connection->log, 0,
                       "http script var: \"%v\"", value);

        *e->sp = *value;
        e->sp++;

        return;
    }

    *e->sp = rap_http_variable_null_value;
    e->sp++;
}


void
rap_http_script_nop_code(rap_http_script_engine_t *e)
{
    e->ip += sizeof(uintptr_t);
}
