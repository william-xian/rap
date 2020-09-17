
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_PERL_MODULE_H_INCLUDED_
#define _RP_HTTP_PERL_MODULE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rap.h>

#include <EXTERN.h>
#include <perl.h>


typedef rp_http_request_t   *rap;

typedef struct {
    rp_http_request_t       *request;

    rp_str_t                 filename;
    rp_str_t                 redirect_uri;

    SV                       *next;

    rp_int_t                 status;

    unsigned                  done:1;
    unsigned                  error:1;
    unsigned                  variable:1;
    unsigned                  header_sent:1;

    rp_array_t              *variables;  /* array of rp_http_perl_var_t */

#if (RP_HTTP_SSI)
    rp_http_ssi_ctx_t       *ssi;
#endif
} rp_http_perl_ctx_t;


typedef struct {
    rp_uint_t    hash;
    rp_str_t     name;
    rp_str_t     value;
} rp_http_perl_var_t;


extern rp_module_t  rp_http_perl_module;


/*
 * workaround for "unused variable `Perl___notused'" warning
 * when building with perl 5.6.1
 */
#ifndef PERL_IMPLICIT_CONTEXT
#undef  dTHXa
#define dTHXa(a)
#endif


extern void boot_DynaLoader(pTHX_ CV* cv);


void rp_http_perl_handle_request(rp_http_request_t *r);
void rp_http_perl_sleep_handler(rp_http_request_t *r);


#endif /* _RP_HTTP_PERL_MODULE_H_INCLUDED_ */
