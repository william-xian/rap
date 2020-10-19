
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_PERL_MODULE_H_INCLUDED_
#define _RAP_HTTP_PERL_MODULE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap.h>

#include <EXTERN.h>
#include <perl.h>


typedef rap_http_request_t   *rap;

typedef struct {
    rap_http_request_t       *request;

    rap_str_t                 filename;
    rap_str_t                 redirect_uri;

    SV                       *next;

    rap_int_t                 status;

    unsigned                  done:1;
    unsigned                  error:1;
    unsigned                  variable:1;
    unsigned                  header_sent:1;

    rap_array_t              *variables;  /* array of rap_http_perl_var_t */

#if (RAP_HTTP_SSI)
    rap_http_ssi_ctx_t       *ssi;
#endif
} rap_http_perl_ctx_t;


typedef struct {
    rap_uint_t    hash;
    rap_str_t     name;
    rap_str_t     value;
} rap_http_perl_var_t;


extern rap_module_t  rap_http_perl_module;


/*
 * workaround for "unused variable `Perl___notused'" warning
 * when building with perl 5.6.1
 */
#ifndef PERL_IMPLICIT_CONTEXT
#undef  dTHXa
#define dTHXa(a)
#endif


extern void boot_DynaLoader(pTHX_ CV* cv);


void rap_http_perl_handle_request(rap_http_request_t *r);
void rap_http_perl_sleep_handler(rap_http_request_t *r);


#endif /* _RAP_HTTP_PERL_MODULE_H_INCLUDED_ */
