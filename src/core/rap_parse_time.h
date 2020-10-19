
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PARSE_TIME_H_INCLUDED_
#define _RAP_PARSE_TIME_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


time_t rap_parse_http_time(u_char *value, size_t len);

/* compatibility */
#define rap_http_parse_time(value, len)  rap_parse_http_time(value, len)


#endif /* _RAP_PARSE_TIME_H_INCLUDED_ */
