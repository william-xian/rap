
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PARSE_TIME_H_INCLUDED_
#define _RP_PARSE_TIME_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


time_t rp_parse_http_time(u_char *value, size_t len);

/* compatibility */
#define rp_http_parse_time(value, len)  rp_parse_http_time(value, len)


#endif /* _RP_PARSE_TIME_H_INCLUDED_ */
