
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_H_INCLUDED_
#define _RAP_H_INCLUDED_


#define rap_version      1018000
#define RAP_VERSION      "1.18.0"
#define RAP_VER          "rap/" RAP_VERSION

#ifdef RP_BUILD
#define RAP_VER_BUILD    RAP_VER " (" RP_BUILD ")"
#else
#define RAP_VER_BUILD    RAP_VER
#endif

#define RAP_VAR          "RAP"
#define RP_OLDPID_EXT     ".oldbin"


#endif /* _RAP_H_INCLUDED_ */
