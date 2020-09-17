
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_DLOPEN_H_INCLUDED_
#define _RP_DLOPEN_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define rp_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
#define rp_dlopen_n               "dlopen()"

#define rp_dlsym(handle, symbol)  dlsym(handle, symbol)
#define rp_dlsym_n                "dlsym()"

#define rp_dlclose(handle)        dlclose(handle)
#define rp_dlclose_n              "dlclose()"


#if (RP_HAVE_DLOPEN)
char *rp_dlerror(void);
#endif


#endif /* _RP_DLOPEN_H_INCLUDED_ */
