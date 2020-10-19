/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Rap, Inc.
/


/  "casa   [%o2] 0x80, %o1, %o0"  and
/  "casxa  [%o2] 0x80, %o1, %o0"  do the following:
/
/       if ([%o2] == %o1) {
/           swap(%o0, [%o2]);
/       } else {
/           %o0 = [%o2];
/       }


/ rap_atomic_uint_t rap_casa(rap_atomic_uint_t set, rap_atomic_uint_t old,
/      rap_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline rap_casa,0
        casa    [%o2] 0x80, %o1, %o0
        .end


/ rap_atomic_uint_t rap_casxa(rap_atomic_uint_t set, rap_atomic_uint_t old,
/      rap_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline rap_casxa,0
        casxa   [%o2] 0x80, %o1, %o0
        .end
