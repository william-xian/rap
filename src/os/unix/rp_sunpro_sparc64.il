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


/ rp_atomic_uint_t rp_casa(rp_atomic_uint_t set, rp_atomic_uint_t old,
/      rp_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline rp_casa,0
        casa    [%o2] 0x80, %o1, %o0
        .end


/ rp_atomic_uint_t rp_casxa(rp_atomic_uint_t set, rp_atomic_uint_t old,
/      rp_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline rp_casxa,0
        casxa   [%o2] 0x80, %o1, %o0
        .end
