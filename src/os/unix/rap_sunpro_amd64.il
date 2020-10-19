/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Rap, Inc.
/

/ rap_atomic_uint_t rap_atomic_cmp_set(rap_atomic_t *lock,
/     rap_atomic_uint_t old, rap_atomic_uint_t set);
/
/ the arguments are passed in %rdi, %rsi, %rdx
/ the result is returned in the %rax

        .inline rap_atomic_cmp_set,0
        movq      %rsi, %rax
        lock
        cmpxchgq  %rdx, (%rdi)
        setz      %al
        movzbq    %al, %rax
        .end


/ rap_atomic_int_t rap_atomic_fetch_add(rap_atomic_t *value,
/     rap_atomic_int_t add);
/
/ the arguments are passed in %rdi, %rsi
/ the result is returned in the %rax

        .inline rap_atomic_fetch_add,0
        movq      %rsi, %rax
        lock
        xaddq     %rax, (%rdi)
        .end


/ rap_cpu_pause()
/
/ the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
/ capability added by linker because Solaris/amd64 does not know about it:
/
/ ld.so.1: rap: fatal: hardware capability unsupported: 0x2000 [ PAUSE ]

        .inline rap_cpu_pause,0
        rep; nop
        .end
