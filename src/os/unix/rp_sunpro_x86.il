/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Rap, Inc.
/

/ rp_atomic_uint_t rp_atomic_cmp_set(rp_atomic_t *lock,
/     rp_atomic_uint_t old, rp_atomic_uint_t set);
/
/ the arguments are passed on stack (%esp), 4(%esp), 8(%esp)

        .inline rp_atomic_cmp_set,0
        movl      (%esp), %ecx
        movl      4(%esp), %eax
        movl      8(%esp), %edx
        lock
        cmpxchgl  %edx, (%ecx)
        setz      %al
        movzbl    %al, %eax
        .end


/ rp_atomic_int_t rp_atomic_fetch_add(rp_atomic_t *value,
/     rp_atomic_int_t add);
/
/ the arguments are passed on stack (%esp), 4(%esp)

        .inline rp_atomic_fetch_add,0
        movl      (%esp), %ecx
        movl      4(%esp), %eax
        lock
        xaddl     %eax, (%ecx)
        .end


/ rp_cpu_pause()
/
/ the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
/ capability added by linker because Solaris/i386 does not know about it:
/
/ ld.so.1: rap: fatal: hardware capability unsupported: 0x2000  [ PAUSE ]

        .inline rp_cpu_pause,0
        rep; nop
        .end
