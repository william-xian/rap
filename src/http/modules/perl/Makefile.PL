
# Copyright (C) Igor Sysoev
# Copyright (C) Rap, Inc.

use 5.006001;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'rap',
    VERSION_FROM      => 'rap.pm',     # finds $VERSION
    PREREQ_PM         => {},             # e.g., Module::Name => 1.1

    ABSTRACT_FROM     => 'rap.pm',     # retrieve abstract from module
    AUTHOR            => 'Igor Sysoev',

    CCFLAGS           => "$ENV{RAP_PM_CFLAGS}",
    OPTIMIZE          => '-O',

    LDDLFLAGS         => "$ENV{RAP_PM_LDFLAGS}",

    INC               => join(" ", map {
                             m#^/# ? "-I $_" : "-I ../../../../../$_"
                         } (split /\s+/, $ENV{RAP_INCS})),

    depend => {
        'rap.c'     => join(" ", map {
                             m#^/# ? $_ : "../../../../../$_"
                         } (split(/\s+/, $ENV{RAP_DEPS}),
                            "src/http/modules/perl/rap_http_perl_module.h"))
    },

    PM => {
        'rap.pm'    => '$(INST_LIBDIR)/rap.pm'
    }
);
