dnl config.m4 for extension stomp

PHP_ARG_ENABLE(stomp, whether to enable stomp support,
[  --enable-stomp           Enable stomp support])

PHP_ARG_WITH(openssl-dir,OpenSSL dir for stomp,
[  --with-openssl-dir[=DIR]  stomp: openssl install prefix], no, no)

if test "$PHP_STOMP" != "no"; then
  PHP_NEW_EXTENSION(stomp, stomp.c php_stomp.c, $ext_shared)

  test -z "$PHP_OPENSSL" && PHP_OPENSSL=no

  if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
    PHP_SETUP_OPENSSL(STOMP_SHARED_LIBADD,
            [
            AC_DEFINE(HAVE_STOMP_SSL,1,[ ])
            ], [
            AC_MSG_ERROR([OpenSSL libraries not found. 

                Check the path given to --with-openssl-dir and output in config.log)
            ])
    ])

    PHP_SUBST(STOMP_SHARED_LIBADD)
  fi
fi
