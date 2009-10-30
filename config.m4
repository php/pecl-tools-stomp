dnl $Id$
dnl config.m4 for extension stomp

PHP_ARG_ENABLE(stomp, whether to enable stomp support,
Make sure that the comment is aligned:
[  --enable-stomp           Enable stomp support])

if test "$PHP_STOMP" != "no"; then
  PHP_NEW_EXTENSION(stomp, stomp.c php_stomp.c, $ext_shared)
fi
