/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2010 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Pierrick Charron <pierrick@php.net>                          |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_STOMP_H
#define PHP_STOMP_H

#include "stomp.h"

typedef struct _stomp_object {
	zend_object std;
	stomp_t *stomp;
} stomp_object_t; 

#define PHP_STOMP_EXTNAME                       "Stomp"
#define PHP_STOMP_MAJOR_VERSION                 "0"
#define PHP_STOMP_MINOR_VERSION                 "4"
#define PHP_STOMP_PATCH_VERSION                 "0"
#define PHP_STOMP_VERSION_STATUS                "-dev"
#define PHP_STOMP_VERSION                       PHP_STOMP_MAJOR_VERSION "." PHP_STOMP_MINOR_VERSION "." PHP_STOMP_PATCH_VERSION PHP_STOMP_VERSION_STATUS

#define PHP_STOMP_RES_NAME                      "stomp connection"

#define PHP_STOMP_CLASSNAME                     "Stomp"
#define PHP_STOMP_FRAME_CLASSNAME               "StompFrame"
#define PHP_STOMP_EXCEPTION_CLASSNAME           "StompException"

#define PHP_STOMP_ERR_UNKNOWN                   "Stomp unknown error"
#define PHP_STOMP_ERR_INVALID_BROKER_URI        "Invalid Broker URI"
#define PHP_STOMP_ERR_INVALID_BROKER_URI_SCHEME "Invalid Broker URI scheme"
#define PHP_STOMP_ERR_SERVER_NOT_RESPONDING     "Server is not responding"
#define PHP_STOMP_ERR_EMPTY_DESTINATION         "Destination can not be empty"
#define PHP_STOMP_ERR_NO_CTR                    "Stomp constructor was not called"

extern zend_module_entry stomp_module_entry;
#define phpext_stomp_ptr &stomp_module_entry

#ifdef PHP_WIN32
#define PHP_STOMP_API __declspec(dllexport)
#else
#define PHP_STOMP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(stomp);
PHP_MSHUTDOWN_FUNCTION(stomp);
PHP_RINIT_FUNCTION(stomp);
PHP_RSHUTDOWN_FUNCTION(stomp);
PHP_MINFO_FUNCTION(stomp);

/* Methods declarations */
PHP_FUNCTION(stomp_version);
PHP_FUNCTION(stomp_connect);
PHP_FUNCTION(stomp_connect_error);
PHP_FUNCTION(stomp_get_session_id);
PHP_FUNCTION(stomp_close);
PHP_FUNCTION(stomp_send);
PHP_FUNCTION(stomp_subscribe);
PHP_FUNCTION(stomp_has_frame);
PHP_FUNCTION(stomp_read_frame);
PHP_FUNCTION(stomp_unsubscribe);
PHP_FUNCTION(stomp_begin);
PHP_FUNCTION(stomp_commit);
PHP_FUNCTION(stomp_abort);
PHP_FUNCTION(stomp_ack);
PHP_FUNCTION(stomp_error);
PHP_FUNCTION(stomp_set_read_timeout);
PHP_FUNCTION(stomp_get_read_timeout);

PHP_METHOD(stompframe, __construct);

ZEND_BEGIN_MODULE_GLOBALS(stomp)
	/* INI */
	char *default_broker;
	long read_timeout_sec;
	long read_timeout_usec;
	long connection_timeout_sec;
	long connection_timeout_usec;

	/* Others */
	long error_no;
	char *error_msg;
ZEND_END_MODULE_GLOBALS(stomp)

#ifdef ZTS
#define STOMP_G(v) TSRMG(stomp_globals_id, zend_stomp_globals *, v)
#else
#define STOMP_G(v) (stomp_globals.v)
#endif 

#endif /* PHP_STOMP_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
