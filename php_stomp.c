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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_stomp.h"

#include "ext/standard/php_smart_str.h"

#define FETCH_STOMP_OBJECT \
	i_obj = (stomp_object_t *) zend_object_store_get_object(stomp_object TSRMLS_CC); \
	if (!(stomp = i_obj->stomp)) { \
		php_error_docref(NULL TSRMLS_CC, E_WARNING, PHP_STOMP_ERR_NO_CTR); \
		RETURN_FALSE; \
	} 

#define INIT_FRAME_L(frame, cmd, l) \
	frame.command = cmd; \
	frame.command_length = l; \
	ALLOC_HASHTABLE(frame.headers); \
	zend_hash_init(frame.headers, 0, NULL, NULL, 0);

#define INIT_FRAME(frame, cmd) INIT_FRAME_L(frame, cmd, sizeof(cmd)-1)

#define FRAME_HEADER_FROM_HASHTABLE(h, p) \
	HashTable *headers_ht = p; \
	zval **value = NULL; \
	char *string_key = NULL; \
	ulong num_key; \
	for (zend_hash_internal_pointer_reset(headers_ht); \
			zend_hash_get_current_data(headers_ht, (void **)&value) == SUCCESS; \
			zend_hash_move_forward(headers_ht)) { \
		if (zend_hash_get_current_key(headers_ht, &string_key, &num_key, 1) != HASH_KEY_IS_STRING) { \
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid argument or parameter array"); \
			break; \
		} else { \
			if (Z_TYPE_PP(value) != IS_STRING) { \
				SEPARATE_ZVAL(value); \
				convert_to_string(*value); \
			} \
			zend_hash_add(h, string_key, strlen(string_key)+1, Z_STRVAL_PP(value), Z_STRLEN_PP(value)+1, NULL); \
			efree(string_key); \
		} \
	} 

#define CLEAR_FRAME(frame) \
	zend_hash_destroy(frame.headers); \
	efree(frame.headers);

#define STOMP_ERROR(errno, msg) \
	STOMP_G(error_no) = errno; \
	if (STOMP_G(error_msg)) { \
		efree(STOMP_G(error_msg)); \
	} \
	STOMP_G(error_msg) = estrdup(msg); \
	if (stomp_object) { \
		zend_throw_exception_ex(stomp_ce_exception, errno TSRMLS_CC, msg); \
	} 

#define STOMP_ERROR_DETAILS(errno, msg, details) \
	STOMP_G(error_no) = errno; \
	if (STOMP_G(error_msg)) { \
		efree(STOMP_G(error_msg)); \
	} \
    STOMP_G(error_msg) = estrdup(msg); \
    if (stomp_object) { \
        zval *object = zend_throw_exception_ex(stomp_ce_exception, errno TSRMLS_CC, msg); \
        if (details) { \
            zend_update_property_string(stomp_ce_exception, object, "details", sizeof("details")-1, (char *) details TSRMLS_CC); \
        } \
    }

static int le_stomp;

ZEND_DECLARE_MODULE_GLOBALS(stomp)
static PHP_GINIT_FUNCTION(stomp);

/* {{{ stomp_class_entry */
zend_class_entry *stomp_ce_stomp;
zend_class_entry *stomp_ce_exception;
zend_class_entry *stomp_ce_frame;
/* }}} */

/* {{{ arg_info */
ZEND_BEGIN_ARG_INFO_EX(stomp_no_args, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_connect_args, 0, 0, 0)
ZEND_ARG_INFO(0, broker)
ZEND_ARG_INFO(0, username)
ZEND_ARG_INFO(0, password)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_link_only, 0, 0, 1)
ZEND_ARG_INFO(0, link)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_send_args, 0, 0, 3)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, destination)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_send_args, 0, 0, 2)
ZEND_ARG_INFO(0, destination)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_subscribe_args, 0, 0, 2)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, destination)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_subscribe_args, 0, 0, 1)
ZEND_ARG_INFO(0, destination)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_readframe_args, 0, 0, 1)
ZEND_ARG_INFO(0, link)	
ZEND_ARG_INFO(0, class_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_readframe_args, 0, 0, 0)
ZEND_ARG_INFO(0, class_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_transaction_args, 0, 0, 2)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, transaction_id)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_transaction_args, 0, 0, 1)
ZEND_ARG_INFO(0, transaction_id)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_ack_args, 0, 0, 2)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_ack_args, 0, 0, 1)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_set_read_timeout_args, 0, 0, 2)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, seconds)
ZEND_ARG_INFO(0, microseconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_set_read_timeout_args, 0, 0, 1)
ZEND_ARG_INFO(0, seconds)
ZEND_ARG_INFO(0, microseconds)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_frame_construct_args, 0, 0, 0)
ZEND_ARG_INFO(0, command)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_ARG_INFO(0, body)
ZEND_END_ARG_INFO()    
/* }}} */

/* {{{ stomp_functions */
zend_function_entry stomp_functions[] = {
	PHP_FE(stomp_version,           stomp_no_args)
	PHP_FE(stomp_connect,           stomp_connect_args)
	PHP_FE(stomp_connect_error,     stomp_no_args)
	PHP_FE(stomp_get_session_id,    stomp_link_only)
	PHP_FE(stomp_close,             stomp_link_only)
	PHP_FE(stomp_send,              stomp_send_args)
	PHP_FE(stomp_subscribe,         stomp_subscribe_args)
	PHP_FE(stomp_has_frame,         stomp_link_only)
	PHP_FE(stomp_read_frame,        stomp_readframe_args)
	PHP_FE(stomp_unsubscribe,       stomp_subscribe_args)
	PHP_FE(stomp_begin,             stomp_transaction_args)
	PHP_FE(stomp_commit,            stomp_transaction_args)
	PHP_FE(stomp_abort,             stomp_transaction_args)
	PHP_FE(stomp_ack,               stomp_ack_args)
	PHP_FE(stomp_error,             stomp_link_only)
	PHP_FE(stomp_set_read_timeout,  stomp_set_read_timeout_args)
	PHP_FE(stomp_get_read_timeout,  stomp_link_only)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ stomp_methods[] */
static zend_function_entry stomp_methods[] = {
	PHP_FALIAS(__construct,     stomp_connect,           stomp_connect_args)
	PHP_FALIAS(getSessionId,    stomp_get_session_id,    stomp_no_args)
	PHP_FALIAS(__destruct,      stomp_close,             stomp_no_args)
	PHP_FALIAS(send,            stomp_send,              stomp_oop_send_args)
	PHP_FALIAS(subscribe,       stomp_subscribe,         stomp_oop_subscribe_args)
	PHP_FALIAS(hasFrame,        stomp_has_frame,         stomp_no_args)
	PHP_FALIAS(readFrame,       stomp_read_frame,        stomp_oop_readframe_args)
	PHP_FALIAS(unsubscribe,     stomp_unsubscribe,       stomp_oop_subscribe_args)
	PHP_FALIAS(begin,           stomp_begin,             stomp_oop_transaction_args)
	PHP_FALIAS(commit,          stomp_commit,            stomp_oop_transaction_args)
	PHP_FALIAS(abort,           stomp_abort,             stomp_oop_transaction_args)
	PHP_FALIAS(ack,             stomp_ack,               stomp_oop_ack_args)
	PHP_FALIAS(error,           stomp_error,             stomp_no_args)
	PHP_FALIAS(setReadTimeout,  stomp_set_read_timeout,  stomp_oop_set_read_timeout_args)
	PHP_FALIAS(getReadTimeout,  stomp_get_read_timeout,  stomp_no_args)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ stomp_frame_methods[] */
static zend_function_entry stomp_frame_methods[] = {
	PHP_ME(stompframe, __construct, stomp_frame_construct_args, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */ 

/* {{{ stomp_exception_methods[] */
static zend_function_entry stomp_exception_methods[] = {
	PHP_ME(stompexception, getDetails, stomp_no_args, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ stomp_module_entry */
zend_module_entry stomp_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	PHP_STOMP_EXTNAME,
	stomp_functions,
	PHP_MINIT(stomp),
	PHP_MSHUTDOWN(stomp),
	PHP_RINIT(stomp),    
	PHP_RSHUTDOWN(stomp),
	PHP_MINFO(stomp),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_STOMP_VERSION,
#endif
	PHP_MODULE_GLOBALS(stomp),
	PHP_GINIT(stomp),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("stomp.default_broker", "tcp://localhost:61613", PHP_INI_ALL, OnUpdateString, default_broker, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_username", "", PHP_INI_ALL, OnUpdateString, default_username, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_password", "", PHP_INI_ALL, OnUpdateString, default_password, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_read_timeout_sec", "2", PHP_INI_ALL, OnUpdateLong, read_timeout_sec, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_read_timeout_usec", "0", PHP_INI_ALL, OnUpdateLong, read_timeout_usec, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_connection_timeout_sec", "2", PHP_INI_ALL, OnUpdateLong, connection_timeout_sec, zend_stomp_globals, stomp_globals)
STD_PHP_INI_ENTRY("stomp.default_connection_timeout_usec", "0", PHP_INI_ALL, OnUpdateLong, connection_timeout_usec, zend_stomp_globals, stomp_globals)
PHP_INI_END()

/* {{{ PHP_GINIT_FUNCTION */
static PHP_GINIT_FUNCTION(stomp)
{
	stomp_globals->default_broker = NULL;
	stomp_globals->default_username = NULL;
	stomp_globals->default_password = NULL;
	stomp_globals->read_timeout_sec = 2;
	stomp_globals->read_timeout_usec = 0;
	stomp_globals->connection_timeout_sec = 2;
	stomp_globals->connection_timeout_usec = 0;
#if HAVE_STOMP_SSL
	SSL_library_init();
#endif
}
/* }}} */

ZEND_DECLARE_MODULE_GLOBALS(stomp)

#ifdef COMPILE_DL_STOMP
ZEND_GET_MODULE(stomp)
#endif

/* {{{ constructor/destructor */
static void stomp_send_disconnect(stomp_t *stomp TSRMLS_DC)
{
	stomp_frame_t frame = {0}; 
	INIT_FRAME(frame, "DISCONNECT");
	
	stomp_send(stomp, &frame TSRMLS_CC);
	CLEAR_FRAME(frame);
}

static void php_destroy_stomp_res(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	stomp_t *stomp = (stomp_t *) rsrc->ptr;
	stomp_send_disconnect(stomp TSRMLS_CC);
	stomp_close(stomp);
} 

static void stomp_object_free_storage(stomp_object_t *intern TSRMLS_DC)
{
	zend_object_std_dtor(&intern->std TSRMLS_CC);
	if (intern->stomp) {
		stomp_send_disconnect(intern->stomp TSRMLS_CC);
		stomp_close(intern->stomp);
	}
	efree(intern);
}

	 
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 4) || (PHP_MAJOR_VERSION > 5)
#define PHP_STOMP_RUNTIME_CACHE 
#endif 
static zend_object_value php_stomp_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	stomp_object_t *intern;
#ifndef PHP_STOMP_RUNTIME_CACHE	
	zval *tmp;
#endif	

	intern = (stomp_object_t *) ecalloc(1, sizeof(stomp_object_t));
	intern->stomp = NULL;
	
	zend_object_std_init(&intern->std, ce TSRMLS_CC);
#ifdef PHP_STOMP_RUNTIME_CACHE
	object_properties_init(&intern->std, ce);
#else
	zend_hash_copy(intern->std.properties, &ce->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
#endif

	retval.handle = zend_objects_store_put(intern, (zend_objects_store_dtor_t)zend_objects_destroy_object, (zend_objects_free_object_storage_t) stomp_object_free_storage, NULL TSRMLS_CC);
	retval.handlers = zend_get_std_object_handlers();

	return retval;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */
PHP_MINIT_FUNCTION(stomp)
{
	zend_class_entry ce;

	/* Ressource */
	le_stomp = zend_register_list_destructors_ex(php_destroy_stomp_res, NULL, PHP_STOMP_RES_NAME, module_number);

	/* Register Stomp class */
	INIT_CLASS_ENTRY(ce, PHP_STOMP_CLASSNAME, stomp_methods);
	stomp_ce_stomp = zend_register_internal_class(&ce TSRMLS_CC);
	stomp_ce_stomp->create_object = php_stomp_new;

	/* Register StompFrame class */
	INIT_CLASS_ENTRY(ce, PHP_STOMP_FRAME_CLASSNAME, stomp_frame_methods);
	stomp_ce_frame = zend_register_internal_class(&ce TSRMLS_CC);

	/* Properties */
	zend_declare_property_null(stomp_ce_frame, "command", sizeof("command")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(stomp_ce_frame, "headers", sizeof("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(stomp_ce_frame, "body", sizeof("body")-1, ZEND_ACC_PUBLIC TSRMLS_CC); 

	/* Register StompException class */
	INIT_CLASS_ENTRY(ce, PHP_STOMP_EXCEPTION_CLASSNAME, stomp_exception_methods);
	stomp_ce_exception = zend_register_internal_class_ex(&ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);

	/* Properties */
	zend_declare_property_null(stomp_ce_exception, "details", sizeof("details")-1, ZEND_ACC_PRIVATE TSRMLS_CC);

	/** Register INI entries **/
	REGISTER_INI_ENTRIES();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */
PHP_MSHUTDOWN_FUNCTION(stomp)
{ 
	/* Unregister INI entries */
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION */
PHP_RINIT_FUNCTION(stomp)
{
	STOMP_G(error_msg) = NULL;
	STOMP_G(error_no) = 0;

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION */
PHP_RSHUTDOWN_FUNCTION(stomp)
{
	if (STOMP_G(error_msg)) {
		efree(STOMP_G(error_msg));
	}

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(stomp)
{
	php_info_print_table_start();
	php_info_print_table_header(2, PHP_STOMP_EXTNAME, "enabled");
	php_info_print_table_row(2, "API version", PHP_STOMP_VERSION);
#if HAVE_STOMP_SSL
	php_info_print_table_row(2, "SSL Support", "enabled");
#else
	php_info_print_table_row(2, "SSL Support", "disabled");
#endif
	php_info_print_table_end();
	DISPLAY_INI_ENTRIES();
}
/* }}} */

/* {{{ proto string stomp_version() 
   Get stomp extension version */
PHP_FUNCTION(stomp_version) 
{
	RETURN_STRINGL(PHP_STOMP_VERSION, sizeof(PHP_STOMP_VERSION)-1, 1);
}
/* }}} */

/* {{{ proto Stomp::__construct([string broker [, string username [, string password [, array headers]]]])
   Connect to server */
PHP_FUNCTION(stomp_connect)
{
	zval *stomp_object = getThis();
	zval *headers = NULL;
	stomp_t *stomp = NULL;
	char *broker = NULL, *username = NULL, *password = NULL;
	int broker_len = 0, username_len = 0, password_len = 0;
	php_url *url_parts;

#ifdef HAVE_STOMP_SSL    
	int use_ssl = 0;
#endif    

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sssa!", &broker, &broker_len, &username, &username_len, &password, &password_len, &headers) == FAILURE) {
		return;
	}

	/* Verify that broker URI */
	if (!broker) {
		broker = STOMP_G(default_broker);
	}

	url_parts = php_url_parse_ex(broker, strlen(broker));
	
	if (!url_parts || !url_parts->host) {
		STOMP_ERROR(0, PHP_STOMP_ERR_INVALID_BROKER_URI);
		php_url_free(url_parts);
		return;
	}

	if (url_parts->scheme) {
		if (strcmp(url_parts->scheme, "ssl") == 0) {
#if HAVE_STOMP_SSL
			use_ssl = 1;
#else
			STOMP_ERROR(0, "SSL DISABLED");
			php_url_free(url_parts);
			return;
#endif        
		} else if (strcmp(url_parts->scheme, "tcp") != 0) {
			STOMP_ERROR(0, PHP_STOMP_ERR_INVALID_BROKER_URI_SCHEME);
			php_url_free(url_parts);
			return;
		}
	}

	stomp = stomp_init();

#if HAVE_STOMP_SSL
	stomp->options.use_ssl = use_ssl;
#endif 

	stomp->options.read_timeout_sec     = STOMP_G(read_timeout_sec);
	stomp->options.read_timeout_usec    = STOMP_G(read_timeout_usec);
	stomp->options.connect_timeout_sec  = STOMP_G(connection_timeout_sec);
	stomp->options.connect_timeout_usec = STOMP_G(connection_timeout_usec);

	stomp->status = stomp_connect(stomp, url_parts->host, url_parts->port ? url_parts->port : 61613 TSRMLS_CC);
	php_url_free(url_parts);

	if (stomp->status) {
		stomp_frame_t *res;
		stomp_frame_t frame = {0};
 
		INIT_FRAME(frame, "CONNECT");
		if (!username) {
			username = STOMP_G(default_username);
			username_len = strlen(username);
		}
		if (!password) {
			password = STOMP_G(default_password);
			password_len = strlen(password);
		}
		zend_hash_add(frame.headers, "login", sizeof("login"), username, username_len + 1, NULL);
		zend_hash_add(frame.headers, "passcode", sizeof("passcode"), password, password_len + 1, NULL);
 
		if (NULL != headers) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
		}

		stomp_send(stomp, &frame TSRMLS_CC);
		CLEAR_FRAME(frame);
 
		/* Retreive Response */
		res = stomp_read_frame(stomp);
		if (NULL == res) {
			STOMP_ERROR(0, PHP_STOMP_ERR_SERVER_NOT_RESPONDING);
		} else if (0 != strncmp("CONNECTED", res->command, sizeof("CONNECTED")-1)) {
			if (stomp->error) {
				STOMP_ERROR_DETAILS(stomp->errnum, stomp->error, stomp->error_details);
			} else {
				STOMP_ERROR(0, PHP_STOMP_ERR_UNKNOWN);
			}
		} else {
			char *key = NULL;

			if (zend_hash_find(res->headers, "session", sizeof("session"), (void **)&key) == SUCCESS) {
				if (stomp->session) {
					efree(stomp->session);
				}
				stomp->session = estrdup(key);
			}

			stomp_free_frame(res);

			if (!stomp_object) {
				ZEND_REGISTER_RESOURCE(return_value, stomp, le_stomp);
				return; 
			} else {
				stomp_object_t *i_obj = (stomp_object_t *) zend_object_store_get_object(stomp_object TSRMLS_CC);
				if (i_obj->stomp) {
					stomp_close(i_obj->stomp);
				}
				i_obj->stomp = stomp;
				RETURN_TRUE;
			}
		} 
	} else {
		STOMP_ERROR_DETAILS(0, stomp->error, stomp->error_details);
	}

	stomp_close(stomp);
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto string stomp_connect_error() 
   Get the last connection error */
PHP_FUNCTION(stomp_connect_error) 
{
	if (STOMP_G(error_msg)) {
		RETURN_STRING(STOMP_G(error_msg),1);
	} else {
		RETURN_NULL();
	}
}
/* }}} */

/* {{{ proto string Stomp::getSessionId() 
   Get the current stomp session ID */
PHP_FUNCTION(stomp_get_session_id)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &arg) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	if (!stomp) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, PHP_STOMP_ERR_NO_CTR);
		RETURN_FALSE;
	}

	if (stomp->session) {
		RETURN_STRING(stomp->session, 1);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto boolean Stomp::__destruct()
   Close stomp connection */
PHP_FUNCTION(stomp_close)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		FETCH_STOMP_OBJECT;
		stomp_send_disconnect(stomp TSRMLS_CC);
		stomp_close(stomp);
		i_obj->stomp = NULL;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &arg) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
		zend_list_delete(Z_RESVAL_P(arg));
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto boolean Stomp::send(string destination, mixed msg [, array headers])
   Sends a message to a destination in the messaging system */
PHP_FUNCTION(stomp_send)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	char *destination = NULL;
	int destination_length = 0;
	zval *msg = NULL, *headers = NULL;
	stomp_frame_t frame = {0}; 
	int success = 0;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|a!", &destination, &destination_length, &msg, &headers) == FAILURE) {
			return;
		} 
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz|a!", &arg, &destination, &destination_length, &msg, &headers) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	/* Verify destination */
	if (0 == destination_length) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "SEND");
	
	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the destination */
	zend_hash_add(frame.headers, "destination", sizeof("destination"), destination, destination_length + 1, NULL);
	 
	if (Z_TYPE_P(msg) == IS_STRING) {
		frame.body = Z_STRVAL_P(msg);
		frame.body_length = Z_STRLEN_P(msg);
	} else if (Z_TYPE_P(msg) == IS_OBJECT && instanceof_function(Z_OBJCE_P(msg), stomp_ce_frame TSRMLS_CC)) {
		zval *frame_obj_prop = NULL;
		frame_obj_prop = zend_read_property(stomp_ce_frame, msg, "command", sizeof("command")-1, 1 TSRMLS_CC);
		if (Z_TYPE_P(frame_obj_prop) == IS_STRING) {
			frame.command = Z_STRVAL_P(frame_obj_prop);
			frame.command_length = Z_STRLEN_P(frame_obj_prop);
		}
		frame_obj_prop = zend_read_property(stomp_ce_frame, msg, "body", sizeof("body")-1, 1 TSRMLS_CC);
		if (Z_TYPE_P(frame_obj_prop) == IS_STRING) {
			frame.body = Z_STRVAL_P(frame_obj_prop);
			frame.body_length = Z_STRLEN_P(frame_obj_prop);
		}
		frame_obj_prop = zend_read_property(stomp_ce_frame, msg, "headers", sizeof("headers")-1, 1 TSRMLS_CC);
		if (Z_TYPE_P(frame_obj_prop) == IS_ARRAY) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(frame_obj_prop));
		}
	} else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Expects parameter %d to be a string or a StompFrame object.", stomp_object?2:3);
		CLEAR_FRAME(frame);
		RETURN_FALSE;
	}

	if (stomp_send(stomp, &frame TSRMLS_CC) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto boolean Stomp::subscribe(string destination [, array headers])
   Register to listen to a given destination */
PHP_FUNCTION(stomp_subscribe)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	char *destination = NULL;
	int destination_length = 0;
	zval *headers = NULL;
	stomp_frame_t frame = {0}; 
	int success = 0;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|a!", &destination, &destination_length, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|a!", &arg, &destination, &destination_length, &headers) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	/* Verify destination */
	if (0 == destination_length) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "SUBSCRIBE");
	 
	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the destination */
	zend_hash_add(frame.headers, "ack", sizeof("ack"), "client", sizeof("client"), NULL);
	zend_hash_add(frame.headers, "destination", sizeof("destination"), destination, destination_length + 1, NULL);
	zend_hash_add(frame.headers, "activemq.prefetchSize", sizeof("activemq.prefetchSize"), "1", sizeof("1"), NULL); 

	if (stomp_send(stomp, &frame TSRMLS_CC) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto boolean Stomp::unsubscribe(string destination [, array headers])
   Remove an existing subscription */
PHP_FUNCTION(stomp_unsubscribe)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	char *destination = NULL;
	int destination_length = 0;
	zval *headers = NULL;
	stomp_frame_t frame = {0}; 
	int success = 0;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|a!", &destination, &destination_length, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|a!", &arg, &destination, &destination_length, &headers) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	/* Verify destination */
	if (0 == destination_length) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "UNSUBSCRIBE");
	 
	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the destination */
	zend_hash_add(frame.headers, "destination", sizeof("destination"), destination, destination_length + 1, NULL);

	if (stomp_send(stomp, &frame TSRMLS_CC) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto boolean Stomp::hasFrame() 
   Indicate whether or not there is a frame ready to read */
PHP_FUNCTION(stomp_has_frame) 
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &arg) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp);
	}

	RETURN_BOOL(stomp_select(stomp) > 0);
}
/* }}} */

/* {{{ proto StompFrame Stomp::readFrame() 
   Read the next frame */
PHP_FUNCTION(stomp_read_frame)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	stomp_frame_t *res = NULL;
	char *class_name = NULL;
	int class_name_len = 0;
	zend_class_entry *ce = NULL;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &class_name, &class_name_len) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|s", &arg, &class_name, &class_name_len) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp);
	}

	if (class_name_len > 0) { 
		ce = zend_fetch_class(class_name, class_name_len, ZEND_FETCH_CLASS_AUTO TSRMLS_CC);
		if (!ce) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Could not find class '%s'", class_name);
			ce = stomp_ce_frame;
		}
	} else if (stomp_object) {
		ce = stomp_ce_frame;
	}


	if ((res = stomp_read_frame(stomp))) {
		zval *headers = NULL;

		if (0 == strncmp("ERROR", res->command, sizeof("ERROR") - 1)) {
			char *error_msg = NULL;
			if (zend_hash_find(res->headers, "message", sizeof("message"), (void **)&error_msg) == SUCCESS) {
				zval *excobj = zend_throw_exception_ex(stomp_ce_exception, 0 TSRMLS_CC, error_msg);
				if (res->body) {
					zend_update_property_string(stomp_ce_exception, excobj, "details", sizeof("details")-1, (char *) res->body TSRMLS_CC);
				}

				stomp_free_frame(res);
				RETURN_FALSE;
			}
		}
	
		MAKE_STD_ZVAL(headers);
		array_init(headers);
		if (res->headers) {
			char *key;
			ulong pos;
			zend_hash_internal_pointer_reset(res->headers);

			while (zend_hash_get_current_key(res->headers, &key, &pos, 0) == HASH_KEY_IS_STRING) {
				char *value = NULL;
				if (zend_hash_get_current_data(res->headers, (void **)&value) == SUCCESS) {
					add_assoc_string(headers, key, value, 1);
				}
				zend_hash_move_forward(res->headers);
			}
		}
		
		if (ce) {
			zend_fcall_info fci;
			zend_fcall_info_cache fcc;
			zval *retval_ptr;

			object_init_ex(return_value, ce);

			if (ce->constructor) {
				zval *cmd = NULL, *body = NULL;
				ALLOC_ZVAL(cmd);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)								
				Z_SET_REFCOUNT_P(cmd, 1);
				Z_UNSET_ISREF_P(cmd);
#else 
				cmd->refcount = 1;
				cmd->is_ref = 0;
#endif
				ZVAL_STRINGL(cmd, res->command, res->command_length, 1);

				ALLOC_ZVAL(body);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)				
				Z_SET_REFCOUNT_P(body, 1); 
				Z_UNSET_ISREF_P(body);
#else
				body->refcount = 1;
				body->is_ref = 0;
#endif
				if (res->body) {
					ZVAL_STRINGL(body, res->body, res->body_length, 1);
				} else {
					ZVAL_NULL(body);
				}

				fci.size = sizeof(fci);
				fci.function_table = &ce->function_table;
				fci.function_name = NULL;
				fci.symbol_table = NULL;
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
				fci.object_ptr = return_value;
#else 
				fci.object_pp = &return_value;
#endif				
				fci.retval_ptr_ptr = &retval_ptr;

				// PARAMS
				fci.param_count = 3;
				fci.params = (zval***) safe_emalloc(sizeof(zval*), 3, 0);
				fci.params[0] = &cmd;
				fci.params[1] = &headers;
				fci.params[2] = &body;

				fci.no_separation = 1;

				fcc.initialized = 1;
				fcc.function_handler = ce->constructor;
				fcc.calling_scope = EG(scope);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)				
				fcc.called_scope = Z_OBJCE_P(return_value);
				fcc.object_ptr = return_value;
#else
				fcc.object_pp = &return_value;
#endif				
				if (zend_call_function(&fci, &fcc TSRMLS_CC) == FAILURE) {
					zend_throw_exception_ex(zend_exception_get_default(TSRMLS_C), 0 TSRMLS_CC, "Could not execute %s::%s()", ce->name, ce->constructor->common.function_name);
				} else {
					if (retval_ptr) {
						zval_ptr_dtor(&retval_ptr);
					}
				}
				if (fci.params) {
					efree(fci.params);
				}
			
				zval_ptr_dtor(&cmd);
				zval_ptr_dtor(&body);
			}

			zval_ptr_dtor(&headers);
		} else {
			array_init(return_value);
			add_assoc_string_ex(return_value, "command", sizeof("command"), res->command, 1);
			if (res->body) {
				add_assoc_stringl_ex(return_value, "body", sizeof("body"), res->body, res->body_length, 1);
			}
			add_assoc_zval_ex(return_value, "headers", sizeof("headers"), headers);
		}

		stomp_free_frame(res);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ _php_stomp_transaction */
static void _php_stomp_transaction(INTERNAL_FUNCTION_PARAMETERS, char *cmd) {
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	char *transaction_id = NULL;
	int transaction_id_length = 0;
	stomp_frame_t frame = {0}; 
	int success = 0;
	zval *headers = NULL;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|a", &transaction_id, &transaction_id_length, &headers) == FAILURE) {
			return;
		} 
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|a", &arg, &transaction_id, &transaction_id_length, &headers) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	INIT_FRAME_L(frame, cmd, strlen(cmd));

	if (transaction_id_length > 0) { 
		zend_hash_add(frame.headers, "transaction", sizeof("transaction"), transaction_id, transaction_id_length + 1, NULL);
	}

	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	if (stomp_send(stomp, &frame TSRMLS_CC) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto boolean Stomp::begin(string transactionId [, array headers ])
   Start a transaction */
PHP_FUNCTION(stomp_begin)
{
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "BEGIN");
}
/* }}} */

/* {{{ proto boolean Stomp::commit(string transactionId [, array headers ])
   Commit a transaction in progress */
PHP_FUNCTION(stomp_commit)
{
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "COMMIT");
}
/* }}} */

/* {{{ proto boolean Stomp::abort(string transactionId [, array headers ])
   Rollback a transaction in progress */
PHP_FUNCTION(stomp_abort)
{
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ABORT");
}
/* }}} */

/* {{{ proto boolean Stomp::ack(mixed msg [, array headers])
   Acknowledge consumption of a message from a subscription using client acknowledgment */
PHP_FUNCTION(stomp_ack)
{
	zval *stomp_object = getThis();
	zval *msg = NULL, *headers = NULL;
	stomp_t *stomp = NULL;
	stomp_frame_t frame = {0}; 
	int success = 0;

	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|a!", &msg, &headers) == FAILURE) {
			return;
		} 
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz|a!", &arg, &msg, &headers) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	INIT_FRAME(frame, "ACK");

	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	if (Z_TYPE_P(msg) == IS_STRING) {
		zend_hash_add(frame.headers, "message-id", sizeof("message-id"), Z_STRVAL_P(msg), Z_STRLEN_P(msg) + 1, NULL);
	} else if (Z_TYPE_P(msg) == IS_OBJECT && instanceof_function(Z_OBJCE_P(msg), stomp_ce_frame TSRMLS_CC)) {
		zval *frame_obj_prop = zend_read_property(stomp_ce_frame, msg, "headers", sizeof("headers")-1, 1 TSRMLS_CC);
		if (Z_TYPE_P(frame_obj_prop) == IS_ARRAY) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(frame_obj_prop));
		}
	} else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Expects parameter %d to be a string or a StompFrame object.", stomp_object?2:3);
		CLEAR_FRAME(frame);
		RETURN_FALSE;
	}
	
	if (stomp_send(stomp, &frame TSRMLS_CC) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto string Stomp::error() 
   Get the last error message */
PHP_FUNCTION(stomp_error)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &arg) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp);
	}

	if (stomp->error) {
		if (stomp->error_details) {
			char *error_msg = (char *) emalloc(strlen(stomp->error) + strlen(stomp->error_details) + 10);
			strcpy(error_msg, stomp->error);
			strcat(error_msg, "\n\n");
			strcat(error_msg, stomp->error_details);
			RETURN_STRING(error_msg, 0);
		} else {
			RETURN_STRING(stomp->error, 1);
		}
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto void Stomp::setTimeout(int seconds [, int microseconds])
   Set the timeout */
PHP_FUNCTION(stomp_set_read_timeout)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	long sec = 0, usec = 0;
	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &sec, &usec) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT; 
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl|l", &arg, &sec, &usec) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	stomp->options.read_timeout_sec = sec;
	stomp->options.read_timeout_usec = usec;
}
/* }}} */

/* {{{ proto array Stomp::getTimeout() 
   Get the timeout */
PHP_FUNCTION(stomp_get_read_timeout)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	if (stomp_object) {
		stomp_object_t *i_obj = NULL;
		FETCH_STOMP_OBJECT; 
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &arg) == FAILURE) {
			return;
		}
		ZEND_FETCH_RESOURCE(stomp, stomp_t *, &arg, -1, PHP_STOMP_RES_NAME, le_stomp); 
	}

	array_init(return_value);
	add_assoc_long_ex(return_value, "sec", sizeof("sec"), stomp->options.read_timeout_sec);
	add_assoc_long_ex(return_value, "usec", sizeof("usec"), stomp->options.read_timeout_usec);
}
/* }}} */

/* {{{ proto void StompFrame::__construct([string command [, array headers [, string body]]])
   Create StompFrame object */
PHP_METHOD(stompframe, __construct)
{
	zval *object = getThis();
	char *command = NULL, *body = NULL;
	int command_length = 0, body_length = -1;
	zval *headers = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sa!s", &command, &command_length, &headers, &body, &body_length) == FAILURE) {
		return;
	}

	if (command_length > 0) {
		zend_update_property_stringl(stomp_ce_frame, object, "command", sizeof("command")-1, command, command_length TSRMLS_CC);
	}
	if (headers) {
		zend_update_property(stomp_ce_frame, object, "headers", sizeof("headers")-1, headers TSRMLS_CC);
	}
	if (body_length > 0) {
		zend_update_property_stringl(stomp_ce_frame, object, "body", sizeof("body")-1, body, body_length TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto string StompException::getDetails()
   Get error details */
PHP_METHOD(stompexception, getDetails)
{
	zval *object = getThis();	
	zval *details = NULL;

	details = zend_read_property(stomp_ce_exception, object, "details", sizeof("details")-1, 1 TSRMLS_CC);

	RETURN_STRINGL(Z_STRVAL_P(details), Z_STRLEN_P(details), 1);
}
/* }}} */

