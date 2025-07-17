/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_stomp.h"
#include "Zend/zend_smart_str.h"

#define GET_STOMP_OBJECT() ((stomp_object_t*) ((char *)Z_OBJ_P(getThis()) - XtOffsetOf(stomp_object_t, std)))
#define FETCH_STOMP_RSRC(result, rsrc) do { \
	result = zend_fetch_resource_ex(rsrc, PHP_STOMP_RES_NAME, le_stomp); \
} while (0)

#define FETCH_STOMP_OBJECT do { \
	stomp_object_t *i_obj = GET_STOMP_OBJECT(); \
	if (!(stomp = i_obj->stomp)) { \
		php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_NO_CTR); \
		RETURN_FALSE; \
	} \
} while (0)

#define INIT_FRAME_HEADERS \
	zend_hash_init(frame.headers, 0, NULL, ZVAL_PTR_DTOR, 0);

#define INIT_FRAME_L(frame, cmd, l) \
	frame.command = cmd; \
	frame.command_length = l; \
	ALLOC_HASHTABLE(frame.headers); \
	INIT_FRAME_HEADERS

#define INIT_FRAME(frame, cmd) INIT_FRAME_L(frame, cmd, sizeof(cmd)-1)

#define FRAME_HEADER_FROM_HASHTABLE(h, p)  do { \
	zval *value, _zv; \
	zend_string *key; \
	ZEND_HASH_FOREACH_STR_KEY_VAL((p), key, value) { \
		if (key == NULL) { \
			php_error_docref(NULL , E_WARNING, "Invalid argument or parameter array"); \
			break; \
		} else { \
			if (strncmp(ZSTR_VAL(key), "content-length", sizeof("content-length")) != 0) { \
				ZVAL_STR(&_zv, zval_get_string(value)); \
				zend_hash_add((h), key, &_zv); \
			} \
		} \
	} ZEND_HASH_FOREACH_END(); \
} while (0)

#define CLEAR_FRAME(frame) \
	zend_hash_destroy(frame.headers); \
	efree(frame.headers);

#define THROW_STOMP_EXCEPTION(excobj, errnum, error) \
	ZVAL_OBJ(excobj, zend_throw_exception_ex(stomp_ce_exception, errnum, "%s", error));

#define STOMP_ERROR(errno, msg) \
	STOMP_G(error_no) = errno; \
	if (STOMP_G(error_msg)) { \
		efree(STOMP_G(error_msg)); \
	} \
	STOMP_G(error_msg) = estrdup(msg); \
	if (stomp_object) { \
		zend_throw_exception_ex(stomp_ce_exception, errno , msg); \
	}

#define STOMP_ERROR_DETAILS(errno, msg, details) \
	STOMP_G(error_no) = errno; \
	if (STOMP_G(error_msg)) { \
		efree(STOMP_G(error_msg)); \
	} \
    STOMP_G(error_msg) = estrdup(msg); \
    if (stomp_object) { \
		zval _object, *object = &_object; \
		THROW_STOMP_EXCEPTION(object, errno, msg) \
        if (details) { \
            zend_update_property_string(stomp_ce_exception, OBJ_FOR_PROP(object), "details", sizeof("details")-1, (char *) details ); \
        } \
    }

#if PHP_VERSION_ID < 70300
#define STOMP_URL_STR(a) (a)
#else
#define STOMP_URL_STR(a) ZSTR_VAL(a)
#endif

#if PHP_VERSION_ID < 80000
#define OBJ_FOR_PROP(zv) (zv)
#else
#define OBJ_FOR_PROP(zv) Z_OBJ_P(zv)
#endif

static int le_stomp;
static zend_object_handlers stomp_obj_handlers;

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

ZEND_BEGIN_ARG_INFO_EX(stomp_nack_args, 0, 0, 2)
ZEND_ARG_INFO(0, link)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_ARRAY_INFO(0, headers, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(stomp_oop_nack_args, 0, 0, 1)
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
	PHP_FE(stomp_nack,              stomp_nack_args)
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
	PHP_FALIAS(nack,            stomp_nack,              stomp_oop_nack_args)
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
	STANDARD_MODULE_HEADER,
	PHP_STOMP_EXTNAME,
	stomp_functions,
	PHP_MINIT(stomp),
	PHP_MSHUTDOWN(stomp),
	PHP_RINIT(stomp),
	PHP_RSHUTDOWN(stomp),
	PHP_MINFO(stomp),
	PHP_STOMP_VERSION,
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
static void stomp_send_disconnect(stomp_t *stomp)
{
	stomp_frame_t frame = {0};
	INIT_FRAME(frame, "DISCONNECT");

	stomp_send(stomp, &frame );
	CLEAR_FRAME(frame);
}

static void php_destroy_stomp_res(zend_resource *rsrc)
{
	stomp_t *stomp = (stomp_t *) rsrc->ptr;
	stomp_send_disconnect(stomp );
	stomp_close(stomp);
}

static zend_object *php_stomp_new(zend_class_entry *ce)
{
	stomp_object_t *intern;

	intern = (stomp_object_t *) ecalloc(1, sizeof(stomp_object_t) + zend_object_properties_size(ce));
	intern->stomp = NULL;

	zend_object_std_init(&intern->std, ce );

	intern->std.handlers = &stomp_obj_handlers;

	return &intern->std;
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
	stomp_ce_stomp = zend_register_internal_class(&ce );
	stomp_ce_stomp->create_object = php_stomp_new;
	memcpy(&stomp_obj_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	stomp_obj_handlers.offset = XtOffsetOf(stomp_object_t, std);

	/* Register StompFrame class */
	INIT_CLASS_ENTRY(ce, PHP_STOMP_FRAME_CLASSNAME, stomp_frame_methods);
	stomp_ce_frame = zend_register_internal_class(&ce );

	/* Properties */
	zend_declare_property_null(stomp_ce_frame, "command", sizeof("command")-1, ZEND_ACC_PUBLIC );
	zend_declare_property_null(stomp_ce_frame, "headers", sizeof("headers")-1, ZEND_ACC_PUBLIC );
	zend_declare_property_null(stomp_ce_frame, "body", sizeof("body")-1, ZEND_ACC_PUBLIC );

	/* Register StompException class */
	INIT_CLASS_ENTRY(ce, PHP_STOMP_EXCEPTION_CLASSNAME, stomp_exception_methods);
	stomp_ce_exception = zend_register_internal_class_ex(&ce, zend_ce_exception);

	/* Properties */
	zend_declare_property_null(stomp_ce_exception, "details", sizeof("details")-1, ZEND_ACC_PRIVATE );

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
	RETURN_STRINGL(PHP_STOMP_VERSION, sizeof(PHP_STOMP_VERSION)-1);
}
/* }}} */

/* {{{ proto Stomp::__construct([string broker [, string username [, string password [, array headers]]]])
   Connect to server */
PHP_FUNCTION(stomp_connect)
{
	zval *stomp_object = getThis();
	zval *headers = NULL;
	stomp_t *stomp = NULL;
	zend_string *broker = NULL, *username = NULL, *password = NULL;
	php_url *url_parts;

#ifdef HAVE_STOMP_SSL
	int use_ssl = 0;
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() , "|SSSa!", &broker, &username, &password, &headers) == FAILURE) {
		return;
	}

	/* Verify that broker URI */
	if (!broker) {
		broker = STOMP_G(default_broker)?
			zend_string_init(STOMP_G(default_broker), strlen(STOMP_G(default_broker)), 0) : NULL;
	} else {
		zend_string_copy(broker);
	}

	url_parts = php_url_parse_ex(ZSTR_VAL(broker), ZSTR_LEN(broker));

	if (!url_parts || !url_parts->host) {
		STOMP_ERROR(0, PHP_STOMP_ERR_INVALID_BROKER_URI);
		zend_string_release(broker);
		php_url_free(url_parts);
		return;
	}
	zend_string_release(broker);

	if (url_parts->scheme) {
		if (strcmp(STOMP_URL_STR(url_parts->scheme), "ssl") == 0) {
#if HAVE_STOMP_SSL
			use_ssl = 1;
#else
			STOMP_ERROR(0, "SSL DISABLED");
			php_url_free(url_parts);
			return;
#endif
		} else if (strcmp(STOMP_URL_STR(url_parts->scheme), "tcp") != 0) {
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

	stomp->status = stomp_connect(stomp, STOMP_URL_STR(url_parts->host), url_parts->port ? url_parts->port : 61613 );
	php_url_free(url_parts);

	if (stomp->status) {
		zval rv;
		stomp_frame_t *res;
		stomp_frame_t frame = {0};
		int send_status;

		INIT_FRAME(frame, "CONNECT");
		if (!username) {
			username = zend_string_init(STOMP_G(default_username), strlen(STOMP_G(default_username)), 0);
		} else {
			zend_string_copy(username);
		}

		if (!password) {
			password = zend_string_init(STOMP_G(default_password), strlen(STOMP_G(default_password)), 0);
		} else {
			zend_string_copy(password);
		}

		/*
		 * Per Stomp 1.1 "login" and "passcode" are optional. (Also this fix makes test pass against RabbitMQ)
		 */
        if (ZSTR_LEN(username) > 0) {
			ZVAL_STR(&rv, zend_string_copy(username));
			zend_hash_str_add(frame.headers, "login", sizeof("login") - 1, &rv);
        }

		if (ZSTR_LEN(password)) {
			ZVAL_STR(&rv, zend_string_copy(password));
			zend_hash_str_add(frame.headers, "passcode", sizeof("passcode"), &rv);
		}

		zend_string_release(username);
		zend_string_release(password);

		if (NULL != headers) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
		}

		send_status = stomp_send(stomp, &frame );
		CLEAR_FRAME(frame);
		if (0 == send_status) {
			zval excobj;
			THROW_STOMP_EXCEPTION(&excobj, stomp->errnum, stomp->error);
			if (stomp->error_details) {
				zend_update_property_string(stomp_ce_exception, OBJ_FOR_PROP(&excobj), "details", sizeof("details")-1, stomp->error_details );
			}
			return;
		}

		/* Retreive Response */
		res = stomp_read_frame_ex(stomp, 0);
		if (NULL == res) {
			STOMP_ERROR(0, PHP_STOMP_ERR_SERVER_NOT_RESPONDING);
		} else if (0 == strncmp("ERROR", res->command, sizeof("ERROR") - 1)) {
			zval *error_msg, excobj;
			if ((error_msg = zend_hash_str_find(res->headers, ZEND_STRL("message"))) != NULL) {
				THROW_STOMP_EXCEPTION(&excobj, 0, ZSTR_VAL(Z_STR_P(error_msg)));
				if (res->body) {
					zend_update_property_string(stomp_ce_exception, OBJ_FOR_PROP(&excobj), "details", sizeof("details")-1, (char *) res->body );
				}
			}
			stomp_free_frame(res);
		} else if (0 != strncmp("CONNECTED", res->command, sizeof("CONNECTED")-1)) {
			if (stomp->error) {
				STOMP_ERROR_DETAILS(stomp->errnum, stomp->error, stomp->error_details);
			} else {
				STOMP_ERROR(0, PHP_STOMP_ERR_UNKNOWN);
			}
			stomp_free_frame(res);
		} else {
			zval *key;
			if ((key = zend_hash_str_find(res->headers, ZEND_STRL("session"))) != NULL) {
				if (stomp->session) {
					efree(stomp->session);
				}
				ZEND_ASSERT(Z_TYPE_P(key) == IS_STRING);
				stomp->session = estrdup(Z_STRVAL_P(key));
			}
			stomp_free_frame(res);
			if (!stomp_object) {
				RETURN_RES(zend_register_resource(stomp, le_stomp));
			} else {
				stomp_object_t *i_obj = GET_STOMP_OBJECT();
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
		RETURN_STRING(STOMP_G(error_msg));
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
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r", &arg) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	if (!stomp) {
		php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_NO_CTR);
		RETURN_FALSE;
	}

	if (stomp->session) {
		RETURN_STRING(stomp->session);
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
		stomp_object_t *i_obj = GET_STOMP_OBJECT();
		if (!(stomp = i_obj->stomp)) {
			php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_NO_CTR);
			RETURN_FALSE;
		}
		stomp_send_disconnect(stomp );
		stomp_close(stomp);
		i_obj->stomp = NULL;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r", &arg) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
		zend_list_close(Z_RES_P(arg));
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
	zend_string *destination;
	zval *msg, *headers = NULL, rv;
	stomp_frame_t frame = {0};
	int success = 0;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "Sz|a!", &destination, &msg, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rSz|a!", &arg, &destination, &msg, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	/* Verify destination */
	if (0 == ZSTR_LEN(destination)) {
		php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "SEND");

	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the destination */
	ZVAL_STR(&rv, zend_string_copy(destination));
	zend_hash_str_add(frame.headers, "destination", sizeof("destination") - 1, &rv);

	if (Z_TYPE_P(msg) == IS_STRING) {
		frame.body = Z_STRVAL_P(msg);
		frame.body_length = Z_STRLEN_P(msg);
	} else if (Z_TYPE_P(msg) == IS_OBJECT && instanceof_function(Z_OBJCE_P(msg), stomp_ce_frame )) {
		zval *frame_obj_prop = NULL;
		frame_obj_prop = zend_read_property(stomp_ce_frame, OBJ_FOR_PROP(msg), "command", sizeof("command")-1, 1, &rv);
		if (Z_TYPE_P(frame_obj_prop) == IS_STRING) {
			frame.command = Z_STRVAL_P(frame_obj_prop);
			frame.command_length = Z_STRLEN_P(frame_obj_prop);
		}
		frame_obj_prop = zend_read_property(stomp_ce_frame, OBJ_FOR_PROP(msg), "body", sizeof("body")-1, 1, &rv);
		if (Z_TYPE_P(frame_obj_prop) == IS_STRING) {
			frame.body = Z_STRVAL_P(frame_obj_prop);
			frame.body_length = Z_STRLEN_P(frame_obj_prop);
		}
		frame_obj_prop = zend_read_property(stomp_ce_frame, OBJ_FOR_PROP(msg), "headers", sizeof("headers")-1, 1, &rv);
		if (Z_TYPE_P(frame_obj_prop) == IS_ARRAY) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(frame_obj_prop));
		}
	} else {
		php_error_docref(NULL , E_WARNING, "Expects parameter %d to be a string or a StompFrame object.", stomp_object?2:3);
		CLEAR_FRAME(frame);
		RETURN_FALSE;
	}

	if (stomp_send(stomp, &frame ) > 0) {
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
	zend_string *destination;
	zval *headers = NULL, rv;
	stomp_frame_t frame = {0};
	int success = 0;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "S|a!", &destination, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rS|a!", &arg, &destination, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	/* Verify destination */
	if (ZSTR_LEN(destination) == 0) {
		php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "SUBSCRIBE");

	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the ack if not already in the headers */
	if (!zend_hash_str_find(frame.headers, ZEND_STRL("ack"))) {
		ZVAL_STRINGL(&rv, "client", sizeof("client") - 1);
		zend_hash_str_update(frame.headers, "ack", sizeof("ack") - 1, &rv);
	}

	/* Add the destination */
	ZVAL_STR(&rv, zend_string_copy(destination));
	zend_hash_str_update(frame.headers, "destination", sizeof("destination") - 1, &rv);
	/* zend_hash_str_add_ptr(frame.headers, ZEND_STRL("activemq.prefetchSize"), estrdup("1")); */

	if (stomp_send(stomp, &frame ) > 0) {
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
	zend_string *destination;
	zval *headers = NULL, rv;
	stomp_frame_t frame = {0};
	int success = 0;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "S|a!", &destination, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg = NULL;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rS|a!", &arg, &destination, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	/* Verify destination */
	if (0 == ZSTR_LEN(destination)) {
		php_error_docref(NULL , E_WARNING, PHP_STOMP_ERR_EMPTY_DESTINATION);
		RETURN_FALSE;
	}

	INIT_FRAME(frame, "UNSUBSCRIBE");

	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	/* Add the destination */
	ZVAL_STR(&rv, zend_string_copy(destination));
	zend_hash_str_add(frame.headers, "destination", sizeof("destination") - 1, &rv);

	if (stomp_send(stomp, &frame ) > 0) {
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
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r", &arg) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
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
	zend_string *class_name = NULL;
	zend_class_entry *ce = NULL;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "|S", &class_name) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r|S", &arg, &class_name) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	if (class_name && ZSTR_LEN(class_name)) {
		ce = zend_fetch_class(class_name, ZEND_FETCH_CLASS_AUTO);
		if (!ce) {
			php_error_docref(NULL , E_WARNING, "Could not find class '%s'", ZSTR_VAL(class_name));
			ce = stomp_ce_frame;
		}
	} else if (stomp_object) {
		ce = stomp_ce_frame;
	}

	if ((res = stomp_read_frame(stomp))) {
		zval headers;

		if (0 == strncmp("ERROR", res->command, sizeof("ERROR") - 1)) {
			zval *error_msg;
			if ((error_msg = zend_hash_str_find(res->headers, "message", sizeof("message") - 1)) != NULL) {
				zval excobj;
				THROW_STOMP_EXCEPTION(&excobj, 0, Z_STRVAL_P(error_msg));
				if (res->body) {
					zend_update_property_string(stomp_ce_exception, OBJ_FOR_PROP(&excobj), ZEND_STRL("details"), (char *)res->body );
				}
				stomp_free_frame(res);
				RETURN_FALSE;
			}
		}

		array_init(&headers);
		if (res->headers) {
			zend_string *key;
			zval *val;
			ZEND_HASH_FOREACH_STR_KEY_VAL(res->headers, key, val) {
				if (!key) {
					break;
				}
				Z_TRY_ADDREF_P(val);
				zend_hash_update(Z_ARRVAL(headers), key, val);
			} ZEND_HASH_FOREACH_END();
		}

		if (ce) {
			zend_fcall_info fci;
			zend_fcall_info_cache fcc;
			zval retval;

			object_init_ex(return_value, ce);

			if (ce->constructor) {
				zval cmd, body;

				ZVAL_STRINGL(&cmd, res->command, res->command_length);

				if (res->body) {
					ZVAL_STRINGL(&body, res->body, res->body_length);
				} else {
					ZVAL_NULL(&body);
				}

				memset(&fci, 0, sizeof(fci));
				memset(&fcc, 0, sizeof(fcc));
				fci.size = sizeof(fci);
#if (PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION == 0)
				fci.function_table = &ce->function_table;
#endif
				/* PARAMS */
				fci.param_count = 3;
				fci.params = (zval*) safe_emalloc(sizeof(zval), 3, 0);
				ZVAL_COPY_VALUE(&fci.params[0], &cmd);
				ZVAL_COPY_VALUE(&fci.params[1], &headers);
				ZVAL_COPY_VALUE(&fci.params[2], &body);

				ZVAL_UNDEF(&fci.function_name);
				fci.object = Z_OBJ_P(return_value);
				fci.retval = &retval;
#if PHP_VERSION_ID < 80000
				fci.no_separation = 1;
#endif
#if PHP_VERSION_ID < 70300
				fcc.initialized = 1;
#endif
				fcc.function_handler = ce->constructor;
#if (PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION == 0)
				fcc.calling_scope = EG(scope);
#else
				fcc.calling_scope = zend_get_executed_scope();
#endif
				fcc.object = Z_OBJ_P(return_value);

				if (zend_call_function(&fci, &fcc ) == FAILURE) {
					zend_throw_exception_ex(zend_ce_exception, 0 , "Could not execute %s::%s()", ZSTR_VAL(ce->name), ZSTR_VAL(ce->constructor->common.function_name));
				} else {
					zval_ptr_dtor(&retval);
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
			add_assoc_string_ex(return_value, "command", sizeof("command") - 1, res->command);
			if (res->body) {
				add_assoc_stringl_ex(return_value, "body", sizeof("body") - 1, res->body, res->body_length);
			}
			add_assoc_zval_ex(return_value, "headers", sizeof("headers") - 1, &headers);
		}

		stomp_free_frame(res);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ _php_stomp_transaction */
static void _php_stomp_transaction(INTERNAL_FUNCTION_PARAMETERS, char *cmd, size_t cmd_len) {
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	zend_string *transaction_id;
	stomp_frame_t frame = {0};
	int success = 0;
	zval *headers = NULL, rv;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "S!|a", &transaction_id, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rS!|a", &arg, &transaction_id, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	INIT_FRAME_L(frame, cmd, cmd_len);

	if (transaction_id && ZSTR_LEN(transaction_id)) {
		ZVAL_STR(&rv, zend_string_copy(transaction_id));
		zend_hash_str_add(frame.headers, "transaction", sizeof("transaction") - 1, &rv);
	}

	/* Translate a PHP array to a stomp_header array */
	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	if (stomp_send(stomp, &frame ) > 0) {
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
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "BEGIN", sizeof("BEGIN") - 1);
}
/* }}} */

/* {{{ proto boolean Stomp::commit(string transactionId [, array headers ])
   Commit a transaction in progress */
PHP_FUNCTION(stomp_commit)
{
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "COMMIT", sizeof("COMMIT") - 1);
}
/* }}} */

/* {{{ proto boolean Stomp::abort(string transactionId [, array headers ])
   Rollback a transaction in progress */
PHP_FUNCTION(stomp_abort)
{
	_php_stomp_transaction(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ABORT", sizeof("ABORT") - 1);
}
/* }}} */

/* {{{ _php_stomp_acknowledgment
 */
static void _php_stomp_acknowledgment(INTERNAL_FUNCTION_PARAMETERS, char *cmd) {
	zval *stomp_object = getThis();
	zval *msg, *headers = NULL;
	stomp_t *stomp = NULL;
	stomp_frame_t frame = {0};
	int success = 0;

	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "z|a!", &msg, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rz|a!", &arg, &msg, &headers) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	INIT_FRAME(frame, cmd);

	if (NULL != headers) {
		FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(headers));
	}

	if (Z_TYPE_P(msg) == IS_STRING) {
		Z_TRY_ADDREF_P(msg);
		zend_hash_str_add(frame.headers, "message-id", sizeof("message-id") - 1, msg);
	} else if (Z_TYPE_P(msg) == IS_OBJECT && instanceof_function(Z_OBJCE_P(msg), stomp_ce_frame )) {
		zval *frame_obj_prop, rv;

		frame_obj_prop = zend_read_property(stomp_ce_frame, OBJ_FOR_PROP(msg), "headers", sizeof("headers")-1, 1, &rv);
		if (Z_TYPE_P(frame_obj_prop) == IS_ARRAY) {
			FRAME_HEADER_FROM_HASHTABLE(frame.headers, Z_ARRVAL_P(frame_obj_prop));
		}
	} else {
		php_error_docref(NULL, E_WARNING,
				"Expects parameter %d to be a string or a StompFrame object.", stomp_object? 2 : 3);
		CLEAR_FRAME(frame);
		RETURN_FALSE;
	}

	if (stomp_send(stomp, &frame ) > 0) {
		success = stomp_valid_receipt(stomp, &frame);
	}

	CLEAR_FRAME(frame);
	RETURN_BOOL(success);
}
/* }}} */

/* {{{ proto boolean Stomp::ack(mixed msg [, array headers])
   Acknowledge consumption of a message from a subscription using client acknowledgment */
PHP_FUNCTION(stomp_ack)
{
	_php_stomp_acknowledgment(INTERNAL_FUNCTION_PARAM_PASSTHRU, "ACK");
}
/* }}} */

/* {{{ proto boolean Stomp::nack(mixed msg [, array headers])
   Negative Acknowledgment of a message from a subscription */
PHP_FUNCTION(stomp_nack)
{
	_php_stomp_acknowledgment(INTERNAL_FUNCTION_PARAM_PASSTHRU, "NACK");
}
/* }}} */

/* {{{ proto string Stomp::error()
   Get the last error message */
PHP_FUNCTION(stomp_error)
{
	zval *stomp_object = getThis();
	stomp_t *stomp = NULL;
	if (stomp_object) {
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r", &arg) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	if (stomp->error) {
		if (stomp->error_details) {
			char *error_msg = (char *) emalloc(strlen(stomp->error) + strlen(stomp->error_details) + 10);
			strcpy(error_msg, stomp->error);
			strcat(error_msg, "\n\n");
			strcat(error_msg, stomp->error_details);
			RETVAL_STRING(error_msg);
			efree(error_msg);
		} else {
			RETURN_STRING(stomp->error);
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
	zend_long sec = 0, usec = 0;
	if (stomp_object) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "l|l", &sec, &usec) == FAILURE) {
			return;
		}
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "rl|l", &arg, &sec, &usec) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
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
		FETCH_STOMP_OBJECT;
	} else {
		zval *arg;
		if (zend_parse_parameters(ZEND_NUM_ARGS() , "r", &arg) == FAILURE) {
			return;
		}
		FETCH_STOMP_RSRC(stomp, arg);
	}

	array_init(return_value);
	add_assoc_long_ex(return_value, "sec", sizeof("sec") - 1, stomp->options.read_timeout_sec);
	add_assoc_long_ex(return_value, "usec", sizeof("usec") - 1, stomp->options.read_timeout_usec);
}
/* }}} */

/* {{{ proto void StompFrame::__construct([string command [, array headers [, string body]]])
   Create StompFrame object */
PHP_METHOD(stompframe, __construct)
{
	zval *object = getThis();
	char *command = NULL, *body = NULL;
	zend_long command_length = 0, body_length = -1;
	zval *headers = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() , "|sa!s", &command, &command_length, &headers, &body, &body_length) == FAILURE) {
		return;
	}

	if (command_length > 0) {
		zend_update_property_stringl(stomp_ce_frame, OBJ_FOR_PROP(object), "command", sizeof("command")-1, command, command_length );
	}
	if (headers) {
		zend_update_property(stomp_ce_frame, OBJ_FOR_PROP(object), "headers", sizeof("headers")-1, headers );
	}
	if (body_length > 0) {
		zend_update_property_stringl(stomp_ce_frame, OBJ_FOR_PROP(object), "body", sizeof("body")-1, body, body_length );
	}
}
/* }}} */

/* {{{ proto string StompException::getDetails()
   Get error details */
PHP_METHOD(stompexception, getDetails)
{
	zval *object = getThis();
	zval rv, *details = zend_read_property(stomp_ce_exception, OBJ_FOR_PROP(object), "details", sizeof("details")-1, 1, &rv);
	RETURN_STR(zval_get_string(details));
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
