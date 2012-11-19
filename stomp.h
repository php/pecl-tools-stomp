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

#ifndef _STOMP_H_
#define _STOMP_H_

#include "php_network.h"

#if HAVE_STOMP_SSL
#include <openssl/ssl.h>
#endif

#define STOMP_BUFSIZE 4096

#define INIT_STOMP_FRAME(f) \
	f = (stomp_frame_t *) emalloc(sizeof(stomp_frame_t)); \
	f->command = NULL; f->body = NULL; \
	ALLOC_HASHTABLE(f->headers); \
	zend_hash_init(f->headers, 0, NULL, NULL, 0);

typedef struct _stomp_options {
	long connect_timeout_sec;
	long connect_timeout_usec;
	long read_timeout_sec;
	long read_timeout_usec;
#if HAVE_STOMP_SSL
	int use_ssl;
#endif    
} stomp_options_t;

typedef struct _stomp_frame {
	char *command;
	int command_length;
	HashTable *headers;
	char *body;
	int body_length;
} stomp_frame_t;

typedef struct _stomp_frame_cell {
	stomp_frame_t *frame;
	struct _stomp_frame_cell *next;
} stomp_frame_cell_t;

typedef struct _stomp {
	php_socket_t fd;    
	php_sockaddr_storage localaddr;
	stomp_options_t options;
	char *host;
	unsigned short port;
	int status;
	char *error;
	int errnum;
	char *error_details;
	char *session;
#if HAVE_STOMP_SSL
	SSL *ssl_handle;
#endif
	stomp_frame_cell_t *buffer;
} stomp_t;

stomp_t *stomp_init();
int stomp_connect(stomp_t *stomp, const char *host, unsigned short port TSRMLS_DC);
void stomp_close(stomp_t *stomp);
int stomp_send(stomp_t *connection, stomp_frame_t *frame TSRMLS_DC);
stomp_frame_t *stomp_read_frame(stomp_t *connection);
int stomp_valid_receipt(stomp_t *connection, stomp_frame_t *frame);
int stomp_select_ex(stomp_t *connection, const long int sec, const long int usec);
void stomp_set_error(stomp_t *stomp, const char *error, int errnum, const char *details);
void stomp_free_frame(stomp_frame_t *frame);

#define stomp_select(s) stomp_select_ex(s, s->options.read_timeout_sec, s->options.read_timeout_sec)
#endif /* _STOMP_H_ */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
