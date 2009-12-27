/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2009 The PHP Group                                |
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

typedef struct _stomp {
	php_socket_t fd;    
	php_sockaddr_storage localaddr;
	char *host;
	unsigned short port;
	int status;
	char *error;
	int errnum;
	long read_timeout_sec;
	long read_timeout_usec;
	char *session;
#if HAVE_STOMP_SSL
	SSL *ssl_handle;
	int use_ssl;
#endif
} stomp_t;

typedef struct _stomp_frame {
	char *command;
	int command_length;
	HashTable *headers;
	char *body;
	int body_length;
} stomp_frame_t;

stomp_t *stomp_init(const char *host, unsigned short port, long read_timeout_sec, long read_timeout_usec);
int stomp_connect(stomp_t *stomp TSRMLS_DC);
void stomp_close(stomp_t *stomp);
int stomp_send(stomp_t *connection, stomp_frame_t *frame TSRMLS_DC);
stomp_frame_t *stomp_read_frame(stomp_t *connection);
int stomp_valid_receipt(stomp_t *connection, stomp_frame_t *frame);
int stomp_select(stomp_t *connection);
void stomp_set_error(stomp_t *stomp, const char *error, int errnum);
void frame_destroy(stomp_frame_t *frame);
#endif /* _STOMP_H_ */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
