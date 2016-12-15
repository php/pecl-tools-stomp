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
#include "ext/standard/php_smart_str.h"
#include "stomp.h"
#include "php_stomp.h"
#ifdef HAVE_NETINET_IN_H
#include <netinet/tcp.h>
#endif
#define RETURN_READ_FRAME_FAIL { stomp_free_frame(f); return NULL; }

ZEND_EXTERN_MODULE_GLOBALS(stomp);
extern zend_class_entry *stomp_ce_exception;

/* {{{ DEBUG */
#if PHP_DEBUG
static void print_stomp_frame(stomp_frame_t *frame TSRMLS_DC) {
	php_printf("------ START FRAME ------\n");
	php_printf("%s\n", frame->command);
	/* Headers */
	if (frame->headers) {
		char *key;
		ulong pos;
		zend_hash_internal_pointer_reset(frame->headers);

		while (zend_hash_get_current_key(frame->headers, &key, &pos, 0) == HASH_KEY_IS_STRING) {
			char *value = NULL;

			php_printf("%s:", key);

			if (zend_hash_get_current_data(frame->headers, (void **)&value) == SUCCESS) {
				php_printf("%s", value);
			}

			php_printf("\n");
			zend_hash_move_forward(frame->headers);
		}
	}
	php_printf("\n%s\n", frame->body);
	php_printf("------ END FRAME ------\n");
}
#endif
/* }}} */

/* {{{ stomp_init
 */
stomp_t *stomp_init()
{
	/* Memory allocation */
	stomp_t *stomp = (stomp_t *) emalloc(sizeof(stomp_t));
	memset(stomp, 0, sizeof(*stomp));

	/* Define all values */
	stomp->host = NULL;
	stomp->port = 0;
	stomp->status = 0;
	stomp->error = NULL;
	stomp->error_details = NULL;
	stomp->errnum = 0;
	stomp->session = NULL;
	stomp->options.connect_timeout_sec = 2;
	stomp->options.connect_timeout_usec = 0;
	stomp->options.read_timeout_sec = 2;
	stomp->options.read_timeout_usec = 0;

#if HAVE_STOMP_SSL
	stomp->options.use_ssl = 0;
	stomp->ssl_handle = NULL;
#endif

	stomp->frame_stack = NULL;
	stomp->read_buffer.size = 0;
	return stomp;
}
/* }}} */

/* {{{ stomp_frame_stack_push
 */
static void stomp_frame_stack_push(stomp_frame_stack_t **stack, stomp_frame_t *frame)
{
	stomp_frame_stack_t *cell = (stomp_frame_stack_t *) emalloc(sizeof(stomp_frame_stack_t));
	cell->frame = frame;
	cell->next = NULL;

	if (!*stack) {
		*stack = cell;
	} else {
		stomp_frame_stack_t *cursor = *stack;
		while (cursor->next != NULL) cursor = cursor->next;
		cursor->next = cell;
	}
}
/* }}} */

/* {{{ stomp_frame_stack_shift
 */
static stomp_frame_t *stomp_frame_stack_shift(stomp_frame_stack_t **stack) {
	stomp_frame_t *frame = NULL;
	if (*stack) {
		stomp_frame_stack_t *cell = *stack;
		*stack = cell->next;
		frame = cell->frame;
		efree(cell);
	}
	return frame;
}
/* }}} */

/* {{{ stomp_frame_stack_clear
 */
static void stomp_frame_stack_clear(stomp_frame_stack_t **stack) {
	stomp_frame_t *frame = NULL;
	while ((frame = stomp_frame_stack_shift(stack))) efree(frame);
}
/* }}} */

/* {{{ stomp_set_error
 */
void stomp_set_error(stomp_t *stomp, const char *error, int errnum, const char *fmt, ...)
{
	va_list ap;
	int len;

	if (stomp->error != NULL) {
		efree(stomp->error);
		stomp->error = NULL;
	}
	if (stomp->error_details != NULL) {
		efree(stomp->error_details);
		stomp->error_details = NULL;
	}
	stomp->errnum = errnum;
	if (error != NULL) {
		stomp->error = estrdup(error);
	}
	if (fmt != NULL) {
		stomp->error_details = emalloc(STOMP_BUFSIZE);
		if (stomp->error_details == NULL) {
			return; /* Nothing else can be done */
		}
		va_start(ap, fmt);
		/*
		 * Would've been better to call vasprintf(), but that
		 * function is missing on some platforms...
		 */
		len = vsnprintf(stomp->error_details, STOMP_BUFSIZE, fmt, ap);
		va_end(ap);
		if (len < STOMP_BUFSIZE) {
			stomp->error_details = erealloc(stomp->error_details, len+1);
		}
	}
}
/* }}} */

/* {{{ stomp_writable
 */
int stomp_writable(stomp_t *stomp)
{
	int     n;

	n = php_pollfd_for_ms(stomp->fd, POLLOUT, 1000);
	if (n != POLLOUT) {
#ifndef PHP_WIN32
		if (n == 0) {
			errno = ETIMEDOUT;
		}
#endif
		return 0;
	}

	return 1;
}
/* }}} */

/* {{{ stomp_connect
 */
int stomp_connect(stomp_t *stomp, const char *host, unsigned short port TSRMLS_DC)
{
	char error[1024];
	socklen_t        size;
	struct timeval tv;
	int flag = 1;

	if (stomp->host != NULL)
	{
		efree(stomp->host);
	}
	stomp->host = (char *) emalloc(strlen(host) + 1);
	memcpy(stomp->host, host, strlen(host));
	stomp->host[strlen(host)] = '\0';

	stomp->port = port;

	tv.tv_sec = stomp->options.connect_timeout_sec;
	tv.tv_usec = stomp->options.connect_timeout_usec;

	stomp->fd = php_network_connect_socket_to_host(stomp->host, stomp->port, SOCK_STREAM, 0, &tv, NULL, NULL, NULL, 0 TSRMLS_CC);
	if (stomp->fd == -1) {
		snprintf(error, sizeof(error), "Unable to connect to %s:%ld", stomp->host, stomp->port);
		stomp_set_error(stomp, error, errno, "%s", strerror(errno));
		return 0;
	}

#ifdef HAVE_NETINET_IN_H
	setsockopt(stomp->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
#endif

	size = sizeof(stomp->localaddr);
	memset(&stomp->localaddr, 0, size);
	if (getsockname(stomp->fd, (struct sockaddr*) &stomp->localaddr, &size) == -1) {
		snprintf(error, sizeof(error), "getsockname failed: %s (%d)", strerror(errno), errno);
		stomp_set_error(stomp, error, errno, NULL);
		return 0;
	}

	if (stomp_writable(stomp)) {
#if HAVE_STOMP_SSL
		if (stomp->options.use_ssl) {
			SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
			int ret;

			if (NULL == ctx) {
				stomp_set_error(stomp, "failed to create the SSL context", 0, NULL);
				return 0;
			}

			SSL_CTX_set_options(ctx, SSL_OP_ALL);

			stomp->ssl_handle = SSL_new(ctx);
			if (stomp->ssl_handle == NULL) {
				stomp_set_error(stomp, "failed to create the SSL handle", 0, NULL);
				SSL_CTX_free(ctx);
				return 0;
			}

			SSL_set_fd(stomp->ssl_handle, stomp->fd);

			if ((ret = SSL_connect(stomp->ssl_handle)) <= 0) {
				stomp_set_error(stomp, "SSL/TLS handshake failed", 0, "SSL error %d", SSL_get_error(stomp->ssl_handle, ret));
				SSL_shutdown(stomp->ssl_handle);
				return 0;
			}
		}
#endif
		return 1;
	} else {
		snprintf(error, sizeof(error), "Unable to connect to %s:%ld", stomp->host, stomp->port);
		stomp_set_error(stomp, error, errno, "%s", strerror(errno));
		return 0;
	}
}
/* }}} */

/* {{{ stomp_close
 */
void stomp_close(stomp_t *stomp)
{
	if (NULL == stomp) {
		return;
	}

	if (stomp->fd != -1) {
#if HAVE_STOMP_SSL
		if(stomp->ssl_handle) {
			SSL_shutdown(stomp->ssl_handle);
		}
#endif
		closesocket(stomp->fd);
	}
	if (stomp->host) {
		efree(stomp->host);
	}
	if (stomp->session) {
		efree(stomp->session);
	}
	if (stomp->error) {
		efree(stomp->error);
	}
	if (stomp->error_details) {
		efree(stomp->error_details);
	}
	stomp_frame_stack_clear(&stomp->frame_stack);
	efree(stomp);
}
/* }}} */

/* {{{ stomp_send
 */
int stomp_send(stomp_t *stomp, stomp_frame_t *frame TSRMLS_DC)
{
	smart_str buf = {0};

	/* Command */
	smart_str_appends(&buf, frame->command);
	smart_str_appendc(&buf, '\n');

	/* Headers */
	if (frame->headers) {

		char *key;
		ulong pos;
		zend_hash_internal_pointer_reset(frame->headers);

		while (zend_hash_get_current_key(frame->headers, &key, &pos, 0) == HASH_KEY_IS_STRING) {
			char *value = NULL;

			smart_str_appends(&buf, key);
			smart_str_appendc(&buf, ':');

			if (zend_hash_get_current_data(frame->headers, (void **)&value) == SUCCESS) {
				smart_str_appends(&buf, value);
			}

			smart_str_appendc(&buf, '\n');

			zend_hash_move_forward(frame->headers);
		}
	}

	if (frame->body_length > 0) {
		smart_str_appendl(&buf, "content-length:", sizeof("content-length:") - 1);
		smart_str_append_long(&buf, frame->body_length);
		smart_str_appendc(&buf, '\n');
	}

	smart_str_appendc(&buf, '\n');

	if (frame->body > 0) {
		smart_str_appendl(&buf, frame->body, frame->body_length > 0 ? frame->body_length : strlen(frame->body));
	}

	smart_str_appendl(&buf, "\0", sizeof("\0")-1);

	if (!stomp_writable(stomp)) {
		smart_str_free(&buf);
		stomp_set_error(stomp, "Unable to send data", errno, "%s", strerror(errno));
		return 0;
	}

#ifdef HAVE_STOMP_SSL
	if (stomp->options.use_ssl) {
		int ret;
		if (-1 == (ret = SSL_write(stomp->ssl_handle, buf.c, buf.len))) {
			smart_str_free(&buf);
			stomp_set_error(stomp, "Unable to send data", errno, "SSL error %d", SSL_get_error(stomp->ssl_handle, ret));
			return 0;
		}
	} else {
#endif
		if (-1 == send(stomp->fd, buf.c, buf.len, 0)) {
			smart_str_free(&buf);
			stomp_set_error(stomp, "Unable to send data", errno, "%s", strerror(errno));
			return 0;
		}
#ifdef HAVE_STOMP_SSL
	}
#endif

	smart_str_free(&buf);

	return 1;
}
/* }}} */

/* {{{ stomp_recv
 */
static int _stomp_recv(stomp_t *stomp, char *msg, const size_t length)
{
	int len;

	stomp_select(stomp);

#if HAVE_STOMP_SSL
	if(stomp->options.use_ssl) {
		len = SSL_read(stomp->ssl_handle, msg, length);
	} else {
#endif
		len = recv(stomp->fd, msg, length, 0);
#if HAVE_STOMP_SSL
	}
#endif

	if (len == -1) {
#if HAVE_STOMP_SSL
		if (stomp->options.use_ssl) {
			stomp_set_error(stomp, "Error reading from socket", errno, "%s. (SSL in use)", strerror(errno));
		} else {
#endif
		stomp_set_error(stomp, "Error reading from socket", errno, "%s. (SSL not in use)", strerror(errno));
#if HAVE_STOMP_SSL
		}
#endif
		stomp->status = -1;
	} else if (len == 0) {
		stomp_set_error(stomp, "Sender closed connection unexpectedly", 0, NULL);
		stomp->status = -1;
	}

	return len;
}

int stomp_recv(stomp_t *stomp, char *msg, const size_t length)
{
	if (stomp->read_buffer.size == 0) {
		if (length >= STOMP_BUFSIZE) {
			return _stomp_recv(stomp, msg, length);
		} else {
			size_t recv_size = _stomp_recv(stomp, stomp->read_buffer.buf, STOMP_BUFSIZE);
			if (recv_size <= length) {
				memcpy(msg, stomp->read_buffer.buf, recv_size);
				return recv_size;
			} else {
				memcpy(msg, stomp->read_buffer.buf, length);
				stomp->read_buffer.pos = stomp->read_buffer.buf + length;
				stomp->read_buffer.size = recv_size - length;
				return length;
			}
		}
	} else if (stomp->read_buffer.size >= length) {
		memcpy(msg, stomp->read_buffer.pos, length);
		stomp->read_buffer.pos += length;
		stomp->read_buffer.size -= length;
		return length;
	} else {
		int len = stomp->read_buffer.size;
		memcpy(msg, stomp->read_buffer.pos, stomp->read_buffer.size);
		stomp->read_buffer.size = 0;
		if (stomp_select_ex(stomp, 0, 0)) {
			return len + stomp_recv(stomp, msg + len, length - len);
		} else {
			return len;
		}
	}
}
/* }}} */

/* {{{ _stomp_read_until
 */
static size_t _stomp_read_until(stomp_t *stomp, char **data, const char delimiter)
{
	size_t length = 0;
	size_t bufsize = STOMP_BUFSIZE;
	char *buffer = (char *) emalloc(STOMP_BUFSIZE);

	while (1) {
		unsigned int i, found;
		char *c;
		found = 0;

		//If read_buffer.size == 0 && _stomp_recv == 0 
		//You have to break, or It's endless loop
		if(stomp->read_buffer.status == -1) {
			break;
		}
		// First populate the buffer
		if (stomp->read_buffer.size == 0) {
			stomp->read_buffer.size = _stomp_recv(stomp, stomp->read_buffer.buf, STOMP_BUFSIZE);

			if (stomp->status == -1) {
				length = 0;
				break;
			}

			stomp->read_buffer.pos = stomp->read_buffer.buf;
		}

		// Then search the delimiter
		c = stomp->read_buffer.pos;
		for (i = 1; i <= stomp->read_buffer.size ; i++) {
			if (*c == delimiter) {
				found = 1;
				break;
			} else {
				c++;
			}
		}
		if (!found) i--;

		// Make sure we have enough place in the buffer
		if ((i+length) >= bufsize) {
			buffer = (char *) erealloc(buffer, bufsize + STOMP_BUFSIZE);
			bufsize += STOMP_BUFSIZE;
		}

		// Copy and update the buffer
		memcpy(buffer + length, stomp->read_buffer.pos, i);
		length += i;
		stomp->read_buffer.pos += i;
		stomp->read_buffer.size -= i;

		if (found) {
			break;
		}
	}

	if (length) {
		*data = buffer;
	} else {
		efree(buffer);
		*data = NULL;
	}

	return length;
}
/* }}} */

/* {{{ stomp_read_buffer
 */
static size_t stomp_read_buffer(stomp_t *stomp, char **data)
{
	size_t length = _stomp_read_until(stomp, data, 0);
	if (stomp_select_ex(stomp, 0, 0)) {
		char endline[1];
		if (1 != stomp_recv(stomp, endline, 1) && '\n' != endline[0]) {
			if (*data) {
				efree(*data);
				*data = NULL;
			}
			return 0;
		}
	}
	if (length > 1) {
		length --;
	} else 	if (length) {
		efree(*data);
		*data = NULL;
		length = 0;
	}
	return length;
}
/* }}} */

/* {{{ stomp_read_line
 */
static int stomp_read_line(stomp_t *stomp, char **data)
{
	size_t length = _stomp_read_until(stomp, data, '\n');
	if (length > 1) {
		(*data)[length - 1] = 0;
		length--;
	} else if (length) {
		efree(*data);
		*data = NULL;
		length = 0;
	}
	return length;
}
/* }}} */

/* {{{ stomp_free_frame
 */
void stomp_free_frame(stomp_frame_t *frame)
{
	if (frame) {
		if (frame->command) {
			efree(frame->command);
		}
		if (frame->body) {
			efree(frame->body);
		}
		if (frame->headers) {
			zend_hash_destroy(frame->headers);
			efree(frame->headers);
		}
		efree(frame);
	}
}
/* }}} */

/* {{{ stomp_read_frame
 */
stomp_frame_t *stomp_read_frame_ex(stomp_t *stomp, int use_stack)
{
	stomp_frame_t *f = NULL;
	char *cmd = NULL, *length_str = NULL;
	int length = 0;

	if (use_stack && stomp->frame_stack) {
		return stomp_frame_stack_shift(&stomp->frame_stack);
	}

	if (!stomp_select(stomp)) {
		return NULL;
	}

	INIT_STOMP_FRAME(f);

	if (NULL == f) {
		return NULL;
	}

	/* Parse the command */
	length = stomp_read_line(stomp, &cmd);
	if (length < 1) {
		RETURN_READ_FRAME_FAIL;
	}

	f->command = cmd;
	f->command_length = length;

	/* Parse the header */
	while (1) {
		char *p = NULL;
		length = stomp_read_line(stomp, &p);

		if (length < 0) {
			RETURN_READ_FRAME_FAIL;
		}

		if (0 == length) {
			break;
		} else {
			char *p2 = NULL;
			char *key;
			char *value;

			p2 = strstr(p,":");

			if (p2 == NULL) {
				efree(p);
				RETURN_READ_FRAME_FAIL;
			}

			/* Null terminate the key */
			*p2=0;
			key = p;

			/* The rest is the value. */
			value = p2+1;

			/* Insert key/value into hash table. */
			zend_hash_add(f->headers, key, strlen(key) + 1, value, strlen(value) + 1, NULL);
			efree(p);
		}
	}

	/* Check for the content length */
	if (zend_hash_find(f->headers, "content-length", sizeof("content-length"), (void **)&length_str) == SUCCESS) {
		int recv_size = 0;
		char endbuffer[2];

		f->body_length = atoi(length_str);
		f->body = (char *) emalloc(f->body_length);

		while (recv_size != f->body_length) {
			int l = stomp_recv(stomp, f->body + recv_size, f->body_length - recv_size);
			if (-1 == l) {
				RETURN_READ_FRAME_FAIL;
			} else {
				recv_size += l;
			}
		}

		length = stomp_recv(stomp, endbuffer, 2);
		if (endbuffer[0] != '\0' || ((2 == length) && (endbuffer[1] != '\n'))) {
			RETURN_READ_FRAME_FAIL;
		}

	} else {
		f->body_length = stomp_read_buffer(stomp, &f->body);
	}

	return f;
}
/* }}} */

/* {{{ stomp_valid_receipt
 */
int stomp_valid_receipt(stomp_t *stomp, stomp_frame_t *frame) {
	int success = 1;
	char *receipt = NULL;

	if (zend_hash_find(frame->headers, "receipt", sizeof("receipt"), (void **)&receipt) == SUCCESS) {
		success = 0;
		while (1) {
			stomp_frame_t *res = stomp_read_frame_ex(stomp, 0);
			if (res) {
				if (0 == strncmp("RECEIPT", res->command, sizeof("RECEIPT") - 1)) {
					char *receipt_id = NULL;
					if (zend_hash_find(res->headers, "receipt-id", sizeof("receipt-id"), (void **)&receipt_id) == SUCCESS
							&& strlen(receipt) == strlen(receipt_id)
							&& !strcmp(receipt, receipt_id)) {
						success = 1;
					} else {
						stomp_set_error(stomp, "Invalid receipt", 0, "%s", receipt_id);
					}
					stomp_free_frame(res);
					return success;
				} else if (0 == strncmp("ERROR", res->command, sizeof("ERROR") - 1)) {
					char *error_msg = NULL;
					if (zend_hash_find(res->headers, "message", sizeof("message"), (void **)&error_msg) == SUCCESS) {
						stomp_set_error(stomp, error_msg, 0, "%s", res->body);
					}
					stomp_free_frame(res);
					return success;
				} else {
					stomp_frame_stack_push(&stomp->frame_stack, res);
				}
			} else {
				return success;
			}
		}
	}
	return success;
}
/* }}} */

/* {{{ stomp_select
 */
int stomp_select_ex(stomp_t *stomp, const long int sec, const long int usec)
{
	int     n;
	struct timeval tv;

	if (stomp->read_buffer.size || stomp->frame_stack) {
		return 1;
	}
	tv.tv_sec = sec;
	tv.tv_usec = usec;

	n = php_pollfd_for(stomp->fd, PHP_POLLREADABLE, &tv);
	if (n < 1) {
#if !defined(PHP_WIN32) && !(defined(NETWARE) && defined(USE_WINSOCK))
		if (n == 0) {
			errno = ETIMEDOUT;
		}
#endif
		return 0;
	}
	return 1;
}
/* }}} */
