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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "ext/standard/php_smart_str.h"
#include "stomp.h"
#include "php_stomp.h"

#define RETURN_READ_FRAME_FAIL { frame_destroy(f); return NULL; }

ZEND_EXTERN_MODULE_GLOBALS(stomp);
extern stomp_ce_exception;

/* {{{ stomp_new
 */
stomp_t *stomp_new(const char *host, unsigned short port, long read_timeout_sec, long read_timeout_usec TSRMLS_DC) 
{
    /* Memory allocation for the stomp */
    stomp_t *stomp = (stomp_t *) emalloc(sizeof(stomp_t));
    memset(stomp, 0, sizeof(*stomp));

    /* Define all values */
    stomp->host = (char *) emalloc(strlen(host) + 1);
    memcpy(stomp->host, host, strlen(host));
    stomp->host[strlen(host)] = '\0';

    stomp->port = port;
    stomp->status = 0;
    stomp->error = NULL;
    stomp->errnum = 0;
    stomp->read_timeout_sec = read_timeout_sec;
    stomp->read_timeout_usec = read_timeout_usec;
    stomp->session = NULL;

#if HAVE_STOMP_SSL
    stomp->ssl_handle = NULL;
    stomp->use_ssl = 0;
#endif

    return stomp;
}
/* }}} */

/* {{{ stomp_set_error 
 */
void stomp_set_error(stomp_t *stomp, const char *error, int errnum) 
{
    if (error != NULL) {
        if (stomp->error != NULL) {
            efree(stomp->error);
        }   
        stomp->error = estrdup(error);
        stomp->errnum = errnum;
    }
}
/* }}} */

/* {{{ stomp_connect 
 */
int stomp_connect(stomp_t *stomp TSRMLS_DC) 
{
    char error[1024];
    socklen_t        size;
    struct timeval tv;
    fd_set rfds;

    tv.tv_sec = STOMP_G(connection_timeout_sec);
    tv.tv_usec = STOMP_G(connection_timeout_usec);

    stomp->fd = php_network_connect_socket_to_host(stomp->host, stomp->port, SOCK_STREAM, 0, &tv, NULL, NULL, NULL, 0 TSRMLS_CC);
    if (stomp->fd == -1) {
        snprintf(error, sizeof(error), "Unable to connect to %s:%ld", stomp->host, stomp->port);
        stomp_set_error(stomp, error, errno);
        return 0;
    }

    size = sizeof(stomp->localaddr);
    memset(&stomp->localaddr, 0, size);
    if (getsockname(stomp->fd, (struct sockaddr*) &stomp->localaddr, &size) == -1) {
        snprintf(error, sizeof(error), "getsockname failed: %s (%d)", strerror(errno), errno);
        stomp_set_error(stomp, error, errno); 
        return 0; 
    }

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(stomp->fd, &rfds);

    if (select(stomp->fd + 1, NULL, &rfds, NULL, &tv) > 0) {
#if HAVE_STOMP_SSL
        if (stomp->use_ssl) {
            SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
            if (NULL == ctx) {
                stomp_set_error(stomp, "failed to create the SSL context", 0);
                return 0;
            }

            SSL_CTX_set_options(ctx, SSL_OP_ALL);

            stomp->ssl_handle = SSL_new(ctx);
            if (stomp->ssl_handle == NULL) {
                stomp_set_error(stomp, "failed to create the SSL handle", 0);
                SSL_CTX_free(ctx);
                return 0;
            }
            
            SSL_set_fd(stomp->ssl_handle, stomp->fd);

            if (SSL_connect(stomp->ssl_handle) <= 0) {
                stomp_set_error(stomp, "SSL/TLS handshake failed", 0);
                SSL_shutdown(stomp->ssl_handle);
                return 0;
            }
        }
#endif        
        return 1;
    } else {
        snprintf(error, sizeof(error), "Unable to connect to %s:%ld", stomp->host, stomp->port);
        stomp_set_error(stomp, error, errno); 
        return 0;
    }
}
/* }}} */

/* {{{ stomp_close
 */
void stomp_close(stomp_t *stomp TSRMLS_DC)
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
        smart_str_appends(&buf, "content-length: ");
        smart_str_append_long(&buf, frame->body_length);
        smart_str_appendc(&buf, '\n');
    }

    smart_str_appendc(&buf, '\n');

    if (frame->body > 0) {
        smart_str_appends(&buf, frame->body);
    }

#ifdef HAVE_STOMP_SSL
    if (stomp->use_ssl) {
        if (-1 == SSL_write(stomp->ssl_handle, buf.c, buf.len) || -1 == SSL_write(stomp->ssl_handle, "\0\n", 2)) {
            char error[1024];
            snprintf(error, sizeof(error), "Unable to send data");
            stomp_set_error(stomp, error, errno);
            return 0;
        }
    } else {
#endif        
        if (-1 == send(stomp->fd, buf.c, buf.len, 0) || -1 == send(stomp->fd, "\0\n", 2, 0)) {
            char error[1024];
            snprintf(error, sizeof(error), "Unable to send data");
            stomp_set_error(stomp, error, errno);
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
int stomp_recv(stomp_t *stomp, char *msg, size_t length)
{
	int len;
#if HAVE_STOMP_SSL
    if(stomp->use_ssl) {
        len = SSL_read(stomp->ssl_handle, msg, length);
    } else {
#endif
        len = recv(stomp->fd, msg, length, 0);
#if HAVE_STOMP_SSL
    }
#endif

    if (len == 0) {
		TSRMLS_FETCH();
		zend_throw_exception_ex(stomp_ce_exception, errno TSRMLS_CC, "Unexpected EOF while reading from socket");
        stomp->status = -1;
    }
    return len;
}
/* }}} */

/* {{{ stomp_read_buffer 
 */
static int stomp_read_buffer(stomp_t *stomp, char **data)
{
    int rc = 0;
    size_t i = 0;
    size_t bufsize = STOMP_BUFSIZE + 1;
    char *buffer = (char *) emalloc(STOMP_BUFSIZE + 1);

    while (1) {

        size_t length = 1;
        rc = stomp_recv(stomp, buffer + i, length);
        if (rc < 1) {
            efree(buffer);
            return -1;
        }

        if (1 == length) {
            i++;

            if (buffer[i-1] == 0) {
                char endline[1];
                if (1 != stomp_recv(stomp, endline, 1) && '\n' != endline[0]) {
                    efree(buffer);
                    return 0;
                }
                break;
            }

            if (i >= bufsize) {
                buffer = (char *) erealloc(buffer, bufsize + STOMP_BUFSIZE);
                bufsize += STOMP_BUFSIZE;
            }

        }
    }

    if (i > 1) {
        *data = (char *) emalloc(i);
        if (NULL == *data) {
            efree(buffer);
            return -1;
        }

        memcpy(*data, buffer, i);
    }

    efree(buffer);

    return i-1;
}
/* }}} */

/* {{{ stomp_read_line
 */
static int stomp_read_line(stomp_t *stomp, char **data)
{
    int rc = 0;
    size_t i = 0;
    size_t bufsize = STOMP_BUFSIZE + 1;
    char *buffer = (char *) emalloc(STOMP_BUFSIZE + 1);

    while (1) {

        size_t length = 1;
        rc = stomp_recv(stomp, buffer + i, length);
        if (rc < 1) {
            efree(buffer);
            return -1;
        }

        if (1 == length) {
            i++; 

            if (buffer[i-1] == '\n') {
                buffer[i-1] = 0;
                break;
            } else if (buffer[i-1] == 0) {
                efree(buffer);
                return 0;
            }

            if (i >= bufsize) {
                buffer = (char *) erealloc(buffer, bufsize + STOMP_BUFSIZE);
                bufsize += STOMP_BUFSIZE;
            }
        }

    }

    if (i > 1) {
        *data = (char *) emalloc(i);
        if (NULL == *data) {
            efree(buffer);
            return -1;
        }

        memcpy(*data, buffer, i);
    }

    efree(buffer);

    return i-1;
}
/* }}} */

/* {{{ frame_destroy
 */
void frame_destroy(stomp_frame_t *frame)
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
stomp_frame_t *stomp_read_frame(stomp_t *stomp)
{
    stomp_frame_t *f = NULL;
    char *cmd = NULL, *length_str = NULL;
    int length = 0;

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

            /* The rest if the value. */
            value = p2+1;

            /* Insert key/value into hash table. */
            zend_hash_add(f->headers, key, strlen(key) + 1, value, strlen(value) + 1, NULL);
            efree(p);
        }
    }

    /* Check for the content length */
    if (zend_hash_find(f->headers, "content-length", strlen("content-length"), (void **)&length_str) == SUCCESS) {
        char endbuffer[2];
        length = 2;

        f->body_length = atoi(length_str);
        f->body = (char *) emalloc(f->body_length);

        if (-1 == stomp_recv(stomp, f->body, f->body_length)) {
            RETURN_READ_FRAME_FAIL;
        }

        if (length != stomp_recv(stomp, endbuffer, length) || endbuffer[0] != '\0' || endbuffer[1] != '\n') {
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
        stomp_frame_t *res = stomp_read_frame(stomp);
        success = 0;
        if (res) {
            if (0 == strncmp("RECEIPT", res->command, sizeof("RECEIPT") - 1)) {
                char *receipt_id = NULL;
                if (zend_hash_find(res->headers, "receipt-id", sizeof("receipt-id"), (void **)&receipt_id) == SUCCESS
                        && strlen(receipt) == strlen(receipt_id)
                        && !strcmp(receipt, receipt_id)) {
                    success = 1;
                }
            } else if (0 == strncmp("ERROR", res->command, sizeof("ERROR") - 1)) {
                char *error_msg = NULL;
                if (zend_hash_find(res->headers, "message", sizeof("message"), (void **)&error_msg) == SUCCESS) {
                    stomp_set_error(stomp, error_msg, 0); 
                }
            }
            frame_destroy(res);
        }
    }
    return success;
}
/* }}} */

/* {{{ stomp_select
 */
int stomp_select(stomp_t *stomp)
{
    struct timeval tv;
    fd_set rfds;

    tv.tv_sec = stomp->read_timeout_sec;
    tv.tv_usec = stomp->read_timeout_usec;

    FD_ZERO(&rfds);
    FD_SET(stomp->fd, &rfds);

    return select(stomp->fd + 1, &rfds, NULL, NULL, &tv);
}
/* }}} */
