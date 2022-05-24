/*
 * Copyright (c) 2022 Devin Smith <devin@devinsmith.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ncx_net.h"

struct ncx_conn {
  int fd;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
};

struct verify_ctx {
  int was_error;
  char *pem;
};
static int ssl_verify_idx;

#define SIN4(x) ((struct sockaddr_in *) (x))
#define SIN6(x) ((struct sockaddr_in6 *) (x))

static size_t sin_len(const struct sockaddr_storage *ss)
{
  if (ss->ss_family == AF_INET6) {
    return sizeof(struct sockaddr_in6);
  }
  return sizeof(struct sockaddr_in);
}

static void sin_set_port(struct sockaddr_storage *ss, unsigned short port)
{
  if (ss->ss_family == AF_INET6) {
    SIN6(ss)->sin6_port = port;
  }
  SIN4(ss)->sin_port = port;
}

static int get_addr(const char *hostname, struct sockaddr_storage *addr)
{
  size_t len;
  int ret;
  struct addrinfo *res = NULL;

  if ((ret = getaddrinfo(hostname, NULL, NULL, &res)) != 0) {
    if (res != NULL) {
      freeaddrinfo(res);
    }
    fprintf(stderr, "getaddrinfo: %s: %s\n", hostname, gai_strerror(ret));
    return -1;
  }

  switch (res->ai_addr->sa_family) {
  case AF_INET:
    len = sizeof(struct sockaddr_in);
    break;

  case AF_INET6:
    len = sizeof(struct sockaddr_in6);
    break;

  default:
    fprintf(stderr, "Unknown family: %d\n", res->ai_addr->sa_family);
    freeaddrinfo(res);
    return -1;
  }

  if (len < res->ai_addrlen) {
    fprintf(stderr, "hostname addr len incorrect: %zu < %u\n", len,
        res->ai_addrlen);
    freeaddrinfo(res);
    return -1;
  }

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);

  return 0;
}

static int sock_connect(struct sockaddr_storage *ss, unsigned short port,
    int *out_sock)
{
  int sock;
  int ret = 0;

  sock = socket(ss->ss_family, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
    return -1;
  }

  sin_set_port(ss, htons(port));
  if (connect(sock, (struct sockaddr *)ss, sin_len(ss)) != 0) {
    if (errno != EINPROGRESS) {
      fprintf(stderr, "connect: %s\n", strerror(errno));
      close(sock);
      return -1;
    }
  }

  *out_sock = sock;
  return ret;
}

// Work in progress
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  //char line[1024];
  char    buf[256];
  X509   *err_cert;
  EVP_PKEY *pub_key;
  int     err, depth;
  SSL    *ssl;
  BIO *bio;
  struct tm t;
  struct verify_ctx *vctx;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
#if 0
  pub_key = X509_get_pubkey(err_cert);

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(bio, pub_key);

  while (1) {
    char line[1024];
    int l = BIO_read(bio, line, sizeof(line));
    if (l <= 0)
      break;
    printf("%s\n", line);
  }
//  X509_print_ex(bio, err_cert, 0, 0);

//  BIO_read(bio, line, sizeof(line) - 1);
//  line[sizeof(line) - 1] = '\0';

//  printf("%s\n", line);


  BIO_free(bio);
#endif

  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  /*
   * Retrieve the pointer to the SSL of the connection currently treated
   * and the application specific data stored into the SSL object.
   */
  ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  vctx = SSL_get_ex_data(ssl, ssl_verify_idx);

  X509_NAME *subj_name = X509_get_subject_name(err_cert);


  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
  ASN1_TIME_to_tm(X509_get_notAfter(err_cert), &t);

  /*
   * Catch a too long certificate chain. The depth limit set using
   * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
   * that whenever the "depth>verify_depth" condition is met, we
   * have violated the limit and want to log this error condition.
   * We must do it here, because the CHAIN_TOO_LONG error would not
   * be found explicitly; only errors introduced by cutting off the
   * additional certificates would be logged.
   */
  if (depth > 150) {
    preverify_ok = 0;
    err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(ctx, err);
  }

  if (!preverify_ok) {
    printf("SSL certificate verification failed\n");
    printf("Error: %d (%s)\n", err, X509_verify_cert_error_string(err));
    printf("Depth: %d\n", depth);
    printf("Subject: %s\n", buf);
    printf("Expiration: %s\n", asctime(&t));

    PEM_write_X509(stdout, err_cert);
  }

   /*
    * At this point, err contains the last verification error. We can use
    * it for something special
    */
   if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
     X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
     printf("issuer= %s\n", buf);
   }

   printf("%d\n", preverify_ok);
   vctx->was_error = preverify_ok == 0;
   return preverify_ok;
}

static int ncx_ssl_connect(struct ncx_conn *conn)
{
  int ret;
  struct verify_ctx verify_ctx = { 0 };

  conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (conn->ssl_ctx == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

#if 0
  if (!SSL_CTX_load_verify_locations(conn->ssl_ctx, "cert.pem", NULL)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
#endif



  SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify_depth(conn->ssl_ctx, 150);

  conn->ssl = SSL_new(conn->ssl_ctx);
  if (conn->ssl == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  ssl_verify_idx = SSL_get_ex_new_index(0, "verify context", NULL, NULL, NULL);
  SSL_set_ex_data(conn->ssl, ssl_verify_idx, &verify_ctx);

  if (!SSL_set_fd(conn->ssl, conn->fd)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (SSL_connect(conn->ssl) == -1) {
    if (verify_ctx.was_error == 1) {
      printf("Failed to connect due to verification errors\n");
    }
    //ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

struct ncx_conn *ncx_connect(struct ncx_opts *opts)
{
  struct sockaddr_storage ss;
  int sock;
  struct ncx_conn *conn;

  printf("Connecting to %s:%d...\n", opts->server_name, opts->port);

  if (get_addr(opts->server_name, &ss) == -1) {
    return NULL;
  }

  if (sock_connect(&ss, opts->port, &sock) < 0) {
    fprintf(stderr, "Failed to connect to %s:%d\n", opts->server_name,
        opts->port);
    return NULL;
  }

  conn = calloc(1, sizeof(struct ncx_conn));
  conn->fd = sock;
  if (opts->use_ssl) {
    if (ncx_ssl_connect(conn) == -1) {
      fprintf(stderr, "Failed to connect to %s:%d\n", opts->server_name,
          opts->port);
      free(conn);
      return NULL;
    }
  }

  printf("Connected!\n");

  return conn;
}

void ncx_disconnect(struct ncx_conn *conn)
{
  if (conn != NULL) {
    if (conn->ssl != NULL) {
      SSL_shutdown(conn->ssl);
      SSL_free(conn->ssl);
    }
    if (conn->ssl_ctx != NULL) {
      SSL_CTX_free(conn->ssl_ctx);
    }
    close(conn->fd);
  }

  free(conn);
}

int ncx_net_getfd(struct ncx_conn *conn)
{
  return conn->fd;
}

void ncx_net_init()
{
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
}

int ncx_send_data(struct ncx_conn *conn, const char *data, size_t sz)
{
  if (conn->ssl) {
    return SSL_write(conn->ssl, data, sz);
  }
  return send(conn->fd, data, sz, 0);
}

int ncx_read_data(struct ncx_conn *conn, char *buffer, size_t szbuffer)
{
  if (conn->ssl) {
    return SSL_read(conn->ssl, buffer, szbuffer);
  }
  return recv(conn->fd, buffer, szbuffer, 0);
}
