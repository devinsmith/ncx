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
  explicit verify_ctx(const CertManager& cm) : was_error(false), certmgr(cm) {}

  bool was_error;
  std::string host;
  std::string fingerprint;
  std::string error;
  std::string cert;
  const CertManager& certmgr;
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
  struct addrinfo *res = nullptr;

  if ((ret = getaddrinfo(hostname, nullptr, nullptr, &res)) != 0) {
    if (res != nullptr) {
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

static std::string calc_fingerprint(X509 *cert)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  std::string hash;
  unsigned int md_len = (unsigned int)sizeof(md);
  static const char hex[] = "0123456789abcdef";

  memset(md, 0, sizeof(md));

  int success = X509_digest(cert, EVP_sha256(), md, &md_len);
  if (success) {
    unsigned int j;
    for (j = 0; j < md_len; ++j) {
      hash += hex[md[j] >> 4];
      hash += hex[md[j]&0xf];
    }
  }

  return hash;
}

// Work in progress
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  struct verify_ctx *vctx;

  X509 *err_cert = X509_STORE_CTX_get_current_cert(ctx);
  int err = X509_STORE_CTX_get_error(ctx);
  int depth = X509_STORE_CTX_get_error_depth(ctx);

  /*
   * Retrieve the pointer to the SSL of the connection currently treated
   * and the application specific data stored into the SSL object.
   */
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx,
      SSL_get_ex_data_X509_STORE_CTX_idx());
  vctx = static_cast<verify_ctx *>(SSL_get_ex_data(ssl, ssl_verify_idx));

  std::string fingerprint = calc_fingerprint(err_cert);
  if (vctx->certmgr.is_whitelisted(vctx->host, fingerprint)) {
    vctx->was_error = false;
    return 1;
  }

  struct tm t;
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
    // We failed verification, so extract some information to indicate the
    // problem
    vctx->error = X509_verify_cert_error_string(err);
    vctx->fingerprint = fingerprint;

    printf("===================================\n");
    printf("SSL certificate verification failed\n");
    printf("Error: %d (%s)\n", err, X509_verify_cert_error_string(err));
    printf("Fingerprint: %s\n", calc_fingerprint(err_cert).c_str());

    // Dump subject and issuer.
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_printf(bio, "Subject: ");
    X509_NAME_print(bio, X509_get_subject_name(err_cert), 0);
    BIO_printf(bio, "\n");
    BIO_printf(bio, "Issuer:  ");
    X509_NAME_print(bio, X509_get_issuer_name(err_cert), 0);
    BIO_printf(bio, "\n");

    while (1) {
      char line[1024];
      int l = BIO_read(bio, line, sizeof(line));
      if (l <= 0)
        break;
      line[l] = '\0';
      printf("%s", line);
    }

    BIO_free(bio);

    printf("Expiration: %04d-%02d-%02d %02d:%02d:%02d\n",
        t.tm_year + 1900, t.tm_mon + 1,
        t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

    printf("===================================\n");
    //PEM_write_X509(stdout, err_cert);
    //

    //X509_print_fp(stdout, err_cert);

    bio = BIO_new(BIO_s_mem());
    X509_print(bio, err_cert);
    while (true) {
      char line[1024];
      int l = BIO_read(bio, line, sizeof(line));
      if (l <= 0)
        break;
      line[l] = '\0';
      vctx->cert += line;
    }
    BIO_free(bio);
    //printf("%s", vctx->cert.c_str());
  }

  vctx->was_error = preverify_ok == 0;
  return preverify_ok;
}

static int ncx_ssl_connect(struct ncx_conn *conn, struct verify_ctx& vctx)
{
  conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (conn->ssl_ctx == nullptr) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify_depth(conn->ssl_ctx, 150);

  conn->ssl = SSL_new(conn->ssl_ctx);
  if (conn->ssl == nullptr) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  ssl_verify_idx = SSL_get_ex_new_index(
      0, (void *)"verify context", nullptr, nullptr, nullptr);
  SSL_set_ex_data(conn->ssl, ssl_verify_idx, &vctx);

  if (!SSL_set_fd(conn->ssl, conn->fd)) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  int ret;
  if ((ret = SSL_connect(conn->ssl)) == -1) {
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ssl_ctx);
    conn->ssl = nullptr;
    conn->ssl_ctx = nullptr;
    return -1;
  }

  return 0;
}

struct ncx_conn *ncx_connect(const Options *opts, CertManager& certmgr)
{
  struct sockaddr_storage ss;
  int sock;
  struct ncx_conn *conn;

  printf("Connecting to %s:%d...\n", opts->m_server_name.c_str(), opts->m_port);
  if (get_addr(opts->m_server_name.c_str(), &ss) == -1) {
    return nullptr;
  }

  bool connected = false;
  while (!connected) {
    if (sock_connect(&ss, opts->m_port, &sock) < 0) {
      fprintf(stderr, "Failed to connect to %s:%d\n",
          opts->m_server_name.c_str(), opts->m_port);
      return nullptr;
    }

    conn = (struct ncx_conn *)calloc(1, sizeof(struct ncx_conn));
    conn->fd = sock;
    if (opts->m_use_ssl) {
      printf("SSL negotionation with %s\n", opts->m_server_name.c_str());

      struct verify_ctx verify_ctx(certmgr);
      verify_ctx.host = opts->m_server_name;
      int ssl_conn = ncx_ssl_connect(conn, verify_ctx);
      if (ssl_conn == -1) {
        if (verify_ctx.was_error) {
          printf("Failed to connect due to verification errors\n");
          bool valid_choice = false;
          while (!valid_choice) {
            printf("You can choose to trust this server:\n"
                "(O)nce\n"
                "(A)lways\n"
                "(N)ever (will disconnect)\n"
                "(V)iew certificate for more information\n");
            printf("> ");
            char ch = getchar();
            printf("%c\n", ch);
            ch = tolower(ch);
            switch (ch) {
            case 'o':
              // once
              certmgr.whitelist_cert(opts->m_server_name,
                  verify_ctx.fingerprint, false);
              valid_choice = true;
              break;
            case 'a':
              // always
              certmgr.whitelist_cert(opts->m_server_name,
                  verify_ctx.fingerprint, true);
              valid_choice = true;
              break;
            case 'n':
              ncx_disconnect(conn);
              return nullptr;
              break;
            case 'v':
              printf("%s\n", verify_ctx.cert.c_str());
              break;
            default:
              break;
            }
          };
        } else {
          fprintf(stderr, "Failed to connect to %s:%d\n",
              opts->m_server_name.c_str(), opts->m_port);
          ncx_disconnect(conn);
          return nullptr;
        }
      } else {
        connected = true;
      }
    } else {
      connected = true;
    }
  }

  printf("Connected!\n");

  return conn;
}

void ncx_disconnect(struct ncx_conn *conn)
{
  if (conn != nullptr) {
    if (conn->ssl != nullptr) {
      SSL_shutdown(conn->ssl);
      SSL_free(conn->ssl);
    }
    if (conn->ssl_ctx != nullptr) {
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
