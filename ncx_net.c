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
#include <string.h>

#include "ncx_net.h"

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

  if (ret == 0) {
    printf("Connected!\n");
  }
  *out_sock = sock;
  return ret;
}

int ncx_connect(const char *serv, unsigned short port)
{
  struct sockaddr_storage ss;
  int sock;

  if (get_addr(serv, &ss) == -1) {
    return -1;
  }

  if (sock_connect(&ss, port, &sock) < 0) {
    return -1;
  }
  return sock;
}

int ncx_send_data(int fd, const char *data, size_t sz)
{
  return send(fd, data, sz, 0);
}

int ncx_read_data(int fd, char *buffer, size_t szbuffer)
{
  return recv(fd, buffer, szbuffer, 0);
}
