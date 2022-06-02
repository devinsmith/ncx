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

#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include "ncx_opts.h"

static char g_config_dir[PATH_MAX];

struct cert {
  char *host;
  char *fingerprint;
};

struct cert_list {
  size_t n;
  struct cert *certs;
} g_cert_list;

static int ncx_mkdir(const char *path)
{
  struct stat st;

  if (stat(path, &st) != 0) {
    if (mkdir(path, 0700) != 0) {
      fprintf(stderr, "Error: mkdir %s: %s\n", path, strerror(errno));
      return -1;
    }
  } else {
    if (!S_ISDIR(st.st_mode)) {
      fprintf(stderr, "Error: %s is not a directory\n", path);
      return -1;
    }
  }
  return 0;
}

static void append_cert(const char *host, const char *fingerprint)
{
  struct cert *resize;
  struct cert *cert;

  g_cert_list.n++;
  if ((resize = (struct cert *)realloc(g_cert_list.certs,
       sizeof(struct cert) * g_cert_list.n)) == NULL) {
    fprintf(stderr, "Failed to allocate room for certificate\n");
    exit(1);
  }
  g_cert_list.certs = resize;

  cert = &g_cert_list.certs[g_cert_list.n - 1];
  cert->host = strdup(host);
  cert->fingerprint = strdup(fingerprint);
}

static void read_certs()
{
  FILE *certfp;
  char cert_file[sizeof(g_config_dir) + 8];
  char line[4096];
  int line_num = 0;

  snprintf(cert_file, sizeof(cert_file), "%s/certs", g_config_dir);

  certfp = fopen(cert_file, "r");
  if (certfp == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), certfp)) {
    char *p;

    line_num++;
    p = strchr(line, '\n');
    if (!p) {
      fprintf(stderr, "%s: Line %d is too long. Skipping.\n", cert_file,
          line_num);
      continue;
    }

    *p = '\0';

    char *sp = strchr(line, ':');
    if (!sp) {
      fprintf(stderr, "%s: Line %d is malformed. Skipping.\n", cert_file,
          line_num);
      continue;
    }
    *sp = '\0';
    append_cert(line, sp + 1);
  }

  fclose(certfp);
}

int ncx_opts_init(struct ncx_opts *opts, int argc, char *argv[])
{
  struct passwd *pw;

  pw = getpwuid(getuid());
  if (pw == NULL) {
    fprintf(stderr, "Fatal: Can't get your user info.\n");
    return -1;
  }

  snprintf(g_config_dir, sizeof(g_config_dir), "%s/.ncx", pw->pw_dir);
  if (ncx_mkdir(g_config_dir) != 0) {
    return -1;
  }

  g_cert_list.n = 0;
  g_cert_list.certs = NULL;
  read_certs();

  if (opts == NULL) {
    return -1;
  }

  // defaults
  opts->use_ssl = 1;
  opts->port = 6667;
  opts->server_name = "mikekohn.net";

  // Quick arg parser...
  while (--argc) {
    char *p = *++argv;
    if (*p == '-') {
      if (!strcmp(p, "-i") || !strcmp(p, "--no-ssl")) {
        opts->use_ssl = 0;
        opts->port = 6666;
      }
    }
  }

  return 0;
}
