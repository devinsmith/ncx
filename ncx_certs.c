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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ncx_certs.h"
#include "ncx_opts.h"

struct cert {
  char *hostname;
  char *fingerprint;
};

struct cert_manager {
  char cert_file[2048];
  struct cert *certs;
  size_t n, m; // cert size.
};

static struct cert_manager manager;

static bool append_cert(const char *host, const char *fingerprint)
{
  if (manager.certs == NULL) {
    manager.m = 8;
    manager.certs = calloc(manager.m, sizeof(struct cert));
  }

  // Resize
  if (manager.n == manager.m) {
    manager.m <<= 1;
    struct cert *resize = realloc(manager.certs, sizeof(struct cert) *
        manager.m);
    if (resize == NULL) {
      return false;
    }
    manager.certs = resize;
  }

  struct cert *c = &manager.certs[manager.n++];
  c->hostname = strdup(host);
  c->fingerprint = strdup(fingerprint);

  return true;
}

static void read_certs(const char *certfile)
{
  FILE *certfp;
  char line[4096];
  int line_num = 0;

  certfp = fopen(certfile, "r");
  if (certfp == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), certfp)) {
    char *p;

    line_num++;
    p = strchr(line, '\n');
    if (!p) {
      fprintf(stderr, "%s: Line %d is too long. Skipping.\n",
          certfile, line_num);
      continue;
    }

    *p = '\0';

    char *sp = strchr(line, ':');
    if (!sp) {
      fprintf(stderr, "%s: Line %d is malformed. Skipping.\n",
          certfile, line_num);
      continue;
    }
    *sp = '\0';
    if (!append_cert(line, sp + 1)) {
      fprintf(stderr, "%s: Failed to add cert on line %d\n",
          certfile, line_num);
      continue;
    }
  }

  fclose(certfp);
}

void ncx_certs_init(void)
{
  snprintf(manager.cert_file, sizeof(manager.cert_file), "%s/certs",
      ncx_opts_dir());

  read_certs(manager.cert_file);
}

void ncx_certs_destroy(void)
{
  for (size_t i = 0; i < manager.n; i++) {
    struct cert *c = &manager.certs[i];
    free(c->hostname);
    free(c->fingerprint);
  }
}

bool ncx_certs_whitelist_get(const char *host, const char *fp)
{
  for (size_t i = 0; i < manager.n; i++) {
    struct cert *c = &manager.certs[i];

    if (strcmp(c->hostname, host) == 0 && strcmp(c->fingerprint, fp) == 0) {
      return true;
    }
  }

  return false;
}

void ncx_certs_whitelist_add(const char *host, const char *fp, bool store)
{
  append_cert(host, fp);

  if (!store) {
    return;
  }

  printf("Storing to %s\n", manager.cert_file);
  FILE *certfp = fopen(manager.cert_file, "a");
  if (certfp == NULL) {
    fprintf(stderr, "Failed to store cert!\n");
    return;
  }

  fprintf(certfp, "%s:%s\n", host, fp);

  fclose(certfp);
}

#if 0
CertManager::CertManager()
{
  _cert_file = ncx_opts_dir();
  _cert_file += "/certs";

  read_certs();
}

void CertManager::read_certs()
{
  FILE *certfp;
  char line[4096];
  int line_num = 0;

  certfp = fopen(_cert_file.c_str(), "r");
  if (certfp == nullptr) {
    return;
  }

  while (fgets(line, sizeof(line), certfp)) {
    char *p;

    line_num++;
    p = strchr(line, '\n');
    if (!p) {
      fprintf(stderr, "%s: Line %d is too long. Skipping.\n",
          _cert_file.c_str(), line_num);
      continue;
    }

    *p = '\0';

    char *sp = strchr(line, ':');
    if (!sp) {
      fprintf(stderr, "%s: Line %d is malformed. Skipping.\n",
          _cert_file.c_str(), line_num);
      continue;
    }
    *sp = '\0';
    append_cert(line, sp + 1);
  }

  fclose(certfp);
}

void CertManager::append_cert(const char *host, const char *fingerprint)
{
  _cert_list.emplace_back(host, fingerprint);
}

bool CertManager::is_whitelisted(const std::string& host,
    const std::string& fp) const
{
  for (const auto& cert : _cert_list) {
    if (cert.hostname == host && cert.fingerprint == fp) {
      return true;
    }
  }

  return false;
}

void CertManager::whitelist_cert(const std::string& host,
    const std::string& fp, bool store)
{
  _cert_list.emplace_back(host, fp);

  if (!store) {
    return;
  }

  printf("Storing to %s\n", _cert_file.c_str());
  FILE *certfp = fopen(_cert_file.c_str(), "a");
  if (certfp == nullptr) {
    fprintf(stderr, "Failed to store cert!\n");
    return;
  }

  fprintf(certfp, "%s:%s\n", host.c_str(), fp.c_str());

  fclose(certfp);
}
#endif

