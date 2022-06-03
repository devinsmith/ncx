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

#include <cstring>

#include "ncx_certs.h"
#include "ncx_opts.h"

CertManager::CertManager(const Options& opts)
{
  _cert_file = opts.conf_dir();
  _cert_file += "/certs";

  read_certs();
}

void CertManager::read_certs()
{
  FILE *certfp;
  char line[4096];
  int line_num = 0;

  certfp = fopen(_cert_file.c_str(), "r");
  if (certfp == NULL) {
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
  if (certfp == NULL) {
    fprintf(stderr, "Failed to store cert!\n");
    return;
  }

  fprintf(certfp, "%s:%s\n", host.c_str(), fp.c_str());

  fclose(certfp);
}

