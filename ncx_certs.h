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

#ifndef NCX_CERTS_H
#define NCX_CERTS_H

#include <string>
#include <vector>

class Options;

struct Cert {
  Cert(const char *hn, const char *fp) : hostname(hn), fingerprint(fp) {}
  std::string hostname;
  std::string fingerprint;
};

class CertManager {
public:
  CertManager(const Options& opts);

private:
  void read_certs();
  void append_cert(const char *hostname, const char *fingerprint);

  std::string _cert_file;
  std::vector<Cert> _cert_list;
};

#endif /* NCX_CERTS_H */
