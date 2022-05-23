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

#include <string.h>

#include "ncx_opts.h"

int ncx_opts_init(struct ncx_opts *opts, int argc, char *argv[])
{
  if (opts == NULL) {
    return -1;
  }

  // defaults
  opts->use_ssl = 1;
  opts->port = 6667;
  opts->server_name = "naken.cc";

  // Quick arg parser...
  while (--argc) {
    char *p = *++argv;
    if (*p == '-') {
      if (!strcmp(p, "-i") || !strcmp(p, "--no-ssl")) {
        opts->use_ssl = 0;
      }
    }
  }

  return 0;
}
