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

#include <cstdio>

#include "ncx_color.h"

void print_color(Color c, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  int c_code = static_cast<int>(c) + 30;

  printf("\x1b[%dm", c_code);
  vprintf(fmt, ap);
  printf("\x1b[m");

  va_end(ap);
}

void print_bold(Color c, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  int c_code = static_cast<int>(c) + 30;

  printf("\x1b[1;%dm", c_code);
  vprintf(fmt, ap);
  printf("\x1b[m");

  va_end(ap);
}

