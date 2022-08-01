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

#ifndef __NCX_MAIN_H__
#define __NCX_MAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

struct ncx_conn;

extern const char *progname;
extern const char *progversion;

struct ncx_app {
  struct ncx_conn *conn;
  int dirty;

  // Input buffer
  int chars;
  char line_buffer[256];
  char m_buffer[1024];

  // Output buffer
  int m_buf_idx;
};


void ncx_exit(struct ncx_app *app);

#ifdef __cplusplus
}
#endif

#endif /* __NCX_MAIN_H__ */
