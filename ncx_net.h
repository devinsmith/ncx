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

#ifndef __NCX_NET_H__
#define __NCX_NET_H__

#include "ncx_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

void ncx_net_init();

struct ncx_conn *ncx_connect(struct ncx_opts *opts);
void ncx_disconnect(struct ncx_conn *conn);
int ncx_net_getfd(struct ncx_conn *conn);
int ncx_send_data(struct ncx_conn *conn, const char *data, size_t sz);
int ncx_read_data(struct ncx_conn *conn, char *buffer, size_t sz_buffer);

#ifdef __cplusplus
}
#endif

#endif /* __NCX_NET_H__ */
