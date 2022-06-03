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

#include <termios.h>
#include <stdio.h>
#include <stdlib.h>

#include "ncx_certs.h"
#include "ncx_io.h"
#include "ncx_main.h"
#include "ncx_net.h"
#include "ncx_opts.h"

static struct termios g_term_attr;
static struct termios g_saved_attr;
static int g_attrs_saved = 0;

static void setup_tty()
{
  if (tcgetattr(fileno(stdin), &g_term_attr) != 0) {
    return;
  }

  if (g_attrs_saved == 0) {
    g_saved_attr = g_term_attr;
    g_attrs_saved = 1;
  }
  g_term_attr.c_lflag &= ~(ECHO | ICANON);
  g_term_attr.c_cc[VMIN] = 1;
  if (tcsetattr(fileno(stdin), TCSAFLUSH, &g_term_attr) != 0) {
    perror("can't change tty modes.");
  }
}

void ncx_exit(struct ncx_app *app)
{
  if (app->conn != NULL) {
    ncx_disconnect(app->conn);
  }

  tcsetattr(fileno(stdin), TCSAFLUSH, &g_saved_attr);
  exit(0);
}

int main(int argc, char *argv[])
{
  struct ncx_app app = { 0 };
  Options opts;

  printf("ncx v0.02\n");

  opts.parse(argc, argv);
  ncx_net_init();

  setup_tty();

  CertManager certmgr(opts);
  app.conn = ncx_connect(&opts, certmgr);
  if (app.conn == NULL) {
//    fprintf(stderr, "Couldn't connect.\n");
    ncx_exit(&app);
  }

  while (1) {
    ncx_io_run(&app);
  }
  return 0;
}
