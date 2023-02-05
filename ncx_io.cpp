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

#include <sys/select.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "ncx_color.h"
#include "ncx_io.h"
#include "ncx_net.h"

static int clear_line(int chars)
{
  int i;

  printf("\r");
  for (i = 0; i <= chars; i++) {
    putchar(' ');
  }
  printf("\r");
  fflush(stdout);

  return 1;
}

static void show_prompt(struct ncx_app *app)
{
  printf("> %s", app->line_buffer);
  fflush(stdout);
}

static void append_byte(struct ncx_app *app, int ch)
{
  app->line_buffer[app->chars++] = ch;
  if (app->chars == sizeof(app->line_buffer) || ch == '\n') {
    ncx_send_data(app->conn, app->line_buffer, app->chars);
    memset(app->line_buffer, 0, app->chars);
    app->chars = 0;
  }
}

static void ncx_getkey(struct ncx_app *app)
{
  unsigned char keybuf[512];
  unsigned char ch;
  ssize_t bsz;

  bsz = read(0, keybuf, sizeof(keybuf));
  if (bsz <= 0) {
    return;
  }
  ch = keybuf[0];

  if (ch == '\b' || ch == 127 || ch == 4) {
    if (app->chars != 0) {
      printf("\b \b");
      app->line_buffer[--app->chars] = 0;
      fflush(stdout);
    }
  } else if (ch == '\n' || ch == '\r') {
    app->dirty = clear_line(app->chars + 1);
    append_byte(app, '\n');
  } else {
    int i;

    for (i = 0; i < bsz; i++) {
      append_byte(app, keybuf[i]);
      putchar(keybuf[i]);
    }
    fflush(stdout);
  }
}

static void process_line(struct ncx_app *app)
{
  char *data = app->m_buffer;

  if (app->user_id < 0) {
    if (strstr(data, ">> You just logged on line") != nullptr) {
      sscanf(data, "%*c%*c %*s %*s %*s %*s %*s %d", &app->user_id);
    }
  }

  if (data[0] == '>') {
    print_bold(Color::Red, "%s\n", app->m_buffer);
    return;
  }

  if (data[0] == '[') {
    // extract number
    char *tmp = strchr(data, ']');
    if (tmp != nullptr) {
      *tmp = '\0';

      int num = atoi(data + 1);
      *tmp = ']';

      if (num == app->user_id) {
        print_bold(Color::Blue, "%s\n", app->m_buffer);
        return;
      }
    }
  }

  printf("%s\n", app->m_buffer);
}

static void process_data(struct ncx_app *app, const char *buffer, ssize_t nbytes)
{
  int i;

  for (i = 0; i < nbytes; i++) {
    if (buffer[i] == '\r') continue;
    if (buffer[i] == '\0') {
      //printf("Got NUL byte in buffer\n");
      continue;
    }

    if (buffer[i] == '\n') {
      app->m_buffer[app->m_buf_idx] = '\0';
      /* Display message to user */
      process_line(app);
      app->dirty = 1;

      /* clear out our input buffer */
      app->m_buf_idx = 0;
    } else {
      app->m_buffer[app->m_buf_idx++] = buffer[i];
    }
  }
}

static int ncx_io_read(struct ncx_app *app)
{
  char buffer[2048];
  int bytes = ncx_read_data(app->conn, buffer, sizeof(buffer));

  if (bytes <= 0) {
    fprintf(stderr, "socket closed\n");
    return -1;
  }

  process_data(app, buffer, bytes);
  return 0;
}

int ncx_io_run(struct ncx_app *app)
{
  struct timeval tv;
  fd_set readfds;
  int conn_fd;

  if (app->conn == nullptr) {
    return -1;
  }

  conn_fd = ncx_net_getfd(app->conn);

  FD_ZERO(&readfds);
  // Add stdin
  FD_SET(fileno(stdin), &readfds);
  FD_SET(conn_fd, &readfds);

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (select(conn_fd + 1, &readfds, nullptr, nullptr, &tv) == -1) {
    // error
    fprintf(stderr, "select error\n");
    return -1;
  }

  if (FD_ISSET(conn_fd, &readfds)) {
    app->dirty = clear_line(app->chars + 1);
    if (ncx_io_read(app) == -1) {
      return -1;
    }
  }

  if (FD_ISSET(0, &readfds)) {
    ncx_getkey(app);
  }

  if (app->dirty == 1) {
    show_prompt(app);
    app->dirty = 0;
  }
  return 0;
}

