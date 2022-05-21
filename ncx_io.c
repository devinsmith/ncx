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

#include <stdio.h>
#include <string.h>

#include "ncx_io.h"
#include "ncx_net.h"

static int clear_line(struct ncx_conn *conn)
{
  int i;

  if (conn->dirty == -1)
    return 0;

  printf("\r");
  for (i = 0; i <= conn->chars; i++) {
    putchar(' ');
  }
  printf("\r");
  fflush(stdout);

  return 1;
}

static void show_prompt(struct ncx_conn *conn)
{
  printf("> %s", conn->line_buffer);
  fflush(stdout);
}

static void ncx_getkey(struct ncx_conn *conn)
{
  int ch;

  ch = getchar();

  if (ch == '\b' || ch == 127 || ch == 4) {
    if (conn->chars != 0) {
      printf("\b \b");
      conn->line_buffer[--conn->chars] = 0;
      fflush(stdout);
    }
  } else if (ch == '\n' || ch == '\r') {
    conn->line_buffer[conn->chars++] = '\n';
    conn->line_buffer[conn->chars] = 0;
    clear_line(conn);
    ncx_send_data(conn->fd, conn->line_buffer);
    memset(conn->line_buffer, 0, conn->chars);
    conn->chars = 0;
    conn->dirty = 1;
  } else {
    conn->line_buffer[conn->chars++] = ch;
    putchar(ch);
    fflush(stdout);
  }
}

static void process_data(struct ncx_conn *conn, char *buffer, ssize_t nbytes)
{
  int i;

  for (i = 0; i < nbytes; i++) {
    if (buffer[i] == '\r') continue;
    if (buffer[i] == '\0') {
      //printf("Got NUL byte in buffer\n");
      continue;
    }

    if (buffer[i] == '\n') {
      /* Display message to user */
      conn->m_buffer[conn->m_buf_idx] = '\0';
      printf("%s\n", conn->m_buffer);
      conn->dirty = 1;

      /* clear out our input buffer */
      conn->m_buf_idx = 0;
    } else {
      conn->m_buffer[conn->m_buf_idx++] = buffer[i];
    }
  }
}

static void ncx_io_read(struct ncx_conn *conn)
{
  char buffer[2048];
  int bytes = ncx_read_data(conn->fd, buffer, sizeof(buffer));

  if (bytes <= 0) {
    fprintf(stderr, "socket closed\n");
    ncx_exit();
  }

  process_data(conn, buffer, bytes);
}

int ncx_io_run(struct ncx_conn *conn)
{
  struct timeval tv;
  fd_set readfds;

  FD_ZERO(&readfds);
  // Add stdin
  FD_SET(0, &readfds);
  FD_SET(conn->fd, &readfds);

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (select(conn->fd + 1, &readfds, NULL, NULL, &tv) == -1) {
    // error
    fprintf(stderr, "select error\n");
    ncx_exit();
  }

  if (FD_ISSET(conn->fd, &readfds)) {
    conn->dirty = clear_line(conn);
    ncx_io_read(conn);
  }

  if (FD_ISSET(0, &readfds)) {
    ncx_getkey(conn);
  }

  if (conn->dirty == 1) {
    show_prompt(conn);
    conn->dirty = 0;
  }
  return 0;
}

