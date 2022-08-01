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

#include <sys/stat.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <pwd.h>
#include <unistd.h>

#include "ncx_opts.h"

static int ncx_mkdir(const char *path)
{
  struct stat st;

  if (stat(path, &st) != 0) {
    if (mkdir(path, 0700) != 0) {
      fprintf(stderr, "Error: mkdir %s: %s\n", path, strerror(errno));
      return -1;
    }
  } else {
    if (!S_ISDIR(st.st_mode)) {
      fprintf(stderr, "Error: %s is not a directory\n", path);
      return -1;
    }
  }
  return 0;
}

Options::Options()
  : m_use_ssl(true), m_port(6667), m_server_name("mikekohn.net")
{
}

int Options::parse(int argc, char *argv[])
{
  struct passwd *pw = getpwuid(getuid());
  if (pw == nullptr) {
    fprintf(stderr, "Fatal: Can't get your user info.\n");
    return -1;
  }

  _conf_dir = pw->pw_dir;
  _conf_dir += "/.ncx";
  if (ncx_mkdir(_conf_dir.c_str()) != 0) {
    return -1;
  }

  // Quick arg parser...
  while (--argc) {
    char *p = *++argv;
    if (*p == '-') {
      if (!strcmp(p, "-i") || !strcmp(p, "--no-ssl")) {
        m_use_ssl = false;
        m_port = 6666;
      }
    }
  }

  return 0;
}
