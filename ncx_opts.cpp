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
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <pwd.h>
#include <unistd.h>

#include "ncx_opts.h"
#include "ncx_main.h"

static char s_conf_dir[1024];

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

static void usage(int err)
{
  if (err) {
    fprintf(stderr, "Invalid argument\n");
  }

  fprintf(stderr, "usage: %s [-i/--no-ssl] [server:port]\n", progname);
  fprintf(stderr, "\t-i           - Connect without SSL.\n");
  fprintf(stderr, "\t--no-ssl     - Connect without SSL.\n");
  fprintf(stderr, "\t--help       - Print this message.\n");
  fprintf(stderr, "\tserver:port  - (optional) Connect to server and port.\n");

  exit(err);
}

int ncx_opts_parse(int argc, char *argv[], struct ncx_options *opts)
{
  struct passwd *pw = getpwuid(getuid());
  if (pw == nullptr) {
    fprintf(stderr, "Fatal: Can't get your user info.\n");
    return -1;
  }

  snprintf(s_conf_dir, sizeof(s_conf_dir), "%s/.ncx", pw->pw_dir);
  if (ncx_mkdir(s_conf_dir) != 0) {
    return -1;
  }

  opts->use_ssl = true;
  opts->port = 6667;
  opts->server = "mikekohn.net";

  // Quick arg parser...
  while (--argc) {
    char *p = *++argv;
    if (*p == '-') {
      if (!strcmp(p, "-i") || !strcmp(p, "--no-ssl")) {
        opts->use_ssl = false;
        opts->port = 6666;
      } else if (!strcmp(p, "--help")) {
        usage(0);
      } else {
        usage(1);
      }
    } else {
      char *p_colon = strchr(p, ':');
      if (p_colon != nullptr) {
        *p_colon = '\0';
        opts->server = p;
        opts->port = atoi(p_colon + 1);
      } else {
        opts->server = p;
      }
    }
  }

  return 0;
}

const char *ncx_opts_dir()
{
  return s_conf_dir;
}

