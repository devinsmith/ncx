# Makefile for ncx

.PHONY: all clean

C_SRCS = ncx_certs.c ncx_color.c ncx_io.c ncx_main.c ncx_net.c ncx_opts.c
OBJS = $(C_SRCS:.c=.o)
DEPS = $(C_SRCS:.c=.d)

CC? = gcc
CXX? = g++

CFLAGS = -Wall -Wextra -g3

EXE = ncx

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJS) -lcrypto -lssl

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -MT $@ -o $@ -c $<

.cpp.o:
	$(CXX) $(CFLAGS) -MMD -MP -MT $@ -o $@ -c $<

clean:
	rm -f $(OBJS) $(EXE) $(DEPS)

-include $(DEPS)
