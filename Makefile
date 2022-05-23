# Makefile for ncx

.PHONY: all clean

C_SRCS = ncx_io.c ncx_main.c ncx_net.c ncx_opts.c
OBJS = $(C_SRCS:.c=.o)
DEPS = $(C_SRCS:.c=.d)

CC? = gcc

CFLAGS = -Wall -O2

EXE = ncx

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -MT $@ -o $@ -c $<

clean:
	rm -f $(OBJS) $(EXE) $(DEPS)

-include $(DEPS)
