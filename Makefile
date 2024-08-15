# Makefile for ncx

.PHONY: all clean

C_SRCS = ncx_color.c ncx_opts.c
CXX_SRCS = ncx_certs.cpp ncx_main.cpp ncx_io.cpp ncx_net.cpp
OBJS = $(CXX_SRCS:.cpp=.o) $(C_SRCS:.c=.o)
DEPS = $(CXX_SRCS:.cpp=.d) $(C_SRCS:.c=.d)

CC? = gcc
CXX? = g++

CFLAGS = -Wall -Wextra -g3

EXE = ncx

all: $(EXE)

$(EXE): $(OBJS)
	$(CXX) $(CFLAGS) -o $(EXE) $(OBJS) -lcrypto -lssl

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -MT $@ -o $@ -c $<

.cpp.o:
	$(CXX) $(CFLAGS) -MMD -MP -MT $@ -o $@ -c $<

clean:
	rm -f $(OBJS) $(EXE) $(DEPS)

-include $(DEPS)
