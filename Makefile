# Makefile for ncx

.PHONY: all clean

CXX_SRCS = ncx_certs.cpp ncx_color.cpp ncx_main.cpp ncx_io.cpp ncx_net.cpp \
					 ncx_opts.cpp
OBJS = $(CXX_SRCS:.cpp=.o)
DEPS = $(CXX_SRCS:.cpp=.d)

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
