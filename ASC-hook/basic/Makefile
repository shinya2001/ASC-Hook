PROGS = ASC_hook_basic.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
# Set CFLAGS for debugging: include -g for debug symbols and reduce optimization to -O0
CFLAGS = -O0 -g -pipe
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
