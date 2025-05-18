PROGS = ASC_hook.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
# Set CFLAGS for debugging: include -g for debug symbols and reduce optimization to -O0
CFLAGS = -O0 -g -pipe -rdynamic
CFLAGS += -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK

LD_VERSION = $(shell ld --version | head -1 | awk '{print $$NF}' | cut -d '.' -f1-2 | tr -d '.')

# differentiate the code according to the library version
ifeq ($(shell test $(LD_VERSION) -ge 235; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_239
else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_229
endif


LDFLAGS += -lopcodes -ldl -lkeystone -lstdc++ -lm



C_SRCS = gacha.c personal_springboard.c Assembly_section.c signal_handler.c static_check.c adrpSpringboard.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS)  -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
