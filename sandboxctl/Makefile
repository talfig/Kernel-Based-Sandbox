
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: sandboxctl

sandboxctl: sandboxctl.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f sandboxctl
