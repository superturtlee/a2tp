CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -pthread
BINS     = a2tp-srv a2tp-cli

all: $(BINS)

a2tp-srv: src/server.c src/common.c src/common.h
	$(CC) $(CFLAGS) -o $@ src/server.c src/common.c

a2tp-cli: src/client.c src/common.c src/common.h
	$(CC) $(CFLAGS) -o $@ src/client.c src/common.c

clean:
	rm -f $(BINS)

.PHONY: all clean
