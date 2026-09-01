CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -pthread
# tcp challenge auth (ssh ed25519 keys) uses OpenSSL libcrypto
CRYPTOLIB = -lcrypto
BINS     = a2tp-srv a2tp-cli

# Windows client (tap-windows6 backend), cross-compiled with MinGW-w64;
# -static so the exe runs without any winpthreads DLL
CROSS    ?= x86_64-w64-mingw32-
WINCC    ?= $(CROSS)gcc
WINFLAGS ?= -O2 -Wall -Wextra -std=c11 -static -pthread
WINLIBS   = -lws2_32 -liphlpapi -lpthread

all: $(BINS)

a2tp-srv: src/server.c src/common.c src/auth.c src/common.h src/auth.h
	$(CC) $(CFLAGS) -o $@ src/server.c src/common.c src/auth.c $(CRYPTOLIB)

a2tp-cli: src/client.c src/common.c src/auth.c src/common.h src/auth.h
	$(CC) $(CFLAGS) -o $@ src/client.c src/common.c src/auth.c $(CRYPTOLIB)

a2tp-cli.exe: src/client-win.c src/proto.h
	$(WINCC) $(WINFLAGS) -o $@ src/client-win.c $(WINLIBS)

auth-test: src/auth_test.c src/auth.c src/common.c src/auth.h
	$(CC) $(CFLAGS) -o $@ src/auth_test.c src/auth.c src/common.c $(CRYPTOLIB)

check: auth-test
	./auth-test

clean:
	rm -f $(BINS) a2tp-cli.exe auth-test

.PHONY: all clean check
