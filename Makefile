CC=gcc
CFLAGS=-Wall -Wextra -g
LIBS=liburing/build/lib/liburing.a
ODIR=build

all: tls_server

tls_server: tls_server.o
	$(CC) $(CFLAGS) -o $@  tls_server.o $(LIBS) -lssl -lcrypto

.PHONY: clean

clean:
	rm -f *.o tls_server