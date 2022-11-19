CC=gcc
CFLAGS=-Wall -Wextra -g
LIBS=liburing/build/lib/liburing.a
ODIR=build

all: tiny_get

tiny_get: tiny_get.o uring_buff_pool.h uring_tls.h
	$(CC) $(CFLAGS) -o $@  tiny_get.o $(LIBS) -lssl -lcrypto

.PHONY: clean

clean:
	rm -f *.o tiny_get