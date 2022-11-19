CC=gcc
CFLAGS=-Wall -Wextra -g
LIBS=/usr/lib/liburing.a
ODIR=build

all: udp_echo tcp_echo tls_server

udp_echo: echo_udp_server.o
	$(CC) $(CFLAGS) -o $@  echo_udp_server.o $(LIBS)

tcp_echo: echo_server.o
	$(CC) $(CFLAGS) -o $@ echo_server.o  $(LIBS)

tls_server: tls_server.o
	$(CC) $(CFLAGS) -o $@  tls_server.o $(LIBS) -lssl -lcrypto

.PHONY: clean

clean:
	rm -f *.o udp_echo tcp_echo tls_server