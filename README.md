# io_uring_tls_proxy
io_uring based TLS proxy

## Prerequisites
1. Linux kernel version 6.0 or higher
2. liburing submodule 
3. libssl3.so is required, running the follwoing should show if it is already on machine `ldconfig -p|grep ssl`

## Build liburing
1. `./configure --prefix=../build`
2. make
3. make install
4, should see liburing shared and static libs in ./build 
