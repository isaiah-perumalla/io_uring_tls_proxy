//
// Created by isaiahp on 11/18/22.
//

#ifndef IOURING_TLS_URING_BUFF_POOL_H
#define IOURING_TLS_URING_BUFF_POOL_H

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <liburing/io_uring.h>
#include <liburing.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>


struct read_buff_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    struct io_uring_buf_ring* buff_ring;
};

struct fixed_buff_pool {
    unsigned int nbuffers;
    unsigned int buff_size;
    void* mem;
};


static void *fixed_pool_get_buffer(struct fixed_buff_pool* pool, __u16 idx) {
    void *buff = pool->mem + (idx * pool->buff_size);
    return buff;
}

unsigned char* buffer_pool_get(struct read_buff_pool* pool, unsigned int idx) {
    unsigned char *buff_base = (unsigned char *) pool->buff_ring +
                               sizeof(struct io_uring_buf) * pool->nbuffers;
    return buff_base + (idx * pool->buff_size);
}

void buffer_pool_release(struct read_buff_pool *buff_pool, unsigned short idx) {
    void *buffer = buffer_pool_get(buff_pool, idx); //base address of buffer at idx
    int mask = io_uring_buf_ring_mask(buff_pool->nbuffers);
    io_uring_buf_ring_add(buff_pool->buff_ring, buffer, buff_pool->buff_size, idx, mask, 0 );
    io_uring_buf_ring_advance(buff_pool->buff_ring, 1);
}

/**buffer pool for reads
 *
 * @param uring
 * @param buff_pool
 * @return
 */
int setup_io_uring_pooled_buffers(struct io_uring *uring, struct read_buff_pool* buff_pool,
                                  __u16 buffer_size, __u16 nbufs) {

    const size_t size = (sizeof(struct io_uring_buf) + buffer_size) * nbufs;
    void *mem = mmap(NULL, size, PROT_WRITE | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to allocate buffers \n");
        return -1;
    }
    struct io_uring_buf_ring *buff_ring = (struct io_uring_buf_ring *) mem;
    io_uring_buf_ring_init(buff_ring);
    struct io_uring_buf_reg buf_reg = {
            .ring_addr = (unsigned long) buff_ring,
            .bgid = 0,
            .ring_entries = nbufs
    };
    int result = io_uring_register_buf_ring(uring, &buf_reg, 0);
    if (result) {
        fprintf(stderr, "failed to register_buf_ring %s \n", strerror(-result));
        return result;
    }
    unsigned char *buffers_base = (unsigned char *) buff_ring + (sizeof(struct io_uring_buf) * nbufs);
    for(unsigned int i = 0; i < nbufs; i++) {
        void *buffer_i = buffers_base + (buffer_size * i);
        io_uring_buf_ring_add(buff_ring, buffer_i, buffer_size, i,
                              io_uring_buf_ring_mask(nbufs), i);
    }
    io_uring_buf_ring_advance(buff_ring, nbufs);
    buff_pool->buff_ring = buff_ring;
    buff_pool->nbuffers = nbufs;
    buff_pool->buff_size = buffer_size;
    return 0;
}

int setup_fixed_buffers(struct io_uring *uring, struct fixed_buff_pool* fixed_pool,
        __u16 buffer_size, __u16 nbuffs) {

    const size_t size = buffer_size * nbuffs;
    void *mem = mmap(NULL, size, PROT_WRITE | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                     0, 0);

    if (mem == MAP_FAILED) {
        fprintf(stderr, "failed to allocate buffers \n");
        return -1;
    }
    struct iovec iov[nbuffs];
    for(int i = 0; i < nbuffs; i++) {
        iov[i].iov_base = mem + (i * buffer_size);
        iov[i].iov_len = buffer_size;
        memset(iov[i].iov_base, 0, buffer_size);
    }
    int ret = io_uring_register_buffers(uring, iov, nbuffs);
    if(ret) {
        fprintf(stderr, "Error registering buffers: %s", strerror(-ret));
        return -1;
    }
    fixed_pool->nbuffers = nbuffs;
    fixed_pool->buff_size = buffer_size;
    fixed_pool->mem = mem;
    return 0;
}

#endif //IOURING_TLS_URING_BUFF_POOL_H
