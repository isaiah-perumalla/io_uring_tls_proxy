#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <liburing/io_uring.h>
#include <liburing.h>
#include "uring_tls.h"
#include "uring_buff_pool.h"

/**
 * small example program tls proxy, which uses io_uring
 * and openssl
 * reads ip and hostname from stdin, establishes a TLS connection and then http get
 *
 * example usage
 * ./tiny_get cacerts.pem
 *
 * > 142.250.80.36 google.com; 142.250.80.31 www.firefox.com
 *
 * the above in stdin will connect to both ips , establish tls connection and perform a http get
 * prints output to stdout
 * all running on a single thread , using io_uring for all IO operations
 */

#define BUFFER_SIZE 2048
#define NBUFFERS 16
#define MAX_CONNS 16
#define ENTRIES 1024
#define NCQES (ENTRIES * 4)

/**
 * pool initialised in main
 */
static struct fixed_buff_pool WRITE_BUFFER_POOL;
static struct read_buff_pool READ_BUFFER_POOL;
static struct ssl_conn CONNECTIONS[MAX_CONNS];

enum {
    STDIN_READ = 200
};
char stdin_buffer[1024];

struct ssl_conn *get_ssl_conn(uint16_t conn_idx) {
    struct ssl_conn* conn = &CONNECTIONS[conn_idx];
    return conn;
}



int setup_socket(char *host_ip, int port, struct sockaddr_in *addr);

int init_conn(char *host_ip, int port, char* host_name, struct ssl_conn* conn) {

    int sock_fd = setup_socket(host_ip, port, &conn->addr_in);
    if (sock_fd < 0) {
        return -1;
    }
    conn->fd = sock_fd;
    strcpy(&conn->host_name[0], host_name);
    return 0;
}
/**
 *
 * @param host_ip
 * @param port
 * @param ring
 * @param host_name
 * @return connection index for this connection , negative value if err
 */
int initiate_tls_connect(char *host_ip, int port, struct io_uring *ring, char *host_name) {
    struct ssl_conn* conn = NULL;
    int conn_idx = -1;
    for(int i = 0; i < 16; i++) {
        conn = get_ssl_conn(i);
        if (conn->ssl == NULL) { //free for use
            conn_idx = i;
            break;
        }
    }
    if (conn_idx == -1) {
        return -2;
    }
    int err = init_conn(host_ip, port, host_name, conn);
    if (err) {
        return -1;
    }

    prep_connect(conn->fd, (struct sockaddr *) &conn->addr_in, sizeof(conn->addr_in), ring, conn_idx);
    return conn_idx;
}

void prep_http_get(struct io_uring *uring, struct uring_user_data *data, struct ssl_conn *conn) {
    char *hostname = conn->host_name;
    char out_buf[512];
    snprintf(
            out_buf,
            512,
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "User-Agent: Example TLS client\r\n"
            "\r\n",
            hostname);
    int request_length = strlen(out_buf);
    int n = SSL_write(conn->ssl, out_buf, request_length);
    assert(n == request_length);
    void *buffer = fixed_pool_get_buffer(&WRITE_BUFFER_POOL, (*data).conn_idx);
    BIO *write_bio = SSL_get_wbio(conn->ssl);
    int read_bytes = BIO_read(write_bio, buffer, BUFFER_SIZE);
    prep_write(conn->fd, uring, (*data).conn_idx, DATA_WRITE, buffer, read_bytes);
}


void on_tls_handshake_complete(struct io_uring *uring, struct uring_user_data data) {
    struct ssl_conn *conn = &CONNECTIONS[data.conn_idx];
    prep_http_get(uring, &data, conn);
    prep_read(conn->fd, uring, DATA_READ, data.conn_idx, READ_BUFFER_POOL.buff_size);

}

void on_tls_handshake_failed(struct io_uring *ring, struct uring_user_data tag) {
    ERR_print_errors_fp(stderr);

    struct ssl_conn *conn = get_ssl_conn(tag.conn_idx);
    fprintf(stderr, "TLS handshake err [%s] \n", conn->host_name);
    clean_up_connection(ring, (tag).conn_idx);
}

void on_data_recv(struct io_uring *uring, struct io_uring_cqe *cqe) {
    struct uring_user_data  data;
    memcpy(&data, &cqe->user_data, sizeof(data));
    struct ssl_conn *conn = &CONNECTIONS[data.conn_idx];
    int read_bytes = cqe->res;
    assert(read_bytes > 0 && "read bytes less than 0");
    fprintf(stderr, "read %d bytes \n", read_bytes);
    const unsigned short buf_idx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    void *buffer = buffer_pool_get(&READ_BUFFER_POOL, buf_idx);
    BIO *read_bio = SSL_get_rbio(conn->ssl);
    BIO_write(read_bio, buffer, read_bytes);
    char out_buff[2048];
    const unsigned int max_buffer_size = READ_BUFFER_POOL.buff_size;

    for(;;) {
        int read = SSL_read(conn->ssl, out_buff, sizeof(out_buff)-1);

        if (read <= 0) {
            //ssl  record needs more data before decrypt so schedule another read
            break;
        }
        out_buff[read] = '\0';
        fprintf(stdout, "%s", out_buff);
    }
    buffer_pool_release(&READ_BUFFER_POOL, buf_idx);
    prep_read(conn->fd, uring, DATA_READ, data.conn_idx, max_buffer_size);
}

void on_tcp_connect_failed(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    __s32 res = cqe->res;
    struct ssl_conn *conn = &CONNECTIONS[tag.conn_idx];
    fprintf(stderr, "TCP-CONNECT host_name=%s, error=[%s], [cqe res=%d tag.conn_idx=%d] \n",
            conn->host_name,
            strerror(res),
            cqe->res,
            tag.conn_idx);
}

void on_tcp_connect(struct io_uring_cqe *cqe, struct io_uring *ring) {
    struct uring_user_data  tag;
    memcpy(&tag, &cqe->user_data, sizeof(tag));
    struct ssl_conn *conn = &CONNECTIONS[tag.conn_idx];
    SSL *ssl = setup_tls_client(ssl_ctx, conn->host_name);
    conn->ssl = ssl;
    assert(conn->ssl && "could not create ssl");
    fprintf(stderr, "tcp connected %d %d \n", tag.conn_idx, tag.req_type);
    int ret = do_ssl_handshake(cqe, ring, &READ_BUFFER_POOL, &WRITE_BUFFER_POOL);
    if (ret == -1) {
        on_tls_handshake_failed(ring, tag);
        //handshake failed;
    }
}
void on_read_err(struct io_uring *uring, struct io_uring_cqe *cqe) {
    if (cqe->res == 0) {
        fprintf(stderr, "zero bytes read \n");
        goto cleanup;
    }
    else if (cqe->res == -ENOBUFS) {
        fprintf(stderr, "READ ERR, no buffers in Pool \n");
        return;
    }
    else {
        fprintf(stderr, "read error %d \n", cqe->res);
        goto cleanup;
    }
    cleanup:
    {
        struct uring_user_data data;
        memcpy(&data, &cqe->user_data, sizeof(struct uring_user_data));
        int conn_idx = data.conn_idx;
        clean_up_connection(uring, conn_idx);
        fflush(stdout);
    }
}

void on_tcp_close(struct io_uring* ring, struct uring_user_data *tag) {
    struct ssl_conn *conn = &CONNECTIONS[(*tag).conn_idx];
    fprintf(stderr, "connection closed %d\n", conn->fd);
    conn->fd = -1;
}


int setup_socket(char *host_ip, int port, struct sockaddr_in *addr) {
    int  fd;
    if (0 > (fd = socket(AF_INET,
                         SOCK_STREAM , //|  SOCK_NONBLOCK,
                         0))) {
        return -1;
    }
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    if (host_ip && (1 != inet_pton(AF_INET, host_ip, &addr->sin_addr))) {
        return -1;
    }

    return fd;
}

int prep_read_stdin(struct io_uring *ring, size_t offset) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
        return -1;
    }
    size_t nbytes = sizeof(stdin_buffer) - offset;
    io_uring_prep_read(sqe, stdin->_fileno, stdin_buffer, nbytes, offset);
    struct uring_user_data data = {
            .conn_idx = 0,
            .req_type = STDIN_READ
    };
    memcpy(&sqe->user_data, &data, sizeof(struct uring_user_data));
    return 0;
}


void on_stdin(struct io_uring* ring, char* buff, size_t len) {

    if (strchr(buff, '\n')) {

        char *delim = " ;";
        char *ip = strtok(buff, delim);
        while(ip) {
            char *hostname = strtok(NULL, delim);
            if (hostname == NULL) break;
            uint32_t ip_addr;
            bool ip_valid = 1 == inet_pton(AF_INET, ip, &ip_addr);

            if (ip_valid) {
                int conn_idx = initiate_tls_connect(ip, 443, ring, hostname);
                if (conn_idx < 0) {
                    fprintf(stderr, "error %d, initiate_tls_connect %s, hostname %s\n",
                            conn_idx,
                            ip, hostname);
                }
                else {
                    fprintf(stderr, "initiating connection to %s; host=%s\n", ip, hostname);
                }
            }
            else {
                fprintf(stderr, "INVALID IP ip=%s , hostname=%s \n", ip,  hostname);
            }
            ip = strtok(NULL, delim);
        }
        //clear buff
        memset(stdin_buffer, 0, sizeof(stdin_buffer));
        prep_read_stdin(ring, 0);
    }
    else {
        prep_read_stdin(ring, len);
    }

}


int main(int argc, char* argv[]) {

    if (argc < 2) {
        fprintf(stderr, "Usage %s  ca-certs-filename\n", argv[0]);
        return 1;
    }

    int port = 443;
    const char *ca_file = argv[1];

    int ctx_err = init_ssl_ctx(ca_file);

    if (ctx_err <= 0 ) {
        fprintf(stderr, "could not load trusted certs from %s\n", ca_file);
        return 1;
    }

    struct io_uring ring;
    memset(&ring, 0, sizeof(ring));
    int ret = setup_iouring(&ring, NCQES, ENTRIES);
    if (ret < 0 ) {
        fprintf(stderr, "unable to setup io uring \n");
        exit(1);
    }
    int err = setup_fixed_buffers(&ring, &WRITE_BUFFER_POOL, BUFFER_SIZE, NBUFFERS);
    if (err) {
        fprintf(stderr, "unable to setup fixed buffers \n");
        exit(1);
    }
    err = setup_io_uring_pooled_buffers(&ring, &READ_BUFFER_POOL, BUFFER_SIZE, NBUFFERS);
    if (err) {
        fprintf(stderr, "unable to io_uring_buf  buffers \n");
        exit(1);
    }

    prep_read_stdin(&ring, stdin->_fileno);
    struct io_uring_cqe *cqes[NCQES];

    while(1) {
        int ret = io_uring_submit_and_wait(&ring, 1);
        if (-EINTR == ret) continue;
        if (ret < 0) {
            fprintf(stderr, "error submit_wait failed %d\n", ret);
//            break;
        }
        const int count = io_uring_peek_batch_cqe(&ring, &cqes[0], NCQES);
        for (int i = 0; i < count; i++) {
            struct io_uring_cqe *cqe = cqes[i];
            struct uring_user_data data;
            memcpy(&data, &cqe->user_data, sizeof(struct uring_user_data));
            if (data.req_type == STDIN_READ) {
                on_stdin(&ring, &stdin_buffer[0], cqe->res);
            } else {
                process_cqe(cqe, &ring, &READ_BUFFER_POOL, &WRITE_BUFFER_POOL);
            }
        }
        io_uring_cq_advance(&ring, count);
    }

}