// Standard and Error
#include <bits/types/sig_atomic_t.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
// Address translation
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
// Event
#include <signal.h>
#include <poll.h>
// OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
// Debug
#include <assert.h>

typedef int Socket;

typedef struct server_t {
    Socket socket;
    int family;
    SSL_CTX* ctx;
} *SERVER;

typedef struct client_t {
    Socket socket;
    int family;
    struct sockaddr sockaddr;
    socklen_t socklen;
    SSL* ssl;
} *CLIENT;

int reuseaddr(Socket fd, int val)
{
    /*
        0 = no reuse
        1 = reuse of address
    */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
        perror("");
        return -1;
    }

    return 0;
}

struct sockaddr* create_sockaddr(int family, const char* address, const char* port)
{
    int rc;

    if (family == AF_INET) {
        static struct sockaddr_in addr;
        rc = inet_pton(AF_INET, address, &addr.sin_addr);
        if (rc <= 0) {
            if (rc == 0)
                fprintf(stderr, "inet_pton: Not in presentation format.");
            else
                perror("inet_pton");
            exit(-1);
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(port));

        return (struct sockaddr*)&addr;
    }

    if (family == AF_INET6) {
        static struct sockaddr_in6 addr;
        rc = inet_pton(AF_INET6, address, &addr.sin6_addr);
        if (rc <= 0) {
            if (rc == 0)
                fprintf(stderr, "inet_pton: Not in presentation format.");
            else
                perror("inet_pton");
            exit(-1);
        }

        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(atoi(port));

        return (struct sockaddr*)&addr;
    }
    else {
        exit(-1);
    }
}

Socket create_socket(int family, const char* address, const char* port, int count)
{
    int fd, rc;
    struct sockaddr* addr;

    addr = create_sockaddr(family, address, port);

    fd = socket(addr->sa_family, SOCK_STREAM, 0); // SOCK_NONBLOCK
    if (fd == -1) {
        perror("socket");
        exit(-1);
    }
    printf("[create_sockaddr] Created\n");

    rc = reuseaddr(fd, 1);
    if (rc == -1) {
        perror("server_reuseaddr");
        exit(-1);
    }
    printf("[create_sockaddr] Address reuse on\n");

    rc = bind(fd, addr, sizeof(*addr));
    if (rc == -1) {
        perror("bind");
        exit(-1);
    }
    printf("[create_sockaddr] Bound to %s:%s\n", address, port);

    rc = listen(fd, count);
    if (rc == -1) {
        perror("listen");
        exit(-1);
    }
    printf("[create_sockaddr] Listening for %i connections\n", count);

    return fd;
}

SSL_CTX* create_ssl_ctx(char* key, char* cert, int type)
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        fprintf(stderr, "SSL_CTX_new: Failed to allocate enough space");
        exit(-1);
    }
    printf("[create_ssl_ctx] SSL context created\n");

    if(!SSL_CTX_use_PrivateKey_file(ctx, key, type)) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("[create_ssl_ctx] Key set to %s\n", key);


    if (!SSL_CTX_use_certificate_file(ctx, cert, type)) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("[create_ssl_ctx] Cert set to %s\n", cert);

    return ctx;
}

SERVER new_server(int family, const char* address, const char* port, int count, char* key, char* cert, int key_type)
{
    SERVER server;

    server = malloc(sizeof(struct server_t));
    memset(server, 0, sizeof(struct server_t));

    server->socket = create_socket(family, address, port, count);
    server->ctx = create_ssl_ctx(key, cert, key_type);

    return server;
}

void close_server(SERVER server)
{
    close(server->socket);
}

void free_server(SERVER server)
{
    SSL_CTX_free(server->ctx);
    free(server);
}

SSL* create_ssl(SSL_CTX* ctx, Socket socket)
{
    SSL* ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "SSL_new: Failed to allocate enough space");
        return NULL;
    }
    printf("[create_ssl] SSL created\n");

    if (SSL_set_fd(ssl, socket) == 0) {
        fprintf(stderr, "SSL_set_fd: %s\n", ERR_reason_error_string(SSL_get_error(ssl, 0)));
        SSL_free(ssl);
        return NULL;
    }
    printf("[create_ssl] SSL set filedescriptor\n");

    return ssl;
}

CLIENT accept_client(SERVER server)
{
    CLIENT client;

    client = malloc(sizeof(struct client_t));
    memset(client, 0, sizeof(struct client_t));

    client->socket = accept(server->socket, &client->sockaddr, &client->socklen);
    if (client->socket == -1) {
        perror("accept");
        free(client);
        return NULL;
    }
    printf("[accept_client] Client accepted\n");

    client->ssl = create_ssl(server->ctx, client->socket);
    if (client->ssl == NULL) {
        fprintf(stderr, "create_ssl: Failed to allocate enough space");
        free(client);
        return NULL;
    }
    printf("[accept_client] Client ssl created\n");

    client->family = client->sockaddr.sa_family;

    if (SSL_accept(client->ssl) <= 0) {
        fprintf(stderr, "SSL_set_fd: Handshake failed\n");
        SSL_free(client->ssl);
        close(client->socket);
        return NULL;
    }
    printf("[accept_client] Client handshake complete\n");

    return client;
}

void close_client(CLIENT client)
{
    while(!SSL_shutdown(client->ssl));
}

void free_client(CLIENT client)
{
    SSL_free(client->ssl);

    close(client->socket);
    free(client);
}

int read_client(CLIENT client, char** buf)
{
    int bytes;

    bytes = SSL_read(client->ssl, NULL, 0);
    if (bytes < 0) {
        ERR_print_errors_fp(stderr);
    }
    printf("[read_client] Empty read %i\n", bytes);

    bytes = SSL_pending(client->ssl);
    printf("[read_client] Bytes pending %i\n", bytes);

    (*buf) = malloc((bytes + 1) * sizeof(char));
    memset((*buf), 0, bytes + 1);
    printf("[read_client] Malloced %i bytes\n", bytes);

    bytes = SSL_read(client->ssl, (*buf), bytes);
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
    }
    printf("[read_client] Read %i into buffer\n", bytes);

    return bytes;
}

volatile sig_atomic_t serving = 1;

void sigint_handler(int sig)
{
    serving = 0;
}

int main(int argc, char* argv[])
{
    signal(SIGINT, sigint_handler);

    SERVER server;
    CLIENT client;

    server = new_server(AF_INET, "0.0.0.0", "3277", 10, "key.pem", "cert.pem", SSL_FILETYPE_PEM);

    LOOP:
    client = accept_client(server);
    
    if(client == NULL) goto IGNORE;

    int by;
    char* buf;

    by = read_client(client, &buf);
    
    printf("%s\nReceived %i\n", buf, by);
    free(buf);
    
    char* send_buf = "HTTP/1.0 200 OK\nconnection: close\n\nHallo das ist ein Text!\n";

    SSL_write(client->ssl, send_buf, strlen(send_buf));

    close_client(client);
    free_client(client);

    goto LOOP;
    
    IGNORE:
    printf("[accept_client] Some strange connection has been ignored\n");
    free(client);
    goto LOOP;

    close_server(server);
    free_server(server);
    return 0;
}