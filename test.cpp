#include <ctype.h>
#include <fcntl.h>
#include <liburing.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct request {
    int          event_type;
    int          client_sockfd;
    int          iovec_count;
    struct iovec iov[];
};

struct io_uring ring;

const char* unimplemented_content =
    "HTTP/1.0 400 Bad Request\r\n"
    "Content-type: text/html\r\n"
    "\r\n"
    "<html>"
    "<head>"
    "<title>ZeroHTTPd: Unimplemented</title>"
    "</head>"
    "<body>"
    "<h1>Bad Request (Unimplemented)</h1>"
    "<p>Your client sent a request ZeroHTTPd did not understand and it is probably "
    "not your fault.</p>"
    "</body>"
    "</html>";

const char* http_404_content =
    "HTTP/1.0 404 Not Found\r\n"
    "Content-type: text/html\r\n"
    "\r\n"
    "<html>"
    "<head>"
    "<title>ZeroHTTPd: Not Found</title>"
    "</head>"
    "<body>"
    "<h1>Not Found (404)</h1>"
    "<p>Your client is asking for an object that was not found on this server.</p>"
    "</body>"
    "</html>";

#define READ_SZ 8192

#define SERVER_STRING "Server: zerohttpd/0.1\r\n"

#define EVENT_TYPE_ACCEPT 0
#define EVENT_TYPE_READ 1
#define EVENT_TYPE_WRITE 2
#define EVENT_TYPE_DINNER 3

//-------helper function-----------

void strtolower(char* str) {
    for (; *str; ++str)
        *str = (char)tolower(*str);
}

void fatal_error(const char* syscall) {
    perror(syscall);
    exit(1);
}

void* zh_malloc(size_t size) {
    void* buf = malloc(size);
    if (!buf) {
        fprintf(stderr, "allocate memory fail!\n");
        exit(1);
    }
    return buf;
}
//--------------

int setup_listening_socket(int port) {
    int                sock;
    struct sockaddr_in srv_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        fatal_error("socket()");
    }
    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        fatal_error("setsockopt(SO_REUSEADDR)");
    }
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        fatal_error("bind()");
    }
    if (listen(sock, SOMAXCONN) < 0) {
        fatal_error("listen()");
    }
    return sock;
}

int add_accept_request(int sockfd, sockaddr_in* clnt_addr, socklen_t* clnt_addr_len) {
    io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, sockfd, (sockaddr*)clnt_addr, clnt_addr_len, 0);
    struct request* req = (request*)malloc(sizeof(struct request));
    req->event_type = EVENT_TYPE_ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);

    return 0;
}

int add_read_request(int client_sockfd) {
    io_uring_sqe*   sqe = io_uring_get_sqe(&ring);
    struct request* req =
        (request*)malloc(sizeof(struct request) + sizeof(struct iovec));
    req->event_type = EVENT_TYPE_READ;
    req->client_sockfd = client_sockfd;
    req->iov[0].iov_base = malloc(READ_SZ);
    req->iov->iov_len = READ_SZ;
    io_uring_prep_readv(sqe, client_sockfd, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_write_request(struct request* req) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_WRITE;
    io_uring_prep_writev(sqe, req->client_sockfd, req->iov, req->iovec_count, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

void send_static_string_content(const char* str, int client_socket) {
    struct request* req = (request*)malloc(sizeof(struct request) + sizeof(iovec));
    unsigned long   slen = strlen(str);
    req->client_sockfd = client_socket;
    req->iovec_count = 1;
    req->iov[0].iov_base = zh_malloc(slen);
    req->iov[0].iov_len = slen;
    memcpy(req->iov[0].iov_base, str, slen);
    add_write_request(req);
}

void handle_unimplement_method(int client_socket) {
    send_static_string_content(unimplemented_content, client_socket);
}

void handle_http_404(int client_socket) {
    send_static_string_content(http_404_content, client_socket);
}

void copy_file_content(char* file_path, off_t file_size, struct iovec* iov) {
    char* buf = (char*)zh_malloc(file_size);
    int   fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        fatal_error("open(file...)");
    }
    int ret = read(fd, buf, file_size);
    if (ret < file_size) {
        fatal_error("read(file..)");
    }
    close(fd);

    iov->iov_base = buf;
    iov->iov_len = ret;
}

const char* get_filename_ext(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename)
        return "";
    return dot + 1;
}

/*
 *根据文件构造报文头部放入iov[5],依次为响应头，Server
 *,Content-type，Content-len,空行:\\r\\n
 */
void send_headers(const char* path, off_t len, struct iovec* iov) {
    char small_case_path[1024];
    char send_buffer[1024];
    strcpy(small_case_path, path);
    strtolower(small_case_path);

    const char*   str = "HTTP/1.0 200 OK\r\n";
    unsigned long slen = strlen(str);
    iov[0].iov_base = zh_malloc(slen);
    iov[0].iov_len = slen;
    memcpy(iov[0].iov_base, str, slen);

    slen = strlen(SERVER_STRING);
    iov[1].iov_base = zh_malloc(slen);
    iov[1].iov_len = slen;
    memcpy(iov[1].iov_base, SERVER_STRING, slen);

    const char* file_ext = get_filename_ext(small_case_path);
    if (strcmp("jpg", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    if (strcmp("jpeg", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    if (strcmp("png", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/png\r\n");
    if (strcmp("gif", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: image/gif\r\n");
    if (strcmp("htm", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/html\r\n");
    if (strcmp("html", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/html\r\n");
    if (strcmp("js", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: application/javascript\r\n");
    if (strcmp("css", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/css\r\n");
    if (strcmp("txt", file_ext) == 0)
        strcpy(send_buffer, "Content-Type: text/plain\r\n");

    slen = strlen(send_buffer);
    iov[2].iov_base = zh_malloc(slen);
    iov[2].iov_len = slen;
    memcpy(iov[2].iov_base, send_buffer, slen);

    sprintf(send_buffer, "content-length: %ld\r\n", len);
    slen = strlen(send_buffer);
    iov[3].iov_base = zh_malloc(slen);
    iov[3].iov_len = slen;
    memcpy(iov[3].iov_base, send_buffer, slen);

    strcpy(send_buffer, "\r\n");
    slen = strlen(send_buffer);
    iov[4].iov_base = zh_malloc(slen);
    iov[4].iov_len = slen;
    memcpy(iov[4].iov_base, send_buffer, slen);
}

void handle_get_method(char* path, int client_sockfd) {
    char final_path[1024];

    strcpy(final_path, "public");
    strcat(final_path, path);
    if (path[strlen(path) - 1] == '/') {
        strcat(final_path, "index.html");
    }

    struct stat path_stat;
    if (stat(final_path, &path_stat) == -1) {
        printf("404 Not Found: %s (%s)\n", final_path, path);
        handle_http_404(client_sockfd);
    } else {
        /* Check if this is a normal/regular file and not a directory or something
         * else */
        if (S_ISREG(path_stat.st_mode)) {
            struct request* req =
                (request*)zh_malloc(sizeof(*req) + (sizeof(struct iovec) * 6));
            req->iovec_count = 6;
            req->client_sockfd = client_sockfd;
            send_headers(final_path, path_stat.st_size, req->iov);
            copy_file_content(final_path, path_stat.st_size, &req->iov[5]);
            printf("200 %s %ld bytes\n", final_path, path_stat.st_size);
            add_write_request(req);
        } else {
            handle_http_404(client_sockfd);
            printf("404 Not Found: %s\n", final_path);
        }
    }
}

//解析http协议第一行
void handle_http_method(char* method_buffer, int client_sockfd) {
    char *method, *path, *saveptr;

    method = strtok_r(method_buffer, " ", &saveptr);  //分割字符串
    strtolower(method);
    path = strtok_r(NULL, " ", &saveptr);

    if (!strcmp(method, "get")) {
        handle_get_method(path, client_sockfd);
    } else {
        handle_http_404(client_sockfd);
    }
}

int get_line(const char* src, char* dest, int dest_sz) {
    for (int i = 0; i < dest_sz; i++) {
        dest[i] = src[i];
        if (src[i] == '\r' && src[i + 1] == '\n') {
            dest[i] = '\0';
            return 0;
        }
    }
    return 1;
}

int handle_client_request(struct request* req) {
    char http_request[1024];
    /* Get the first line, which will be the request */
    if (get_line((const char*)req->iov[0].iov_base, http_request,
                 sizeof(http_request))) {
        fprintf(stderr, "Malformed request\n");
        exit(1);
    }
    handle_http_method(http_request, req->client_sockfd);
    return 0;
}

void server_loop(int server_sockfd) {
    struct io_uring_cqe* cqe;
    struct sockaddr_in   client_addr;
    socklen_t            client_addr_len = sizeof(client_addr);

    add_accept_request(server_sockfd, &client_addr, &client_addr_len);
    while (true) {
        int             ret = io_uring_wait_cqe(&ring, &cqe);
        struct request* req = (struct request*)cqe->user_data;
        if (ret < 0)
            fatal_error("io_uring_wait_cqe");
        if (cqe->res < 0) {
            fprintf(stderr, "Async request failed: %s for event: %d\n",
                    strerror(-cqe->res), req->event_type);
            exit(1);
        }

        switch (req->event_type) {
        case EVENT_TYPE_ACCEPT:
            //因为前一个监听新连接事件已经被处理，需要再补充，为了之后的新连接
            add_accept_request(server_sockfd, &client_addr, &client_addr_len);
            add_read_request(cqe->res);
            free(req);
            break;
        case EVENT_TYPE_READ:
            if (!cqe->res) {
                fprintf(stderr, "Empty request!\n");
                break;
            }
            handle_client_request(req);
            free(req->iov[0].iov_base);
            free(req);
            break;
        case EVENT_TYPE_WRITE:
            for (int i = 0; i < req->iovec_count; i++) {
                free(req->iov[i].iov_base);
            }
            close(req->client_sockfd);
            free(req);
            break;
        }
        /* Mark this request as processed */
        io_uring_cqe_seen(&ring, cqe);
    }
}

void sigint_handler(int signo) {
    printf("^C pressed. Shutting down.\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

int main() {
    int server_socket = setup_listening_socket(8888);

    signal(SIGINT, sigint_handler);
    io_uring_queue_init(256, &ring, 0);
    server_loop(server_socket);

    return 0;
}