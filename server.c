#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netdb.h>
#include <stdbool.h>
#include <fcntl.h>

#define PORT 8080
#define BACKLOG 10
#define RECV_BUFFER_SIZE 2048
#define POST_DATA_SIZE 1024
#define MAX_ENTRIES 100
#define MAX_SSE_CLIENTS 10

static char submitted_data_list[MAX_ENTRIES][POST_DATA_SIZE];
static size_t entries_count = 0;

static int sse_clients[MAX_SSE_CLIENTS];
static size_t sse_client_count = 0;

// Check if IPv4 is private/loopback
static bool is_private_ip(struct sockaddr_in *addr) {
    unsigned char *octets = (unsigned char *)&addr->sin_addr.s_addr;
    if (octets[0] == 10) return true;
    if (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)) return true;
    if (octets[0] == 192 && octets[1] == 168) return true;
    if (octets[0] == 127) return true; // loopback
    return false;
}

static void url_decode(char *src) {
    char *dst = src;
    while (*src) {
        if (*src == '%') {
            int val;
            if (sscanf(src+1, "%2x", &val) == 1) {
                *dst++ = (char)val;
                src += 3;
            } else {
                *dst++ = *src++;
            }
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static int get_local_ip(char *ip_str, size_t ip_str_size) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) < 0) {
        perror("getsockname");
        close(sock);
        return -1;
    }

    if (inet_ntop(AF_INET, &name.sin_addr, ip_str, (socklen_t)ip_str_size) == NULL) {
        perror("inet_ntop");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

static void send_response_header(int client_fd, int status_code, const char *status_text, const char *content_type, ssize_t content_length, const char *extra_header) {
    dprintf(client_fd, "HTTP/1.1 %d %s\r\n", status_code, status_text);
    dprintf(client_fd, "Content-Type: %s\r\n", content_type);
    if (content_length >= 0)
        dprintf(client_fd, "Content-Length: %zd\r\n", content_length);
    if (extra_header) {
        dprintf(client_fd, "%s\r\n", extra_header);
    }
    dprintf(client_fd, "Connection: keep-alive\r\n\r\n");
}

// Broadcast SSE event
static void broadcast_sse_event(const char *event, const char *data) {
    char msg[POST_DATA_SIZE + 50];
    snprintf(msg, sizeof(msg), "event: %s\ndata: %s\n\n", event, data);
    for (size_t i = 0; i < sse_client_count; i++) {
        int fd = sse_clients[i];
        if (fd >= 0) {
            ssize_t written = write(fd, msg, strlen(msg));
            if (written < 0) {
                close(fd);
                sse_clients[i] = -1;
            }
        }
    }

    // Compact array
    for (size_t i = 0; i < sse_client_count; ) {
        if (sse_clients[i] < 0) {
            sse_client_count--;
            for (size_t j = i; j < sse_client_count; j++) {
                sse_clients[j] = sse_clients[j+1];
            }
        } else {
            i++;
        }
    }
}

static void handle_root_request(int client_fd) {
    // No full page reload after submission: we'll handle the form via JS fetch
    // The SSE updates the list without reloading.
    char html[8192];
    char initial_items[4096] = "";
    for (size_t i = 0; i < entries_count; i++) {
        strcat(initial_items, "<li>");
        strcat(initial_items, submitted_data_list[i]);
        strcat(initial_items, "</li>");
    }

    snprintf(html, sizeof(html),
        "<!DOCTYPE html>"
        "<html><head><title>Live Updates</title></head><body>"
        "<h1>cupid-safeguard</h1>"
        "<ul id=\"entries\">%s</ul>"
        "<form id=\"dataForm\">"
        "<input type=\"text\" name=\"data\" placeholder=\"Enter data\"/>"
        "<input type=\"submit\" value=\"Submit\"/>"
        "</form>"
        "<script>"
        "  var evtSource = new EventSource('/events');"
        "  evtSource.addEventListener('newEntry', function(e) {"
        "    var ul = document.getElementById('entries');"
        "    var li = document.createElement('li');"
        "    li.textContent = e.data;"
        "    ul.appendChild(li);"
        "  });"
        "  document.getElementById('dataForm').addEventListener('submit', function(ev) {"
        "    ev.preventDefault();"
        "    var formData = new FormData(this);"
        "    fetch('/submit', {method:'POST', body:new URLSearchParams(formData)}).then(r=>r.text()).then(t=>{"
        "      console.log('Server response:', t);"
        "    });"
        "  });"
        "</script>"
        "</body></html>",
        initial_items
    );

    send_response_header(client_fd, 200, "OK", "text/html", strlen(html), NULL);
    write(client_fd, html, strlen(html));
}

// Handle SSE endpoint
static void handle_events_request(int client_fd) {
    dprintf(client_fd, "HTTP/1.1 200 OK\r\n");
    dprintf(client_fd, "Content-Type: text/event-stream\r\n");
    dprintf(client_fd, "Cache-Control: no-cache\r\n");
    dprintf(client_fd, "Connection: keep-alive\r\n\r\n");

    if (sse_client_count < MAX_SSE_CLIENTS) {
        sse_clients[sse_client_count++] = client_fd;
    } else {
        close(client_fd);
    }
}

// Handle POST /submit
static void handle_submit_request(int client_fd, const char *request, const char *client_ip) {
    const char *body = strstr(request, "\r\n\r\n");
    if (!body) {
        send_response_header(client_fd, 400, "Bad Request", "text/plain", 11, NULL);
        write(client_fd, "Bad Request", 11);
        return;
    }

    body += 4;
    char *data_param = strstr(body, "data=");
    if (!data_param) {
        send_response_header(client_fd, 400, "Bad Request", "text/plain", 11, NULL);
        write(client_fd, "Bad Request", 11);
        return;
    }

    data_param += 5;
    char temp_data[POST_DATA_SIZE] = {0};
    size_t i = 0;
    while (*data_param && *data_param != '&' && i < POST_DATA_SIZE - 1) {
        temp_data[i++] = *data_param++;
    }
    temp_data[i] = '\0';
    url_decode(temp_data);

    if (entries_count < MAX_ENTRIES) {
        strncpy(submitted_data_list[entries_count], temp_data, POST_DATA_SIZE - 1);
        submitted_data_list[entries_count][POST_DATA_SIZE - 1] = '\0';
        entries_count++;

        printf("[LOG] Data submitted by %s: %s\n", client_ip, temp_data);
        // Broadcast new entry to SSE clients
        broadcast_sse_event("newEntry", temp_data);

        // No redirect, just respond with a simple "OK"
        const char *resp = "OK";
        send_response_header(client_fd, 200, "OK", "text/plain", strlen(resp), NULL);
        write(client_fd, resp, strlen(resp));
    } else {
        printf("[LOG] Submission attempted by %s but list is full.\n", client_ip);
        const char *resp = "List Full";
        send_response_header(client_fd, 400, "Bad Request", "text/plain", strlen(resp), NULL);
        write(client_fd, resp, strlen(resp));
    }
}

// Handle /shutdown
static bool handle_shutdown_request(int client_fd) {
    const char *msg = "<html><body><h1>Shutting down...</h1></body></html>";
    send_response_header(client_fd, 200, "OK", "text/html", strlen(msg), NULL);
    write(client_fd, msg, strlen(msg));
    return true; 
}

static void handle_not_found(int client_fd) {
    const char *msg = "404 Not Found";
    send_response_header(client_fd, 404, "Not Found", "text/plain", strlen(msg), NULL);
    write(client_fd, msg, strlen(msg));
}

static bool parse_request_line(const char *line, char *method, size_t method_size, char *path, size_t path_size) {
    const char *space1 = strchr(line, ' ');
    if (!space1) return false;
    const char *space2 = strchr(space1 + 1, ' ');
    if (!space2) return false;

    size_t mlen = space1 - line;
    size_t plen = space2 - (space1 + 1);

    if (mlen < 1 || mlen >= method_size) return false;
    if (plen < 1 || plen >= path_size) return false;

    strncpy(method, line, mlen);
    method[mlen] = '\0';

    strncpy(path, space1 + 1, plen);
    path[plen] = '\0';

    return true;
}

int main(void) {
    for (int i = 0; i < MAX_SSE_CLIENTS; i++) sse_clients[i] = -1;

    char local_ip[INET_ADDRSTRLEN] = {0};
    if (get_local_ip(local_ip, sizeof(local_ip)) < 0) {
        fprintf(stderr, "Failed to determine local IP.\n");
        return 1;
    }

    printf("Local IP determined: %s\n", local_ip);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, local_ip, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("Server listening on http://%s:%d/\n", local_ip, PORT);

    bool running = true;
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        if (!is_private_ip(&client_addr)) {
            close(client_fd);
            continue;
        }

        char request[RECV_BUFFER_SIZE];
        memset(request, 0, sizeof(request));
        ssize_t received = recv(client_fd, request, sizeof(request)-1, 0);
        if (received <= 0) {
            close(client_fd);
            continue;
        }
        request[received] = '\0';

        char *first_line_end = strstr(request, "\r\n");
        if (!first_line_end) {
            handle_not_found(client_fd);
            close(client_fd);
            continue;
        }

        char first_line[256];
        size_t flen = first_line_end - request;
        if (flen >= sizeof(first_line)) flen = sizeof(first_line)-1;
        strncpy(first_line, request, flen);
        first_line[flen] = '\0';

        char method[16], path[256];
        if (!parse_request_line(first_line, method, sizeof(method), path, sizeof(path))) {
            send_response_header(client_fd, 400, "Bad Request", "text/plain", 11, NULL);
            write(client_fd, "Bad Request", 11);
            close(client_fd);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        bool keep_open = false;

        if (strcmp(method, "GET") == 0) {
            if (strcmp(path, "/") == 0) {
                handle_root_request(client_fd);
            } else if (strcmp(path, "/shutdown") == 0) {
                running = !handle_shutdown_request(client_fd);
            } else if (strcmp(path, "/events") == 0) {
                handle_events_request(client_fd);
                keep_open = true; // Keep SSE open
            } else {
                handle_not_found(client_fd);
            }
        } else if (strcmp(method, "POST") == 0) {
            if (strcmp(path, "/submit") == 0) {
                handle_submit_request(client_fd, request, client_ip);
            } else {
                handle_not_found(client_fd);
            }
        } else {
            handle_not_found(client_fd);
        }

        if (!keep_open) {
            // Close non-SSE connections
            close(client_fd);
        }
    }

    for (size_t i = 0; i < sse_client_count; i++) {
        if (sse_clients[i] >= 0) {
            close(sse_clients[i]);
        }
    }
    close(listen_fd);
    printf("Server has shut down.\n");
    return 0;
}
