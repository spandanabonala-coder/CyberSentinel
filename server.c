#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "url_detection.h"
#include "log_analysis.h"
#include "stack.h"
#include "queue.h"
#include "bst.h"

#define BUFFER_SIZE 8192

static void send_all(int client, const char *data, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(client, data + sent, length - sent, 0);
        if (n <= 0) return;
        sent += (size_t)n;
    }
}

static void send_response(int client, int status, const char *reason,
                          const char *body)
{
    char header[1024];
    size_t body_len = strlen(body);
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, reason, body_len);
    send_all(client, header, (size_t)header_len);
    send_all(client, body, body_len);
}

static int read_request(int client, char *buffer, size_t capacity)
{
    size_t used = 0;
    size_t header_end = 0;
    int content_length = 0;

    while (used < capacity - 1) {
        ssize_t n = recv(client, buffer + used, capacity - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buffer[used] = '\0';

        char *end = strstr(buffer, "\r\n\r\n");
        if (end && header_end == 0) {
            header_end = (size_t)(end - buffer) + 4;
            char *cl = strcasestr(buffer, "Content-Length:");
            if (cl) content_length = atoi(cl + 15);
            if (used >= header_end + (size_t)content_length) break;
        }
        if (header_end && used >= header_end + (size_t)content_length) break;
    }
    buffer[used] = '\0';
    return (int)used;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    int port = 8080;
    const char *port_env = getenv("PORT");
    if (port_env && *port_env) {
        int parsed = atoi(port_env);
        if (parsed > 0 && parsed <= 65535) port = parsed;
    }

    addURL("http://malware.test");
    addURL("http://phishing.test");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((unsigned short)port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 20) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("CyberSentinel cloud server running on port %d\n", port);
    fflush(stdout);

    while (1) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) continue;

        char buffer[BUFFER_SIZE] = {0};
        int received = read_request(client, buffer, sizeof(buffer));

        if (received <= 0) {
            close(client);
            continue;
        }

        char method[16] = {0};
        char path[128] = {0};
        sscanf(buffer, "%15s %127s", method, path);

        char *body = strstr(buffer, "\r\n\r\n");
        body = body ? body + 4 : (char *)"";

        if (strcmp(method, "OPTIONS") == 0) {
            send_response(client, 204, "No Content", "");
        } else if (strcmp(method, "GET") == 0 &&
                   (strcmp(path, "/") == 0 || strcmp(path, "/health") == 0)) {
            send_response(client, 200, "OK", "CyberSentinel Server Running");
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/check-url") == 0) {
            char url[500] = {0};
            snprintf(url, sizeof(url), "%.*s", 499, body);
            url[strcspn(url, "\r\n")] = '\0';
            if (checkURL(url))
                send_response(client, 200, "OK", "Suspicious URL found!");
            else
                send_response(client, 200, "OK", "URL appears safe");
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/analyze-log") == 0) {
            char log[500] = {0};
            snprintf(log, sizeof(log), "%.*s", 499, body);
            log[strcspn(log, "\r\n")] = '\0';
            analyzeLog(log);
            if (strstr(log, "FAILED"))
                send_response(client, 200, "OK", "Failed login attempt detected!");
            else if (strstr(log, "ERROR"))
                send_response(client, 200, "OK", "Security error detected!");
            else
                send_response(client, 200, "OK", "Normal log entry");
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/add-alert") == 0) {
            char alert[200] = {0};
            snprintf(alert, sizeof(alert), "%.*s", 199, body);
            alert[strcspn(alert, "\r\n")] = '\0';
            pushAlert(alert);
            send_response(client, 200, "OK", "Security alert added to stack!");
        } else if (strcmp(method, "GET") == 0 && strcmp(path, "/alerts") == 0) {
            char output[2048] = {0};
            getAlerts(output, sizeof(output));
            send_response(client, 200, "OK",
                output[0] ? output : "No alerts stored.");
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/add-log") == 0) {
            char log[200] = {0};
            snprintf(log, sizeof(log), "%.*s", 199, body);
            log[strcspn(log, "\r\n")] = '\0';
            enqueueLog(log);
            send_response(client, 200, "OK", "Log added to Queue!");
        } else if (strcmp(method, "GET") == 0 && strcmp(path, "/queue-logs") == 0) {
            char output[2048] = {0};
            getLogs(output, sizeof(output));
            send_response(client, 200, "OK",
                output[0] ? output : "No security logs stored.");
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/add-severity") == 0) {
            int severity = 0;
            if (sscanf(body, "%d", &severity) == 1 && severity >= 1 && severity <= 10) {
                insertAlert(severity);
                send_response(client, 200, "OK", "Severity added to BST!");
            } else {
                send_response(client, 400, "Bad Request", "Invalid severity value");
            }
        } else if (strcmp(method, "GET") == 0 && strcmp(path, "/bst-alerts") == 0) {
            char output[2048] = {0};
            getBSTAlerts(output, sizeof(output));
            send_response(client, 200, "OK",
                output[0] ? output : "No BST alerts stored.");
        } else {
            send_response(client, 404, "Not Found", "Endpoint not found");
        }

        close(client);
    }

    close(server_fd);
    return 0;
}
