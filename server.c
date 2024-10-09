#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <errno.h>

#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int fd;
    char nickname[13]; // Maximum of 12 characters + null terminator
    int has_nickname;
} Client;

Client clients[MAX_CLIENTS];

// Function to validate nickname using a regular expression
int validate_nickname(const char *nickname) {
    regex_t regex;
    int reti;

    // Compile regex for nickname (A-Za-z0-9_)
    reti = regcomp(&regex, "^[A-Za-z0-9_]{1,12}$", REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "ERROR Could not compile regex\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Execute the regex match
    reti = regexec(&regex, nickname, 0, NULL, 0);
    regfree(&regex);

    // Return whether it's valid
    return !reti;
}

// Function to send a message to all clients, including the sender
void broadcast_message(const char *message) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1) {
            // Send message to all clients
            if (send(clients[i].fd, message, strlen(message), 0) == -1) {
                perror("send");
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "ERROR Usage: %s <IP:PORT>\n", argv[0]);
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Parse IP:PORT
    char *ip_port = strdup(argv[1]);
    char *ip = strtok(ip_port, ":");
    char *port_str = strtok(NULL, ":");
    if (!ip || !port_str) {
        fprintf(stderr, "ERROR Invalid IP:PORT format\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }
    int port = atoi(port_str);

    // Set up server socket
    int listener;
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;      // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;      // Fill in my IP for me

    if (getaddrinfo(ip, port_str, &hints, &res) != 0) {
        fprintf(stderr, "ERROR getaddrinfo: %s\n", gai_strerror(errno));
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Loop through all the results and bind to the first we can
    for (p = res; p != NULL; p = p->ai_next) {
        if ((listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }

        // Reuse the address
        int yes = 1;
        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            close(listener);
            continue;
        }

        if (bind(listener, p->ai_addr, p->ai_addrlen) == -1) {
            close(listener);
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "ERROR Failed to bind\n");
        fflush(stderr);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    // Listen
    if (listen(listener, 10) == -1) {
        perror("listen");
        close(listener);
        exit(EXIT_FAILURE);
    }

    // Initialize client list
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
    }

    // Set up select for multiplexing input/output
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(listener, &master);
    int fdmax = listener;

    char buf[BUFFER_SIZE];
    printf("[x] Listening on %s:%d\n", ip, port);
    fflush(stdout);  // Flush to ensure immediate output

    // Main loop
    while (1) {
        read_fds = master;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "ERROR select: %s\n", strerror(errno));
            fflush(stderr);
            exit(EXIT_FAILURE);
        }

        // Loop through file descriptors
        for (int i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == listener) {
                    // New client connection
                    struct sockaddr_storage remoteaddr;
                    socklen_t addrlen = sizeof remoteaddr;
                    int newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
                    if (newfd == -1) {
                        perror("accept");
                    } else {
                        // Add new client to the list
                        int j;
                        for (j = 0; j < MAX_CLIENTS; j++) {
                            if (clients[j].fd == -1) {
                                clients[j].fd = newfd;
                                clients[j].has_nickname = 0;
                                memset(clients[j].nickname, 0, sizeof(clients[j].nickname));
                                break;
                            }
                        }
                        if (j == MAX_CLIENTS) {
                            // Too many clients
                            send(newfd, "ERROR Server full\n", 18, 0);
                            close(newfd);
                        } else {
                            FD_SET(newfd, &master);
                            if (newfd > fdmax) {
                                fdmax = newfd;
                            }
                            // Get client IP
                            char client_ip[INET6_ADDRSTRLEN];
                            if (remoteaddr.ss_family == AF_INET) {
                                struct sockaddr_in *s = (struct sockaddr_in *)&remoteaddr;
                                inet_ntop(AF_INET, &s->sin_addr, client_ip, sizeof client_ip);
                            } else {
                                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&remoteaddr;
                                inet_ntop(AF_INET6, &s->sin6_addr, client_ip, sizeof client_ip);
                            }
                            printf("Client connected from %s\n", client_ip);
                            fflush(stdout);

                            // Send greeting to the new client
                            const char *greeting = "HELLO 1\n";
                            send(newfd, greeting, strlen(greeting), 0);
                        }
                    }
                } else {
                    // Handle data from a client
                    int nbytes = recv(i, buf, sizeof buf - 1, 0);
                    if (nbytes <= 0) {
                        // Client disconnected
                        if (nbytes == 0) {
                            printf("Client %d disconnected\n", i);
                        } else {
                            perror("recv");
                        }
                        close(i);
                        FD_CLR(i, &master);
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (clients[j].fd == i) {
                                clients[j].fd = -1;
                                break;
                            }
                        }
                    } else {
                        // Null-terminate the received data
                        buf[nbytes] = '\0';

                        // Find the client
                        Client *client = NULL;
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (clients[j].fd == i) {
                                client = &clients[j];
                                break;
                            }
                        }

                        // Handle NICK command
                        if (strncmp(buf, "NICK ", 5) == 0) {
                            char *nick = buf + 5;
                            nick[strcspn(nick, "\n")] = '\0'; // Remove newline
                            if (validate_nickname(nick)) {
                                strncpy(client->nickname, nick, 12);
                                client->nickname[12] = '\0'; // Ensure null-terminated
                                client->has_nickname = 1;
                                send(i, "OK\n", 3, 0);
                                printf("Name '%s' is allowed\n", client->nickname);
                                fflush(stdout);
                            } else {
                                send(i, "ERROR Invalid nickname\n", 23, 0);
                            }
                        }
                        // Handle MSG command
                        else if (client->has_nickname && strncmp(buf, "MSG ", 4) == 0) {
                            char *message = buf + 4;  // Skip "MSG " and get the actual message
                            message[strcspn(message, "\n")] = '\0'; // Remove newline

                            // Limit message length to 255 characters
                            if (strlen(message) > 255) {
                                send(i, "ERROR Message too long\n", 23, 0);
                                continue;
                            }

                            char outbuf[BUFFER_SIZE];

                            // Format the message according to the protocol
                            snprintf(outbuf, sizeof(outbuf), "MSG %s %s\n", client->nickname, message);

                            // Send to all clients, including the sender
                            broadcast_message(outbuf);
                        } else {
                            send(i, "ERROR Unknown command\n", 22, 0);
                        }
                    }
                }
            }
        }
    }

    close(listener);
    return 0;
}


