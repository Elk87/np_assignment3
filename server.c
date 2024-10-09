#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>

#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int fd;
    char nickname[13]; // Maximum of 12 characters + '\0'
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
        fprintf(stderr, "Could not compile regex\n");
        exit(EXIT_FAILURE);
    }

    // Execute the regex match
    reti = regexec(&regex, nickname, 0, NULL, 0);
    regfree(&regex);

    // Return whether it's valid
    return !reti;
}

// Function to broadcast a message to all clients, including the sender
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
        fprintf(stderr, "Usage: %s <IP:PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse IP:PORT
    char *ip_port = strdup(argv[1]);
    char *ip = strtok(ip_port, ":");
    char *port_str = strtok(NULL, ":");
    if (!ip || !port_str) {
        fprintf(stderr, "Invalid IP:PORT format\n");
        exit(EXIT_FAILURE);
    }
    int port = atoi(port_str);

    // Set up server socket
    int listener;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(ip, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    // Create socket
    if ((listener = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Reuse the address
    int yes = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind
    if (bind(listener, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        close(listener);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Listen
    if (listen(listener, 10) == -1) {
        perror("listen");
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
    fflush(stdout);

    // Main loop
    while (1) {
        read_fds = master;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
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
                        int added = 0;
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (clients[j].fd == -1) {
                                clients[j].fd = newfd;
                                clients[j].has_nickname = 0;
                                clients[j].nickname[0] = '\0';
                                added = 1;
                                break;
                            }
                        }
                        if (!added) {
                            fprintf(stderr, "Maximum clients reached. Connection refused.\n");
                            close(newfd);
                            continue;
                        }

                        FD_SET(newfd, &master);
                        if (newfd > fdmax) {
                            fdmax = newfd;
                        }
                        printf("Client connected\n");
                        fflush(stdout);

                        // Send greeting to the new client
                        const char *greeting = "HELLO 1\n";
                        send(newfd, greeting, strlen(greeting), 0);
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

                        if (!client) {
                            fprintf(stderr, "Unknown client fd: %d\n", i);
                            continue;
                        }

                        // Remove trailing newline characters
                        buf[strcspn(buf, "\r\n")] = '\0';

                        // Handle NICK command
                        if (strncmp(buf, "NICK ", 5) == 0) {
                            char *nick = buf + 5;
                            if (validate_nickname(nick)) {
                                strncpy(client->nickname, nick, 12);
                                client->nickname[12] = '\0'; // Ensure null-termination
                                client->has_nickname = 1;
                                send(i, "OK\n", 3, 0);
                                printf("Client %d set nickname: %s\n", i, client->nickname);
                                fflush(stdout);
                            } else {
                                send(i, "ERR Invalid nickname\n", 21, 0);
                            }
                        }
                        // Handle MSG command
                        else if (client->has_nickname && strncmp(buf, "MSG ", 4) == 0) {
                            char *message = buf + 4; // Skip "MSG " and get the actual message
                            char outbuf[BUFFER_SIZE];

                            // Format the message according to the protocol
                            snprintf(outbuf, sizeof(outbuf), "MSG %s %s\n", client->nickname, message);

                            // Send to all clients, including the sender
                            broadcast_message(outbuf);
                        } else {
                            send(i, "ERR Unknown command\n", 20, 0);
                        }
                    }
                }
            }
        }
    }

    close(listener);
    return 0;
}



