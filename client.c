#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>

#define BUFFER_SIZE 1024

// Function to set stdin to non-blocking
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP:PORT> <NICKNAME>\n", argv[0]);
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

    // Validate nickname
    char *nickname = argv[2];
    if (strlen(nickname) > 12) {
        fprintf(stderr, "Invalid nickname. Must be up to 12 characters.\n");
        exit(EXIT_FAILURE);
    }
    if (!validate_nickname(nickname)) {
        fprintf(stderr, "Invalid nickname format. Only A-Za-z0-9_ allowed.\n");
        exit(EXIT_FAILURE);
    }

    // Resolve hostname and create socket
    struct addrinfo hints, *res;
    int sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("connect");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    printf("Connected to %s:%s\n", ip, port_str);
    fflush(stdout);

    // Set STDIN to non-blocking mode
    set_nonblocking(STDIN_FILENO);

    // Set socket to non-blocking mode
    set_nonblocking(sockfd);

    // Variables to track connection state
    int received_hello = 0;
    int nickname_accepted = 0;

    char buf[BUFFER_SIZE];

    // Set up select for multiplexing input/output
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(sockfd, &master);
    FD_SET(STDIN_FILENO, &master);

    int fdmax = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

    // Main loop for chat
    while (1) {
        read_fds = master; // Copy the master set

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        // Check for data from server
        if (FD_ISSET(sockfd, &read_fds)) {
            int numbytes = recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (numbytes <= 0) {
                if (numbytes == 0) {
                    printf("Server closed connection\n");
                } else {
                    perror("recv");
                }
                break;
            }
            buf[numbytes] = '\0';

            // Process the message
            if (!received_hello) {
                // Expecting HELLO <VERSION>
                if (strncmp(buf, "HELLO ", 6) == 0) {
                    printf("%s", buf);
                    fflush(stdout);
                    received_hello = 1;

                    // Send NICK command to the server
                    snprintf(buf, sizeof buf, "NICK %s\n", nickname);
                    send(sockfd, buf, strlen(buf), 0);
                } else {
                    fprintf(stderr, "Invalid greeting from server\n");
                    exit(EXIT_FAILURE);
                }
            } else if (!nickname_accepted) {
                if (strncmp(buf, "OK", 2) == 0) {
                    printf("Nickname accepted!\n");
                    fflush(stdout);
                    nickname_accepted = 1;
                } else if (strncmp(buf, "ERR", 3) == 0) {
                    fprintf(stderr, "Server error: %s\n", buf);
                    exit(EXIT_FAILURE);
                } else {
                    fprintf(stderr, "Unexpected response from server\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                // Remove trailing newline characters
                buf[strcspn(buf, "\r\n")] = '\0';

                if (strncmp(buf, "MSG ", 4) == 0) {
                    // Extract the nick
                    char *nick_start = buf + 4;
                    char *nick_end = strchr(nick_start, ' ');
                    if (nick_end != NULL) {
                        *nick_end = '\0';
                        char *message = nick_end + 1;

                        // Check if the nick is the client's own nickname
                        if (strcmp(nick_start, nickname) != 0) {
                            // Print messages from other users
                            printf("%s: %s\n", nick_start, message);
                            fflush(stdout);
                        }
                        // Else, do not print the message (we already have it)
                    } else {
                        // Invalid MSG format; print the raw message
                        printf("%s\n", buf);
                        fflush(stdout);
                    }
                } else if (strncmp(buf, "ERR", 3) == 0) {
                    // Print error messages from server
                    printf("%s\n", buf);
                    fflush(stdout);
                }
            }
        }

        // Check for user input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char input_buf[BUFFER_SIZE];
            int bytes_read = read(STDIN_FILENO, input_buf, sizeof(input_buf) - 1);
            if (bytes_read > 0) {
                input_buf[bytes_read] = '\0';

                // Remove trailing newline characters
                input_buf[strcspn(input_buf, "\r\n")] = '\0';

                if (strcmp(input_buf, "/quit") == 0) {
                    break; // Quit the chat
                }

                // Send the message to the server
                snprintf(buf, sizeof(buf), "MSG %s\n", input_buf);
                send(sockfd, buf, strlen(buf), 0);
            }
        }
    }

    close(sockfd);
    return 0;
}

