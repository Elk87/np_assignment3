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
#define MAX_BUFFER_SIZE 8192  // Maximum size for the receive buffer

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "ERROR Usage: %s <IP:PORT> <NICKNAME>\n", argv[0]);
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

    // Validate nickname
    char *nickname = argv[2];
    if (strlen(nickname) > 12 || !validate_nickname(nickname)) {
        fprintf(stderr, "ERROR Invalid nickname. Must be up to 12 characters and contain only A-Za-z0-9_.\n");
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Resolve hostname and create socket
    struct addrinfo hints, *res, *p;
    int sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // Support IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

    if (getaddrinfo(ip, port_str, &hints, &res) != 0) {
        fprintf(stderr, "ERROR getaddrinfo: %s\n", gai_strerror(errno));
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    // Try to connect to one of the addresses
    for (p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue; // Try next address
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue; // Try next address
        }
        break; // Successfully connected
    }

    if (p == NULL) {
        fprintf(stderr, "ERROR Could not connect to server\n");
        fflush(stderr);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Connected to server
    printf("Connected to %s:%s\n", ip, port_str);
    fflush(stdout);

    // Set STDIN to non-blocking mode
    set_nonblocking(STDIN_FILENO);

    // Set up select for multiplexing input/output
    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(sockfd, &master);
    FD_SET(STDIN_FILENO, &master);

    int fdmax = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

    char recv_buffer[MAX_BUFFER_SIZE];
    int recv_buffer_len = 0;
    int logged_in = 0;

    // Main loop for chat
    while (1) {
        read_fds = master; // Copy the master set

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "ERROR select: %s\n", strerror(errno));
            fflush(stderr);
            exit(EXIT_FAILURE);
        }

        // Check for data from server
        if (FD_ISSET(sockfd, &read_fds)) {
            char buf[BUFFER_SIZE];
            int numbytes = recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (numbytes <= 0) {
                if (numbytes == 0) {
                    printf("Server closed connection\n");
                } else {
                    fprintf(stderr, "ERROR recv: %s\n", strerror(errno));
                    fflush(stderr);
                }
                break;
            }

            // Append received data to the receive buffer
            if (recv_buffer_len + numbytes > MAX_BUFFER_SIZE - 1) {
                fprintf(stderr, "ERROR Receive buffer overflow\n");
                fflush(stderr);
                exit(EXIT_FAILURE);
            }
            memcpy(recv_buffer + recv_buffer_len, buf, numbytes);
            recv_buffer_len += numbytes;
            recv_buffer[recv_buffer_len] = '\0';

            // Process complete messages in the buffer
            char *line_start = recv_buffer;
            char *newline_pos = NULL;
            while ((newline_pos = strchr(line_start, '\n')) != NULL) {
                *newline_pos = '\0'; // Replace newline with null terminator
                char *message = line_start;

                // Process the message
                if (!logged_in) {
                    // Expecting "HELLO 1" or "OK" messages
                    if (strncmp(message, "HELLO ", 6) == 0) {
                        // Send NICK command to the server
                        char nick_cmd[BUFFER_SIZE];
                        snprintf(nick_cmd, sizeof nick_cmd, "NICK %s\n", nickname);
                        send(sockfd, nick_cmd, strlen(nick_cmd), 0);
                    } else if (strncmp(message, "OK", 2) == 0) {
                        logged_in = 1;
                        printf("Name accepted!\n");
                    } else if (strncmp(message, "ERR", 3) == 0 || strncmp(message, "ERROR", 5) == 0) {
                        // Handle errors
                        printf("%s\n", message);
                        fflush(stdout);
                        close(sockfd);
                        exit(EXIT_FAILURE);
                    } else {
                        // Unexpected response
                        printf("Unexpected response from server: %s\n", message);
                        fflush(stdout);
                        close(sockfd);
                        exit(EXIT_FAILURE);
                    }
                } else {
                    if (strncmp(message, "MSG ", 4) == 0) {
                        // Extract the nick and message
                        char *nick_start = message + 4;
                        char *nick_end = strchr(nick_start, ' ');
                        if (nick_end != NULL) {
                            *nick_end = '\0';
                            char *msg_content = nick_end + 1;

                            // Check if the nick is the client's own nickname
                            if (strcmp(nick_start, nickname) != 0) {
                                // Print messages from other users
                                printf("%s: %s\n", nick_start, msg_content);
                            }
                            // Else, do not print the message (we already have it)
                        } else {
                            // Invalid MSG format; print the raw message
                            printf("%s\n", message);
                        }
                    } else if (strncmp(message, "ERR", 3) == 0 || strncmp(message, "ERROR", 5) == 0) {
                        // Print error messages
                        printf("%s\n", message);
                    }
                    // Ignore other messages
                    fflush(stdout);  // Ensure immediate output
                }

                // Move to the next line
                line_start = newline_pos + 1;
            }

            // Move any remaining partial message to the beginning of the buffer
            recv_buffer_len = strlen(line_start);
            memmove(recv_buffer, line_start, recv_buffer_len);
            recv_buffer[recv_buffer_len] = '\0';
        }

        // Check for user input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char input_buf[BUFFER_SIZE];
            if (fgets(input_buf, sizeof(input_buf), stdin) != NULL) {
                // Remove newline character
                input_buf[strcspn(input_buf, "\n")] = '\0';

                if (strncmp(input_buf, "/quit", 5) == 0) {
                    break; // Quit the chat
                }

                // Limit message length to 255 characters
                if (strlen(input_buf) > 255) {
                    printf("Message too long. Maximum length is 255 characters.\n");
                    fflush(stdout);
                    continue;
                }

                // Send the message to the server
                char msgbuf[BUFFER_SIZE];
                snprintf(msgbuf, sizeof(msgbuf), "MSG %s\n", input_buf);
                send(sockfd, msgbuf, strlen(msgbuf), 0);
            }
        }
    }

    close(sockfd);
    return 0;
}

