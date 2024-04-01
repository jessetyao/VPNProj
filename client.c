#include "client.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080

int main(int argc, char const* argv[])
{
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    char buffer[1024] = { 0 };
    char input[1024];

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("\nInvalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        perror("\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    // Loop to continuously read input and send messages
    while (1) {
        printf("Enter message to send to server (type '.quit' to quit): ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0; // Remove trailing newline
        send(client_fd, input, strlen(input), 0);

        // Check if the user wants to quit
        if (strcmp(input, ".quit") == 0) {
            printf("Quitting client\n");
            break;
        }

        // Receive response from server
        valread = read(client_fd, buffer, sizeof(buffer) - 1);
        if (valread < 0) {
            perror("read failed");
            exit(EXIT_FAILURE);
        } else if (valread == 0) {
            printf("Server closed connection\n");
            break;
        }

        buffer[valread] = '\0'; // Null-terminate the received data
        printf("Server: %s\n", buffer);

        // Check if server sent ".quit"
        if (strcmp(buffer, ".quit") == 0) {
            printf("Server requested client to quit. Closing connection.\n");
            break;
        }
    }

    // Closing the connected socket
    close(client_fd);
    return 0;
}