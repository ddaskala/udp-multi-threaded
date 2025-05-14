#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERVER_PORT 2048
#define BUFFER_SIZE 1024
#define NUM_SOCKETS 32
#define NUM_MESSAGES 100

int main() {
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    int sockfd[NUM_SOCKETS];

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Create multiple sockets
    for (int i = 0; i < NUM_SOCKETS; i++) {
        if ((sockfd[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("Socket creation failed");
            return 1;
        }

        // Bind to different local ports
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = INADDR_ANY;
        client_addr.sin_port = htons(10000 + i); // Different source ports

        if (bind(sockfd[i], (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("Client bind failed");
            return 1;
        }
    }

    // Send messages from different sockets
    for (int j = 0; j < NUM_MESSAGES; j++) {
        for (int i = 0; i < NUM_SOCKETS; i++) {
            sprintf(buffer, "Message %d from client %d", j, i);
            sendto(sockfd[i], buffer, strlen(buffer), 0,
                  (struct sockaddr *)&server_addr, sizeof(server_addr));
            usleep(1000); // Small delay
        }
    }

    // Close all sockets
    for (int i = 0; i < NUM_SOCKETS; i++) {
        close(sockfd[i]);
    }

    return 0;
}
