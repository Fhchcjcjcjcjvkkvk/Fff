#ifndef BRUTE_H
#define BRUTE_H

#define MAX_BUF_SIZE 1024

// Function prototypes
int init_winsock();
SOCKET create_socket(const char *host, int port);
int smtp_send_receive(SOCKET sock, const char *message);
int try_login(const char *host, int port, const char *username, const char *password);
const char *base64_encode(const char *str);  // Add this line

#endif // BRUTE_H
