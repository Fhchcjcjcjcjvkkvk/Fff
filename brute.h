#ifndef BRUTE_H
#define BRUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#define MAX_BUFFER_SIZE 2048
#define MAX_PASSWORD_LEN 256
#define MAX_THREADS 8  // Maximum number of threads for brute-forcing

// Function to send HTTP POST request to the login page
int try_login(const char *url, const char *username, const char *password, const char *userAgent);

// Function to read passwords from a file and try each one
void brute_force(const char *url, const char *username, const char *password_file, const char *userAgent);

// Function to handle login attempts in a separate thread
DWORD WINAPI brute_force_thread(LPVOID param);

// Struct to pass parameters to threads
typedef struct {
    const char *url;
    const char *username;
    FILE *password_file;
    const char *userAgent;
    int start_index;
    int end_index;
} BruteForceThreadParams;

#endif // BRUTE_H
