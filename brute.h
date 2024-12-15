#ifndef BRUTE_H
#define BRUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#define MAX_BUFFER_SIZE 1024

// Function to send HTTP POST request to the login page
int try_login(const char *url, const char *username, const char *password);

// Function to read passwords from a file and try each one
void brute_force(const char *url, const char *username, const char *password_file);

#endif // BRUTE_H
