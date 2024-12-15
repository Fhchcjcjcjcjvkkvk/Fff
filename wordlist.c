#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 7

// Define the characters we will use in the wordlist
const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ#@&?!";
const int charset_size = sizeof(charset) - 1;  // Don't count the null terminator

// Function to generate all combinations
void generate_combinations(char *buffer, int length, int max_len) {
    if (length == max_len) {
        // Print the current combination
        buffer[length] = '\0';  // Null-terminate the string
        printf("%s\n", buffer);
        return;
    }

    for (int i = 0; i < charset_size; i++) {
        buffer[length] = charset[i];
        generate_combinations(buffer, length + 1, max_len);  // Recursive call
    }
}

// Main function to start generating the wordlist
int main() {
    // Create a buffer to store each word
    char buffer[MAX_LENGTH + 1];  // +1 for the null terminator

    // Loop through lengths from 1 to MAX_LENGTH
    for (int length = 1; length <= MAX_LENGTH; length++) {
        generate_combinations(buffer, 0, length);
    }

    return 0;
}
