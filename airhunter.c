#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>

#define MAX_OUTPUT_SIZE 8192

// Function to run the netsh command and capture its output
void runNetshCommand(char *command, char *output, size_t output_size) {
    FILE *fp;
    fp = _popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run netsh command\n");
        return;
    }

    // Clear the output buffer
    memset(output, 0, output_size);

    // Read the output of the command
    size_t n = fread(output, 1, output_size - 1, fp);
    output[n] = '\0';

    fclose(fp);
}

// Function to get the current time as a string
void getCurrentTime(char *buffer, size_t buffer_size) {
    SYSTEMTIME time;
    GetLocalTime(&time);
    snprintf(buffer, buffer_size, "%04d-%02d-%02d %02d:%02d:%02d",
             time.wYear, time.wMonth, time.wDay,
             time.wHour, time.wMinute, time.wSecond);
}

// Function to calculate elapsed time since the start
void getElapsedTime(time_t start_time) {
    time_t current_time = time(NULL);
    int elapsed = (int)difftime(current_time, start_time);
    printf("[ Elapsed: %ds ]", elapsed);
}

// Function to parse and display network information
void displayNetworkInfo(char *output) {
    char *line = strtok(output, "\n");

    // Print header
    printf("[ Elapsed: 0s ] [ ");
    char time_str[20];
    getCurrentTime(time_str, sizeof(time_str));
    printf("%s ]\n", time_str);
    printf(" BSSID              PWR ENC  CIPHER  AUTH\n");

    char essid[256], bssid[256], pwr[256], enc[256], cipher[256], auth[256];

    while (line != NULL) {
        // Extracting ESSID, BSSID, Signal (PWR), Encryption (ENC), Cipher, Authentication
        if (strstr(line, "SSID") != NULL) {
            sscanf(line, "    SSID %*d : %255[^\n]", essid);
        }
        if (strstr(line, "BSSID") != NULL) {
            sscanf(line, "    BSSID %*d : %255[^\n]", bssid);
        }
        if (strstr(line, "Signal") != NULL) {
            sscanf(line, "    Signal             : %255[^\n]", pwr);
        }
        if (strstr(line, "Encryption") != NULL) {
            sscanf(line, "    Encryption         : %255[^\n]", enc);
        }
        if (strstr(line, "Cipher") != NULL) {
            sscanf(line, "    Cipher             : %255[^\n]", cipher);
        }
        if (strstr(line, "Authentication") != NULL) {
            sscanf(line, "    Authentication     : %255[^\n]", auth);
        }

        // Once all information for a network is gathered, print it in the desired format
        if (strlen(bssid) > 0 && strlen(pwr) > 0 && strlen(enc) > 0) {
            // Print each network's info in the required format
            printf(" %-18s %-4s %-4s %-6s %-6s\n", bssid, pwr, enc, cipher, auth);

            // Reset variables for next network
            memset(bssid, 0, sizeof(bssid));
            memset(pwr, 0, sizeof(pwr));
            memset(enc, 0, sizeof(enc));
            memset(cipher, 0, sizeof(cipher));
            memset(auth, 0, sizeof(auth));
        }

        line = strtok(NULL, "\n");
    }

    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: airhunter.exe <interface_name>\n");
        return 1;
    }

    // Get the interface name from the command-line argument
    char command[256];
    snprintf(command, sizeof(command), "netsh wlan show networks mode=bssid interface=%s", argv[1]);

    // Buffer to store the output of the netsh command
    char output[MAX_OUTPUT_SIZE];

    // Start the timer for elapsed time
    time_t start_time = time(NULL);

    // Run the netsh command and capture the output
    runNetshCommand(command, output, sizeof(output));

    // Display the extracted network information
    getElapsedTime(start_time);
    displayNetworkInfo(output);

    return 0;
}
