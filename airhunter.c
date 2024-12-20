#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>

#define MAX_CMD_OUTPUT 2048
#define MAX_LINE_LENGTH 512

// Function to get the current time in a formatted string
void get_current_time(char *buffer) {
    time_t rawtime;
    struct tm *timeinfo;
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
}

// Function to execute the netsh command and capture its output
void execute_command(const char *cmd, char *output) {
    FILE *fp;
    char path[MAX_CMD_OUTPUT];

    fp = _popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command.\n");
        exit(1);
    }

    while (fgets(path, sizeof(path), fp) != NULL) {
        strcat(output, path);
    }

    _pclose(fp);
}

// Function to parse and display the network information
void parse_and_display_networks(char *networks_output) {
    char line[MAX_LINE_LENGTH];
    char bssid[18], pwr[10], enc[10], cipher[10];
    char essid[MAX_LINE_LENGTH];
    int line_count = 0;
    
    char *ptr = networks_output;

    while (ptr) {
        // Process each line
        if (sscanf(ptr, "    BSSID %17s", bssid)) {
            // Extract BSSID
            printf("BSSID: %s ", bssid);
        } else if (sscanf(ptr, "    Signal %9s", pwr)) {
            // Extract signal strength
            printf("PWR: %s ", pwr);
        } else if (sscanf(ptr, "    Encryption %9s", enc)) {
            // Extract encryption type
            printf("ENCR: %s ", enc);
        } else if (sscanf(ptr, "    Cipher %9s", cipher)) {
            // Extract cipher
            printf("CIPHER: %s\n", cipher);
        }
        
        ptr = strchr(ptr, '\n');
        if (ptr) ptr++;
    }
}

// Function to display usage
void display_usage(const char *prog_name) {
    printf("Usage: %s <interface>\n", prog_name);
    printf("Example: %s Wi-Fi\n", prog_name);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        display_usage(argv[0]);
        return 1;
    }

    char interface_name[MAX_LINE_LENGTH];
    char command[MAX_CMD_OUTPUT];
    char networks_output[MAX_CMD_OUTPUT] = {0};
    char current_time[80];

    // Get the interface name from the command-line argument
    strncpy(interface_name, argv[1], MAX_LINE_LENGTH);

    // Run netsh command to get Wi-Fi network details
    snprintf(command, sizeof(command), "netsh wlan show networks interface=%s", interface_name);

    // Get networks output
    execute_command(command, networks_output);

    // Get the current date and time
    get_current_time(current_time);

    // Print header information
    printf("[ Elapsed: 5s ] [ %s ]\n", current_time);
    printf("BSSID              PWR   ENCR  CIPHER\n");

    // Parse and display the networks data
    parse_and_display_networks(networks_output);

    return 0;
}
