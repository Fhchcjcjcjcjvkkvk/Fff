#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <windows.h>
#include <ctime>
#include <regex>
#include <stdexcept>

using namespace std;

// Function to execute the netsh command and get the output for a specific interface
string executeCommand(const string &interfaceName) {
    string result;
    string command = "netsh wlan show networks mode=bssid interface=\"" + interfaceName + "\"";  // Specify interface name
    char buffer[128];
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) throw runtime_error("popen() failed!");
    
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

// Function to parse the netsh output and extract network information
vector<vector<string>> parseNetworks(const string &netshOutput) {
    vector<vector<string>> networks;
    vector<string> currentNetwork;
    stringstream ss(netshOutput);
    string line;
    regex bssidRegex("BSSID\\s+([\\w:]+)");        // Regex for BSSID
    regex pwrRegex("Signal\\s+Strength\\s+\\d+\\s+\\(([-\\d]+)\\)"); // Regex for Signal Strength
    regex encRegex("Encryption\\s+\\: (\\w+)");    // Regex for Encryption (WEP, WPA2, etc.)
    regex cipherRegex("Cipher\\s+\\: (\\w+)");     // Regex for Cipher (CCMP, TKIP)
    regex authRegex("Authentication\\s+\\: (\\w+)"); // Regex for Authentication (PSK, Open)

    while (getline(ss, line)) {
        smatch match;

        // Match BSSID
        if (regex_search(line, match, bssidRegex)) {
            if (!currentNetwork.empty()) {
                networks.push_back(currentNetwork); // Store previous network
            }
            currentNetwork = {match.str(1)}; // Start a new network with BSSID
        }

        // Match Signal Strength
        if (regex_search(line, match, pwrRegex)) {
            currentNetwork.push_back(match.str(1)); // Add Signal Strength (PWR)
        }

        // Match Encryption
        if (regex_search(line, match, encRegex)) {
            currentNetwork.push_back(match.str(1)); // Add Encryption (ENCR)
        }

        // Match Cipher
        if (regex_search(line, match, cipherRegex)) {
            currentNetwork.push_back(match.str(1)); // Add Cipher
        }

        // Match Authentication
        if (regex_search(line, match, authRegex)) {
            currentNetwork.push_back(match.str(1)); // Add Authentication
        }
    }

    if (!currentNetwork.empty()) {
        networks.push_back(currentNetwork); // Store the last network
    }

    return networks;
}

// Function to get current timestamp
string getCurrentTimestamp() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return string(buf);
}

// Function to display the network information
void displayNetworkInfo(const vector<vector<string>>& networks, int elapsedTime) {
    string timestamp = getCurrentTimestamp();
    cout << "[ Elapsed: " << elapsedTime << "s ] [ " << timestamp << " ]\n";
    cout << "BSSID              PWR ENC  CIPHER  AUTH\n";

    for (const auto &network : networks) {
        if (network.size() == 5) {
            cout << network[0] << "  " 
                 << network[1] << "   " 
                 << network[2] << "   " 
                 << network[3] << "   " 
                 << network[4] << "\n";
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: airhunter.exe INTERFACE_NAME" << endl;
        return 1;
    }

    string interfaceName = argv[1];  // Get the interface name from the command line argument

    try {
        while (true) {
            // Get available networks using netsh for the specified interface
            string netshOutput = executeCommand(interfaceName);

            // If no networks found, print a message
            if (netshOutput.find("There are no hosted networks") != string::npos || 
                netshOutput.find("No wireless networks were found") != string::npos) {
                cout << "No networks found." << endl;
                return 0;
            }

            // Parse the netsh output to extract network information
            vector<vector<string>> networks = parseNetworks(netshOutput);

            // Display the network info
            static int elapsedTime = 0;
            displayNetworkInfo(networks, elapsedTime);

            Sleep(5000); // Sleep for 5 seconds
            elapsedTime += 5;  // Increment elapsed time
        }
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
