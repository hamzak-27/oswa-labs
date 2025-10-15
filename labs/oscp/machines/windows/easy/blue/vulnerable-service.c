/*
 * Vulnerable Service for OSCP Blue Machine
 * Buffer Overflow Practice - Educational Purpose Only
 * 
 * This service simulates a vulnerable Windows application
 * that is susceptible to stack-based buffer overflow attacks.
 * 
 * Vulnerability: Stack buffer overflow in handle_client function
 * Exploit: Send payload > 1024 bytes to overflow return address
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#define PORT 9999
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Function prototypes
void handle_client(int client_socket);
void setup_signal_handlers();
void sigchld_handler(int sig);
void banner();
void log_message(const char* message);

// Global variables
int server_socket;

int main() {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    int client_socket;
    pid_t child_pid;

    banner();
    setup_signal_handlers();

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_socket);
        exit(1);
    }

    // Listen for connections
    if (listen(server_socket, MAX_CLIENTS) == -1) {
        perror("Listen failed");
        close(server_socket);
        exit(1);
    }

    log_message("Vulnerable service started on port 9999");
    log_message("WARNING: This service is intentionally vulnerable for educational purposes");

    // Main server loop
    while (1) {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket == -1) {
            if (errno == EINTR) continue;  // Interrupted by signal
            perror("Accept failed");
            continue;
        }

        log_message("Client connected");

        // Fork a child process to handle the client
        child_pid = fork();
        if (child_pid == 0) {
            // Child process
            close(server_socket);
            handle_client(client_socket);
            close(client_socket);
            exit(0);
        } else if (child_pid > 0) {
            // Parent process
            close(client_socket);
        } else {
            perror("Fork failed");
            close(client_socket);
        }
    }

    close(server_socket);
    return 0;
}

/* 
 * VULNERABLE FUNCTION: handle_client
 * This function contains a classic stack buffer overflow vulnerability
 */
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];  // Vulnerable buffer
    char response[2048];
    int bytes_received;

    // Send welcome message
    const char* welcome = 
        "Welcome to Blue Vulnerable Service\\n"
        "OSCP Buffer Overflow Practice Lab\\n"
        "====================================\\n"
        "Enter your command: ";
    
    send(client_socket, welcome, strlen(welcome), 0);

    // VULNERABILITY: No bounds checking on recv()
    // This allows buffer overflow attacks
    bytes_received = recv(client_socket, buffer, 2000, 0);  // Receives more than buffer can hold!
    
    if (bytes_received <= 0) {
        log_message("Client disconnected or error receiving data");
        return;
    }

    // Log the received data (for debugging)
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Received %d bytes from client", bytes_received);
    log_message(log_msg);

    // Null terminate the buffer (this may not work if buffer is overflowed)
    if (bytes_received < BUFFER_SIZE) {
        buffer[bytes_received] = '\\0';
    }

    // Check for specific commands (vulnerable string operations)
    if (strncmp(buffer, "HELP", 4) == 0) {
        const char* help_msg = 
            "Available commands:\\n"
            "HELP    - Show this help message\\n"
            "STATUS  - Show system status\\n"
            "EXIT    - Disconnect\\n"
            "FLAG    - Show flag (admin only)\\n"
            "\\nBuffer Overflow Hint: Try sending more than 1024 characters!\\n";
        send(client_socket, help_msg, strlen(help_msg), 0);
    }
    else if (strncmp(buffer, "STATUS", 6) == 0) {
        const char* status_msg = 
            "System Status: VULNERABLE\\n"
            "Buffer size: 1024 bytes\\n"
            "Stack protection: DISABLED\\n"
            "ASLR: DISABLED\\n"
            "DEP/NX: DISABLED\\n"
            "This is perfect for buffer overflow practice!\\n";
        send(client_socket, status_msg, strlen(status_msg), 0);
    }
    else if (strncmp(buffer, "FLAG", 4) == 0) {
        const char* flag_msg = "Access denied! You need to exploit the buffer overflow to get the flag!\\n";
        send(client_socket, flag_msg, strlen(flag_msg), 0);
    }
    else if (strncmp(buffer, "EXIT", 4) == 0) {
        const char* bye_msg = "Goodbye!\\n";
        send(client_socket, bye_msg, strlen(bye_msg), 0);
        return;
    }
    else {
        // Echo back the command (vulnerable to buffer overflow)
        snprintf(response, sizeof(response), 
            "Unknown command: %s\\n"
            "Use HELP for available commands\\n", buffer);
        send(client_socket, response, strlen(response), 0);
    }

    // Recursive call to handle more commands (keeps connection alive)
    handle_client(client_socket);
}

void setup_signal_handlers() {
    signal(SIGCHLD, sigchld_handler);  // Handle zombie processes
    signal(SIGPIPE, SIG_IGN);          // Ignore broken pipe signals
}

void sigchld_handler(int sig) {
    // Reap zombie child processes
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void banner() {
    printf("\\n");
    printf("================================\\n");
    printf("  BLUE VULNERABLE SERVICE v1.0  \\n");
    printf("     Buffer Overflow Practice   \\n");
    printf("================================\\n");
    printf("Port: %d\\n", PORT);
    printf("Educational Purpose Only\\n");
    printf("Stack Protection: DISABLED\\n");
    printf("ASLR: DISABLED\\n");
    printf("================================\\n");
    printf("\\n");
}

void log_message(const char* message) {
    printf("[BLUE] %s\\n", message);
    fflush(stdout);
}