#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string> // For dynamic ID generation

int main() {
    // 1. Create the socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);

    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address" << std::endl;
        return -1;
    }

    // 2. Connect to the Listener
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed. Is the Listener running?" << std::endl;
        return -1;
    }

    // 3. SMART-AUTOMATION: Generate Unique ID using Process ID
    int pid = getpid(); 
    std::string auto_id = "NODE_PROTOTYPE_" + std::to_string(pid);

    // 4. Send the Automated Payload
    send(sock, auto_id.c_str(), auto_id.length(), 0);
    std::cout << "[CLIENT] Autonomous ID sent to Mesh: " << auto_id << std::endl;

    // 5. Read the response from the Listener
    char buffer[1024] = {0};
    read(sock, buffer, 1024);
    std::cout << "[MESH RESPONSE]: " << buffer << std::endl;

    // 6. Clean up
    close(sock);
    return 0;
}
