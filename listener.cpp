#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) { return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed. Use 'fuser -k 8080/tcp' if port is stuck." << std::endl;
        return 1;
    }

    listen(server_fd, 3);
    std::cout << "[NEURO-MESH] Node Active on Port 8080..." << std::endl;

    while(true) {
        int new_socket = accept(server_fd, NULL, NULL);
        if (new_socket >= 0) {
            std::cout << "[SUCCESS] Peer connected!" << std::endl;

            const char* message = "NEURO-MESH: Handshake Verified. Send your ID:\n";
            send(new_socket, message, strlen(message), 0);

            char buffer[1024] = {0};
            int valread = read(new_socket, buffer, 1024);
            
            if (valread > 0) {
                std::cout << "[DATA RECEIVED]: " << buffer << std::endl;
            }
            close(new_socket);
        }
    }
    return 0;
}
