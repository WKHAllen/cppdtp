/**
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "client.hpp"
#include "socket.hpp"
#include "exceptions.hpp"

#include <string>
#include <thread>

namespace cppdtp {

    // A socket server
    class Server {
    private:
        friend class Client;

        // If the server will block while serving clients.
        bool blocking = false;

        // If the server will block while calling event methods.
        bool event_blocking = false;

        // If the server is currently serving.
        bool serving = false;

        // The maximum number of clients the server can serve at once.
        size_t max_clients;

        // The number of clients currently being served.
        size_t num_clients = 0;

        // The server socket.
        _Socket sock;

        // The client sockets.
        _Socket* clients = new _Socket[1];

        // An array noting the client slots that are being used.
        bool* allocated_clients = new bool[1];

        // The thread from which the server will serve clients.
        std::thread* serve_thread;

        /**
         * Get a new client ID.
         *
         * Returns: The next available client ID.
         */
        size_t next_client_id() {
            if (num_clients >= max_clients) {
                return CPPDTP_SERVER_MAX_CLIENTS_REACHED;
            }

            for (size_t i = 0; i < max_clients; i++) {
                if (!allocated_clients[i]) {
                    return i;
                }
            }

            return CPPDTP_SERVER_MAX_CLIENTS_REACHED;
        }

        /**
         * Send a status message to a client.
         *
         * client_sock: The socket of the client to send the status to.
         * status_code: The status code to send.
         */
#ifdef _WIN32
        void send_status(SOCKET client_sock, int status_code)
#else
        void send_status(int client_sock, int status_code)
#endif
        {
            std::string message = _construct_message(&status_code, sizeof(status_code));

            if (::send(client_sock, &message[0], CPPDTP_LENSIZE + sizeof(status_code), 0) < 0) {
                throw CPPDTPException(CPPDTP_STATUS_SEND_FAILED, "failed to send status code to client");
            }
        }

        /**
         * Disconnect a client from the server.
         *
         * client_id: The ID of the client to disconnect.
         */
        void disconnect_sock(size_t client_id) {
#ifdef _WIN32
            closesocket(clients[client_id].sock);
#else
            close(clients[client_id].sock);
#endif

            allocated_clients[client_id] = false;
            num_clients--;
        }

        /**
         * Call the serve method.
         */
        void call_serve() {
            if (blocking) {
                serve();
            }
            else {
                serve_thread = new std::thread(&cppdtp::Server::serve, this);
            }
        }

        /**
         * Serve clients.
         */
        void serve() {
            fd_set read_socks;
            int activity;
            struct sockaddr_in address;
            int addrlen = sizeof(address);

#ifdef _WIN32
            SOCKET new_sock;
            int max_sd = 0;
#else
            int new_sock;
            int max_sd = sock.sock;
#endif

            unsigned char size_buffer[CPPDTP_LENSIZE];

            while (serving) {
                // Create the read sockets
                FD_ZERO(&read_socks);
                FD_SET(sock.sock, &read_socks);

                for (size_t i = 0; i < max_clients; i++) {
                    if (allocated_clients[i]) {
                        FD_SET(clients[i].sock, &read_socks);

#ifndef _WIN32
                        if (clients[i].sock > max_sd) {
                            max_sd = clients[i].sock;
                        }
#endif
                    }
                }

                // Wait for activity
                activity = select(max_sd + 1, &read_socks, NULL, NULL, NULL);

                // Check if the server has been stopped
                if (!serving) {
                    return;
                }

                // Check for select errors
                if (activity < 0) {
                    throw CPPDTPException(CPPDTP_SELECT_FAILED, "server socket select failed");
                }

                // Check if something happened on the main socket
                if (FD_ISSET(sock.sock, &read_socks)) {
                    // Accept the new socket and check if an error has occurred
#ifdef _WIN32
                    new_sock = accept(sock.sock, (struct sockaddr*)&address, (int*)&addrlen);

                    if (new_sock == INVALID_SOCKET) {
                        int err_code = WSAGetLastError();

                        if (err_code != WSAENOTSOCK || serving) {
                            throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, err_code, "failed to accept client socket");
                        }

                        return;
                    }
#else
                    new_sock = accept(sock.sock, (struct sockaddr*)&address, (socklen_t*)&addrlen);

                    if (new_sock < 0) {
                        int err_code = errno;

                        if (err_code != ENOTSOCK || serving) {
                            throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, err_code, "failed to accept client socket");
                        }

                        return;
                    }
#endif

                    // Put new socket in the client list
                    size_t new_client_id = next_client_id();

                    if (new_client_id != CPPDTP_SERVER_MAX_CLIENTS_REACHED) {
                        // Add the new socket to the client array
                        clients[new_client_id].sock = new_sock;
                        clients[new_client_id].address = address;
                        allocated_clients[new_client_id] = true;
                        num_clients++;
                        send_status(new_sock, CPPDTP_SUCCESS);
                        call_on_connect(new_client_id);
                    }
                    else {
                        // Tell the client that the server is full
                        send_status(new_sock, CPPDTP_SERVER_FULL);

#ifdef _WIN32
                        closesocket(new_sock);
#else
                        close(new_sock);
#endif

                    }
                }

                // Check if something happened on one of the client sockets
                for (size_t i = 0; i < max_clients; i++) {
                    if (allocated_clients[i] && FD_ISSET(clients[i].sock, &read_socks)) {
#ifdef _WIN32
                        int recv_code = recv(clients[i].sock, (char*)size_buffer, CPPDTP_LENSIZE, 0);

                        if (recv_code == SOCKET_ERROR) {
                            int err_code = WSAGetLastError();

                            if (err_code == WSAECONNRESET) {
                                disconnect_sock(i);
                                call_on_disconnect(i);
                            }
                            else {
                                throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, err_code, "failed to receive data from client");
                            }
                        }
                        else if (recv_code == 0) {
                            disconnect_sock(i);
                            call_on_disconnect(i);
                        }
                        else {
                            size_t msg_size = _decode_message_size(size_buffer);
                            char* buffer = (char*)malloc(msg_size * sizeof(char));

                            // Wait in case the message is sent in multiple chunks
                            sleep(0.01);

                            recv_code = recv(clients[i].sock, buffer, msg_size, 0);

                            if (recv_code == SOCKET_ERROR) {
                                int err_code = WSAGetLastError();

                                if (err_code == WSAECONNRESET) {
                                    disconnect_sock(i);
                                    call_on_disconnect(i);
                                }
                                else {
                                    throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, err_code, "failed to receive data from client");
                                }
                            }
                            else if (recv_code == 0) {
                                disconnect_sock(i);
                                call_on_disconnect(i);
                            }
                            else {
                                call_on_receive(i, (void*)buffer, msg_size);
                            }
                        }
#else
                        int recv_code = read(clients[i].sock, size_buffer, CPPDTP_LENSIZE);

                        if (recv_code == 0) {
                            disconnect_sock(i);
                            call_on_disconnect(i);
                        }
                        else {
                            size_t msg_size = _decode_message_size(size_buffer);
                            char* buffer = (char*)malloc(msg_size * sizeof(char));

                            // Wait in case the message is sent in multiple chunks
                            sleep(0.01);

                            recv_code = read(clients[i].sock, buffer, msg_size);

                            if (recv_code == 0) {
                                disconnect_sock(i);
                                call_on_disconnect(i);
                            }
                            else {
                                call_on_receive(i, (void*)buffer, msg_size);
                            }
                        }
#endif
                    }
                }
            }
        }

        /**
         * Call the receive event method.
         */
        void call_on_receive(size_t client_id, void* data, size_t data_size) {
            if (!event_blocking) {
                receive(client_id, data, data_size);
            }
            else {
                std::thread t(&cppdtp::Server::receive, this, client_id, data, data_size);
            }
        }

        /**
         * Call the connect event method.
         */
        void call_on_connect(size_t client_id) {
            if (!event_blocking) {
                connect(client_id);
            }
            else {
                std::thread t(&cppdtp::Server::connect, this, client_id);
            }
        }

        /**
         * Call the disconnect event method.
         */
        void call_on_disconnect(size_t client_id) {
            if (!event_blocking) {
                disconnect(client_id);
            }
            else {
                std::thread t(&cppdtp::Server::disconnect, this, client_id);
            }
        }

        /**
         * An event method, called when a message is received from a client.
         *
         * client_id: The ID of the client who sent the message.
         * data:      The data received from the client.
         * data_size: The size of the data received, in bytes.
         */
        virtual void receive(size_t client_id, void* data, size_t data_size);

        /**
         * An event method, called when a client connects.
         *
         * client_id: The ID of the client who connected.
         */
        virtual void connect(size_t client_id);

        /**
         * An event method, called when a client disconnects.
         *
         * client_id: The ID of the client who disconnected.
         */
        virtual void disconnect(size_t client_id);

    public:
        /**
         * Instantiate a socket server.
         *
         * blocking_:       If the server should block while serving clients.
         * event_blocking_: If the server should block when calling event methods.
         * max_clients_:    The maximum number of clients the server can serve at once.
         *
         * Returns: The socket server.
         */
        Server(bool blocking_, bool event_blocking_, size_t max_clients_) {
            blocking = blocking_;
            event_blocking = event_blocking_;
            max_clients = max_clients_;

            delete[] clients;
            delete[] allocated_clients;

            clients = new _Socket[max_clients];
            allocated_clients = new bool[max_clients] {false};

            // Initialize the library
            if (!_cppdtp_init_status) {
                int return_code = _cppdtp_init();

                if (return_code != 0) {
                    throw CPPDTPException(CPPDTP_WINSOCK_INIT_FAILED, return_code, "failed to initialize Winsock");
                }
            }

            // Initialize the socket info
            int opt = 1;

#ifdef _WIN32
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == INVALID_SOCKET) {
                throw CPPDTPException(CPPDTP_SERVER_SOCK_INIT_FAILED, "failed to initialize server socket");
            }
            if (setsockopt(sock.sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
                throw CPPDTPException(CPPDTP_SERVER_SETSOCKOPT_FAILED, "failed to set server socket options");
            }
#else
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                throw CPPDTPException(CPPDTP_SERVER_SOCK_INIT_FAILED, "failed to initialize server socket");
            }
            if (setsockopt(sock.sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
                throw CPPDTPException(CPPDTP_SERVER_SETSOCKOPT_FAILED, "failed to set server socket options");
            }
#endif
        }

        /**
         * Instantiate a socket server.
         *
         * max_clients_: The maximum number of clients the server can serve at once.
         *
         * Returns: The socket server.
         */
        Server(size_t max_clients_) : Server(false, false, max_clients_) {}

        /**
         * Drop the socket server.
         */
        ~Server() {
            if (serving) {
                stop();
                delete[] clients;
                delete[] allocated_clients;
            }
        }

        /**
         * Start the socket server.
         *
         * host: The address to host the server on.
         * port: The port to host the server on.
         */
        void start(std::string host, uint16_t port) {
            // Change 'localhost' to '127.0.0.1'
            if (host == "localhost") {
                host = "127.0.0.1";
            }

            // Make sure the server is not already serving
            if (serving) {
                throw CPPDTPException(CPPDTP_SERVER_ALREADY_SERVING, 0, "server is already serving");
            }

            // Set the server address
#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            if (WSAStringToAddress(&host[0], CPPDTP_ADDRESS_FAMILY, NULL, (LPSOCKADDR) & (sock.address), &addrlen) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }
#else
            if (inet_pton(CPPDTP_ADDRESS_FAMILY, &host[0], &(sock.address)) != 1) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            // Bind the address to the server
            if (bind(sock.sock, (struct sockaddr*)&(sock.address), sizeof(sock.address)) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_BIND_FAILED, "server failed to bind to address");
            }

            // Listen for connections
            if (listen(sock.sock, CPPDTP_SERVER_LISTEN_BACKLOG) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_LISTEN_FAILED, "server failed to listen for connections");
            }

            // Serve
            serving = true;
            call_serve();
        }

        /**
         * Start the socket server, using the default port.
         *
         * host: The address to host the server on.
         */
        void start(std::string host) {
            start(host, CPPDTP_PORT);
        }

        /**
         * Start the socket server, using the default host and port.
         */
        void start() {
            start(INADDR_ANY, CPPDTP_PORT);
        }

        /**
         * Stop the server.
         */
        void stop() {
            serving = false;

            // Make sure the server is serving
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

#ifdef _WIN32
            // Close sockets
            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (closesocket(clients[i].sock) != 0) {
                        throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close client sockets");
                    }
                }
            }

            if (closesocket(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close server socket");
            }
#else
            // Close sockets
            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (close(clients[i].sock) != 0) {
                        throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close client sockets");
                    }
                }
            }

            // Force the select function to return by attempting to connect
            struct sockaddr_in addr;
            addr.sin_addr.s_addr = sock.address.sin_addr.s_addr;
            addr.sin_family = sock.address.sin_family;
            addr.sin_port = sock.address.sin_port;
            int client_sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0);

            if (client_sock == -1) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to initialize local client socket while shutting down");
            }

            if (::connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to connect local client to server while shutting down");
            }

            sleep(0.01);

            if (close(client_sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to disconnect local client while shutting down");
            }

            if (close(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close server socket");
            }
#endif

            if (!blocking) {
                serve_thread->join();
                delete serve_thread;
            }
        }

        /**
         * Check if the server is serving.
         *
         * Returns: If the server is serving.
         */
        bool is_serving() {
            return serving;
        }

        /**
         * Get the host of the server.
         *
         * Returns: The host address of the server.
         */
        std::string get_host() {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            char* addr = (char*)malloc(CPPDTP_ADDRSTRLEN * sizeof(char));

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            if (WSAAddressToString((LPSOCKADDR) & (sock.address), sizeof(sock.address), NULL, addr, (LPDWORD)&addrlen) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            // Remove the port
            for (int i = 0; i < CPPDTP_ADDRSTRLEN && addr[i] != '\0'; i++) {
                if (addr[i] == ':') {
                    addr[i] = '\0';
                    break;
                }
            }
#else
            if (inet_ntop(CPPDTP_ADDRESS_FAMILY, &(sock.address), addr, CPPDTP_ADDRSTRLEN) == NULL) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }
#endif

            std::string addr_str(addr);
            free(addr);

            return addr_str;
        }

        /**
         * Get the port of the server.
         *
         * Returns: The port of the server.
         */
        uint16_t get_port() {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            return ntohs(sock.address.sin_port);
        }

        /**
         * Disconnect a client from the server.
         *
         * client_id: The ID of the client to disconnect.
         */
        void remove_client(size_t client_id) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            // Make sure the client exists
            if (client_id >= max_clients || !allocated_clients[client_id]) {
                throw CPPDTPException(CPPDTP_CLIENT_DOES_NOT_EXIST, 0, "client does not exist");
            }

#ifdef _WIN32
            if (closesocket(clients[client_id].sock) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_REMOVE_FAILED, "failed to remove client from server");
            }
#else
            if (close(clients[client_id].sock) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_REMOVE_FAILED, "failed to remove client from server");
            }
#endif

            allocated_clients[client_id] = false;
        }

        /**
         * Send data to a client.
         *
         * client_id: The ID of the client to send the data to.
         * data:      The data to send.
         * data_size: The size of the data being sent, in bytes.
         */
        void send(size_t client_id, void* data, size_t data_size) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            std::string message = _construct_message(data, data_size);

            if (::send(clients[client_id].sock, &message[0], CPPDTP_LENSIZE + data_size, 0) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_SEND_FAILED, "failed to send data to client");
            }
        }

        /**
         * Send data to a client.
         *
         * client_id: The ID of the client to send the data to.
         * data:      The data to send.
         * data_size: The size of the data being sent, in bytes.
         */
        template <typename T>
        void send(size_t client_id, T data, size_t data_size) {
            send(client_id, (void*)data, data_size);
        }

        /**
         * Send data to a client.
         *
         * client_id: The ID of the client to send the data to.
         * data:      The data to send.
         */
        template <typename T>
        void send(size_t client_id, T data) {
            send(client_id, (void*)data, sizeof(data));
        }

        /**
         * Send data to all clients.
         *
         * data:      The data to send.
         * data_size: The size of the data being sent, in bytes.
         */
        void send_all(void* data, size_t data_size) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            std::string message = _construct_message(data, data_size);

            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (::send(clients[i].sock, &message[0], CPPDTP_LENSIZE + data_size, 0) < 0) {
                        throw CPPDTPException(CPPDTP_SERVER_SEND_FAILED, "failed to send data to client");
                    }
                }
            }
        }

        /**
         * Send data to all clients.
         *
         * data:      The data to send.
         * data_size: The size of the data being sent, in bytes.
         */
        template <typename T>
        void send_all(T data, size_t data_size) {
            send_all((void*)data, data_size);
        }

        /**
         * Send data to all clients.
         *
         * data: The data to send.
         */
        template <typename T>
        void send_all(T data) {
            send_all((void*)data, sizeof(data));
        }
    }; // class Server

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
