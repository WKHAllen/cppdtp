/*
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "client.hpp"
#include "socket.hpp"

#include <string>
#include <thread>

namespace cppdtp {

    class Server {
    private:
        friend class Client;

        bool blocking = false;
        bool event_blocking = false;
        bool serving = false;
        size_t max_clients;
        size_t num_clients = 0;
        _Socket sock;
        _Socket* clients = new _Socket[1];
        bool* allocated_clients = new bool[1];
        std::thread* serve_thread;

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

#ifdef _WIN32
        void send_status(SOCKET client_sock, int status_code)
#else
        void send_status(int client_sock, int status_code)
#endif
        {
            std::string message = _construct_message(&status_code, sizeof(status_code));

            if (::send(client_sock, &message[0], CPPDTP_LENSIZE + sizeof(status_code), 0) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_STATUS_SEND_FAILED);
            }
        }

        void disconnect_sock(size_t client_id) {
#ifdef _WIN32
            closesocket(clients[client_id].sock);
#else
            close(clients[client_id].sock);
#endif

            allocated_clients[client_id] = false;
            num_clients--;
        }

        void call_serve() {
            if (blocking) {
                serve();
            }
            else {
                serve_thread = new std::thread(&cppdtp::Server::serve, this);
            }
        }

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
                    // TODO: throw error
                    // _cdtp_set_err(CPPDTP_SELECT_FAILED);
                    // return;
                }

                // Check if something happened on the main socket
                if (FD_ISSET(sock.sock, &read_socks)) {
                    // Accept the new socket and check if an error has occurred
#ifdef _WIN32
                    new_sock = accept(sock.sock, (struct sockaddr*)&address, (int*)&addrlen);

                    if (new_sock == INVALID_SOCKET) {
                        int err_code = WSAGetLastError();

                        if (err_code != WSAENOTSOCK || serving) {
                            // TODO: throw error
                            // _cdtp_set_error(CPPDTP_SOCKET_ACCEPT_FAILED, err_code);
                        }

                        return;
                    }
#else
                    new_sock = accept(sock.sock, (struct sockaddr*)&address, (socklen_t*)&addrlen);

                    if (new_sock < 0) {
                        int err_code = errno;

                        if (err_code != ENOTSOCK || serving) {
                            // TODO: throw error
                            // _cdtp_set_error(CPPDTP_SOCKET_ACCEPT_FAILED, err_code);
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
                                // TODO: throw error
                                // _cdtp_set_error(CPPDTP_SERVER_RECV_FAILED, err_code);
                                // return;
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
                                    // TODO: throw error
                                    // _cdtp_set_error(CPPDTP_SERVER_RECV_FAILED, err_code);
                                    // return;
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

        void call_on_receive(size_t client_id, void* data, size_t data_size) {
            if (!event_blocking) {
                receive(client_id, data, data_size);
            }
            else {
                std::thread t(&cppdtp::Server::receive, this, client_id, data, data_size);
            }
        }

        void call_on_connect(size_t client_id) {
            if (!event_blocking) {
                connect(client_id);
            }
            else {
                std::thread t(&cppdtp::Server::connect, this, client_id);
            }
        }

        void call_on_disconnect(size_t client_id) {
            if (!event_blocking) {
                disconnect(client_id);
            }
            else {
                std::thread t(&cppdtp::Server::disconnect, this, client_id);
            }
        }

        virtual void receive(size_t client_id, void* data, size_t data_size);

        virtual void connect(size_t client_id);

        virtual void disconnect(size_t client_id);

    public:
        Server(bool blocking_, bool event_blocking_, size_t max_clients_) {
            blocking = blocking_;
            event_blocking = event_blocking_;
            max_clients = max_clients_;

            delete[] clients;
            delete[] allocated_clients;

            clients = new _Socket[max_clients];
            allocated_clients = new bool[max_clients] {false};

            // Initialize the library
            if (!cppdtp_init) {
                int return_code = _cppdtp_init();

                if (return_code != 0) {
                    // TODO: throw error
                    // _cdtp_set_error(CPPDTP_WINSOCK_INIT_FAILED, return_code);
                    // return NULL;
                }
            }

            // Initialize the socket info
            int opt = 1;

#ifdef _WIN32
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == INVALID_SOCKET) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_SOCK_INIT_FAILED);
                // return NULL;
            }
            if (setsockopt(sock.sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_SETSOCKOPT_FAILED);
                // return NULL;
            }
#else
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_SOCK_INIT_FAILED);
                // return NULL;
            }
            if (setsockopt(sock.sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_SETSOCKOPT_FAILED);
                // return NULL;
            }
#endif
        }

        Server(size_t max_clients_) {
            Server(false, false, max_clients_);
        }

        ~Server() {
            if (serving) {
                stop();
                delete[] clients;
                delete[] allocated_clients;
            }
        }

        void start(std::string host, uint16_t port) {
            // Change 'localhost' to '127.0.0.1'
            if (host == "localhost") {
                host = "127.0.0.1";
            }

            // Make sure the server is not already serving
            if (serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_ALREADY_SERVING, 0);
                // return;
            }

            // Set the server address
#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            if (WSAStringToAddress(&host[0], CPPDTP_ADDRESS_FAMILY, NULL, (LPSOCKADDR) & (sock.address), &addrlen) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_ADDRESS_FAILED);
                // return;
            }
#else
            if (inet_pton(CPPDTP_ADDRESS_FAMILY, &host[0], &(sock.address)) != 1) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_ADDRESS_FAILED);
                // return;
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            // Bind the address to the server
            if (bind(sock.sock, (struct sockaddr*)&(sock.address), sizeof(sock.address)) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_BIND_FAILED);
                // return;
            }

            // Listen for connections
            if (listen(sock.sock, CPPDTP_SERVER_LISTEN_BACKLOG) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_LISTEN_FAILED);
                // return;
            }

            // Serve
            serving = true;
            call_serve();
        }

        void start(std::string host) {
            start(host, CPPDTP_PORT);
        }

        void start() {
            start(INADDR_ANY, CPPDTP_PORT);
        }

        void stop() {
            serving = false;

#ifdef _WIN32
            // Close sockets
            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (closesocket(clients[i].sock) != 0) {
                        // TODO: throw error
                        // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                        // return;
                    }
                }
            }

            if (closesocket(sock.sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                // return;
            }
#else
            // Close sockets
            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (close(clients[i].sock) != 0) {
                        // TODO: throw error
                        // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                        // return;
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
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                // return;
            }

            if (::connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                // return;
            }

            sleep(0.01);

            if (close(client_sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                // return;
            }

            if (close(sock.sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_STOP_FAILED);
                // return;
            }
#endif

            if (!blocking) {
                serve_thread->join();
                delete serve_thread;
            }
                    }

        bool is_serving() {
            return serving;
        }

        std::string get_host() {
            // Make sure the server is running
            if (!serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_NOT_SERVING, 0);
                // return NULL;
            }

            char* addr = (char*)malloc(CPPDTP_ADDRSTRLEN * sizeof(char));

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            if (WSAAddressToString((LPSOCKADDR) & (sock.address), sizeof(sock.address), NULL, addr, (LPDWORD)&addrlen) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_ADDRESS_FAILED);
                // return NULL;
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
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_ADDRESS_FAILED);
                // return NULL;
            }
#endif

            std::string addr_str(addr);
            free(addr);

            return addr_str;
        }

        uint16_t get_port() {
            // Make sure the server is running
            if (!serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_NOT_SERVING, 0);
                // return 0;
            }

            return ntohs(sock.address.sin_port);
        }

        void remove_client(size_t client_id) {
            // Make sure the server is running
            if (!serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_NOT_SERVING, 0);
                // return;
            }

            // Make sure the client exists
            if (client_id >= max_clients || !allocated_clients[client_id]) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_DOES_NOT_EXIST, 0);
                // return;
            }

#ifdef _WIN32
            if (closesocket(clients[client_id].sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_REMOVE_FAILED);
                // return;
            }
#else
            if (close(clients[client_id].sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_REMOVE_FAILED);
                // return;
            }
#endif

            allocated_clients[client_id] = false;
            }

        void send(size_t client_id, void* data, size_t data_size) {
            // Make sure the server is running
            if (!serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_NOT_SERVING, 0);
                // return;
            }

            std::string message = _construct_message(data, data_size);

            if (::send(clients[client_id].sock, &message[0], CPPDTP_LENSIZE + data_size, 0) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_SERVER_SEND_FAILED);
            }
        }

        template <typename T>
        void send(size_t client_id, T data, size_t data_size) {
            send(client_id, (void*)data, data_size);
        }

        template <typename T>
        void send(size_t client_id, T data) {
            send(client_id, (void*)data, sizeof(data));
        }

        void send_all(void* data, size_t data_size) {
            // Make sure the server is running
            if (!serving) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_SERVER_NOT_SERVING, 0);
                // return;
            }

            std::string message = _construct_message(data, data_size);

            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (::send(clients[i].sock, &message[0], CPPDTP_LENSIZE + data_size, 0) < 0) {
                        // TODO: throw error
                        // _cdtp_set_err(CDTP_SERVER_SEND_FAILED);
                    }
                }
            }
        }

        template <typename T>
        void send_all(T data, size_t data_size) {
            send_all((void*)data, data_size);
        }

        template <typename T>
        void send_all(T data) {
            send_all((void*)data, sizeof(data));
        }
        }; // class Server

                } // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
