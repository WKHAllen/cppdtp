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

        void call_serve() {
            if (blocking) {
                serve();
            }
            else {
                serve_thread = new std::thread(&cppdtp::Server::serve, this);
            }
        }

        void serve() {
            // TODO: serve
        }

    public:
        Server(bool blocking_, bool event_blocking_, size_t max_clients_) {
            blocking = blocking_;
            event_blocking = event_blocking_;
            max_clients = max_clients_;

            delete[] clients;
            delete[] allocated_clients;

            clients = new _Socket[max_clients];
            allocated_clients = new bool[max_clients] {false};

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

            if (connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
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
    };

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
