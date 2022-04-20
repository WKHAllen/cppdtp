/*
 * Client services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_CLIENT_HPP
#define CPPDTP_CLIENT_HPP

#include "util.hpp"
#include "server.hpp"
#include "socket.hpp"

#include <string>
#include <thread>

namespace cppdtp {

    class Client {
    private:
        friend class Server;

        bool blocking = false;
        bool event_blocking = false;
        bool connected = false;
        _Socket sock;
        std::thread* handle_thread;
#ifndef _WIN32
        Server local_server;
#endif

        void call_handle() {
            if (blocking) {
                handle();
            }
            else {
                handle_thread = new std::thread(&cppdtp::Client::handle, this);
            }
        }

        void handle() {
#ifdef _WIN32
            unsigned char size_buffer[CPPDTP_LENSIZE];

            while (connected) {
                int recv_code = recv(sock.sock, (char*)size_buffer, CPPDTP_LENSIZE, 0);

                // Check if the client has disconnected
                if (!connected) {
                    return;
                }

                if (recv_code == SOCKET_ERROR) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAECONNRESET) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        // TODO: throw error
                        // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                        // return;
                    }
                }
                else if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    size_t msg_size = _decode_message_size(size_buffer);
                    char* buffer = (char*)malloc(msg_size * sizeof(char));

                    // Wait in case the message is sent in multiple chunks
                    sleep(0.01);

                    recv_code = recv(sock.sock, buffer, msg_size, 0);

                    if (recv_code == SOCKET_ERROR) {
                        int err_code = WSAGetLastError();

                        if (err_code == WSAECONNRESET) {
                            disconnect();
                            call_on_disconnected();
                            return;
                        }
                        else {
                            // TODO: throw error
                            // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                            // return;
                        }
                    }
                    else if (recv_code == 0) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        call_on_receive((void*)buffer, msg_size);
                    }
                }
            }
#else
            fd_set read_socks;
            local_server.start(CPPDTP_LOCAL_SERVER_HOST, CPPDTP_LOCAL_SERVER_PORT);
            int max_sd = sock.sock > local_server.sock.sock ? sock.sock : local_server.sock.sock;
            int activity;
            unsigned char size_buffer[CPPDTP_LENSIZE];

            while (connected) {
                // Set sockets for select
                FD_ZERO(&read_socks);
                FD_SET(sock.sock, &read_socks);
                FD_SET(local_server.sock.sock, &read_socks);

                // Wait for activity
                activity = select(max_sd + 1, &read_socks, NULL, NULL, NULL);

                // Check if the client has disconnected
                if (!connected) {
                    local_server.stop();
                    return;
                }

                // Check for select errors
                if (activity < 0) {
                    // TODO: throw error
                    // _cdtp_set_err(CPPDTP_SELECT_FAILED);
                    // return;
                }

                // Wait in case the message is sent in multiple chunks
                sleep(0.01);

                int recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

                if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    size_t msg_size = _decode_message_size(size_buffer);
                    char* buffer = (char*)malloc(msg_size * sizeof(char));

                    // Wait in case the message is sent in multiple chunks
                    sleep(0.01);

                    recv_code = read(sock.sock, buffer, msg_size);

                    if (recv_code == 0) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        call_on_receive((void*)buffer, msg_size);
                    }
                }
            }
#endif
        }

        void call_on_receive(void* data, size_t data_size) {
            if (!event_blocking) {
                receive(data, data_size);
            }
            else {
                std::thread t(&cppdtp::Client::receive, this, data, data_size);
            }
        }

        void call_on_disconnected() {
            if (!event_blocking) {
                disconnected();
            }
            else {
                std::thread t(&cppdtp::Client::disconnected, this);
            }
        }

        virtual void receive(void* data, size_t data_size);

        virtual void disconnected();

    public:
        Client(bool blocking_, bool event_blocking_)
#ifndef _WIN32
            : local_server(1)
#endif
        {
            blocking = blocking_;
            event_blocking = event_blocking_;

#ifdef _WIN32
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == INVALID_SOCKET) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_SOCK_INIT_FAILED);
                // return NULL;
            }
#else
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_SOCK_INIT_FAILED);
                // return NULL;
            }
#endif
        }

        Client()
#ifndef _WIN32
            : local_server(1)
#endif
        {
            Client(false, false);
        }

        ~Client() {
            if (connected) {
                disconnect();
            }
        }

        void connect(std::string host, uint16_t port) {
            // Change 'localhost' to '127.0.0.1'
            if (host == "localhost") {
                host = "127.0.0.1";
            }

            // Make sure the client is not already connected
            if (connected) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_ALREADY_CONNECTED, 0);
                // return;
            }

            // Set the client address
#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;
            if (WSAStringToAddress(&host[0], CPPDTP_ADDRESS_FAMILY, NULL, (LPSOCKADDR) & (sock.address), &addrlen) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_ADDRESS_FAILED);
                // return;
            }
#else
            if (inet_pton(CPPDTP_ADDRESS_FAMILY, &host[0], &(sock.address)) != 1) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_ADDRESS_FAILED);
                // return;
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            if (::connect(sock.sock, (struct sockaddr*)&(sock.address), sizeof(sock.address)) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_CONNECT_FAILED);
                // return;
            }

            // Check the return code
            unsigned char size_buffer[CPPDTP_LENSIZE];
#ifdef _WIN32
            int recv_code = recv(sock.sock, (char*)size_buffer, CPPDTP_LENSIZE, 0);

            if (recv_code == SOCKET_ERROR) {
                int err_code = WSAGetLastError();

                if (err_code == WSAECONNRESET) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    // TODO: throw error
                    // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                    // return;
                }
            }
            else if (recv_code == 0) {
                disconnect();
                call_on_disconnected();
                return;
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer);
                char* buffer = (char*)malloc(msg_size * sizeof(char));
                recv_code = recv(sock.sock, buffer, msg_size, 0);

                if (recv_code == SOCKET_ERROR) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAECONNRESET) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        // TODO: throw error
                        // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                        // return;
                    }
                }
                else if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    int connect_code = *(int*)buffer;

                    if (connect_code == CPPDTP_SERVER_FULL) {
                        // TODO: throw error
                        // _cdtp_set_error(CPPDTP_SERVER_FULL, 0);
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                }
            }
#else
            int recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

            if (recv_code == 0) {
                disconnect();
                call_on_disconnected();
                return;
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer);
                char* buffer = (char*)malloc(msg_size * sizeof(char));
                recv_code = read(sock.sock, buffer, msg_size);

                if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    int connect_code = *(int*)buffer;

                    if (connect_code == CPPDTP_SERVER_FULL) {
                        // TODO: throw error
                        // _cdtp_set_error(CPPDTP_SERVER_FULL, 0);
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                }
            }
#endif

            // Handle received data
            connected = true;
            call_handle();
        }

        void connect(std::string host) {
            connect(host, CPPDTP_PORT);
        }

        void connect() {
            connect(INADDR_ANY, CPPDTP_PORT);
        }

        void disconnect() {
            connected = false;

#ifdef _WIN32
            // Close the socket
            if (closesocket(sock.sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_DISCONNECT_FAILED);
                // return;
            }
#else
            // Close the socket
            if (close(sock.sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_DISCONNECT_FAILED);
                // return;
            }

            // Connect to the local server to simulate activity
            std::string local_server_host = local_server.get_host();
            uint16_t local_server_port = local_server.get_port();

            int local_client_sock;
            struct sockaddr_in local_client_address;

            if ((local_client_sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_SOCK_INIT_FAILED);
                // return;
            }

            if (inet_pton(CPPDTP_ADDRESS_FAMILY, &local_server_host[0], &(local_client_address)) != 1) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_ADDRESS_FAILED);
                // return;
            }

            local_client_address.sin_family = CPPDTP_ADDRESS_FAMILY;
            local_client_address.sin_port = htons(local_server_port);

            if (::connect(local_client_sock, (struct sockaddr*)&(local_client_address), sizeof(local_client_address)) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_CONNECT_FAILED);
                // return;
            }

            sleep(0.01);

            if (close(local_client_sock) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_DISCONNECT_FAILED);
                // return;
            }
#endif

            // Wait for threads to exit
            if (!blocking) {
                handle_thread->join();
                delete handle_thread;
            }
        }

        bool is_connected() {
            return connected;
        }

        std::string get_host() {
            // Make sure the client is connected
            if (!connected) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_NOT_CONNECTED, 0);
                // return NULL;
            }

            char* addr = (char*)malloc(CPPDTP_ADDRSTRLEN * sizeof(char));

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            if (WSAAddressToString((LPSOCKADDR) & (sock.address), sizeof(sock.address), NULL, addr, (LPDWORD)&addrlen) != 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_ADDRESS_FAILED);
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
                // _cdtp_set_err(CPPDTP_CLIENT_ADDRESS_FAILED);
                // return NULL;
            }
#endif

            std::string addr_str(addr);
            free(addr);

            return addr_str;
        }

        uint16_t get_port() {
            // Make sure the client is connected
            if (!connected) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_NOT_CONNECTED, 0);
                // return 0;
            }

            return ntohs(sock.address.sin_port);
        }

        void send(void* data, size_t data_size) {
            // Make sure the client is connected
            if (!connected) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_NOT_CONNECTED, 0);
                // return;
            }

            std::string message = _construct_message(data, data_size);

            if (::send(sock.sock, &message[0], CPPDTP_LENSIZE + data_size, 0) < 0) {
                // TODO: throw error
                // _cdtp_set_err(CPPDTP_CLIENT_SEND_FAILED);
            }
        }

        template <typename T>
        void send(T data, size_t data_size) {
            send((void*)data, data_size);
        }

        template <typename T>
        void send(T data) {
            send((void*)data, sizeof(data));
        }
    }; // class Client

} // namespace cppdtp

#endif // CPPDTP_CLIENT_HPP
