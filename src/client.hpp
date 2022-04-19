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

namespace cppdtp {

    class Client {
    private:
        bool blocking = false;
        bool event_blocking = false;
        bool connected = false;
        _Socket sock;
#ifdef _WIN32
        HANDLE handle_thread;
#else
        pthread_t handle_thread;
        Server local_server;
#endif

    public:
        Client(bool blocking_, bool event_blocking_) {
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

        Client() {
            Client(false, false);
        }

        ~Client() {
            // TODO: disconnect if still connected
        }

        void connect(std::string host, unsigned short port) {
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
                    // TODO: disconnect
                    // cdtp_client_disconnect(client);
                    // _cdtp_client_call_on_disconnected(client);
                    // return;
                }
                else {
                    // TODO: throw error
                    // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                    // return;
                }
            }
            else if (recv_code == 0) {
                // TODO: disconnect
                // cdtp_client_disconnect(client);
                // _cdtp_client_call_on_disconnected(client);
                // return;
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer);
                char* buffer = (char*)malloc(msg_size * sizeof(char));
                recv_code = recv(sock.sock, buffer, msg_size, 0);

                if (recv_code == SOCKET_ERROR) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAECONNRESET) {
                        // TODO: disconnect
                        // cdtp_client_disconnect(client);
                        // _cdtp_client_call_on_disconnected(client);
                        // return;
                    }
                    else {
                        // TODO: throw error
                        // _cdtp_set_error(CPPDTP_CLIENT_RECV_FAILED, err_code);
                        // return;
                    }
                }
                else if (recv_code == 0) {
                    // TODO: disconnect
                    // cdtp_client_disconnect(client);
                    // _cdtp_client_call_on_disconnected(client);
                    // return;
                }
                else {
                    int connect_code = *(int*)buffer;

                    if (connect_code == CPPDTP_SERVER_FULL) {
                        // TODO: disconnect and throw error
                        // _cdtp_set_error(CPPDTP_SERVER_FULL, 0);
                        // cdtp_client_disconnect(client);
                        // _cdtp_client_call_on_disconnected(client);
                        // return;
                    }
                }
            }
#else
            int recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

            if (recv_code == 0) {
                // TODO: disconnect
                // cdtp_client_disconnect(client);
                // _cdtp_client_call_on_disconnected(client);
                // return;
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer);
                char* buffer = (char*)malloc(msg_size * sizeof(char));
                recv_code = read(sock.sock, buffer, msg_size);

                if (recv_code == 0) {
                    // TODO: disconnect
                    // cdtp_client_disconnect(client);
                    // _cdtp_client_call_on_disconnected(client);
                    // return;
                }
                else {
                    int connect_code = *(int*)buffer;

                    if (connect_code == CPPDTP_SERVER_FULL) {
                        // TODO: disconnect and throw error
                        // _cdtp_set_error(CPPDTP_SERVER_FULL, 0);
                        // cdtp_client_disconnect(client);
                        // _cdtp_client_call_on_disconnected(client);
                        // return;
                    }
                }
            }
#endif

            // Handle received data
            connected = true;
            // TODO: call connection handle method
            // _cdtp_client_call_handle(client);
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

            // Wait for threads to exit
            if (!blocking && WaitForSingleObject(handle_thread, INFINITE) == WAIT_FAILED) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_HANDLE_THREAD_NOT_CLOSING, GetLastError());
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
            unsigned short local_server_port = local_server.get_port();

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

            // Wait for threads to exit
            if (!blocking) {
                int err_code = pthread_join(handle_thread, NULL);

                if (err_code != 0) {
                    // TODO: throw error
                    // _cdtp_set_error(CPPDTP_HANDLE_THREAD_NOT_CLOSING, err_code);
                    // return;
                }
            }
#endif
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

        unsigned short get_port() {
            // Make sure the client is connected
            if (!connected) {
                // TODO: throw error
                // _cdtp_set_error(CPPDTP_CLIENT_NOT_CONNECTED, 0);
                // return 0;
            }

            return ntohs(sock.address.sin_port);
        }

        template <typename T>
        void send(T data, size_t data_size) {
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
        void send(T data) {
            send(data, sizeof(data));
        }
    }; // class Client

} // namespace cppdtp

#endif // CPPDTP_CLIENT_HPP
