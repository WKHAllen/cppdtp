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
    }; // class Client

} // namespace cppdtp

#endif // CPPDTP_CLIENT_HPP
