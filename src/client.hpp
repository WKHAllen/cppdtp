/**
 * Client services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_CLIENT_HPP
#define CPPDTP_CLIENT_HPP

#include "util.hpp"
#include "server.hpp"
#include "socket.hpp"
#include "exceptions.hpp"

#include <string>
#include <thread>
#include <memory>
#include <utility>

namespace cppdtp {
    template<typename S, typename R>
    class Server;

    /**
     * A socket client.
     *
     * @tparam S The type of data that will be sent from the client.
     * @tparam R The type of data that will be received by the client.
     */
    template<typename S, typename R>
    class Client {
    private:
        friend class Server<R, S>;

        // If the client is currently connected.
        bool connected = false;

        // The client socket.
        _Socket sock;

        // The thread from which the client will await messages from the server.
        std::thread *handle_thread;

#ifndef _WIN32
        // A local socket server, used for disconnecting the socket.
        Server<R, S> local_server;
#endif

        /**
         * Call the handle method.
         */
        void call_handle() {
            handle_thread = new std::thread(&cppdtp::Client<S, R>::handle, this);
        }

        /**
         * Handle messages from the server.
         */
        void handle() {
#ifdef _WIN32
            char size_buffer[CPPDTP_LENSIZE];

            while (connected) {
                int recv_code = recv(sock.sock, size_buffer, CPPDTP_LENSIZE, 0);

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
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, err_code, "failed to receive data from server");
                    }
                }
                else if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                    size_t msg_size = _decode_message_size(size_buffer_vec);
                    std::vector<char> buffer_vec;
                    buffer_vec.reserve(msg_size);
                    char *buffer = buffer_vec.data();

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
                            throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, err_code, "failed to receive data from server");
                        }
                    }
                    else if (recv_code == 0) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        std::vector<char> data_vec(buffer, buffer + msg_size);
                        call_on_receive(data_vec);
                    }
                }
            }
#else
            fd_set read_socks;
            local_server.start(CPPDTP_LOCAL_SERVER_HOST, CPPDTP_LOCAL_SERVER_PORT);
            int max_sd = sock.sock > local_server.sock.sock ? sock.sock : local_server.sock.sock;
            int activity;
            char size_buffer[CPPDTP_LENSIZE];

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
                    throw CPPDTPException(CPPDTP_SELECT_FAILED, "client socket select failed");
                }

                // Wait in case the message is sent in multiple chunks
                sleep(0.01);

                int recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

                if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                } else {
                    std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                    size_t msg_size = _decode_message_size(size_buffer_vec);
                    std::vector<char> buffer_vec;
                    buffer_vec.reserve(msg_size);
                    char *buffer = buffer_vec.data();

                    // Wait in case the message is sent in multiple chunks
                    sleep(0.01);

                    recv_code = read(sock.sock, buffer, msg_size);

                    if (recv_code == 0) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    } else {
                        std::vector<char> data_vec(buffer, buffer + msg_size);
                        call_on_receive(data_vec);
                    }
                }
            }
#endif
        }

        /**
         * Call the receive event method.
         */
        void call_on_receive(std::vector<char> data) {
            R data_deserialized;
            _deserialize(data_deserialized, data);
            std::thread t(&cppdtp::Client<S, R>::receive, this, std::move(data_deserialized));
            (void) t;
        }

        /**
         * Call the disconnect event method.
         */
        void call_on_disconnected() {
            std::thread t(&cppdtp::Client<S, R>::disconnected, this);
            (void) t;
        }

        /**
         * An event method, called when a message is received from the server.
         *
         * @param data The data received from the server.
         */
        virtual void receive(R data) {
            (void) data;
        }

        /**
         * An event method, called when the server has disconnected the client.
         */
        virtual void disconnected() {}

    public:
        /**
         * Instantiate a socket client.
         */
        Client()
#ifndef _WIN32
                : local_server(1)
#endif
        {
            // Initialize the library
            if (!_cppdtp_init_status) {
                int return_code = _cppdtp_init();

                if (return_code != 0) {
                    throw CPPDTPException(CPPDTP_WINSOCK_INIT_FAILED, return_code, "failed to initialize Winsock");
                }
            }

#ifdef _WIN32
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == INVALID_SOCKET) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }
#else
            // Initialize the socket
            if ((sock.sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }
#endif
        }

        /**
         * Drop the socket client.
         */
        ~Client() {
            if (connected) {
                disconnect();

                handle_thread->join();
                delete handle_thread;
            }
        }

        /**
         * Connect to a server.
         *
         * @param host The server host.
         * @param port The server port.
         */
        void connect(std::string host, uint16_t port) {
            // Change 'localhost' to '127.0.0.1'
            if (host == "localhost") {
                host = "127.0.0.1";
            }

            // Make sure the client is not already connected
            if (connected) {
                throw CPPDTPException(CPPDTP_CLIENT_ALREADY_CONNECTED, 0, "client is already connected to a server");
            }

            // Set the client address
#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            const char *host_cstr = host.c_str();
            wchar_t *host_wc = cstr_to_wchar(host_cstr);

            if (WSAStringToAddressW(host_wc, CPPDTP_ADDRESS_FAMILY, NULL, (LPSOCKADDR) & (sock.address), &addrlen) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            delete[] host_wc;
#else
            const char *host_cstr = host.c_str();

            if (inet_pton(CPPDTP_ADDRESS_FAMILY, host_cstr, &(sock.address)) != 1) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            if (::connect(sock.sock, (struct sockaddr *) &(sock.address), sizeof(sock.address)) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_CONNECT_FAILED, "client failed to connect to server");
            }

            // Check the return code
            char size_buffer[CPPDTP_LENSIZE];
#ifdef _WIN32
            int recv_code = recv(sock.sock, size_buffer, CPPDTP_LENSIZE, 0);

            if (recv_code == SOCKET_ERROR) {
                int err_code = WSAGetLastError();

                if (err_code == WSAECONNRESET) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else {
                    throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, err_code, "failed to receive data from server");
                }
            }
            else if (recv_code == 0) {
                disconnect();
                call_on_disconnected();
                return;
            }
            else {
                std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                size_t msg_size = _decode_message_size(size_buffer_vec);
                std::vector<char> buffer_vec;
                buffer_vec.reserve(msg_size);
                char *buffer = buffer_vec.data();

                recv_code = recv(sock.sock, buffer, msg_size, 0);

                if (recv_code == SOCKET_ERROR) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAECONNRESET) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else {
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, err_code, "failed to receive data from server");
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
                        disconnect();
                        call_on_disconnected();
                        throw CPPDTPException(CPPDTP_SERVER_FULL, 0, "server is full");
                    }
                }
            }
#else
            int recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

            if (recv_code == 0) {
                disconnect();
                call_on_disconnected();
                return;
            } else {
                std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                size_t msg_size = _decode_message_size(size_buffer_vec);
                std::vector<char> buffer_vec;
                buffer_vec.reserve(msg_size);
                char *buffer = buffer_vec.data();

                recv_code = read(sock.sock, buffer, msg_size);

                if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                } else {
                    int connect_code = *(int *) buffer;

                    if (connect_code == CPPDTP_SERVER_FULL) {
                        disconnect();
                        call_on_disconnected();
                        throw CPPDTPException(CPPDTP_SERVER_FULL, 0, "server is full");
                    }
                }
            }
#endif

            // Handle received data
            connected = true;
            call_handle();
        }

        /**
         * Connect to a server, using the default port.
         *
         * @param host The server host.
         */
        void connect(std::string host) {
            connect(host, CPPDTP_PORT);
        }

        /**
         * Connect to a server, using the default host.
         *
         * @param port The server port.
         */
        void connect(uint16_t port) {
            connect(CPPDTP_HOST, port);
        }

        /**
         * Connect to a server, using the default host and port.
         */
        void connect() {
            connect(CPPDTP_HOST, CPPDTP_PORT);
        }

        /**
         * Disconnect from the server.
         */
        void disconnect() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            connected = false;

#ifdef _WIN32
            // Close the socket
            if (closesocket(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DISCONNECT_FAILED, "failed to disconnect from server");
            }
#else
            // Close the socket
            if (close(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DISCONNECT_FAILED, "failed to disconnect from server");
            }

            // Connect to the local server to simulate activity
            std::string local_server_host = local_server.get_host();
            uint16_t local_server_port = local_server.get_port();
            const char *local_server_host_cstr = local_server_host.c_str();

            int local_client_sock;
            struct sockaddr_in local_client_address;

            if ((local_client_sock = socket(CPPDTP_ADDRESS_FAMILY, SOCK_STREAM, 0)) == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED,
                                      "client failed to initialize client socket while disconnecting");
            }

            if (inet_pton(CPPDTP_ADDRESS_FAMILY, local_server_host_cstr, &(local_client_address)) != 1) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED,
                                      "client address conversion failed while disconnecting");
            }

            local_client_address.sin_family = CPPDTP_ADDRESS_FAMILY;
            local_client_address.sin_port = htons(local_server_port);

            if (::connect(local_client_sock, (struct sockaddr *) &(local_client_address),
                          sizeof(local_client_address)) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_CONNECT_FAILED,
                                      "client failed to connect to local server while disconnecting");
            }

            sleep(0.01);

            if (close(local_client_sock) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DISCONNECT_FAILED,
                                      "client failed to disconnect from local server while disconnecting");
            }
#endif
        }

        /**
         * Check if the client is connected to a server.
         *
         * @return If the client is connected to a server.
         */
        bool is_connected() {
            return connected;
        }

        /**
         * Get the host address of the server the client is connected to.
         *
         * @return The host address of the server.
         */
        std::string get_host() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            wchar_t *addr_wc = new wchar_t[CPPDTP_ADDRSTRLEN];

            if (WSAAddressToStringW((LPSOCKADDR) & (sock.address), sizeof(sock.address), NULL, addr_wc, (LPDWORD)&addrlen) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            // Remove the port
            for (int i = 0; i < CPPDTP_ADDRSTRLEN && addr_wc[i] != '\0'; i++) {
                if (addr_wc[i] == ':') {
                    addr_wc[i] = '\0';
                    break;
                }
            }

            char *addr_cstr = wchar_to_cstr(addr_wc);
            std::string addr_str(addr_cstr);
            delete[] addr_wc;
            delete[] addr_cstr;
#else
            char *addr = new char[CPPDTP_ADDRSTRLEN];

            if (inet_ntop(CPPDTP_ADDRESS_FAMILY, &(sock.address), addr, CPPDTP_ADDRSTRLEN) == NULL) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            std::string addr_str(addr);
            delete[] addr;
#endif

            return addr_str;
        }

        /**
         * Get the port of the server the client is connected to.
         *
         * @return The port of the server.
         */
        uint16_t get_port() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            return ntohs(sock.address.sin_port);
        }

        /**
         * Send data to the server.
         *
         * @param data The data to send.
         */
        void send(S data) {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            std::vector<char> message = _construct_message(data);
            const char *message_buffer = message.data();

            if (::send(sock.sock, message_buffer, message.size(), 0) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SEND_FAILED, "failed to send data to server");
            }
        }
    }; // class Client

} // namespace cppdtp

#endif // CPPDTP_CLIENT_HPP
