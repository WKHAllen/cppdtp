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
    template<typename S, typename R>
    class Client;

    /**
     * A socket server.
     *
     * @tparam S The type of data that will be sent from the server.
     * @tparam R The type of data that will be received by the server.
     */
    template<typename S, typename R>
    class Server {
        static_assert(is_streamable<S>::value, "S must be streamable");
        static_assert(is_streamable<R>::value, "R must be streamable");

    private:
        friend class Client<R, S>;

        // If the server is currently serving.
        bool serving = false;

        // The maximum number of clients the server can serve at once.
        size_t max_clients;

        // The number of clients currently being served.
        size_t num_clients = 0;

        // The server socket.
        _Socket sock;

        // The client sockets.
        _Socket *clients = new _Socket[1];

        // An array noting the client slots that are being used.
        bool *allocated_clients = new bool[1];

        // The thread from which the server will serve clients.
        std::thread *serve_thread;

        /**
         * Get a new client ID.
         *
         * @return The next available client ID.
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
         * @param client_sock The socket of the client to send the status to.
         * @param status_code The status code to send.
         */
#ifdef _WIN32
        void send_status(SOCKET client_sock, int status_code)
#else

        void send_status(int client_sock, int status_code)
#endif
        {
            std::string message = _construct_message(&status_code);
            const char *message_buffer = message.c_str();

            if (::send(client_sock, message_buffer, message.length(), 0) < 0) {
                throw CPPDTPException(CPPDTP_STATUS_SEND_FAILED, "failed to send status code to client");
            }
        }

        /**
         * Disconnect a client from the server.
         *
         * @param client_id The ID of the client to disconnect.
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
            serve_thread = new std::thread(&cppdtp::Server<S, R>::serve, this);
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

            char size_buffer[CPPDTP_LENSIZE];

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
                    new_sock = accept(sock.sock, (struct sockaddr *) &address, (socklen_t * ) & addrlen);

                    if (new_sock < 0) {
                        int err_code = errno;

                        if (err_code != ENOTSOCK || serving) {
                            throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, err_code,
                                                  "failed to accept client socket");
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
                    } else {
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
                        int recv_code = recv(clients[i].sock, size_buffer, CPPDTP_LENSIZE, 0);

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
                            std::string size_buffer_str(size_buffer);
                            size_t msg_size = _decode_message_size(size_buffer_str);
                            char* buffer = new char[msg_size];

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
                                call_on_receive(i, buffer, msg_size);
                            }
                        }
#else
                        int recv_code = read(clients[i].sock, size_buffer, CPPDTP_LENSIZE);

                        if (recv_code == 0) {
                            disconnect_sock(i);
                            call_on_disconnect(i);
                        } else {
                            std::string size_buffer_str(size_buffer);
                            size_t msg_size = _decode_message_size(size_buffer_str);
                            char *buffer = new char[msg_size];

                            // Wait in case the message is sent in multiple chunks
                            sleep(0.01);

                            recv_code = read(clients[i].sock, buffer, msg_size);

                            if (recv_code == 0) {
                                disconnect_sock(i);
                                call_on_disconnect(i);
                            } else {
                                call_on_receive(i, buffer, msg_size);
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
        void call_on_receive(size_t client_id, char* data, size_t data_size) {
            std::string data_str(data, data_size);
            R data_deserialized = _deserialize<R>(data_str);
            delete[] data;
            std::thread t(&cppdtp::Server<S, R>::receive, this, client_id, data_deserialized);
            (void) t;
            (void) data_size;
        }

        /**
         * Call the connect event method.
         */
        void call_on_connect(size_t client_id) {
            std::thread t(&cppdtp::Server<S, R>::connect, this, client_id);
            (void) t;
        }

        /**
         * Call the disconnect event method.
         */
        void call_on_disconnect(size_t client_id) {
            std::thread t(&cppdtp::Server<S, R>::disconnect, this, client_id);
            (void) t;
        }

        /**
         * An event method, called when a message is received from a client.
         *
         * @param client_id The ID of the client who sent the message.
         * @param data The data received from the client.
         */
        virtual void receive(size_t client_id, R data) {
            (void) client_id;
            (void) data;
        }

        /**
         * An event method, called when a client connects.
         *
         * @param client_id The ID of the client who connected.
         */
        virtual void connect(size_t client_id) {
            (void) client_id;
        }

        /**
         * An event method, called when a client disconnects.
         *
         * @param client_id The ID of the client who disconnected.
         */
        virtual void disconnect(size_t client_id) {
            (void) client_id;
        }

    public:
        /**
         * Instantiate a socket server.
         *
         * @param max_clients_ The maximum number of clients the server can serve at once.
         */
        Server(size_t max_clients_) {
            max_clients = max_clients_;

            delete[] clients;
            delete[] allocated_clients;

            clients = new _Socket[max_clients];
            allocated_clients = new bool[max_clients]{false};

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
         * Drop the socket server.
         */
        ~Server() {
            if (serving) {
                stop();
                delete[] clients;
                delete[] allocated_clients;

                serve_thread->join();
                delete serve_thread;
            }
        }

        /**
         * Start the socket server.
         *
         * @param host The address to host the server on.
         * @param port The port to host the server on.
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

            const char *host_cstr = host.c_str();
            wchar_t *host_wc = cstr_to_wchar(host_cstr);

            if (WSAStringToAddressW(host_wc, CPPDTP_ADDRESS_FAMILY, NULL, (LPSOCKADDR) & (sock.address), &addrlen) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            delete[] host_wc;
#else
            const char *host_cstr = host.c_str();

            if ((sock.address.sin_addr.s_addr = inet_addr(host_cstr)) == (in_addr_t)(-1)) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            // Bind the address to the server
            if (bind(sock.sock, (struct sockaddr *) &(sock.address), sizeof(sock.address)) < 0) {
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
         * @param host The address to host the server on.
         */
        void start(std::string host) {
            start(host, CPPDTP_PORT);
        }

        /**
         * Start the socket server, using the default host.
         *
         * @param port The port to host the server on.
         */
        void start(uint16_t port) {
            start(CPPDTP_HOST, port);
        }

        /**
         * Start the socket server, using the default host and port.
         */
        void start() {
            start(CPPDTP_HOST, CPPDTP_PORT);
        }

        /**
         * Stop the server.
         */
        void stop() {
            // Make sure the server is serving
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            serving = false;

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
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED,
                                      "server failed to initialize local client socket while shutting down");
            }

            if (::connect(client_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED,
                                      "server failed to connect local client to server while shutting down");
            }

            sleep(0.01);

            if (close(client_sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED,
                                      "server failed to disconnect local client while shutting down");
            }

            if (close(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close server socket");
            }
#endif
        }

        /**
         * Check if the server is serving.
         *
         * @return If the server is serving.
         */
        bool is_serving() {
            return serving;
        }

        /**
         * Get the host of the server.
         *
         * @return The host address of the server.
         */
        std::string get_host() {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            wchar_t *addr_wc = new wchar_t[CPPDTP_ADDRSTRLEN];

            if (WSAAddressToStringW((LPSOCKADDR) & (sock.address), sizeof(sock.address), NULL, addr_wc, (LPDWORD)&addrlen) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
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
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            std::string addr_str(addr);
            delete[] addr;
#endif

            return addr_str;
        }

        /**
         * Get the port of the server.
         *
         * @return The port of the server.
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
         * @param client_id The ID of the client to disconnect.
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
         * @param client_id The ID of the client to send the data to.
         * @param data The data to send.
         */
        void send(size_t client_id, S data) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            std::string message = _construct_message(data);
            const char *message_buffer = message.c_str();

            if (::send(clients[client_id].sock, message_buffer, message.length(), 0) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_SEND_FAILED, "failed to send data to client");
            }
        }

        /**
         * Send data to all clients.
         *
         * @param data The data to send.
         */
        void send_all(S data) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            std::string message = _construct_message(data);
            const char *message_buffer = message.c_str();

            for (size_t i = 0; i < max_clients; i++) {
                if (allocated_clients[i]) {
                    if (::send(clients[i].sock, message_buffer, message.length(), 0) < 0) {
                        throw CPPDTPException(CPPDTP_SERVER_SEND_FAILED, "failed to send data to client");
                    }
                }
            }
        }
    }; // class Server

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
