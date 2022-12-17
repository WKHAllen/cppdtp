/**
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "crypto.hpp"
#include "client.hpp"
#include "socket.hpp"
#include "exceptions.hpp"

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <iterator>
#include <utility>

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
        static_assert(std::is_default_constructible<S>::value, "S must be default constructible");
        static_assert(std::is_default_constructible<R>::value, "R must be default constructible");

    private:
        friend class Client<R, S>;

        // If the server is currently serving.
        bool serving = false;

        // The server socket.
        _Socket sock;

        // The client sockets.
        std::map<size_t, _Socket> clients;

        // The client crypto keys.
        std::map<size_t, std::vector<char>> keys;

        // The next available client ID.
        size_t next_client_id = 0;

        // The thread from which the server will serve clients.
        std::thread serve_thread;

        /**
         * Get a new client ID.
         *
         * @return The next available client ID.
         */
        size_t new_client_id() {
            return next_client_id++;
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
        }

        /**
         * Call the serve method.
         */
        void call_serve() {
            serve_thread = std::thread(&cppdtp::Server<S, R>::serve, this);
        }

        /**
         * Serve clients.
         */
        void serve() {
            struct sockaddr_in address;
            int addrlen = sizeof(address);

#ifdef _WIN32
            // Set non-blocking
            unsigned long mode = 1;

            if (ioctlsocket(sock.sock, FIONBIO, &mode) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_SOCK_INIT_FAILED, "failed to initialize server socket");
            }

            SOCKET new_sock;
#else
            // Set non-blocking
            if (fcntl(sock.sock, F_SETFL, fcntl(sock.sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
                throw CPPDTPException(CPPDTP_SERVER_SOCK_INIT_FAILED, "failed to initialize server socket");
            }

            int new_sock;
#endif

            char size_buffer[CPPDTP_LENSIZE];
            int recv_code;

            while (serving) {
                // Accept incoming connections
#ifdef _WIN32
                new_sock = accept(sock.sock, (struct sockaddr*)&address, (int*)&addrlen);
#else
                new_sock = accept(sock.sock, (struct sockaddr*)&address, (socklen_t*)&addrlen);
#endif

                // Check if the server has been stopped
                if (!serving) {
                    return;
                }

#ifdef _WIN32
                if (new_sock == INVALID_SOCKET) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAEWOULDBLOCK) {
                        // No new connections, do nothing
                    }
                    else if (err_code != WSAENOTSOCK || serving) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, err_code, "failed to accept client socket");
                    }
                    else {
                        return;
                    }
                }
                else {
                    size_t client_id = new_client_id();

                    // Set blocking for key exchange
                    mode = 0;

                    if (ioctlsocket(new_sock, FIONBIO, &mode) != 0) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, "failed to accept client socket");
                    }

                    // Exchange keys
                    exchange_keys(client_id, new_sock);

                    // Set non-blocking
                    mode = 1;

                    if (ioctlsocket(new_sock, FIONBIO, &mode) != 0) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, "failed to accept client socket");
                    }

                    // Add the new socket to the client map
                    _Socket new_client;
                    new_client.sock = new_sock;
                    new_client.address = address;
                    clients.insert(std::pair<size_t, _Socket>(client_id, new_client));

                    call_on_connect(client_id);
                }
#else
                if (new_sock < 0) {
                    int err_code = errno;

                    if (CPPDTP_EAGAIN_OR_WOULDBLOCK(err_code)) {
                        // No new connections, do nothing
                    }
                    else if (err_code != ENOTSOCK || serving) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, err_code, "failed to accept client socket");
                    }
                    else {
                        return;
                    }
                }
                else {
                    size_t client_id = new_client_id();

                    // Set blocking for key exchange
                    if (fcntl(new_sock, F_SETFL, fcntl(new_sock, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, "failed to accept client socket");
                    }

                    // Exchange keys
                    exchange_keys(client_id, new_sock);

                    // Set non-blocking
                    if (fcntl(new_sock, F_SETFL, fcntl(new_sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
                        throw CPPDTPException(CPPDTP_SOCKET_ACCEPT_FAILED, "failed to accept client socket");
                    }

                    // Add the new socket to the client map
                    _Socket new_client;
                    new_client.sock = new_sock;
                    new_client.address = address;
                    clients.insert(std::pair<size_t, _Socket>(client_id, new_client));

                    call_on_connect(client_id);
                }
#endif

                // Check for messages from client sockets
                for (std::map<size_t, _Socket>::iterator entry = clients.begin(); entry != clients.end(); ) {
                    size_t client_id = entry->first;
                    _Socket client_sock = entry->second;
                    bool do_next_entry = true;

#ifdef _WIN32
                    recv_code = recv(client_sock.sock, size_buffer, CPPDTP_LENSIZE, 0);

                    if (recv_code == SOCKET_ERROR) {
                        int err_code = WSAGetLastError();

                        if (err_code == WSAECONNRESET || err_code == WSAENOTSOCK) {
                            disconnect_sock(client_id);
                            call_on_disconnect(client_id);

                            if (clients.count(client_id) != 0) {
                                entry++;
                                do_next_entry = false;
                                clients.erase(client_id);
                                keys.erase(client_id);
                            }
                        }
                        else if (err_code == WSAEWOULDBLOCK) {
                            // Nothing happened on the socket, do nothing
                        }
                        else {
                            throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, err_code, "failed to receive data from client");
                        }
                    }
                    else if (recv_code == 0) {
                        disconnect_sock(client_id);
                        call_on_disconnect(client_id);

                        if (clients.count(client_id) != 0) {
                            entry++;
                            do_next_entry = false;
                            clients.erase(client_id);
                            keys.erase(client_id);
                        }
                    }
                    else {
                        std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                        size_t msg_size = _decode_message_size(size_buffer_vec);
                        std::vector<char> buffer_vec;
                        buffer_vec.resize(msg_size);
                        char *buffer = buffer_vec.data();

                        // Wait in case the message is sent in multiple chunks
                        sleep(CPPDTP_SLEEP_TIME);

                        recv_code = recv(client_sock.sock, buffer, msg_size, 0);

                        if (recv_code == SOCKET_ERROR) {
                            int err_code = WSAGetLastError();

                            if (err_code == WSAECONNRESET || err_code == WSAENOTSOCK) {
                                disconnect_sock(client_id);
                                call_on_disconnect(client_id);

                                if (clients.count(client_id) != 0) {
                                    entry++;
                                    do_next_entry = false;
                                    clients.erase(client_id);
                                    keys.erase(client_id);
                                }
                            }
                            else {
                                throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, err_code, "failed to receive data from client");
                            }
                        }
                        else if (recv_code == 0) {
                            disconnect_sock(client_id);
                            call_on_disconnect(client_id);

                            if (clients.count(client_id) != 0) {
                                entry++;
                                do_next_entry = false;
                                clients.erase(client_id);
                                keys.erase(client_id);
                            }
                        }
                        else if (((size_t)recv_code) != msg_size) {
                            throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, "failed to receive data from client");
                        }
                        else {
                            std::vector<char> data_vec(buffer, buffer + msg_size);
                            call_on_receive(client_id, data_vec);
                        }
                    }
#else
                    recv_code = read(client_sock.sock, size_buffer, CPPDTP_LENSIZE);

                    if (recv_code == 0) {
                        disconnect_sock(client_id);
                        call_on_disconnect(client_id);

                        if (clients.count(client_id) != 0) {
                            entry++;
                            do_next_entry = false;
                            clients.erase(client_id);
                            keys.erase(client_id);
                        }
                    }
                    else if (recv_code == -1) {
                        int err_code = errno;

                        if (err_code == EBADF) {
                            disconnect_sock(client_id);
                            call_on_disconnect(client_id);

                            if (clients.count(client_id) != 0) {
                                entry++;
                                do_next_entry = false;
                                clients.erase(client_id);
                                keys.erase(client_id);
                            }
                        }
                        else if (CPPDTP_EAGAIN_OR_WOULDBLOCK(err_code)) {
                            // Nothing happened on the socket, do nothing
                        }
                        else {
                            throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, err_code, "failed to receive data from client");
                        }
                    }
                    else {
                        std::vector<char> size_buffer_vec(size_buffer, size_buffer + CPPDTP_LENSIZE);
                        size_t msg_size = _decode_message_size(size_buffer_vec);
                        std::vector<char> buffer_vec;
                        buffer_vec.resize(msg_size);
                        char *buffer = buffer_vec.data();

                        // Wait in case the message is sent in multiple chunks
                        sleep(CPPDTP_SLEEP_TIME);

                        recv_code = read(client_sock.sock, buffer, msg_size);

                        if (recv_code == -1) {
                            int err_code = errno;

                            if (err_code == EBADF) {
                                disconnect_sock(client_id);
                                call_on_disconnect(client_id);

                                if (clients.count(client_id) != 0) {
                                    entry++;
                                    do_next_entry = false;
                                    clients.erase(client_id);
                                    keys.erase(client_id);
                                }
                            } else {
                                throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, "failed to receive data from client");
                            }
                        }
                        else if (recv_code == 0) {
                            disconnect_sock(client_id);
                            call_on_disconnect(client_id);

                            if (clients.count(client_id) != 0) {
                                entry++;
                                do_next_entry = false;
                                clients.erase(client_id);
                                keys.erase(client_id);
                            }
                        }
                        else if (((size_t)recv_code) != msg_size) {
                            throw CPPDTPException(CPPDTP_SERVER_RECV_FAILED, "failed to receive data from client");
                        }
                        else {
                            std::vector<char> data_vec(buffer, buffer + msg_size);
                            call_on_receive(client_id, data_vec);
                        }
                    }
#endif
                    if (do_next_entry) {
                        entry++;
                    }
                }
            }
        }

        /**
         * Exchange crypto keys with a client.
         *
         * @param client_id The ID of the new client.
         * @param client_sock The client socket.
         */
#ifdef _WIN32
        void exchange_keys(size_t client_id, SOCKET client_sock)
#else
        void exchange_keys(size_t client_id, int client_sock)
#endif
        {
            std::pair<std::vector<char>, std::vector<char>> rsa_keys = _new_rsa_keys();
            std::vector<char> public_key = rsa_keys.first;
            std::vector<char> private_key = rsa_keys.second;
            std::vector<char> public_key_encoded = _encode_message(public_key);
            const char *message_buffer = public_key_encoded.data();

            if (::send(client_sock, message_buffer, public_key_encoded.size(), 0) < 0) {
                throw CPPDTPException(CPPDTP_SERVER_KEY_EXCHANGE_FAILED, "failed to send public key to client");
            }

            std::vector<char> size_buffer_vec;
            size_buffer_vec.resize(CPPDTP_LENSIZE);
            char *size_buffer = size_buffer_vec.data();
            std::vector<char> buffer_vec;
            int recv_code;

#ifdef _WIN32
            recv_code = recv(client_sock, size_buffer, CPPDTP_LENSIZE, 0);

            if (recv_code == SOCKET_ERROR || recv_code == 0) {
                throw CPPDTPException(CPPDTP_SERVER_KEY_EXCHANGE_FAILED, "failed to get key from client");
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer_vec);
                buffer_vec.resize(msg_size);
                char *buffer = buffer_vec.data();

                recv_code = recv(client_sock, buffer, msg_size, 0);

                if (recv_code == SOCKET_ERROR || recv_code == 0 || (size_t)recv_code != msg_size) {
                    throw CPPDTPException(CPPDTP_SERVER_KEY_EXCHANGE_FAILED, "failed to get key from client");
                }
            }
#else
            recv_code = read(client_sock, size_buffer, CPPDTP_LENSIZE);

            if (recv_code == 0 || recv_code == -1) {
                throw CPPDTPException(CPPDTP_SERVER_KEY_EXCHANGE_FAILED, "failed to get key from client");
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer_vec);
                buffer_vec.resize(msg_size);
                char *buffer = buffer_vec.data();

                recv_code = read(client_sock, buffer, msg_size);

                if (recv_code == 0 || recv_code == -1 || (size_t)recv_code != msg_size) {
                    throw CPPDTPException(CPPDTP_SERVER_KEY_EXCHANGE_FAILED, "failed to get key from client");
                }
            }
#endif

            std::vector<char> key = _rsa_decrypt(private_key, buffer_vec);
            keys.insert(std::pair<size_t, std::vector<char>>(client_id, key));
        }

        /**
         * Call the receive event method.
         */
        void call_on_receive(size_t client_id, std::vector<char> data) {
            std::vector<char> data_decrypted = _aes_decrypt(keys[client_id], data);
            R data_deserialized;
            _deserialize(data_deserialized, data_decrypted);
            std::thread t(&cppdtp::Server<S, R>::receive, this, client_id, std::move(data_deserialized));
            t.detach();
        }

        /**
         * Call the connect event method.
         */
        void call_on_connect(size_t client_id) {
            std::thread t(&cppdtp::Server<S, R>::connect, this, client_id);
            t.detach();
        }

        /**
         * Call the disconnect event method.
         */
        void call_on_disconnect(size_t client_id) {
            std::thread t(&cppdtp::Server<S, R>::disconnect, this, client_id);
            t.detach();
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
         */
        Server() {
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
            start(CPPDTP_SERVER_HOST, port);
        }

        /**
         * Start the socket server, using the default host and port.
         */
        void start() {
            start(CPPDTP_SERVER_HOST, CPPDTP_PORT);
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
            for (std::map<size_t, _Socket>::iterator entry = clients.begin(); entry != clients.end(); ++entry) {
                _Socket client_sock = entry->second;

                if (closesocket(client_sock.sock) != 0) {
                    int err_code = WSAGetLastError();

                    if (err_code == WSAECONNRESET || err_code == WSAENOTSOCK) {
                        // The client is already disconnected
                    } else {
                        throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close client sockets");
                    }
                }
            }

            if (closesocket(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close server socket");
            }
#else
            // Close sockets
            for (std::map<size_t, _Socket>::iterator entry = clients.begin(); entry != clients.end(); ++entry) {
                _Socket client_sock = entry->second;

                if (close(client_sock.sock) != 0) {
                    int err_code = errno;

                    if (err_code == EBADF) {
                        // The client is already disconnected
                    } else {
                        throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close client sockets");
                    }
                }
            }

            if (close(sock.sock) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_STOP_FAILED, "server failed to close server socket");
            }
#endif

            clients.clear();
            keys.clear();

            if (serve_thread.joinable()) {
                if (serve_thread.get_id() != std::this_thread::get_id()) {
                    serve_thread.join();
                } else {
                    serve_thread.detach();
                }
            }
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

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getsockname(sock.sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            wchar_t addr_wc[CPPDTP_ADDRSTRLEN];

            if (WSAAddressToStringW((LPSOCKADDR)s, sizeof(*s), NULL, addr_wc, (LPDWORD)&addrlen) != 0) {
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
            delete[] addr_cstr;
#else
            char host[CPPDTP_ADDRSTRLEN];

            if (inet_ntop(CPPDTP_ADDRESS_FAMILY, &s->sin_addr, host, CPPDTP_ADDRSTRLEN) == NULL) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            std::string addr_str(host);
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

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getsockname(sock.sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;
            uint16_t port = ntohs(s->sin_port);

            return port;
        }

        /**
         * Get the host of a client.
         *
         * @param client_id The ID of the client.
         * @return The host address of the client.
         */
        std::string get_client_host(size_t client_id) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            // Make sure the client exists
            if (clients.count(client_id) == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DOES_NOT_EXIST, 0, "client does not exist");
            }

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getpeername(clients[client_id].sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            wchar_t addr_wc[CPPDTP_ADDRSTRLEN];

            if (WSAAddressToStringW((LPSOCKADDR)s, sizeof(*s), NULL, addr_wc, (LPDWORD)&addrlen) != 0) {
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
            delete[] addr_cstr;
#else
            char host[CPPDTP_ADDRSTRLEN];

            if (inet_ntop(CPPDTP_ADDRESS_FAMILY, &s->sin_addr, host, CPPDTP_ADDRSTRLEN) == NULL) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            std::string addr_str(host);
#endif

            return addr_str;
        }

        /**
         * Get the port of a client.
         *
         * @param client_id The ID of the client.
         * @return The port of the client.
         */
        uint16_t get_client_port(size_t client_id) {
            // Make sure the server is running
            if (!serving) {
                throw CPPDTPException(CPPDTP_SERVER_NOT_SERVING, 0, "server is not serving");
            }

            // Make sure the client exists
            if (clients.count(client_id) == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DOES_NOT_EXIST, 0, "client does not exist");
            }

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getpeername(clients[client_id].sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;
            uint16_t port = ntohs(s->sin_port);

            return port;
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
            if (clients.count(client_id) == 0) {
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

            clients.erase(client_id);
            keys.erase(client_id);
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

            // Make sure the client exists
            if (clients.count(client_id) == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_DOES_NOT_EXIST, 0, "client does not exist");
            }

            std::vector<char> data_serialized = _serialize(data);
            std::vector<char> data_encrypted = _aes_encrypt(keys[client_id], data_serialized);
            std::vector<char> message = _encode_message(data_encrypted);
            const char *message_buffer = message.data();

            if (::send(clients[client_id].sock, message_buffer, message.size(), 0) < 0) {
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

            for (std::map<size_t, _Socket>::iterator entry = clients.begin(); entry != clients.end(); ++entry) {
                size_t client_id = entry->first;
                send(client_id, data);
            }
        }
    }; // class Server

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
