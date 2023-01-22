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
#include <vector>
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
        static_assert(std::is_default_constructible<S>::value, "S must be default constructible");
        static_assert(std::is_default_constructible<R>::value, "R must be default constructible");

    private:
        friend class Server<R, S>;

        // If the client is currently connected.
        bool connected = false;

        // The client socket.
        _Socket sock;

        // The client crypto key.
        std::vector<char> key;

        // The thread from which the client will await messages from the server.
        std::thread handle_thread;

        /**
         * Call the handle method.
         */
        void call_handle() {
            handle_thread = std::thread(&cppdtp::Client<S, R>::handle, this);
        }

        /**
         * Handle messages from the server.
         */
        void handle() {
#ifdef _WIN32
            // Set non-blocking
            unsigned long mode = 1;

            if (ioctlsocket(sock.sock, FIONBIO, &mode) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }

            char size_buffer[CPPDTP_LENSIZE];
            int recv_code;

            while (connected) {
                recv_code = recv(sock.sock, size_buffer, CPPDTP_LENSIZE, 0);

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
                    else if (err_code == WSAEWOULDBLOCK) {
                        // Nothing happened on the socket, do nothing
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
                    buffer_vec.resize(msg_size);
                    char *buffer = buffer_vec.data();

                    // Wait in case the message is sent in multiple chunks
                    sleep(CPPDTP_SLEEP_TIME);

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
                    else if (((size_t)recv_code) != msg_size) {
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, "failed to receive data from server");
                    }
                    else {
                        std::vector<char> data_vec(buffer, buffer + msg_size);
                        call_on_receive(data_vec);
                    }
                }

                sleep(CPPDTP_SLEEP_TIME);
            }
#else
            // Set non-blocking
            if (fcntl(sock.sock, F_SETFL, fcntl(sock.sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }

            char size_buffer[CPPDTP_LENSIZE];
            int recv_code;

            while (connected) {
                recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

                // Check if the client has disconnected
                if (!connected) {
                    return;
                }

                if (recv_code == 0) {
                    disconnect();
                    call_on_disconnected();
                    return;
                }
                else if (recv_code == -1) {
                    int err_code = errno;

                    if (CPPDTP_EAGAIN_OR_WOULDBLOCK(err_code)) {
                        // Nothing happened on the socket, do nothing
                    }
                    else {
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, err_code, "failed to receive data from server");
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

                    recv_code = read(sock.sock, buffer, msg_size);

                    if (recv_code == -1) {
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, "failed to receive data from server");
                    }
                    else if (recv_code == 0) {
                        disconnect();
                        call_on_disconnected();
                        return;
                    }
                    else if (((size_t)recv_code) != msg_size) {
                        throw CPPDTPException(CPPDTP_CLIENT_RECV_FAILED, "failed to receive data from server");
                    }
                    else {
                        std::vector<char> data_vec(buffer, buffer + msg_size);
                        call_on_receive(data_vec);
                    }
                }

                sleep(CPPDTP_SLEEP_TIME);
            }
#endif
        }

        /**
         * Exchange crypto keys with the server.
         */
        void exchange_keys() {
            std::vector<char> size_buffer_vec;
            size_buffer_vec.resize(CPPDTP_LENSIZE);
            char *size_buffer = size_buffer_vec.data();
            std::vector<char> buffer_vec;
            int recv_code;

#ifdef _WIN32
            recv_code = recv(sock.sock, size_buffer, CPPDTP_LENSIZE, 0);

            if (recv_code == SOCKET_ERROR || recv_code == 0) {
                throw CPPDTPException(CPPDTP_CLIENT_KEY_EXCHANGE_FAILED, "failed to get public key from server");
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer_vec);
                buffer_vec.resize(msg_size);
                char *buffer = buffer_vec.data();

                // Wait in case the message is sent in multiple chunks
                sleep(CPPDTP_SLEEP_TIME);

                recv_code = recv(sock.sock, buffer, msg_size, 0);

                if (recv_code == SOCKET_ERROR || recv_code == 0 || (size_t)recv_code != msg_size) {
                throw CPPDTPException(CPPDTP_CLIENT_KEY_EXCHANGE_FAILED, "failed to get public key from server");
                }
            }
#else
            recv_code = read(sock.sock, size_buffer, CPPDTP_LENSIZE);

            if (recv_code == 0 || recv_code == -1) {
                throw CPPDTPException(CPPDTP_CLIENT_KEY_EXCHANGE_FAILED, "failed to get public key from server");
            }
            else {
                size_t msg_size = _decode_message_size(size_buffer_vec);
                buffer_vec.resize(msg_size);
                char *buffer = buffer_vec.data();

                // Wait in case the message is sent in multiple chunks
                sleep(CPPDTP_SLEEP_TIME);

                recv_code = read(sock.sock, buffer, msg_size);

                if (recv_code == 0 || recv_code == -1 || (size_t)recv_code != msg_size) {
                    throw CPPDTPException(CPPDTP_CLIENT_KEY_EXCHANGE_FAILED, "failed to get public key from server");
                }
            }
#endif

            std::vector<char> aes_key = _new_aes_key();
            std::vector<char> aes_key_encrypted = _rsa_encrypt(buffer_vec, aes_key);
            std::vector<char> aes_key_encoded = _encode_message(aes_key_encrypted);
            const char *message_buffer = aes_key_encoded.data();

            if (::send(sock.sock, message_buffer, aes_key_encoded.size(), 0) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_KEY_EXCHANGE_FAILED, "failed to send public key to server");
            }

            key = aes_key;
        }

        /**
         * Call the receive event method.
         */
        void call_on_receive(std::vector<char> data) {
            std::vector<char> data_decrypted = _aes_decrypt(key, data);
            R data_deserialized;
            _deserialize(data_deserialized, data_decrypted);
            std::thread t(&cppdtp::Client<S, R>::receive, this, std::move(data_deserialized));
            t.detach();
        }

        /**
         * Call the disconnect event method.
         */
        void call_on_disconnected() {
            std::thread t(&cppdtp::Client<S, R>::disconnected, this);
            t.detach();
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
        Client() {
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

            if (inet_pton(CPPDTP_ADDRESS_FAMILY, host_cstr, &(sock.address.sin_addr)) != 1) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }
#endif

            sock.address.sin_family = CPPDTP_ADDRESS_FAMILY;
            sock.address.sin_port = htons(port);

            if (::connect(sock.sock, (struct sockaddr *) &(sock.address), sizeof(sock.address)) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_CONNECT_FAILED, "client failed to connect to server");
            }

            connected = true;

            // Set blocking for key exchange
#ifdef _WIN32
            unsigned long mode = 0;

            if (ioctlsocket(sock.sock, FIONBIO, &mode) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }
#else
            if (fcntl(sock.sock, F_SETFL, fcntl(sock.sock, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
                throw CPPDTPException(CPPDTP_CLIENT_SOCK_INIT_FAILED, "failed to initialize client socket");
            }
#endif

            exchange_keys();

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
            connect(CPPDTP_CLIENT_HOST, port);
        }

        /**
         * Connect to a server, using the default host and port.
         */
        void connect() {
            connect(CPPDTP_CLIENT_HOST, CPPDTP_PORT);
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
#endif

            if (handle_thread.joinable()) {
                if (handle_thread.get_id() != std::this_thread::get_id()) {
                    handle_thread.join();
                } else {
                    handle_thread.detach();
                }
            }
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
         * Get the host of the client.
         *
         * @return The host address of the client.
         */
        std::string get_host() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
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
         * Get the port of the client.
         *
         * @return The port of the client.
         */
        uint16_t get_port() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getsockname(sock.sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_CLIENT_ADDRESS_FAILED, "client address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;
            uint16_t port = ntohs(s->sin_port);

            return port;
        }

        /**
         * Get the host address of the server the client is connected to.
         *
         * @return The host address of the server.
         */
        std::string get_server_host() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getpeername(sock.sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;

#ifdef _WIN32
            int addrlen = CPPDTP_ADDRSTRLEN;

            wchar_t addr_wc[CPPDTP_ADDRSTRLEN];

            if (WSAAddressToStringW((LPSOCKADDR)(s), sizeof(*s), NULL, addr_wc, (LPDWORD)&addrlen) != 0) {
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
         * Get the port of the server the client is connected to.
         *
         * @return The port of the server.
         */
        uint16_t get_server_port() {
            // Make sure the client is connected
            if (!connected) {
                throw CPPDTPException(CPPDTP_CLIENT_NOT_CONNECTED, 0, "client is not connected to a server");
            }

            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);

            if (getpeername(sock.sock, (struct sockaddr*)&addr, &len) != 0) {
                throw CPPDTPException(CPPDTP_SERVER_ADDRESS_FAILED, "server address conversion failed");
            }

            struct sockaddr_in *s = (struct sockaddr_in*)&addr;
            uint16_t port = ntohs(s->sin_port);

            return port;
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

            std::vector<char> data_serialized = _serialize(data);
            std::vector<char> data_encrypted = _aes_encrypt(key, data_serialized);
            std::vector<char> message = _encode_message(data_encrypted);
            const char *message_buffer = message.data();

            if (::send(sock.sock, message_buffer, message.size(), 0) < 0) {
                throw CPPDTPException(CPPDTP_CLIENT_SEND_FAILED, "failed to send data to server");
            }
        }
    }; // class Client

} // namespace cppdtp

#endif // CPPDTP_CLIENT_HPP
