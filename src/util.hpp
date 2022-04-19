/*
 * Utility functions and definitions for cppdtp.
 */

#pragma once
#ifndef CPPDTP_UTIL_HPP
#define CPPDTP_UTIL_HPP

#include <string>

#ifdef _WIN32
#  include <WinSock2.h>
#  include <Windows.h>
#  include <WS2tcpip.h>
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <errno.h>
#  include <time.h>
#endif

 // CPPDTP error codes
#define CPPDTP_SUCCESS                     0
#define CPPDTP_WINSOCK_INIT_FAILED         1
#define CPPDTP_SERVER_SOCK_INIT_FAILED     2
#define CPPDTP_SERVER_SETSOCKOPT_FAILED    3
#define CPPDTP_SERVER_CANNOT_RESTART       4
#define CPPDTP_SERVER_NOT_SERVING          5
#define CPPDTP_SERVER_ALREADY_SERVING      6
#define CPPDTP_SERVER_ADDRESS_FAILED       7
#define CPPDTP_SERVER_BIND_FAILED          8
#define CPPDTP_SERVER_LISTEN_FAILED        9
#define CPPDTP_SERVER_STOP_FAILED         10
#define CPPDTP_SERVE_THREAD_NOT_CLOSING   11
#define CPPDTP_CLIENT_DOES_NOT_EXIST      12
#define CPPDTP_CLIENT_REMOVE_FAILED       13
#define CPPDTP_SERVER_SEND_FAILED         14
#define CPPDTP_EVENT_THREAD_START_FAILED  15
#define CPPDTP_SERVE_THREAD_START_FAILED  16
#define CPPDTP_HANDLE_THREAD_START_FAILED 17
#define CPPDTP_SELECT_FAILED              18
#define CPPDTP_SOCKET_ACCEPT_FAILED       19
#define CPPDTP_SERVER_RECV_FAILED         20
#define CPPDTP_STATUS_SEND_FAILED         21
#define CPPDTP_SERVER_FULL                22
#define CPPDTP_CLIENT_SOCK_INIT_FAILED    23
#define CPPDTP_CLIENT_CANNOT_RECONNECT    24
#define CPPDTP_CLIENT_ALREADY_CONNECTED   25
#define CPPDTP_CLIENT_ADDRESS_FAILED      26
#define CPPDTP_CLIENT_CONNECT_FAILED      27
#define CPPDTP_CLIENT_DISCONNECT_FAILED   28
#define CPPDTP_HANDLE_THREAD_NOT_CLOSING  29
#define CPPDTP_CLIENT_NOT_CONNECTED       30
#define CPPDTP_CLIENT_SEND_FAILED         31
#define CPPDTP_CLIENT_RECV_FAILED         32

 // Global address family to use
#ifndef CPPDTP_ADDRESS_FAMILY
#  define CPPDTP_ADDRESS_FAMILY AF_INET
#endif

// INET and INET6 address string length
#define CPPDTP_INET_ADDRSTRLEN  22
#define CPPDTP_INET6_ADDRSTRLEN 65

// Global address string length
#if (CPPDTP_ADDRESS_FAMILY == AF_INET)
#  define CPPDTP_ADDRSTRLEN CPPDTP_INET_ADDRSTRLEN
#elif (CPPDTP_ADDRESS_FAMILY == AF_INET6)
#  define CPPDTP_ADDRSTRLEN CPPDTP_INET6_ADDRSTRLEN
#endif

// Default CPPDTP port
#ifndef CPPDTP_PORT
#  define CPPDTP_PORT 29275
#endif

// Default CPPDTP local server host and port
#ifndef CPPDTP_LOCAL_SERVER_HOST
#  if (CPPDTP_ADDRESS_FAMILY == AF_INET)
#    define CPPDTP_LOCAL_SERVER_HOST "127.0.0.1"
#  else
#    define CPPDTP_LOCAL_SERVER_HOST "::1"
#  endif
#endif
#ifndef CPPDTP_LOCAL_SERVER_PORT
#  define CPPDTP_LOCAL_SERVER_PORT (CPPDTP_PORT + 1)
#endif

// Length of the size portion of each message
#define CPPDTP_LENSIZE 5

namespace cppdtp {

    template <typename T>
    bool equal(T a, T b) {
        return a == b;
    }

    unsigned char* _encode_message_size(size_t size) {
        unsigned char* encoded_size = new unsigned char[CPPDTP_LENSIZE];

        for (int i = CPPDTP_LENSIZE - 1; i >= 0; i--) {
            encoded_size[i] = size % 256;
            size = size >> 8;
        }

        return encoded_size;
    }

    size_t _decode_message_size(unsigned char encoded_size[CPPDTP_LENSIZE]) {
        size_t size = 0;

        for (int i = 0; i < CPPDTP_LENSIZE; i++) {
            size = size << 8;
            size += encoded_size[i];
        }

        return size;
    }

    template <typename T>
    std::string _construct_message(T data, size_t data_size) {
        char* data_str = (char*)data;
        char* message = (char*)malloc((CPPDTP_LENSIZE + data_size) * sizeof(char));
        unsigned char size[CPPDTP_LENSIZE] = _encode_message_size(data_size);

        for (int i = 0; i < CPPDTP_LENSIZE; i++) {
            message[i] = size[i];
        }

        for (size_t i = 0; i < data_size; i++) {
            message[i + CPPDTP_LENSIZE] = data_str[i];
        }

        std::string message_str(message);

        delete[] size;
        free(message);

        return message_str;
    }

    template <typename T>
    T _deconstruct_message(std::string message) {
        // only the first CPPDTP_LENSIZE bytes of message will be read as the size
        size_t data_size = _decode_message_size((unsigned char*)(&message[0]));
        char* data = (char*)malloc(data_size * sizeof(char));

        for (size_t i = 0; i < data_size; i++) {
            data[i] = message[i + CPPDTP_LENSIZE];
        }

        return (T)data;
    }

    void sleep(double seconds) {
#ifdef _WIN32
        Sleep(seconds * 1000);
#else
        struct timespec ts;
        ts.tv_sec = seconds;
        ts.tv_nsec = ((int)(seconds * 1000) % 1000) * 1000000;
        nanosleep(&ts, NULL);
#endif
    }

} // namespace cppdtp

#endif // CPPDTP_UTIL_HPP
