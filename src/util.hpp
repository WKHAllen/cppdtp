/**
 * Utility functions and definitions for cppdtp.
 */

#pragma once
#ifndef CPPDTP_UTIL_HPP
#define CPPDTP_UTIL_HPP

#include <string>
#include <vector>
#include <type_traits>
#include <utility>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "../include/SimpleBinStream.h"

#pragma GCC diagnostic pop

#ifdef _WIN32
#  include <WinSock2.h>
#  include <Windows.h>
#  include <WS2tcpip.h>
#else

#  include <unistd.h>
#  include <sys/socket.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <errno.h>
#  include <time.h>
#  include <limits.h>

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
#define CPPDTP_OPENSSL_ERROR              33

// Global address family to use
#ifndef CPPDTP_ADDRESS_FAMILY
#  define CPPDTP_ADDRESS_FAMILY AF_INET
#endif

// INET and INET6 address string length
#define CPPDTP_INET_ADDRSTRLEN  INET_ADDRSTRLEN
#define CPPDTP_INET6_ADDRSTRLEN INET6_ADDRSTRLEN

// Global address string length
#if (CPPDTP_ADDRESS_FAMILY == AF_INET)
#  define CPPDTP_ADDRSTRLEN CPPDTP_INET_ADDRSTRLEN
#elif (CPPDTP_ADDRESS_FAMILY == AF_INET6)
#  define CPPDTP_ADDRSTRLEN CPPDTP_INET6_ADDRSTRLEN
#endif

// Default CPPDTP server host address
#define CPPDTP_SERVER_HOST "0.0.0.0"

// Default CPPDTP client host address
#define CPPDTP_CLIENT_HOST "127.0.0.1"

// Default CPPDTP port
#ifndef CPPDTP_PORT
#  define CPPDTP_PORT 29275
#endif

// Default CPPDTP server listen backlog
#ifndef CPPDTP_SERVER_LISTEN_BACKLOG
#  define CPPDTP_SERVER_LISTEN_BACKLOG 8
#endif

// Length of the size portion of each message
#define CPPDTP_LENSIZE 5

// Determine if a blocking error has occurred
// This is necessary because -Wlogical-op causes a compile-time error on machines where EAGAIN and EWOULDBLOCK are equal
#ifndef _WIN32
#  if EAGAIN == EWOULDBLOCK
#    define CPPDTP_EAGAIN_OR_WOULDBLOCK(e) (e == EAGAIN)
#  else
#    define CPPDTP_EAGAIN_OR_WOULDBLOCK(e) (e == EAGAIN || e == EWOULDBLOCK)
#  endif
#endif

namespace cppdtp {

    using mem_ostream = simple::mem_ostream<std::true_type>;
    using mem_istream = simple::mem_istream<std::true_type>;

    static bool _cppdtp_init_status = false;
    static bool _cppdtp_exit_status = false;

    /**
     * Called on exit.
     */
    void _cppdtp_exit() {
        if (!_cppdtp_exit_status) {
            _cppdtp_exit_status = true;

#ifdef _WIN32
            WSACleanup();
#endif

        }
    }

    /**
     * Called on library initialization.
     *
     * @return The initialization return status.
     */
    int _cppdtp_init() {
        if (!_cppdtp_init_status) {
            _cppdtp_init_status = true;
            std::atexit(_cppdtp_exit);

#ifdef _WIN32
            WSADATA wsa;
            return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
            return 0;
#endif

        }

        return 0;
    }

    /**
     * Serialize an object to bytes.
     *
     * @tparam T The type of object. This must override the streaming operators to be serialized.
     * @param object The object to serialize.
     * @return A string representing the binary representation of the object.
     */
    template<typename T>
    const std::vector<char> _serialize(const T &object) {
        mem_ostream out;
        out << object;

        return out.get_internal_vec();
    }

    /**
     * Deserialize an object from bytes.
     *
     * @tparam T The type of object.
     * @param object The object to deserialize into.
     * @param bytes The byte representation of the object.
     */
    template<typename T>
    void _deserialize(T &object, const std::vector<char> &bytes) {
        mem_istream in(bytes);
        in >> object;
    }

    /**
     * Encode the size portion of a message.
     *
     * @param size The message size.
     * @return The message size encoded in bytes.
     */
    const std::vector<char> _encode_message_size(size_t size) {
        std::vector<char> encoded_size;

        for (int i = CPPDTP_LENSIZE - 1; i >= 0; i--) {
            encoded_size.insert(encoded_size.begin(), size % 256);
            size = size >> 8;
        }

        return encoded_size;
    }

    /**
     * Decode the size portion of a message.
     *
     * @param encoded_size The message size encoded in bytes.
     * @return The size of the message.
     */
    size_t _decode_message_size(const std::vector<char> &encoded_size) {
        size_t size = 0;

        for (int i = 0; i < CPPDTP_LENSIZE; i++) {
            size = size << 8;
            size += (unsigned char) (encoded_size[i]);
        }

        return size;
    }

    /**
     * Construct a message.
     *
     * @tparam T The type of data in the message.
     * @param data The message data.
     * @return The constructed message.
     */
    template<typename T>
    const std::vector<char> _construct_message(const T &data) {
        const std::vector<char> data_serialized = _serialize(data);
        const std::vector<char> size = _encode_message_size(data_serialized.size());

        std::vector<char> message;
        message.reserve(size.size() + data_serialized.size());
        message.insert(message.end(), size.begin(), size.end());
        message.insert(message.end(), data_serialized.begin(), data_serialized.end());

        return message;
    }

    /**
     * Deconstruct a message.
     *
     * @tparam T The type of data in the message.
     * @param object The object to deconstruct into.
     * @param message The message to be deconstructed.
     */
    template<typename T>
    void _deconstruct_message(T &object, const std::vector<char> &message) {
        std::vector<char> data_serialized(message.begin() + CPPDTP_LENSIZE, message.end());
        _deserialize<T>(object, data_serialized);
    }

    /**
     * Sleep for a number of seconds.
     *
     * @param seconds The number of seconds to sleep.
     */
    void sleep(double seconds) {
#ifdef _WIN32
        Sleep(seconds * 1000);
#else
        struct timespec ts;
        ts.tv_sec = seconds;
        ts.tv_nsec = ((int) (seconds * 1000) % 1000) * 1000000;
        nanosleep(&ts, NULL);
#endif
    }

#ifdef _WIN32
    /**
     * Convert a C-style string to a wide character type.
     *
     * @param cstr The C-style string.
     * @return The wide character string.
     */
    wchar_t *cstr_to_wchar(const char *cstr) {
        size_t newsize = strlen(cstr) + 1;
        wchar_t *wchar = new wchar_t[newsize];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, wchar, newsize, cstr, _TRUNCATE);
        return wchar;
    }

    /**
     * Convert a wide character string to a C-string.
     *
     * @param wchar The wide character string.
     * @return The C-style string.
     */
    char *wchar_to_cstr(const wchar_t *wchar) {
        size_t wcharsize = wcslen(wchar) + 1;
        size_t convertedChars = 0;
        const size_t newsize = wcharsize * 2;
        char* cstr = new char[newsize];
        wcstombs_s(&convertedChars, cstr, newsize, wchar, _TRUNCATE);
        return cstr;
    }
#endif

} // namespace cppdtp

template<typename T>
cppdtp::mem_ostream &operator<<(cppdtp::mem_ostream &out, const std::vector <T> &vec) {
    static_assert(std::is_default_constructible<T>::value, "T must be default constructible");

    size_t size = vec.size();
    out << size;

    for (size_t i = 0; i < vec.size(); i++) {
        out << vec[i];
    }

    return out;
}

template<typename T>
cppdtp::mem_istream &operator>>(cppdtp::mem_istream &in, std::vector <T> &vec) {
    static_assert(std::is_default_constructible<T>::value, "T must be default constructible");

    size_t size = 0;
    in >> size;

    for (size_t i = 0; i < size; i++) {
        T val;
        in >> val;
        vec.push_back(val);
    }

    return in;
}

#endif // CPPDTP_UTIL_HPP
