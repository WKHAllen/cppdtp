/**
 * Utility functions and definitions for cppdtp.
 */

#pragma once
#ifndef CPPDTP_UTIL_HPP
#define CPPDTP_UTIL_HPP

#include <string>
#include <type_traits>
#include <utility>
#include "../include/c_plus_plus_serializer.h"

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
#define CPPDTP_GET_HOST_NAME_FAILED       33

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

// Default CPPDTP host address
#define CPPDTP_HOST "0.0.0.0"

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

// Default CPPDTP server listen backlog
#ifndef CPPDTP_SERVER_LISTEN_BACKLOG
#  define CPPDTP_SERVER_LISTEN_BACKLOG 8
#endif

// Length of the size portion of each message
#define CPPDTP_LENSIZE 5

// Server max clients indicator
#define CPPDTP_SERVER_MAX_CLIENTS_REACHED UINT64_MAX

// Hostname
#ifdef _WIN32
#  define CPPDTP_HOST_NAME_MAX_LEN MAX_COMPUTERNAME_LENGTH
#else
#  define CPPDTP_HOST_NAME_MAX_LEN HOST_NAME_MAX
#endif

namespace cppdtp {

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
     * Tests if a type can be streamed.
     *
     * @tparam T The type to be streamed.
     */
    template<typename T>
    class is_streamable
    {
        template<typename TT>
        static auto test_out(int) -> decltype( std::declval<std::ostream&>() << std::declval<Bits<TT&>>(), std::true_type() );

        template<typename>
        static auto test_out(...) -> std::false_type;

        template<typename TT>
        static auto test_in(int) -> decltype( std::declval<std::istream&>() >> std::declval<Bits<TT&>>(), std::true_type() );

        template<typename>
        static auto test_in(...) -> std::false_type;

    public:
        static const bool value = decltype(test_out<T>(0))::value && decltype(test_in<T>(0))::value;
    };

    /**
     * Serialize an object to bytes.
     *
     * @tparam T The type of object.
     * @param object The object to serialize.
     * @return A string representing the binary representation of the object.
     */
    template<typename T>
    const std::string _serialize(const T &object) {
        static_assert(is_streamable<T>::value, "T must be streamable");

        std::stringstream out;
        out << bits(object);

        const std::string bytes = out.str();
        return bytes;

//        std::array<unsigned char, sizeof(T)> bytes;
//
//        const unsigned char *begin = reinterpret_cast<const unsigned char *>(std::addressof(object));
//        const unsigned char *end = begin + sizeof(T);
//        std::copy(begin, end, std::begin(bytes));
//
//        return bytes;
    }

    /**
     * Deserialize an object from bytes.
     *
     * @tparam T The type of object.
     * @param bytes The byte representation of the object.
     * @return The deserialized object.
     */
    template<typename T>
    T _deserialize(const std::string &bytes) {
        static_assert(is_streamable<T>::value, "T must be streamable");

        T object;
        std::stringstream in(bytes);
        in >> bits(object);

        return object;

//        static_assert(std::is_trivially_copyable<T>::value, "not a TriviallyCopyable type");
//
//        T object;
//
//        unsigned char *begin_object = reinterpret_cast<unsigned char *>(std::addressof(object));
//        std::copy(std::begin(bytes), std::end(bytes), begin_object);
//
//        return object;
    }

    /**
     * Encode the size portion of a message.
     *
     * @param size The message size.
     * @return The message size encoded in bytes.
     */
    const std::string _encode_message_size(size_t size) {
        std::string encoded_size;

        for (int i = CPPDTP_LENSIZE - 1; i >= 0; i--) {
            encoded_size.insert(0, 1, size % 256);
            size = size >> 8;
        }

        return encoded_size;

//        std::array<unsigned char, CPPDTP_LENSIZE> encoded_size;
//
//        for (int i = CPPDTP_LENSIZE - 1; i >= 0; i--) {
//            encoded_size[i] = size % 256;
//            size = size >> 8;
//        }
//
//        return encoded_size;
    }

    /**
     * Decode the size portion of a message.
     *
     * @param encoded_size The message size encoded in bytes.
     * @return The size of the message.
     */
    size_t _decode_message_size(const std::string &encoded_size) {
        size_t size = 0;

        for (int i = 0; i < CPPDTP_LENSIZE; i++) {
            size = size << 8;
            size += (unsigned char)(encoded_size[i]);
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
    const std::string _construct_message(const T &data) {
        std::string data_serialized = _serialize(data);
        std::string size = _encode_message_size(data_serialized.length());
        std::string message = size + data_serialized;

        return message;

//        std::array<unsigned char, sizeof(T)> data_serialized = _serialize(data);
//        std::array<unsigned char, CPPDTP_LENSIZE> size = _encode_message_size(sizeof(T));
//
//        std::array<unsigned char, CPPDTP_LENSIZE + sizeof(T)> message;
//        std::copy(size.begin(), size.end(), message.begin());
//        std::copy(data_serialized.begin(), data_serialized.end(), message.begin() + CPPDTP_LENSIZE);
//
//        return message;
    }

    /**
     * Deconstruct a message.
     *
     * @tparam T The type of data in the message.
     * @param message The message to be deconstructed.
     * @return The deconstructed message.
     */
    template<typename T>
    T _deconstruct_message(const std::string &message) {
//        std::string size_portion = message.substr(0, CPPDTP_LENSIZE);
//        size_t data_size = _decode_message_size(size_portion);

        std::string data_serialized = message.substr(CPPDTP_LENSIZE, message.length() - CPPDTP_LENSIZE);
        T data = _deserialize<T>(data_serialized);

        return data;

//        // std::array<unsigned char, CPPDTP_LENSIZE> size_portion;
//        // std::copy(message.begin(), message.begin() + CPPDTP_LENSIZE, size_portion.begin());
//        // size_t data_size = _decode_message_size(size_portion);
//
//        std::array<unsigned char, sizeof(T)> data_serialized;
//        std::copy(message.begin() + CPPDTP_LENSIZE, message.end(), data_serialized);
//        T data = _deserialize<T>(data_serialized);
//
//        return data;
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

#endif // CPPDTP_UTIL_HPP
