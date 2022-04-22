/**
 * Socket services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SOCKET_HPP
#define CPPDTP_SOCKET_HPP

#include "util.hpp"

namespace cppdtp {

    // Socket type, containing the socket itself and the address
    struct _Socket {
#ifdef _WIN32
        // Windows socket
        SOCKET sock;
#else
        // Non-Windows socket
        int sock;
#endif
        // Socket address
        struct sockaddr_in address;
    }; // struct _Socket

} // namespace cppdtp

#endif // CPPDTP_SOCKET_HPP
