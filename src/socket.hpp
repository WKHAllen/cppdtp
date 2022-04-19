/*
 * Socket services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SOCKET_HPP
#define CPPDTP_SOCKET_HPP

#include "util.hpp"

namespace cppdtp {

    struct _Socket {
#ifdef _WIN32
        SOCKET sock;
#else
        int sock;
#endif
        struct sockaddr_in address;
    }; // struct _Socket

} // namespace cppdtp

#endif // CPPDTP_SOCKET_HPP
