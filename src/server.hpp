/*
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "socket.hpp"

namespace cppdtp {

    class Server {
    private:
        size_t max_clients;
        bool blocking;
        bool event_blocking;
        bool serving;
        size_t num_clients;
        _Socket sock;
        _Socket* clients = new _Socket[0];
        int* allocated_clients = new int[0];
#ifdef _WIN32
        HANDLE serve_thread;
#else
        pthread_t serve_thread;
#endif

    public:

    };

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
