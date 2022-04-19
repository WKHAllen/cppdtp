/*
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "socket.hpp"

#include <string>

namespace cppdtp {

    class Server {
    private:
        size_t max_clients;
        bool blocking;
        bool event_blocking;
        bool serving;
        size_t num_clients;
        _Socket sock;
        _Socket* clients = new _Socket[1];
        int* allocated_clients = new int[1];
#ifdef _WIN32
        HANDLE serve_thread;
#else
        pthread_t serve_thread;
#endif

    public:
        std::string get_host() {
            // TODO: return host
            return "";
        }

        unsigned short get_port() {
            // TODO: return port
            return 0;
        }
    };

} // namespace cppdtp

#endif // CPPDTP_SERVER_HPP
