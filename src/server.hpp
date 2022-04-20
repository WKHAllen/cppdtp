/*
 * Server services for cppdtp.
 */

#pragma once
#ifndef CPPDTP_SERVER_HPP
#define CPPDTP_SERVER_HPP

#include "util.hpp"
#include "client.hpp"
#include "socket.hpp"

#include <string>
#include <thread>

namespace cppdtp {

    class Server {
    private:
        friend class Client;

        bool blocking = false;
        bool event_blocking = false;
        bool serving = false;
        size_t max_clients;
        size_t num_clients = 0;
        _Socket sock;
        _Socket* clients = new _Socket[1];
        bool* allocated_clients = new bool[1];
        std::thread serve_thread;

    public:
        Server(bool blocking_, bool event_blocking_, size_t max_clients_) {
            blocking = blocking_;
            event_blocking = event_blocking_;
            max_clients = max_clients_;

            delete[] clients;
            delete[] allocated_clients;

            clients = new _Socket[max_clients];
            allocated_clients = new bool[max_clients] {false};
        }

        Server(size_t max_clients_) {
            Server(false, false, max_clients_);
        }

        void start(std::string host, unsigned short port) {
            // TODO: start server
            (void)host;
            (void)port;
        }

        void stop() {
            // TODO: stop server
        }

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
