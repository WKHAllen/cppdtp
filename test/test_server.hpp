/**
 * A test server.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>

using namespace std;

class TestServer : public cppdtp::Server {
    using cppdtp::Server::Server;

private:
    void receive(size_t client_id, void *data, size_t data_size) override {
        if (!receiving_random_message) {
            string message = string((char *) data);
            cout << "[SERVER] Received data from client #" << client_id << ": " << message << " (size " << data_size
                 << ")" << endl;
        } else {
            cout << "[SERVER] Received large random message from client (size " << data_size << ", "
                 << random_message_len << ")" << endl;
            assert(data_size == random_message_len);
            assert(memcmp(data, (void *) random_message, data_size) == 0);
        }

        delete[] (char *) data;
    }

    void connect(size_t client_id) override {
        cout << "[SERVER] Client #" << client_id << " connected" << endl;
    }

    void disconnect(size_t client_id) override {
        cout << "[SERVER] Client #" << client_id << " disconnected" << endl;
    }

public:
    bool receiving_random_message = false;
    size_t random_message_len;
    char *random_message;
};
