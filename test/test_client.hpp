/**
 * A test client.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>

using namespace std;

class TestClient : public cppdtp::Client {
    using cppdtp::Client::Client;

private:
    void receive(void *data, size_t data_size) override {
        if (!receiving_random_message) {
            string message = string((char *) data);
            cout << "[CLIENT] Received data from server: " << message << " (size " << data_size << ")" << endl;
        } else {
            cout << "[CLIENT] Received large random message from client (size " << data_size << ", "
                 << random_message_len << ")" << endl;
            assert(data_size == random_message_len);
            assert(memcmp(data, (void *) random_message, data_size) == 0);
        }

        delete[] (char *) data;
    }

    void disconnected() override {
        cout << "[CLIENT] Unexpectedly disconnected from server" << endl;
    }

public:
    bool receiving_random_message = false;
    size_t random_message_len;
    char *random_message;
};
