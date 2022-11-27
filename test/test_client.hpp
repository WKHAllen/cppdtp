/**
 * A test client.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>

using namespace std;

template<typename S, typename R>
class TestClient : public cppdtp::Client<S, R> {
    using cppdtp::Client<S, R>::Client;

private:
    void receive(R data) override {
        receive_count--;
        received.push_back(data);
//        if (!receiving_random_message) {
//            string message = string((char *) data);
//            cout << "[CLIENT] Received data from server: " << message << " (size " << data_size << ")" << endl;
//        } else {
//            cout << "[CLIENT] Received large random message from client (size " << data_size << ", "
//                 << random_message_len << ")" << endl;
//            assert(data_size == random_message_len);
//            assert(memcmp(data, (void *) random_message, data_size) == 0);
//        }
    }

    void disconnected() override {
        disconnected_count--;
//        cout << "[CLIENT] Unexpectedly disconnected from server" << endl;
    }

public:
    int receive_count = 0;
    int disconnected_count = 0;
    vector <R> received;
//    bool receiving_random_message = false;
//    size_t random_message_len;
//    char *random_message;

    bool events_done() {
        return receive_count == 0 && disconnected_count == 0;
    }
};
