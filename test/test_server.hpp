/**
 * A test server.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>
#include <utility>

using namespace std;

template<typename S, typename R>
class TestServer : public cppdtp::Server<S, R> {
    using cppdtp::Server<S, R>::Server;

private:
    void receive(size_t client_id, R data) override {
        if (reply_with_string_length) {
            string str_data((string) data);
            size_t str_len = str_data.length();
            S send_len = (S) str_len;
            this->send(client_id, send_len);
        }

        receive_count--;
        received.push_back(std::move(data));
        received_client_ids.push_back(client_id);
    }

    void connect(size_t client_id) override {
        connect_count--;
        connect_client_ids.push_back(client_id);
    }

    void disconnect(size_t client_id) override {
        disconnect_count--;
        disconnect_client_ids.push_back(client_id);
    }

public:
    bool reply_with_string_length = false;
    int receive_count = 0;
    int connect_count = 0;
    int disconnect_count = 0;
    vector <R> received;
    vector <size_t> received_client_ids;
    vector <size_t> connect_client_ids;
    vector <size_t> disconnect_client_ids;

    bool events_done() {
        return receive_count == 0 && connect_count == 0 && disconnect_count == 0;
    }
};
