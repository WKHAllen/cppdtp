/**
 * A test client.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>
#include <utility>

using namespace std;

template<typename S, typename R>
class TestClient : public cppdtp::Client<S, R> {
    using cppdtp::Client<S, R>::Client;

private:
    void receive(R data) override {
        receive_count--;
        received.push_back(std::move(data));
    }

    void disconnected() override {
        disconnected_count--;
    }

public:
    int receive_count = 0;
    int disconnected_count = 0;
    vector <R> received;

    bool events_done() {
        return receive_count == 0 && disconnected_count == 0;
    }
};
