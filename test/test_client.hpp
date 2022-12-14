/**
 * A test client.
 */

#include "../src/cppdtp.hpp"

#include <iostream>
#include <stdlib.h>
#include <assert.h>
#include <cstring>
#include <utility>
#include <vector>

using namespace std;

template<typename S, typename R>
class TestClient : public cppdtp::Client<S, R> {
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

    TestClient(int receive_count_, int disconnected_count_)
            : cppdtp::Client<S, R>(),
              receive_count(receive_count_), disconnected_count(disconnected_count_) {}

    bool events_done() {
        return receive_count == 0 && disconnected_count == 0;
    }
};
