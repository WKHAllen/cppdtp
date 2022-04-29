/**
 * Tests for cppdtp.
 */

#include "../bin/include/cppdtp.hpp"

#include <iostream>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <cstring>

using namespace std;

int randint(int min, int max) {
    return min + (rand() % (max - min + 1));
}

char* randbytes(size_t size) {
    char* bytes = (char*)malloc(size * sizeof(char));

    for (size_t i = 0; i < size; i++) {
        bytes[i] = (char)randint(0, 255);
    }

    return bytes;
}

class TestServer : public cppdtp::Server {
    using cppdtp::Server::Server;

private:
    void receive(size_t client_id, void* data, size_t data_size) override {
        if (!receiving_random_message) {
            string message = string((char*)data);
            cout << "[SERVER] Received data from client #" << client_id << ": " << message << " (size " << data_size << ")" << endl;
        }
        else {
            cout << "[SERVER] Received large random message from client (size " << data_size << ", " << random_message_len << ")" << endl;
            assert(data_size == random_message_len);
            assert(memcmp(data, (void*)random_message, data_size) == 0);
        }

        free(data);
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
    char* random_message;
};

class TestClient : public cppdtp::Client {
    using cppdtp::Client::Client;

private:
    void receive(void* data, size_t data_size) override {
        if (!receiving_random_message) {
            string message = string((char*)data);
            cout << "[CLIENT] Received data from server: " << message << " (size " << data_size << ")" << endl;
        }
        else {
            cout << "[CLIENT] Received large random message from client (size " << data_size << ", " << random_message_len << ")" << endl;
            assert(data_size == random_message_len);
            assert(memcmp(data, (void*)random_message, data_size) == 0);
        }

        free(data);
    }

    void disconnected() override {
        cout << "[CLIENT] Unexpectedly disconnected from server" << endl;
    }

public:
    bool receiving_random_message = false;
    size_t random_message_len;
    char* random_message;
};

int main() {
    const double wait_time = 0.1;

    // Generate large random messages
    srand(time(NULL));
    size_t random_message_to_server_len = randint(32768, 65535);
    size_t random_message_to_client_len = randint(65536, 82175); // fails on Linux at values >= 82176?
    char* random_message_to_server = randbytes(random_message_to_server_len);
    char* random_message_to_client = randbytes(random_message_to_client_len);
    cout << "Large random message sizes: " << random_message_to_server_len << ", " << random_message_to_client_len << endl;

    // Begin testing
    cout << "Running tests..." << endl;

    // Start server
    string host = "127.0.0.1";
    TestServer server(16);
    server.random_message_len = random_message_to_server_len;
    server.random_message = random_message_to_server;
    server.start(host);

    // Get IP address and port
    string ip_address = server.get_host();
    uint16_t port = server.get_port();
    cout << "IP address: " << ip_address << endl;
    cout << "Port:       " << port << endl;

    // Test that the client does not exist
    try {
        server.remove_client(0);
        cout << "Did not throw on removal of unknown client" << endl;
        assert(false);
    }
    catch (cppdtp::CPPDTPException& e) {
        cout << "Throws on removal of unknown client: '" << e.what() << "'" << endl;
        assert(e.error_code() == CPPDTP_CLIENT_DOES_NOT_EXIST);
        assert(e.underlying_error_code() == 0);
    }

    cppdtp::sleep(wait_time);

    // Start client
    TestClient client;
    client.random_message_len = random_message_to_client_len;
    client.random_message = random_message_to_client;
    client.connect(ip_address);

    // Get IP address and port
    string client_ip_address = client.get_host();
    uint16_t client_port = client.get_port();
    cout << "IP address: " << client_ip_address << endl;
    cout << "Port:       " << client_port << endl;

    cppdtp::sleep(wait_time);

    // Client send
    string client_message = "Hello, server.";
    client.send((void*)(&client_message[0]), client_message.size() + 1);

    cppdtp::sleep(wait_time);

    // Server send
    string server_message = "Hello, client #0.";
    server.send(0, (void*)(&server_message[0]), server_message.size() + 1);

    cppdtp::sleep(wait_time);

    server.receiving_random_message = true;
    client.receiving_random_message = true;

    // Client send large message
    client.send((void*)random_message_to_server, random_message_to_server_len);

    cppdtp::sleep(wait_time);

    // Server send large message
    server.send_all((void*)random_message_to_client, random_message_to_client_len);

    cppdtp::sleep(wait_time);

    server.receiving_random_message = false;
    client.receiving_random_message = false;

    // Client disconnect
    client.disconnect();

    cppdtp::sleep(wait_time);

    // Server stop
    server.stop();

    // Done
    cout << "Successfully passed all tests" << endl;
    return 0;
}
