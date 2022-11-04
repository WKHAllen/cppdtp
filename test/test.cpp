/**
 * Tests for cppdtp.
 */

#include "../src/cppdtp.hpp"
#include "test_server.hpp"
#include "test_client.hpp"
#include "test_util.hpp"

#include <iostream>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

using namespace std;

/**
 * Time to wait between network operations.
 */
const double wait_time = 0.1;

/**
 * Test utility functions.
 */
void test_util() {
    // Test message size encoding
    unsigned char *expected_msg_size1 = new unsigned char[CPPDTP_LENSIZE]{0, 0, 0, 0, 0};
    unsigned char *expected_msg_size2 = new unsigned char[CPPDTP_LENSIZE]{0, 0, 0, 0, 1};
    unsigned char *expected_msg_size3 = new unsigned char[CPPDTP_LENSIZE]{0, 0, 0, 0, 255};
    unsigned char *expected_msg_size4 = new unsigned char[CPPDTP_LENSIZE]{0, 0, 0, 1, 0};
    unsigned char *expected_msg_size5 = new unsigned char[CPPDTP_LENSIZE]{0, 0, 0, 1, 1};
    unsigned char *expected_msg_size6 = new unsigned char[CPPDTP_LENSIZE]{1, 1, 1, 1, 1};
    unsigned char *expected_msg_size7 = new unsigned char[CPPDTP_LENSIZE]{1, 2, 3, 4, 5};
    unsigned char *expected_msg_size8 = new unsigned char[CPPDTP_LENSIZE]{11, 7, 5, 3, 2};
    unsigned char *expected_msg_size9 = new unsigned char[CPPDTP_LENSIZE]{255, 255, 255, 255, 255};
    unsigned char *msg_size1 = cppdtp::_encode_message_size(0);
    unsigned char *msg_size2 = cppdtp::_encode_message_size(1);
    unsigned char *msg_size3 = cppdtp::_encode_message_size(255);
    unsigned char *msg_size4 = cppdtp::_encode_message_size(256);
    unsigned char *msg_size5 = cppdtp::_encode_message_size(257);
    unsigned char *msg_size6 = cppdtp::_encode_message_size(4311810305);
    unsigned char *msg_size7 = cppdtp::_encode_message_size(4328719365);
    unsigned char *msg_size8 = cppdtp::_encode_message_size(47362409218);
    unsigned char *msg_size9 = cppdtp::_encode_message_size(1099511627775);
    assert_arrays_equal(msg_size1, expected_msg_size1, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size2, expected_msg_size2, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size3, expected_msg_size3, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size4, expected_msg_size4, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size5, expected_msg_size5, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size6, expected_msg_size6, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size7, expected_msg_size7, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size8, expected_msg_size8, CPPDTP_LENSIZE);
    assert_arrays_equal(msg_size9, expected_msg_size9, CPPDTP_LENSIZE);
    delete[] msg_size1;
    delete[] msg_size2;
    delete[] msg_size3;
    delete[] msg_size4;
    delete[] msg_size5;
    delete[] msg_size6;
    delete[] msg_size7;
    delete[] msg_size8;
    delete[] msg_size9;

    // Test message size decoding
    assert_equal(cppdtp::_decode_message_size(expected_msg_size1), (size_t) 0);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size2), (size_t) 1);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size3), (size_t) 255);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size4), (size_t) 256);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size5), (size_t) 257);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size6), (size_t) 4311810305);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size7), (size_t) 4328719365);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size8), (size_t) 47362409218);
    assert_equal(cppdtp::_decode_message_size(expected_msg_size9), (size_t) 1099511627775);

    // Cleanup
    delete[] expected_msg_size1;
    delete[] expected_msg_size2;
    delete[] expected_msg_size3;
    delete[] expected_msg_size4;
    delete[] expected_msg_size5;
    delete[] expected_msg_size6;
    delete[] expected_msg_size7;
    delete[] expected_msg_size8;
    delete[] expected_msg_size9;
}

/**
 * Test crypto functions.
 */
void test_crypto() {}

/**
 * Test server creation and serving.
 */
void test_server_serve() {}

/**
 * Test getting server and client addresses.
 */
void test_addresses() {}

/**
 * Test sending messages between server and client.
 */
void test_send_receive() {}

/**
 * Test sending large random messages between server and client.
 */
void test_send_large_messages() {}

/**
 * Test sending numerous random messages between server and client.
 */
void test_sending_numerous_messages() {}

/**
 * Test having multiple clients connected.
 */
void test_multiple_clients() {}

/**
 * Test clients disconnecting from the server.
 */
void test_client_disconnected() {}

/**
 * Test removing a client from the server.
 */
void test_remove_client() {}

/**
 * Test stopping a server while a client is connected.
 */
void test_stop_server_while_client_connected() {}

/**
 * Test address defaults.
 */
void test_server_client_address_defaults() {}

int main() {
    cout << "Beginning tests" << endl;
    // Initialize the random number generator
    srand(time(NULL));

    // Run tests
    cout << endl << "Testing utilities..." << endl;
    test_util();
    cout << endl << "Testing crypto..." << endl;
    test_crypto();
    cout << endl << "Testing server creation and serving..." << endl;
    test_server_serve();
    cout << endl << "Testing addresses..." << endl;
    test_addresses();
    cout << endl << "Testing send and receive..." << endl;
    test_send_receive();
    cout << endl << "Testing sending large messages..." << endl;
    test_send_large_messages();
    cout << endl << "Testing sending numerous messages..." << endl;
    test_sending_numerous_messages();
    cout << endl << "Testing with multiple clients..." << endl;
    test_multiple_clients();
    cout << endl << "Testing disconnecting clients..." << endl;
    test_client_disconnected();
    cout << endl << "Testing removing clients..." << endl;
    test_remove_client();
    cout << endl << "Testing stopping the server with the client connected..." << endl;
    test_stop_server_while_client_connected();
    cout << endl << "Testing address defaults..." << endl;
    test_server_client_address_defaults();

    // Done
    cout << endl << "Completed tests" << endl;
}

//int main() {
//    srand(time(NULL));
//
//    // Generate large random messages
//    size_t random_message_to_server_len = rand_int(32768, 65535);
//    size_t random_message_to_client_len = rand_int(65536, 82175); // fails on Linux at values >= 82176?
//    char *random_message_to_server = rand_bytes(random_message_to_server_len);
//    char *random_message_to_client = rand_bytes(random_message_to_client_len);
//    cout << "Large random message sizes: " << random_message_to_server_len << ", " << random_message_to_client_len
//         << endl;
//
//    // Begin testing
//    cout << "Running tests..." << endl;
//
//    // Start server
//    string host = "127.0.0.1";
//    TestServer server(16);
//    server.random_message_len = random_message_to_server_len;
//    server.random_message = random_message_to_server;
//    server.start(host);
//
//    // Get IP address and port
//    string ip_address = server.get_host();
//    uint16_t port = server.get_port();
//    cout << "IP address: " << ip_address << endl;
//    cout << "Port:       " << port << endl;
//
//    // Test that the client does not exist
//    try {
//        server.remove_client(0);
//        cout << "Did not throw on removal of unknown client" << endl;
//        assert(false);
//    }
//    catch (cppdtp::CPPDTPException &e) {
//        cout << "Throws on removal of unknown client: '" << e.what() << "'" << endl;
//        assert(e.error_code() == CPPDTP_CLIENT_DOES_NOT_EXIST);
//        assert(e.underlying_error_code() == 0);
//    }
//
//    cppdtp::sleep(wait_time);
//
//    // Start client
//    TestClient client;
//    client.random_message_len = random_message_to_client_len;
//    client.random_message = random_message_to_client;
//    client.connect(ip_address);
//
//    // Get IP address and port
//    string client_ip_address = client.get_host();
//    uint16_t client_port = client.get_port();
//    cout << "IP address: " << client_ip_address << endl;
//    cout << "Port:       " << client_port << endl;
//
//    cppdtp::sleep(wait_time);
//
//    // Client send
//    string client_message = "Hello, server.";
//    client.send((void *) (&client_message[0]), client_message.size() + 1);
//
//    cppdtp::sleep(wait_time);
//
//    // Server send
//    string server_message = "Hello, client #0.";
//    server.send(0, (void *) (&server_message[0]), server_message.size() + 1);
//
//    cppdtp::sleep(wait_time);
//
//    server.receiving_random_message = true;
//    client.receiving_random_message = true;
//
//    // Client send large message
//    client.send((void *) random_message_to_server, random_message_to_server_len);
//
//    cppdtp::sleep(wait_time);
//
//    // Server send large message
//    server.send_all((void *) random_message_to_client, random_message_to_client_len);
//
//    cppdtp::sleep(wait_time);
//
//    server.receiving_random_message = false;
//    client.receiving_random_message = false;
//
//    // Client disconnect
//    client.disconnect();
//
//    cppdtp::sleep(wait_time);
//
//    // Server stop
//    server.stop();
//
//    delete[] random_message_to_server;
//    delete[] random_message_to_client;
//
//    // Done
//    cout << "Successfully passed all tests" << endl;
//    return 0;
//}
