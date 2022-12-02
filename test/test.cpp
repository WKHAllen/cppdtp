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
 * The maximum number of clients a server can serve at once.
 */
const size_t max_clients = 16;

/**
 * A custom class for serializing/deserializing.
 */
class Custom {
public:
    int a;
    string b;
    vector <string> c;

    friend cppdtp::mem_ostream &operator<<(cppdtp::mem_ostream &out, const Custom &my) {
        out << my.a << my.b << my.c;
        return out;
    }

    friend cppdtp::mem_istream &operator>>(cppdtp::mem_istream &in, Custom &my) {
        in >> my.a >> my.b >> my.c;
        return in;
    }

    friend bool operator==(const Custom &lhs, const Custom &rhs) {
        return lhs.a == rhs.a && lhs.b == rhs.b && lhs.c == rhs.c;
    }

    friend bool operator!=(const Custom &lhs, const Custom &rhs) {
        return !(lhs == rhs);
    }

    friend ostream &operator<<(ostream &out, const Custom &my) {
        out << my.a << ", \"" << my.b << "\", vec(" << my.c.size() << ")[";

        for (size_t i = 0; i < my.c.size(); i++) {
            out << my.c[i];

            if (i < my.c.size() - 1) {
                out << ", ";
            }
        }

        out << "]";
        return out;
    }
};

/**
 * Test utility functions.
 */
void test_util() {
    // Test serialization and deserialization
    bool test_bool = true;
    int test_int = 1729;
    size_t test_size_t = 47362409218;
    float test_float = 3.14;
    double test_double = 2.718;
    array<int, 8> test_array = {0, 1, 1, 2, 3, 5, 8, 13};
    vector<char> test_vector_char = {'d', 't', 'p'};
    vector <string> test_vector_str = {"Hello", "from", "the serializer", ": )"};
    string test_string = "Hello, cppdtp!";
    Custom test_custom_class;
    test_custom_class.a = 123;
    test_custom_class.b = "Hello, custom class!";
    test_custom_class.c.push_back("first item");
    test_custom_class.c.push_back("second item");
    bool test_bool_de;
    int test_int_de;
    size_t test_size_t_de;
    float test_float_de;
    double test_double_de;
    array<int, 8> test_array_de;
    vector<char> test_vector_char_de;
    vector <string> test_vector_str_de;
    string test_string_de;
    Custom test_custom_class_de;
    cppdtp::_deserialize(test_bool_de, cppdtp::_serialize(test_bool));
    cppdtp::_deserialize(test_int_de, cppdtp::_serialize(test_int));
    cppdtp::_deserialize(test_size_t_de, cppdtp::_serialize(test_size_t));
    cppdtp::_deserialize(test_float_de, cppdtp::_serialize(test_float));
    cppdtp::_deserialize(test_double_de, cppdtp::_serialize(test_double));
    cppdtp::_deserialize(test_array_de, cppdtp::_serialize(test_array));
    cppdtp::_deserialize(test_vector_char_de, cppdtp::_serialize(test_vector_char));
    cppdtp::_deserialize(test_vector_str_de, cppdtp::_serialize(test_vector_str));
    cppdtp::_deserialize(test_string_de, cppdtp::_serialize(test_string));
    cppdtp::_deserialize(test_custom_class_de, cppdtp::_serialize(test_custom_class));
    assert_equal(test_bool_de, test_bool);
    assert_equal(test_int_de, test_int);
    assert_equal(test_size_t_de, test_size_t);
    assert_floats_equal(test_float_de, test_float);
    assert_floats_equal(test_double_de, test_double);
    assert_arrays_equal(test_array_de, test_array);
    assert_arrays_equal(test_vector_char_de, test_vector_char);
    assert_arrays_equal(test_vector_str_de, test_vector_str);
    assert_equal(test_string_de, test_string);
    assert_equal(test_custom_class_de, test_custom_class);

    // Test message size encoding
    const unsigned char expected_msg_size_arr1[CPPDTP_LENSIZE] = {0, 0, 0, 0, 0};
    const unsigned char expected_msg_size_arr2[CPPDTP_LENSIZE] = {0, 0, 0, 0, 1};
    const unsigned char expected_msg_size_arr3[CPPDTP_LENSIZE] = {0, 0, 0, 0, 255};
    const unsigned char expected_msg_size_arr4[CPPDTP_LENSIZE] = {0, 0, 0, 1, 0};
    const unsigned char expected_msg_size_arr5[CPPDTP_LENSIZE] = {0, 0, 0, 1, 1};
    const unsigned char expected_msg_size_arr6[CPPDTP_LENSIZE] = {1, 1, 1, 1, 1};
    const unsigned char expected_msg_size_arr7[CPPDTP_LENSIZE] = {1, 2, 3, 4, 5};
    const unsigned char expected_msg_size_arr8[CPPDTP_LENSIZE] = {11, 7, 5, 3, 2};
    const unsigned char expected_msg_size_arr9[CPPDTP_LENSIZE] = {255, 255, 255, 255, 255};
    vector<char> expected_msg_size1(expected_msg_size_arr1, expected_msg_size_arr1 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size2(expected_msg_size_arr2, expected_msg_size_arr2 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size3(expected_msg_size_arr3, expected_msg_size_arr3 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size4(expected_msg_size_arr4, expected_msg_size_arr4 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size5(expected_msg_size_arr5, expected_msg_size_arr5 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size6(expected_msg_size_arr6, expected_msg_size_arr6 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size7(expected_msg_size_arr7, expected_msg_size_arr7 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size8(expected_msg_size_arr8, expected_msg_size_arr8 + CPPDTP_LENSIZE);
    vector<char> expected_msg_size9(expected_msg_size_arr9, expected_msg_size_arr9 + CPPDTP_LENSIZE);
    vector<char> msg_size1 = cppdtp::_encode_message_size(0);
    vector<char> msg_size2 = cppdtp::_encode_message_size(1);
    vector<char> msg_size3 = cppdtp::_encode_message_size(255);
    vector<char> msg_size4 = cppdtp::_encode_message_size(256);
    vector<char> msg_size5 = cppdtp::_encode_message_size(257);
    vector<char> msg_size6 = cppdtp::_encode_message_size(4311810305);
    vector<char> msg_size7 = cppdtp::_encode_message_size(4328719365);
    vector<char> msg_size8 = cppdtp::_encode_message_size(47362409218);
    vector<char> msg_size9 = cppdtp::_encode_message_size(1099511627775);
    assert_arrays_equal(msg_size1, expected_msg_size1);
    assert_arrays_equal(msg_size2, expected_msg_size2);
    assert_arrays_equal(msg_size3, expected_msg_size3);
    assert_arrays_equal(msg_size4, expected_msg_size4);
    assert_arrays_equal(msg_size5, expected_msg_size5);
    assert_arrays_equal(msg_size6, expected_msg_size6);
    assert_arrays_equal(msg_size7, expected_msg_size7);
    assert_arrays_equal(msg_size8, expected_msg_size8);
    assert_arrays_equal(msg_size9, expected_msg_size9);

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
}

/**
 * Test crypto functions.
 */
void test_crypto() {
    // TODO: test crypto functions
}

/**
 * Test server creation and serving.
 */
void test_server_serve() {
    // Create server
    TestServer<int, string> s(max_clients);
    assert(!s.is_serving());

    // Start server
    s.start();
    assert(s.is_serving());
    cppdtp::sleep(wait_time);

    // Check server address info
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;

    // Stop server
    s.stop();
    assert(!s.is_serving());
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
}

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
