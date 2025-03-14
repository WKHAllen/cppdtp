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
#include <array>
#include <vector>

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
    array<int, 8> test_array = { 0, 1, 1, 2, 3, 5, 8, 13 };
    vector<char> test_vector_char = { 'd', 't', 'p' };
    vector<string> test_vector_str = { "Hello", "from", "the serializer", ": )" };
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
    vector<string> test_vector_str_de;
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
    vector<char> expected_msg_size1 = { 0, 0, 0, 0, 0 };
    vector<char> expected_msg_size2 = { 0, 0, 0, 0, 1 };
    vector<char> expected_msg_size3 = { 0, 0, 0, 0, (char) 255 };
    vector<char> expected_msg_size4 = { 0, 0, 0, 1, 0 };
    vector<char> expected_msg_size5 = { 0, 0, 0, 1, 1 };
    vector<char> expected_msg_size6 = { 1, 1, 1, 1, 1 };
    vector<char> expected_msg_size7 = { 1, 2, 3, 4, 5 };
    vector<char> expected_msg_size8 = { 11, 7, 5, 3, 2 };
    vector<char> expected_msg_size9 = { (char) 255, (char) 255, (char) 255, (char) 255, (char) 255 };
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
    // Test RSA
    string rsa_message_str = "Hello, RSA!";
    vector<char> rsa_message(rsa_message_str.begin(), rsa_message_str.end());
    pair<vector<char>, vector<char>> keys = cppdtp::_new_rsa_keys();
    vector<char> public_key = keys.first;
    vector<char> private_key = keys.second;
    vector<char> rsa_encrypted = cppdtp::_rsa_encrypt(public_key, rsa_message);
    vector<char> rsa_decrypted = cppdtp::_rsa_decrypt(private_key, rsa_encrypted);
    assert(rsa_decrypted == rsa_message);
    assert(rsa_encrypted != rsa_message);

    // Test AES
    string aes_message_str = "Hello, AES!";
    vector<char> aes_message(aes_message_str.begin(), aes_message_str.end());
    vector<char> key = cppdtp::_new_aes_key();
    vector<char> aes_encrypted = cppdtp::_aes_encrypt(key, aes_message);
    vector<char> aes_decrypted = cppdtp::_aes_decrypt(key, aes_encrypted);
    assert(aes_decrypted == aes_message);
    assert(aes_encrypted != aes_message);

    // Test encrypting/decrypting AES key with RSA
    vector<char> encrypted_key = cppdtp::_rsa_encrypt(public_key, key);
    vector<char> decrypted_key = cppdtp::_rsa_decrypt(private_key, encrypted_key);
    assert(decrypted_key == key);
    assert(encrypted_key != key);
}

/**
 * Test server creation and serving.
 */
void test_server_serve() {
    // Create server
    TestServer<int, string> s(0, 0, 0);
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
void test_addresses() {
    // Create server
    TestServer<int, string> s(0, 1, 1);
    assert(!s.is_serving());
    s.start();
    assert(s.is_serving());
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<string, int> c(0, 0);
    assert(!c.is_connected());
    c.connect();
    assert(c.is_connected());
    string client_host = c.get_host();
    uint16_t client_port = c.get_port();
    cout << "Client address: " << client_host << ":" << client_port << endl;
    cppdtp::sleep(wait_time);

    // Check addresses
    cout << "Server (according to server): " << s.get_host() << ":" << s.get_port() << endl;
    cout << "Server (according to client): " << c.get_server_host() << ":" << c.get_server_port() << endl;
    cout << "Client (according to client): " << c.get_host() << ":" << c.get_port() << endl;
    cout << "Client (according to server): " << s.get_client_host(0) << ":" << s.get_client_port(0) << endl;
    assert(s.get_host() == "0.0.0.0");
    assert(c.get_server_host() == "127.0.0.1");
    assert(s.get_port() == c.get_server_port());
    assert(c.get_host() == s.get_client_host(0));
    assert(c.get_port() == s.get_client_port(0));

    // Disconnect client
    c.disconnect();
    assert(!c.is_connected());
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    assert(!s.is_serving());
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <string> s_received;
    vector <size_t> s_received_ids;
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert_arrays_equal(s.received, s_received);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    vector<int> c_received;
    assert_arrays_equal(c.received, c_received);
}

/**
 * Test sending messages between server and client.
 */
void test_send_receive() {
    // Create server
    TestServer<string, string> s(1, 1, 1);
    s.start();
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<string, string> c(1, 0);
    c.connect();
    cppdtp::sleep(wait_time);

    // Send messages
    string server_message = "Hello, server!";
    string client_message = "Hello, client #0!";
    c.send(server_message);
    s.send(0, client_message);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <string> s_received = { server_message };
    vector <size_t> s_received_ids = { 0 };
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert_arrays_equal(s.received, s_received);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    vector <string> c_received = { client_message };
    assert_arrays_equal(c.received, c_received);
}

/**
 * Test sending large random messages between server and client.
 */
void test_send_large_messages() {
    // Create server
    TestServer<vector<char>, vector<char>> s(1, 1, 1);
    s.start();
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<vector<char>, vector<char>> c(1, 0);
    c.connect();
    cppdtp::sleep(wait_time);

    // Send messages
    size_t large_server_message_len = rand_int(32768, 65536);
    vector<char> large_server_message = rand_bytes(large_server_message_len);
    size_t large_client_message_len = rand_int(16384, 32768);
    vector<char> large_client_message = rand_bytes(large_client_message_len);
    c.send(large_server_message);
    s.send(0, large_client_message);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <size_t> s_received_ids = { 0 };
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert(s.received.size() == 1);
    assert(s.received[0] == large_server_message);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    assert(c.received.size() == 1);
    assert(c.received[0] == large_client_message);

    // Log message sizes
    cout << "Server message sizes: " << s.received[0].size() << ", " << large_server_message_len << ", " << large_server_message.size() << endl;
    cout << "Client message sizes: " << c.received[0].size() << ", " << large_client_message_len << ", " << large_client_message.size() << endl;
}

/**
 * Test sending numerous random messages between server and client.
 */
void test_sending_numerous_messages() {
    // Messages
    size_t num_server_messages = rand_int(64, 128);
    vector<int> server_messages;
    server_messages.reserve(num_server_messages);
    for (size_t i = 0; i < num_server_messages; i++) server_messages.push_back(rand());
    size_t num_client_messages = rand_int(128, 256);
    vector<int> client_messages;
    client_messages.reserve(num_client_messages);
    for (size_t i = 0; i < num_client_messages; i++) client_messages.push_back(rand());

    // Create server
    TestServer<int, int> s(num_server_messages, 1, 1);
    s.start();
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<int, int> c(num_client_messages, 0);
    c.connect();
    cppdtp::sleep(wait_time);

    // Send messages
    for (size_t i = 0; i < num_server_messages; i++) {
        c.send(server_messages[i]);
        cppdtp::sleep(0.01);
    }
    for (size_t i = 0; i < num_client_messages; i++) {
        s.send_all(client_messages[i]);
        cppdtp::sleep(0.01);
    }
    cppdtp::sleep(5);

    // Disconnect client
    c.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert_arrays_equal(s.received, server_messages);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    assert_arrays_equal(c.received, client_messages);

    // Log number of messages
    cout << "Number of server messages: " << s.received.size() << ", " << num_server_messages << ", " << server_messages.size() << endl;
    cout << "Number of client messages: " << c.received.size() << ", " << num_client_messages << ", " << client_messages.size() << endl;
}

/**
 * Test sending and receiving custom types.
 */
void test_sending_custom_types() {
    // Create server
    TestServer<Custom, Custom> s(1, 1, 1);
    s.start();
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<Custom, Custom> c(1, 0);
    c.connect();
    cppdtp::sleep(wait_time);

    // Send messages
    Custom custom_server_message;
    custom_server_message.a = 234;
    custom_server_message.b = "Hello, custom class (server)!";
    custom_server_message.c.push_back("first server item");
    custom_server_message.c.push_back("second server item");
    Custom custom_client_message;
    custom_client_message.a = 345;
    custom_client_message.b = "Hello, custom class (client)!";
    custom_client_message.c.push_back("only client item");
    c.send(custom_server_message);
    s.send(0, custom_client_message);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <size_t> s_received_ids = { 0 };
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert(s.received.size() == 1);
    assert(s.received[0] == custom_server_message);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    assert(c.received.size() == 1);
    assert(c.received[0] == custom_client_message);

    // Log custom messages
    cout << "Server message (sent):     " << custom_server_message << endl;
    cout << "Server message (received): " << s.received[0] << endl;
    cout << "Client message (sent):     " << custom_client_message << endl;
    cout << "Client message (received): " << c.received[0] << endl;
}

/**
 * Test having multiple clients connected.
 */
void test_multiple_clients() {
    // Messages
    string message_from_client1 = "Hello from client #1!";
    string message_from_client2 = "Goodbye from client #2!";
    size_t message_from_server = 29275;

    // Create server
    TestServer<size_t, string> s(2, 2, 2);
    s.reply_with_string_length = true;
    s.start();
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client 1
    TestClient<string, size_t> c1(2, 0);
    c1.connect();
    cppdtp::sleep(wait_time);

    // Check client 1 address info
    cout << "Client #1 (according to client #1): " << c1.get_host() << ":" << c1.get_port() << endl;
    cout << "Client #1 (according to server):    " << s.get_client_host(0) << ":" << s.get_client_port(0) << endl;
    assert(c1.get_host() == s.get_client_host(0));
    assert(c1.get_port() == s.get_client_port(0));

    // Create client 2
    TestClient<string, size_t> c2(2, 0);
    c2.connect();
    cppdtp::sleep(wait_time);

    // Check client 2 address info
    cout << "Client #2 (according to client #2): " << c2.get_host() << ":" << c2.get_port() << endl;
    cout << "Client #2 (according to server):    " << s.get_client_host(1) << ":" << s.get_client_port(1) << endl;
    assert(c2.get_host() == s.get_client_host(1));
    assert(c2.get_port() == s.get_client_port(1));

    // Send message from client 1
    c1.send(message_from_client1);
    cppdtp::sleep(wait_time);

    // Send message from client 2
    c2.send(message_from_client2);
    cppdtp::sleep(wait_time);

    // Send message to all clients
    s.send_all(message_from_server);
    cppdtp::sleep(wait_time);

    // Disconnect client 1
    c1.disconnect();
    cppdtp::sleep(wait_time);

    // Disconnect client 2
    c2.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s.stop();
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <string> s_received = { message_from_client1, message_from_client2 };
    vector <size_t> s_received_ids = { 0, 1 };
    vector <size_t> s_connect_ids = { 0, 1 };
    vector <size_t> s_disconnect_ids = { 0, 1 };
    assert_arrays_equal(s.received, s_received);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c1.receive_count, 0);
    assert_equal(c1.disconnected_count, 0);
    assert(c1.events_done());
    vector <size_t> c1_received = { message_from_client1.length(), message_from_server };
    assert_arrays_equal(c1.received, c1_received);
    assert_equal(c2.receive_count, 0);
    assert_equal(c2.disconnected_count, 0);
    assert(c2.events_done());
    vector <size_t> c2_received = { message_from_client2.length(), message_from_server };
    assert_arrays_equal(c2.received, c2_received);
}

/**
 * Test clients disconnecting from the server.
 */
void test_client_disconnected() {
    // Create server
    TestServer<int, string> s(0, 1, 0);
    assert(!s.is_serving());
    s.start();
    assert(s.is_serving());
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<string, int> c(0, 1);
    assert(!c.is_connected());
    c.connect();
    assert(c.is_connected());
    cppdtp::sleep(wait_time);

    // Stop server
    assert(s.is_serving());
    assert(c.is_connected());
    s.stop();
    assert(!s.is_serving());
    cppdtp::sleep(wait_time);
    assert(!c.is_connected());

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <string> s_received = {};
    vector <size_t> s_received_ids = {};
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = {};
    assert_arrays_equal(s.received, s_received);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    vector <int> c_received = {};
    assert_arrays_equal(c.received, c_received);
}

/**
 * Test removing a client from the server.
 */
void test_remove_client() {
    // Create server
    TestServer<int, string> s(0, 1, 1);
    assert(!s.is_serving());
    s.start();
    assert(s.is_serving());
    string server_host = s.get_host();
    uint16_t server_port = s.get_port();
    cout << "Server address: " << server_host << ":" << server_port << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<string, int> c(0, 1);
    assert(!c.is_connected());
    c.connect();
    assert(c.is_connected());
    cppdtp::sleep(wait_time);

    // Disconnect the client
    assert(c.is_connected());
    s.remove_client(0);
    cppdtp::sleep(wait_time);
    assert(!c.is_connected());

    // Stop server
    assert(s.is_serving());
    s.stop();
    assert(!s.is_serving());
    cppdtp::sleep(wait_time);

    // Check event counts
    assert_equal(s.receive_count, 0);
    assert_equal(s.connect_count, 0);
    assert_equal(s.disconnect_count, 0);
    assert(s.events_done());
    vector <string> s_received = {};
    vector <size_t> s_received_ids = {};
    vector <size_t> s_connect_ids = { 0 };
    vector <size_t> s_disconnect_ids = { 0 };
    assert_arrays_equal(s.received, s_received);
    assert_arrays_equal(s.received_client_ids, s_received_ids);
    assert_arrays_equal(s.connect_client_ids, s_connect_ids);
    assert_arrays_equal(s.disconnect_client_ids, s_disconnect_ids);
    assert_equal(c.receive_count, 0);
    assert_equal(c.disconnected_count, 0);
    assert(c.events_done());
    vector <int> c_received = {};
    assert_arrays_equal(c.received, c_received);
}

/**
 * Test address defaults.
 */
void test_server_client_address_defaults() {
    // Create server
    TestServer<int, string> s1(0, 1, 1);
    s1.start();
    string server_host1 = s1.get_host();
    uint16_t server_port1 = s1.get_port();
    cout << "Server address: " << server_host1 << ":" << server_port1 << endl;
    cppdtp::sleep(wait_time);

    // Create client
    TestClient<string, int> c1(0, 0);
    c1.connect();
    cppdtp::sleep(wait_time);

    // Disconnect client
    c1.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s1.stop();
    cppdtp::sleep(wait_time);

    // Create server with host
    TestServer<int, string> s2(0, 1, 1);
    s2.start("127.0.0.1");
    string server_host2 = s2.get_host();
    uint16_t server_port2 = s2.get_port();
    cout << "Server address: " << server_host2 << ":" << server_port2 << endl;
    cppdtp::sleep(wait_time);

    // Create client with host
    TestClient<string, int> c2(0, 0);
    c2.connect(server_host2);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c2.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s2.stop();
    cppdtp::sleep(wait_time);

    // Create server with port
    TestServer<int, string> s3(0, 1, 1);
    s3.start(35792);
    string server_host3 = s3.get_host();
    uint16_t server_port3 = s3.get_port();
    cout << "Server address: " << server_host3 << ":" << server_port3 << endl;
    cppdtp::sleep(wait_time);

    // Create client with port
    TestClient<string, int> c3(0, 0);
    c3.connect(server_port3);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c3.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s3.stop();
    cppdtp::sleep(wait_time);

    // Create server with host and port
    TestServer<int, string> s4(0, 1, 1);
    s4.start("127.0.0.1", 35792);
    string server_host4 = s4.get_host();
    uint16_t server_port4 = s4.get_port();
    cout << "Server address: " << server_host4 << ":" << server_port4 << endl;
    cppdtp::sleep(wait_time);

    // Create client with host and port
    TestClient<string, int> c4(0, 0);
    c4.connect(server_host4, server_port4);
    cppdtp::sleep(wait_time);

    // Disconnect client
    c4.disconnect();
    cppdtp::sleep(wait_time);

    // Stop server
    s4.stop();
    cppdtp::sleep(wait_time);
}

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
    cout << endl << "Testing sending custom types..." << endl;
    test_sending_custom_types();
    cout << endl << "Testing with multiple clients..." << endl;
    test_multiple_clients();
    cout << endl << "Testing disconnecting clients..." << endl;
    test_client_disconnected();
    cout << endl << "Testing removing clients..." << endl;
    test_remove_client();
    cout << endl << "Testing address defaults..." << endl;
    test_server_client_address_defaults();

    // Done
    cout << endl << "Completed tests" << endl;
}
