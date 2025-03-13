# Data Transfer Protocol for C++

Modern cross-platform networking interfaces for C++.

## Data Transfer Protocol

The Data Transfer Protocol (DTP) is a larger project to make ergonomic network programming available in any language.
See the full project [here](https://wkhallen.com/dtp/).

## Creating a server

A server can be built using the `Server` implementation:

```c++
#include "cppdtp.hpp"
#include <iostream>

using namespace std;

// Create a server that receives strings and returns the length of each string
class MyServer : cppdtp::Server<int, string> {
private:
    void receive(size_t client_id, string data) override {
        // Send back the length of the string
        send(client_id, data.length());
    }

    void connect(size_t client_id) override {
        cout << "Client with ID " << client_id << " connected" << endl;
    }

    void disconnect(size_t client_id) override {
        cout << "Client with ID " << client_id << " disconnected" << endl;
    }

public:
    MyServer() : cppdtp::Server<int, string>() {}
};

int main() {
    // Start the server
    MyServer server;
    server.start("127.0.0.1", 29275);

    return 0;
}
```

## Creating a client

A client can be built using the `Client` implementation:

```c++
#include "cppdtp.hpp"
#include <iostream>
#include <assert.h>

using namespace std;

// Create a client that sends a message to the server and receives the length of the message
class MyClient : cppdtp::Client<string, int> {
private:
    string message;

    void receive(int data) override {
        // Validate the response
        cout << "Received response from server: " << data << endl;
        assert(data == message.length());
    }

    void disconnected() override {
        cout << "Unexpectedly disconnected from server" << endl;
    }

public:
    MyClient(string message_) : cppdtp::Client<string, int>(), message(message_) {}
};

int main() {
    // Connect to the server
    string message = "Hello, server!";
    MyClient client(message);
    client.connect("127.0.0.1", 29275);

    // Send a message to the server
    client.send(message);

    return 0;
}
```

## Serialization

The protocol is able to serialize and deserialize most types with ease. Custom types can be used, though for
deserialization purposes, they must be default constructible. For custom types that
are [POD types](https://stackoverflow.com/questions/146452/what-are-pod-types-in-c), the default
serialization/deserialization implementations should be sufficient. For custom types that contain pointers, contain
dynamically sized members, or are in some other way not POD types, it will be necessary to provide a
serialization/deserialization implementation for them. To do this, write an implementation for streaming the type
to `cppdtp::mem_ostream` and from `cppdtp::mem_istream`. Below is an example, which is already implemented for you
in [`src/util.hpp`](src/util.hpp):

```c++
template<typename T>
cppdtp::mem_ostream &operator<<(cppdtp::mem_ostream &out, const std::vector <T> &vec) {
    static_assert(std::is_default_constructible<T>::value, "T must be default constructible");

    // Serialize a std::vector<T>

    size_t size = vec.size();
    out << size;

    for (size_t i = 0; i < vec.size(); i++) {
        out << vec[i];
    }

    return out;
}

template<typename T>
cppdtp::mem_istream &operator>>(cppdtp::mem_istream &in, std::vector <T> &vec) {
    static_assert(std::is_default_constructible<T>::value, "T must be default constructible");

    // Deserialize a std::vector<T>

    size_t size = 0;
    in >> size;

    for (size_t i = 0; i < size; i++) {
        T val;  // This is why `T` must be default constructible
        in >> val;
        vec.push_back(val);
    }

    return in;
}
```

For more information on the serialization/deserialization implementation details,
see [github.com/shaovoon/simplebinstream](https://github.com/shaovoon/simplebinstream).

## Compilation

The protocol has a few dependencies that must be included when compiling:

### Compiling on Windows

- Link Winsock (`-lWs2_32`)
- Link OpenSSL 3.0

### Compiling on other platforms

- Link pthread (`-lpthread`)
- Link OpenSSL 3.0

For more information on the compilation process, see the [Makefile](Makefile).

## Security

Information security comes included. Every message sent over a network interface is encrypted with AES-256. Key
exchanges are performed using a 2048-bit RSA key-pair.
