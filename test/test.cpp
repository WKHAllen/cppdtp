#include "../bin/include/cppdtp.hpp"

#include <iostream>

using namespace std;

int main() {
    cout << cppdtp::equal(13, 79) << cppdtp::equal(123, 123) << cppdtp::equal("baz", "baz") << cppdtp::equal("foo", "bar") << endl;

    return 0;
}
