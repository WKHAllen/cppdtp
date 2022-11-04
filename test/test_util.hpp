/**
 * Testing utilities.
 */

#include <iostream>
#include <stdlib.h>

using namespace std;

/**
 * Generate a random number.
 *
 * @param min The random range minimum.
 * @param max The random range maximum.
 * @return The randomly generated number.
 */
int rand_int(int min, int max) {
    return min + (rand() % (max - min + 1));
}

/**
 * Generate a random number.
 *
 * @param max The random range maximum.
 * @return The randomly generated number.
 */
int rand_int(int max) {
    return rand_int(0, max);
}

/**
 * Generate a random number.
 *
 * @return The randomly generated number.
 */
int rand_int() {
    return rand();
}

/**
 * Generate a set of random bytes.
 *
 * @param size The number of bytes to generate.
 * @return The randomly generated series of bytes.
 */
char *rand_bytes(size_t size) {
    char *bytes = new char[size];

    for (size_t i = 0; i < size; i++) {
        bytes[i] = (char) rand_int(255);
    }

    return bytes;
}

/**
 * Display an array in the console.
 *
 * @tparam T The type of item stored in the array.
 * @param arr The array.
 * @param size The size of the array.
 */
template<typename T>
void display_array(T arr[], size_t size) {
    cout << "[ ";

    for (size_t i = 0; i < size; i++) {
        cout << arr[i];

        if (i < size - 1) {
            cout << ", ";
        }
    }

    cout << " ]";
}

/**
 * Assert that two values are equal.
 *
 * @tparam T The type of value being checked.
 * @param a The first value.
 * @param b The second value.
 */
template<typename T>
void assert_equal(T a, T b) {
    if (a != b) {
        cout << "Equality check failed:" << endl;
        cout << "  " << a << " != " << b << endl;
        assert(a == b);
    }
}

/**
 * Assert that two values are not equal.
 *
 * @tparam T The type of value being checked.
 * @param a The first value.
 * @param b The second value.
 */
template<typename T>
void assert_not_equal(T a, T b) {
    if (a == b) {
        cout << "Inequality check failed:" << endl;
        cout << "  " << a << " == " << b << endl;
        assert(a != b);
    }
}

/**
 * Assert that two arrays are equal.
 *
 * @tparam T The type of item stored in the arrays.
 * @param a The first array.
 * @param b The second array.
 * @param size The size of the arrays.
 */
template<typename T>
void assert_arrays_equal(T a[], T b[], size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            cout << "Arrays do not match:" << endl;
            cout << "  First:    ";
            display_array(a, size);
            cout << endl;
            cout << "  Second:   ";
            display_array(b, size);
            cout << endl;
            cout << "Mismatch at index " << i << endl;
            cout << "  " << a[i] << " != " << b[i] << endl;
            assert(a[i] == b[i]);
        }
    }
}
