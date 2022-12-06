/**
 * Testing utilities.
 */

#include <iostream>
#include <stdlib.h>
#include <math.h>

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
 * Display a C-style array in the console.
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

    cout << " ]" << flush;
}

/**
 * Display a std::array in the console.
 *
 * @tparam T The type of item stored in the array.
 * @tparam N The size of the array.
 * @param arr The array.
 */
template<typename T, size_t N>
void display_array(array <T, N> arr) {
    cout << "[ ";

    for (size_t i = 0; i < N; i++) {
        cout << arr[i];

        if (i < N - 1) {
            cout << ", ";
        }
    }

    cout << " ]" << flush;
}

/**
 * Display a std::vector in the console.
 *
 * @tparam T The type of item stored in the vector.
 * @param arr The vector.
 */
template<typename T>
void display_array(vector <T> arr) {
    cout << "[ ";

    for (size_t i = 0; i < arr.size(); i++) {
        cout << arr[i];

        if (i < arr.size() - 1) {
            cout << ", ";
        }
    }

    cout << " ]" << flush;
}

/**
 * Display a string functioning as an array of characters.
 *
 * @param str The string.
 */
void display_arr_str(string str) {
    const char *cstr = str.c_str();
    const unsigned char *cstr_unsigned = reinterpret_cast<const unsigned char *>(cstr);

    cout << "[ ";

    for (size_t i = 0; i < str.length(); i++) {
        cout << (unsigned int) (cstr_unsigned[i]);

        if (i < str.length() - 1) {
            cout << ", ";
        }
    }

    cout << " ]" << flush;
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
 * Assert that two C-style arrays are equal.
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

/**
 * Assert that two std::arrays are equal.
 *
 * @tparam T The type of item stored in the arrays.
 * @tparam N The size of the arrays.
 * @param a The first array.
 * @param b The second array.
 */
template<typename T, size_t N>
void assert_arrays_equal(array <T, N> a, array <T, N> b) {
    for (size_t i = 0; i < N; i++) {
        if (a[i] != b[i]) {
            cout << "Arrays do not match:" << endl;
            cout << "  First:    ";
            display_array(a);
            cout << endl;
            cout << "  Second:   ";
            display_array(b);
            cout << endl;
            cout << "Mismatch at index " << i << endl;
            cout << "  " << a[i] << " != " << b[i] << endl;
            assert(a[i] == b[i]);
        }
    }
}

/**
 * Assert that two std::vectors are equal.
 *
 * @tparam T The type of item stored in the vectors.
 * @param a The first vector.
 * @param b The second vector.
 */
template<typename T>
void assert_arrays_equal(vector <T> a, vector <T> b) {
    if (a.size() != b.size()) {
        cout << "Vectors do not match:" << endl;
        cout << "  First:    ";
        display_array(a);
        cout << endl;
        cout << "  Second:   ";
        display_array(b);
        cout << endl;
        assert(a == b);
    }

    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] != b[i]) {
            cout << "Arrays do not match:" << endl;
            cout << "  First:    ";
            display_array(a);
            cout << endl;
            cout << "  Second:   ";
            display_array(b);
            cout << endl;
            cout << "Mismatch at index " << i << endl;
            cout << "  " << a[i] << " != " << b[i] << endl;
            assert(a[i] == b[i]);
        }
    }
}

/**
 * Assert that two strings representing character arrays are equal.
 *
 * @param a The first string.
 * @param b The second string.
 */
void assert_equal_arr_str(string a, string b) {
    const char *a_cstr = a.c_str();
    const unsigned char *a_cstr_unsigned = reinterpret_cast<const unsigned char *>(a_cstr);
    const char *b_cstr = b.c_str();
    const unsigned char *b_cstr_unsigned = reinterpret_cast<const unsigned char *>(b_cstr);

    if (a.length() != b.length()) {
        cout << "String character arrays do not match:" << endl;
        cout << "  First:    ";
        display_arr_str(a);
        cout << endl;
        cout << "  Second:   ";
        display_arr_str(b);
        cout << endl;
        assert(a == b);
    }

    for (size_t i = 0; i < a.length(); i++) {
        unsigned int a_i = (unsigned int) (a_cstr_unsigned[i]);
        unsigned int b_i = (unsigned int) (b_cstr_unsigned[i]);

        if (a_i != b_i) {
            cout << "String character arrays do not match:" << endl;
            cout << "  First:    ";
            display_arr_str(a);
            cout << endl;
            cout << "  Second:   ";
            display_arr_str(b);
            cout << endl;
            cout << "Mismatch at index " << i << endl;
            cout << "  " << a_i << " != " << b_i << endl;
            assert(a_i == b_i);
        }
    }
}

/**
 * Assert that two floating point values are equal.
 *
 * @param a The first float.
 * @param b The second float.
 */
template<typename T>
void assert_floats_equal(T a, T b) {
    assert(abs(a - b) < numeric_limits<T>::epsilon());
}
