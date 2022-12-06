/**
 * Exceptions thrown from cppdtp.
 */

#pragma once
#ifndef CPPDTP_EXCEPTIONS_HPP
#define CPPDTP_EXCEPTIONS_HPP

#include <exception>
#include <string>

#ifdef _WIN32
#  include <WinSock2.h>
#else

#  include <errno.h>

#endif

namespace cppdtp {

    // Exceptions caused within cppdtp.
    class CPPDTPException : public std::exception {
    private:
        // The exception code.
        int code;

        // The underlying exception code.
        int underlying_code;

        // The exception message.
        std::string message;

        // The exception info message.
        std::string info_message;

    public:
        /**
         * Instantiate an exception.
         *
         * code_:            The exception code.
         * underlying_code_: The underlying exception code.
         * message_:         The exception message.
         *
         * Returns: An exception instance.
         */
        CPPDTPException(int code_, int underlying_code_, std::string message_) {
            code = code_;
            underlying_code = underlying_code_;
            message = message_;
            info_message = message + " (error code: " + std::to_string(code) + ", underlying error code: " +
                           std::to_string(underlying_code) + ")";
        }

        /**
         * Instantiate an exception, getting the underlying error code from the socket library.
         */
        CPPDTPException(int code_, std::string message_) {
            code = code_;
#ifdef _WIN32
            underlying_code = WSAGetLastError();
#else
            underlying_code = errno;
#endif
            message = message_;
            info_message = message + " (error code: " + std::to_string(code) + ", underlying error code: " +
                           std::to_string(underlying_code) + ")";
        }

        /**
         * Get the error code of the exception.
         *
         * Returns: The exception code.
         */
        int error_code() {
            return code;
        }

        /**
         * Get the underlying error code of the exception.
         *
         * Returns: The underlying exception code.
         */
        int underlying_error_code() {
            return underlying_code;
        }

        /**
         * Get the error message of the exception.
         *
         * Returns: The exception message.
         */
        const char *what() const throw() {
            return info_message.c_str();
        }
    }; // class CPPDTPException

} // namespace cppdtp

#endif // CPPDTP_EXCEPTIONS_HPP
