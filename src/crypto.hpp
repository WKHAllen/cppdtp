/**
 * Crypto utilities.
 */

#pragma once
#ifndef CPPDTP_CRYPTO_HPP
#define CPPDTP_CRYPTO_HPP

#include <vector>
#include <utility>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "util.hpp"
#include "exceptions.hpp"

namespace cppdtp {

    /**
     * The RSA key size.
     */
    static const int _rsa_key_size = 2048;

    /**
     * The AES key size.
     */
    static const size_t _aes_key_size = 32;

    /**
     * The AES nonce size.
     */
    static const size_t _aes_nonce_size = 16;

    /**
     * Pad a section of bytes to ensure its size is never a multiple of 16 bytes.
     *
     * @param data The bytes to pad.
     * @return The padded bytes.
     */
    std::vector<char> _pad_data(const std::vector<char> &data) {
        std::vector<char> padded;

        if ((data.size() + 1) % 16 == 0) {
            padded.push_back((char) 1);
            padded.push_back((char) 255);
        } else {
            padded.push_back((char) 0);
        }

        padded.insert(padded.end(), data.begin(), data.end());

        return padded;
    }

    /**
     * Unpad a section of padded bytes.
     *
     * @param data The padded bytes.
     * @return The unpadded bytes.
     */
    std::vector<char> _unpad_data(const std::vector<char> &data) {
        std::vector<char> unpadded;

        if (data[0] == ((char) 1)) {
            unpadded.insert(unpadded.end(), data.begin() + 2, data.end());
        } else {
            unpadded.insert(unpadded.end(), data.begin() + 1, data.end());
        }

        return unpadded;
    }

    /**
     * Get an OpenSSL representation of a public key from the public key itself.
     *
     * @param public_key The public key.
     * @return The OpenSSL representation of the public key.
     */
    EVP_PKEY *_rsa_public_key_from_bytes(const std::vector<char> &public_key) {
        const char *pub_key = public_key.data();
        int pub_len = public_key.size();

        BIO *pbkeybio = NULL;

        if ((pbkeybio = BIO_new_mem_buf((const void *) pub_key, pub_len)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to create RSA public key BIO from buffer");
        }

        EVP_PKEY *pb_rsa = NULL;

        if ((pb_rsa = PEM_read_bio_PUBKEY(pbkeybio, &pb_rsa, NULL, NULL)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read BIO into RSA public key");
        }

        BIO_free(pbkeybio);

        return pb_rsa;
    }

    /**
     * Get an OpenSSL representation of a private key from the private key itself.
     *
     * @param private_key The private key.
     * @return The OpenSSL representation of the private key.
     */
    EVP_PKEY *_rsa_private_key_from_bytes(const std::vector<char> &private_key) {
        const char *pri_key = private_key.data();
        int pri_len = private_key.size();

        BIO *prkeybio = NULL;

        if ((prkeybio = BIO_new_mem_buf((const void *) pri_key, pri_len)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to create RSA private key BIO from buffer");
        }

        EVP_PKEY *p_rsa = NULL;

        if ((p_rsa = PEM_read_bio_PrivateKey(prkeybio, &p_rsa, NULL, NULL)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read BIO into RSA private key");
        }

        BIO_free(prkeybio);

        return p_rsa;
    }

    /**
     * Clean up the RSA public key after usage.
     *
     * @param public_key The RSA public key.
     */
    void _free_rsa_public_key(EVP_PKEY *public_key) {
        EVP_PKEY_free(public_key);
    }

    /**
     * Clean up the RSA private key after usage.
     *
     * @param private_key The RSA private key.
     */
    void _free_rsa_private_key(EVP_PKEY *private_key) {
        EVP_PKEY_free(private_key);
    }

    /**
     * Generate a pair of RSA keys.
     *
     * @return The generated key pair.
     */
    std::pair <std::vector<char>, std::vector<char>> _new_rsa_keys() {
        EVP_PKEY *r;

        if ((r = EVP_RSA_gen((unsigned int) _rsa_key_size)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to generate RSA key pair");
        }

        BIO *bp_public;
        BIO *bp_private;

        if ((bp_public = BIO_new(BIO_s_mem())) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create BIO for RSA public key");
        }

        if (PEM_write_bio_PUBKEY(bp_public, r) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to write RSA public key");
        }

        if ((bp_private = BIO_new(BIO_s_mem())) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create BIO for RSA private key");
        }

        if (PEM_write_bio_PrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to write RSA private key");
        }

        size_t pub_len = BIO_pending(bp_public);
        size_t pri_len = BIO_pending(bp_private);
        std::vector<char> public_key;
        public_key.resize(pub_len);
        std::vector<char> private_key;
        private_key.resize(pri_len);

        if (BIO_read(bp_public, public_key.data(), pub_len) < 1) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read RSA public key BIO");
        }

        if (BIO_read(bp_private, private_key.data(), pri_len) < 1) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read RSA private key BIO");
        }

        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        EVP_PKEY_free(r);

        return std::pair<std::vector<char>, std::vector<char>>(public_key, private_key);
    }

    /**
     * Encrypt data with RSA.
     *
     * @param public_key The RSA public key.
     * @param plaintext The data to encrypt.
     * @return The encrypted data.
     */
    std::vector<char> _rsa_encrypt(const std::vector<char> &public_key, const std::vector<char> &plaintext) {
        EVP_PKEY *evp_public_key = _rsa_public_key_from_bytes(public_key);
        std::vector<char> plaintext_padded = _pad_data(plaintext);
        std::vector<unsigned char> plaintext_unsigned(plaintext_padded.begin(), plaintext_padded.end());
        int plaintext_len = plaintext_unsigned.size();

        int encrypted_key_len;

        int nonce_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        std::vector<unsigned char> nonce;
        nonce.resize(nonce_len);

        if ((encrypted_key_len = EVP_PKEY_size(evp_public_key)) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to get RSA public key size");
        }

        std::vector<unsigned char> encrypted_key;
        encrypted_key.resize(encrypted_key_len);

        EVP_CIPHER_CTX *ctx;
        int ciphertext_len;
        int len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate RSA cipher context for encryption");
        }

        unsigned char *encrypted_key_buffer = encrypted_key.data();

        if (EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key_buffer, &encrypted_key_len, nonce.data(), &evp_public_key,
                         1) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to initialize RSA encryption cipher");
        }

        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        std::vector<unsigned char> ciphertext_unsigned;
        ciphertext_unsigned.resize(plaintext_len + block_size - 1);

        len = ciphertext_unsigned.size();

        if (EVP_SealUpdate(ctx, ciphertext_unsigned.data(), &len, plaintext_unsigned.data(), plaintext_len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to update RSA encryption cipher");
        }

        ciphertext_len = len;

        if (EVP_SealFinal(ctx, ciphertext_unsigned.data() + len, &len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to finalize RSA encryption cipher");
        }

        ciphertext_len += len;
        ciphertext_unsigned.resize(ciphertext_len);

        std::vector<unsigned char> all_unsigned;
        all_unsigned.reserve(CPPDTP_LENSIZE + encrypted_key_len + nonce_len + ciphertext_len);
        std::vector<char> encoded_encrypted_key_len = _encode_message_size((size_t) encrypted_key_len);
        all_unsigned.insert(all_unsigned.end(), encoded_encrypted_key_len.begin(), encoded_encrypted_key_len.end());
        all_unsigned.insert(all_unsigned.end(), encrypted_key.begin(), encrypted_key.end());
        all_unsigned.insert(all_unsigned.end(), nonce.begin(), nonce.end());
        all_unsigned.insert(all_unsigned.end(), ciphertext_unsigned.begin(), ciphertext_unsigned.end());
        std::vector<char> ciphertext(all_unsigned.begin(), all_unsigned.end());

        EVP_CIPHER_CTX_free(ctx);
        _free_rsa_public_key(evp_public_key);

        return ciphertext;
    }

    /**
     * Decrypt data with RSA.
     *
     * @param private_key The RSA private key.
     * @param ciphertext The data to decrypt.
     * @return The decrypted data.
     */
    std::vector<char> _rsa_decrypt(const std::vector<char> &private_key, const std::vector<char> &ciphertext) {
        EVP_PKEY *evp_private_key = _rsa_private_key_from_bytes(private_key);
        int nonce_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        std::vector<unsigned char> all_unsigned(ciphertext.begin(), ciphertext.end());
        std::vector<char> encoded_encrypted_key_len(all_unsigned.begin(), all_unsigned.begin() + CPPDTP_LENSIZE);
        int encrypted_key_len = (int) _decode_message_size(encoded_encrypted_key_len);
        std::vector<unsigned char> encrypted_key(all_unsigned.begin() + CPPDTP_LENSIZE,
                                                 all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len);
        std::vector<unsigned char> nonce(all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len,
                                      all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len + nonce_len);
        std::vector<unsigned char> ciphertext_unsigned(
                all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len + nonce_len, all_unsigned.end());
        int ciphertext_len = ciphertext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate RSA cipher context for decryption");
        }

        if (EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key.data(), encrypted_key_len, nonce.data(), evp_private_key) ==
            0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to initialize RSA decryption cipher");
        }

        std::vector<unsigned char> plaintext_unsigned;
        plaintext_unsigned.resize(ciphertext_len);

        if (EVP_OpenUpdate(ctx, plaintext_unsigned.data(), &len, ciphertext_unsigned.data(), ciphertext_len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to update RSA decryption cipher");
        }

        plaintext_len = len;

        if (EVP_OpenFinal(ctx, plaintext_unsigned.data() + len, &len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to finalize RSA decryption cipher");
        }

        plaintext_len += len;
        plaintext_unsigned.resize(plaintext_len);
        std::vector<char> plaintext_padded(plaintext_unsigned.begin(), plaintext_unsigned.end());
        std::vector<char> plaintext = _unpad_data(plaintext_padded);

        EVP_CIPHER_CTX_free(ctx);
        _free_rsa_private_key(evp_private_key);

        return plaintext;
    }

    /**
     * Generate a new AES key.
     *
     * @return The generated AES key.
     */
    std::vector<char> _new_aes_key() {
        std::vector<unsigned char> key_unsigned;
        key_unsigned.resize(_aes_key_size);

        if (RAND_bytes(key_unsigned.data(), _aes_key_size) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to get random bytes for AES key");
        }

        std::vector<char> key(key_unsigned.begin(), key_unsigned.end());

        return key;
    }

    /**
     * Encrypt data with AES.
     *
     * @param key The AES key.
     * @param plaintext The data to encrypt.
     * @return The encrypted data with the nonce prepended.
     */
    std::vector<char> _aes_encrypt(const std::vector<char> &key, const std::vector<char> &plaintext) {
        std::vector<unsigned char> key_unsigned(key.begin(), key.end());
        std::vector<unsigned char> nonce_unsigned;
        nonce_unsigned.resize(_aes_nonce_size);

        if (RAND_bytes(nonce_unsigned.data(), _aes_nonce_size) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to get random bytes for AES nonce");
        }

        std::vector<char> plaintext_padded = _pad_data(plaintext);
        std::vector<unsigned char> plaintext_unsigned(plaintext_padded.begin(), plaintext_padded.end());
        int plaintext_len = plaintext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate AES cipher context for encryption");
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_unsigned.data(), nonce_unsigned.data()) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to initialize AES encryption cipher");
        }

        int block_size = EVP_CIPHER_CTX_block_size(ctx);
        std::vector<unsigned char> ciphertext_unsigned;
        ciphertext_unsigned.resize(plaintext_len + block_size - 1);

        len = ciphertext_unsigned.size();

        if (EVP_EncryptUpdate(ctx, ciphertext_unsigned.data(), &len, plaintext_unsigned.data(), plaintext_len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to update AES encryption cipher");
        }

        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext_unsigned.data() + len, &len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to finalize AES encryption cipher");
        }

        ciphertext_len += len;
        ciphertext_unsigned.resize(ciphertext_len);
        std::vector<char> ciphertext_with_nonce(ciphertext_unsigned.begin(), ciphertext_unsigned.end());
        ciphertext_with_nonce.insert(ciphertext_with_nonce.begin(), nonce_unsigned.begin(), nonce_unsigned.end());

        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_with_nonce;
    }

    /**
     * Decrypt data with AES.
     *
     * @param key The AES key.
     * @param ciphertext_with_nonce The data to decrypt, containing the prepended nonce.
     * @return The decrypted data.
     */
    std::vector<char> _aes_decrypt(const std::vector<char> &key, const std::vector<char> &ciphertext_with_nonce) {
        std::vector<unsigned char> key_unsigned(key.begin(), key.end());
        std::vector<unsigned char> nonce_unsigned(ciphertext_with_nonce.begin(), ciphertext_with_nonce.begin() + _aes_nonce_size);
        std::vector<unsigned char> ciphertext_unsigned(ciphertext_with_nonce.begin() + _aes_nonce_size, ciphertext_with_nonce.end());
        int ciphertext_len = ciphertext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate AES cipher context for decryption");
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_unsigned.data(), nonce_unsigned.data()) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to initialize AES decryption cipher");
        }

        std::vector<unsigned char> plaintext_unsigned;
        plaintext_unsigned.resize(ciphertext_len);

        if (EVP_DecryptUpdate(ctx, plaintext_unsigned.data(), &len, ciphertext_unsigned.data(), ciphertext_len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to update AES decryption cipher");
        }

        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext_unsigned.data() + len, &len) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to finalize AES decryption cipher");
        }

        plaintext_len += len;
        plaintext_unsigned.resize(plaintext_len);
        std::vector<char> plaintext_padded(plaintext_unsigned.begin(), plaintext_unsigned.end());
        std::vector<char> plaintext = _unpad_data(plaintext_padded);

        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }

}

#endif // CPPDTP_CRYPTO_HPP
