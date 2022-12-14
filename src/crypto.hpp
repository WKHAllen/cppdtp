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
     * The AES IV size.
     */
    static const size_t _aes_iv_size = 16;

    /**
     * Get an OpenSSL representation of a public key from the public key itself.
     *
     * @param public_key The public key.
     * @return The OpenSSL representation of the public key.
     */
    EVP_PKEY *_rsa_public_key_from_bytes(std::vector<char> public_key) {
        char *pub_key = public_key.data();
        int pub_len = public_key.size();

        BIO *pbkeybio = NULL;

        if ((pbkeybio = BIO_new_mem_buf((void *) pub_key, pub_len)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to create RSA public key BIO from buffer");
        }

        RSA *pb_rsa = NULL;

        if ((pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read BIO into RSA public key");
        }

        EVP_PKEY *evp_pbkey;

        if ((evp_pbkey = EVP_PKEY_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create public key envelope");
        }

        if (EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to assign RSA public key");
        }

        BIO_free(pbkeybio);

        return evp_pbkey;
    }

    /**
     * Get an OpenSSL representation of a private key from the private key itself.
     *
     * @param private_key The private key.
     * @return The OpenSSL representation of the private key.
     */
    EVP_PKEY *_rsa_private_key_from_bytes(std::vector<char> private_key) {
        char *pri_key = private_key.data();
        int pri_len = private_key.size();

        BIO *prkeybio = NULL;

        if ((prkeybio = BIO_new_mem_buf((void *) pri_key, pri_len)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to create RSA private key BIO from buffer");
        }

        RSA *p_rsa = NULL;

        if ((p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL)) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read BIO into RSA private key");
        }

        EVP_PKEY *evp_prkey;

        if ((evp_prkey = EVP_PKEY_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create private key envelope");
        }

        if (EVP_PKEY_assign_RSA(evp_prkey, p_rsa) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to assign RSA private key");
        }

        BIO_free(prkeybio);

        return evp_prkey;
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
        BIGNUM *bne;

        if ((bne = BN_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed BN allocation");
        }

        if (BN_set_word(bne, RSA_F4) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to set BN word");
        }

        RSA *r;

        if ((r = RSA_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to allocate RSA structure");
        }

        if (RSA_generate_key_ex(r, _rsa_key_size, bne, NULL) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to generate RSA keys");
        }

        BIO *bp_public;
        BIO *bp_private;

        if ((bp_public = BIO_new(BIO_s_mem())) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create BIO for RSA public key");
        }

        if (PEM_write_bio_RSAPublicKey(bp_public, r) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to write RSA public key");
        }

        if ((bp_private = BIO_new(BIO_s_mem())) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to create BIO for RSA private key");
        }

        if (PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to write RSA private key");
        }

        size_t pri_len = BIO_pending(bp_private);
        size_t pub_len = BIO_pending(bp_public);
        char *pri_key = new char[pri_len + 1];
        char *pub_key = new char[pub_len + 1];

        if (BIO_read(bp_private, pri_key, pri_len) < 1) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read RSA private key BIO");
        }

        if (BIO_read(bp_public, pub_key, pub_len) < 1) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to read RSA public key BIO");
        }

        pri_key[pri_len] = '\0';
        pub_key[pub_len] = '\0';

        std::vector<char> public_key(pub_key, pub_key + pub_len + 1);
        std::vector<char> private_key(pri_key, pri_key + pri_len + 1);

        delete[] pri_key;
        delete[] pub_key;
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        BN_free(bne);
        RSA_free(r);

        return std::pair < std::vector < char > , std::vector < char > > (public_key, private_key);
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
        std::vector<unsigned char> plaintext_unsigned(plaintext.begin(), plaintext.end());
        int plaintext_len = plaintext.size();

        int encrypted_key_len;

        int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        std::vector<unsigned char> iv;
        iv.resize(iv_len);

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

        if (EVP_SealInit(ctx, EVP_aes_256_cbc(), &encrypted_key_buffer, &encrypted_key_len, iv.data(), &evp_public_key,
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
        all_unsigned.reserve(CPPDTP_LENSIZE + encrypted_key_len + iv_len + ciphertext_len);
        std::vector<char> encoded_encrypted_key_len = _encode_message_size((size_t) encrypted_key_len);
        all_unsigned.insert(all_unsigned.end(), encoded_encrypted_key_len.begin(), encoded_encrypted_key_len.end());
        all_unsigned.insert(all_unsigned.end(), encrypted_key.begin(), encrypted_key.end());
        all_unsigned.insert(all_unsigned.end(), iv.begin(), iv.end());
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
        int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        std::vector<unsigned char> all_unsigned(ciphertext.begin(), ciphertext.end());
        std::vector<char> encoded_encrypted_key_len(all_unsigned.begin(), all_unsigned.begin() + CPPDTP_LENSIZE);
        int encrypted_key_len = (int) _decode_message_size(encoded_encrypted_key_len);
        std::vector<unsigned char> encrypted_key(all_unsigned.begin() + CPPDTP_LENSIZE,
                                                 all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len);
        std::vector<unsigned char> iv(all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len,
                                      all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len + iv_len);
        std::vector<unsigned char> ciphertext_unsigned(
                all_unsigned.begin() + CPPDTP_LENSIZE + encrypted_key_len + iv_len, all_unsigned.end());
        int ciphertext_len = ciphertext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate RSA cipher context for decryption");
        }

        if (EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key.data(), encrypted_key_len, iv.data(), evp_private_key) ==
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
        std::vector<char> plaintext(plaintext_unsigned.begin(), plaintext_unsigned.end());

        EVP_CIPHER_CTX_free(ctx);
        _free_rsa_private_key(evp_private_key);

        return plaintext;
    }

    /**
     * Generate a new AES key and IV.
     *
     * @return The generated AES key and IV.
     */
    std::vector<char> _new_aes_key_iv() {
        int num_rounds = 5;
        std::vector<unsigned char> key_unsigned;
        key_unsigned.resize(_aes_key_size);
        std::vector<unsigned char> iv_unsigned;
        iv_unsigned.resize(_aes_iv_size);
        std::vector<unsigned char> key_data;
        key_data.resize(_aes_key_size);

        if (RAND_bytes(key_data.data(), _aes_key_size) == 0) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "failed to get random bytes for AES key");
        }

        if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data.data(), key_data.size(), num_rounds,
                           key_unsigned.data(), iv_unsigned.data()) != _aes_key_size) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(), "incorrect number of bytes in AES key");
        }

        std::vector<char> key_iv(key_unsigned.begin(), key_unsigned.end());
        key_iv.insert(key_iv.end(), iv_unsigned.begin(), iv_unsigned.end());

        return key_iv;
    }

    /**
     * Encrypt data with AES.
     *
     * @param key_iv The AES key and IV.
     * @param plaintext The data to encrypt.
     * @return The encrypted data.
     */
    std::vector<char> _aes_encrypt(const std::vector<char> &key_iv, const std::vector<char> &plaintext) {
        std::vector<unsigned char> key(key_iv.begin(), key_iv.begin() + _aes_key_size);
        std::vector<unsigned char> iv(key_iv.begin() + _aes_key_size, key_iv.end());
        std::vector<unsigned char> plaintext_unsigned(plaintext.begin(), plaintext.end());
        int plaintext_len = plaintext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate AES cipher context for encryption");
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) == 0) {
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
        std::vector<char> ciphertext(ciphertext_unsigned.begin(), ciphertext_unsigned.end());

        EVP_CIPHER_CTX_free(ctx);

        return ciphertext;
    }

    /**
     * Decrypt data with AES.
     *
     * @param key_iv The AES key and IV.
     * @param ciphertext The data to decrypt.
     * @return The decrypted data.
     */
    std::vector<char> _aes_decrypt(const std::vector<char> &key_iv, const std::vector<char> &ciphertext) {
        std::vector<unsigned char> key(key_iv.begin(), key_iv.begin() + _aes_key_size);
        std::vector<unsigned char> iv(key_iv.begin() + _aes_key_size, key_iv.end());
        std::vector<unsigned char> ciphertext_unsigned(ciphertext.begin(), ciphertext.end());
        int ciphertext_len = ciphertext_unsigned.size();

        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
            throw CPPDTPException(CPPDTP_OPENSSL_ERROR, ERR_get_error(),
                                  "failed to allocate AES cipher context for decryption");
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) == 0) {
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
        std::vector<char> plaintext(plaintext_unsigned.begin(), plaintext_unsigned.end());

        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }

}

#endif // CPPDTP_CRYPTO_HPP
