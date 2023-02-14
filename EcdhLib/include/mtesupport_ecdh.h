/*******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) Eclypses, Inc.
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/
#ifndef MTESUPPORT_ECDH_H
#define MTESUPPORT_ECDH_H

#if defined(_WIN32)
  #ifdef ECDH_P256_BUILD_DLL
    #define EXPORT __declspec(dllexport)
  #else
    #define EXPORT __declspec(dllimport)
  #endif
#else
  #define EXPORT
#endif

#include <stddef.h>
#include <stdint.h>



/*************************************
 * Constants for key and secrets sizes
 *************************************/
#define SZ_ECDH_P256_PUBLIC_KEY  64
#define SZ_ECDH_P256_PRIVATE_KEY 32
#define SZ_ECDH_P256_SECRET_DATA 32



/*************************
 * Status code definitions
 *************************/
#define ECDH_P256_SUCCESS            0
#define ECDH_P256_RANDOM_FAIL       -1
#define ECDH_P256_INVALID_PUBKEY    -2
#define ECDH_P256_INVALID_PRIVKEY   -3
#define ECDH_P256_MEMORY_FAIL       -4
#define ECDH_P256_X509_FAIL         -5



#ifdef __cplusplus
extern "C" {
#endif



/********************************************************************************
 * A simple struct for managing a uint8_t* along with a size; used to lower
 * the number of parameters which have to be passed to functions. The "size"
 * member can be used to define the actual size of the byte array or the number
 * of bytes used in a byte array, depending on the context.
 ********************************************************************************/
typedef struct byte_array_ {
  size_t size;
  uint8_t *data;
} byte_array;



/********************************************************************************
 * The ecdh_get_entropy() callback function
 * 
 * Use of this function is mandatory if the operating system does not supply 
 * a crypographically random number generator. In the Windows, Linux and MacOS
 * environments the use of this function is optional, depending on the security
 * requirements of the application.
 * In order to provide 256 bits of security for the generation of an EC P256
 * Diffie-Hellman keypair, 256 bits of entropy must be provided.
 ********************************************************************************/
typedef int(*ecdh_p256_get_entropy)(void *context, byte_array entropy_input);



/********************************************************************************
 * Generate a Diffie-Hellman key pair
 *
 * [in] none, draws from mte_generate_random()
 * [out] private_key: on success, holds the private key, as a big-endian integer
 * [out] public_key: on success, holds the public key, as two big-endian integers
 *
 * return:  ECDH_SUCCESS on success
 *          ECDH_RANDOM_FAILED on failure
 ********************************************************************************/
extern EXPORT int ecdh_p256_create_keypair(byte_array private_key,
                                           byte_array public_key,
                                           ecdh_p256_get_entropy entropy_cb,
                                           void *entropy_context);



/****************************************************************************
 * Compute a Diffie-Hellman shared secret
 *
 * [in] private_key: our private key as a big-endian integer
 * [in] public_key: the peer's public key, as two big-endian integers
 * [out] secret: on success, holds the shared secret, as a big-endian integer
 *
 * return:  P256_SUCCESS on success
 *          P256_INVALID_PRIVKEY if priv is invalid
 *          P256_INVALID_PUBKEY if pub is invalid
 ****************************************************************************/
extern EXPORT int ecdh_p256_create_secret(const byte_array private_key,
                                          const byte_array peer_public_key,
                                          byte_array secret);



/****************************************************************************
 * Return the size of a public key as an ASN.1 object in a binary
 * DER sequence (ANSI X9.62) encoded to the X.509 standard.
 *
 * [in] algorithm: the Diffie-Hellman algorithm to be used (for key size)
 *
 * return:  On success, the size of the X.509 record in bytes
 *          ECDH_X509_FAIL if Diffie-Hellman algorithm is not supported
 ****************************************************************************/
extern EXPORT int ecdh_p256_get_x509_record_size(void);



/****************************************************************************
 * ECDH encode a public key as an ASN.1 object in a binary DER sequence
 * (ANSI X9.62) according to the X.509 standard.
 *
 * [in] algorithm: the Diffie-Hellman algorithm to be used (for key size)
 * [in] input: the public key in raw format
 * [out] output: on success, the public key in X.509 format
 *
 * return:  On success, a positive number, size of decoded key
 *          ECDH_X509_FAIL if input cannot be decoded
 ****************************************************************************/
extern EXPORT int ecdh_p256_encode_key_x509(const byte_array input,
                                            byte_array output);



/****************************************************************************
 * ECDH decode a public key from an ASN.1 object in a binary DER sequence
 * (ANSI X9.62) according to the X.509 standard.
 *
 * [in] algorithm: the Diffie-Hellman algorithm to be used (for key size)
 * [in] input: the X.509 formatted data containing a public key
 * [out] output: on success, the public key in raw format
 *
 * return:  On success, a positive number, size of decoded key
 *          ECDH_X509_FAIL if input cannot be decoded
 ****************************************************************************/
extern EXPORT int ecdh_p256_decode_key_x509(const byte_array input,
                                            byte_array output);



/****************************************************************************
 * Zeroize memory - use this function to zero out sensitive data.
 *
 * This function shall be implemented in a way so that its
 * functionality will not be optimized away (contrary to a
 * simple memset call which gets special treatment by the
 * compiler's code optimizer).
 ****************************************************************************/
extern EXPORT void ecdh_p256_zeroize(void *s, size_t n);



/****************************************************************************
 * Generate random numbers using the OS supplied RNG. If an OS supplied RNG
 * is not present, this function will fail.
 * 
 * [out] output: the buffer to be filled with random bytes
 * [out] output_size: size in bytes of the output buffer
 *
 * return:  ECDH_SUCCESS on success
 *          ECDH_RANDOM_FAIL if there was an error
 ****************************************************************************/
extern EXPORT int ecdh_p256_random(byte_array output);



#ifdef __cplusplus
}
#endif

#endif /* MTESUPPORT_ECDH_H */
