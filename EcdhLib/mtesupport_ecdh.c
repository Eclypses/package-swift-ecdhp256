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
#include <string.h>
#if defined(_WIN32)
  #include "platform.h"
  #include <bcrypt.h>
#elif defined(linux)

#endif

#include "mtesupport_ecdh.h"



/****************************************************************************
 * This data array contains 27 bytes of information as it appears in an ASN.1
 * object encoded in a DER sequence for a 64-byte public key. Since this
 * information is consistent across programming languages and there is no
 * published information on what to expect otherwise, we will simply us this
 * data as a header for encoding and as a reference for decoding.
 ****************************************************************************/
static const uint8_t asn1_der_header_p256[27] = {
  0x30,                      /* DER sequence ID                        */
  89,                        /* sequence length in bytes               */
  0x30,                      /* DER sequence ID                        */
  19,                        /* sequence length in bytes               */
  0x06,                      /* DER object ID                          */
  7,                         /* length in bytes of this ID             */
  0x2A, 0x86, 0x48, 0xCE,
  0x3D, 0x02, 0x01,          /* 7 bytes ID for "ecPublicKey"           */
  0x06,                      /* DER object ID                          */
  8,                         /* length in bytes of this ID             */
  0x2A, 0x86, 0x48, 0xCE,
  0x3D, 0x03, 0x01, 0x07,	   /* 8 bytes ID for "prime256v1"            */
  0x03,                      /* DER BitString ID                       */
  66,                        /* length of bitstring                    */
  0,                         /* 1st byte of bitstring which specifies
                                the number of unused least significant
                                bits in last byte                      */
  0x04                       /* key type, 0x04 means uncompressed,
                                which is a 64-byte x/y key pair        */
                             /* This header data is followed by the
                                64 bytes of raw binary key data.       */
};



/****************************************************************************
 * Return the size of a public key as an ASN.1 object in a binary
 * DER sequence (ANSI X9.62) encoded to the X.509 standard.
 *
 * return:  On success, the size of the X.509 record in bytes
 *          ECDH_X509_FAIL if Diffie-Hellman algorithm is not supported
 ****************************************************************************/
int ecdh_p256_get_x509_record_size() {
  return sizeof(asn1_der_header_p256) + SZ_ECDH_P256_PUBLIC_KEY;
}



/****************************************************************************
 * ECDH encode a public key as an ASN.1 object in a binary DER sequence
 * (ANSI X9.62) according to the X.509 standard.
 *
 * [in] input: the public key in raw format
 * [out] output: on success, the public key in X.509 format
 *
 * return:  On success, a positive number, size of decoded key
 *          ECDH_X509_FAIL if input cannot be decoded
 ****************************************************************************/
extern int ecdh_p256_encode_key_x509(const byte_array input, byte_array output) {
  if (input.size != SZ_ECDH_P256_PUBLIC_KEY)
    return ECDH_P256_X509_FAIL;
  if (output.size < (sizeof(asn1_der_header_p256) + SZ_ECDH_P256_PUBLIC_KEY))
    return ECDH_P256_MEMORY_FAIL;
  memcpy(output.data, asn1_der_header_p256, sizeof(asn1_der_header_p256));
  memcpy(output.data + sizeof(asn1_der_header_p256), input.data, SZ_ECDH_P256_PUBLIC_KEY);
  return sizeof(asn1_der_header_p256) + SZ_ECDH_P256_PUBLIC_KEY;
}



/****************************************************************************
 * ECDH decode a public key from an ASN.1 object in a binary DER sequence
 * (ANSI X9.62) according to the X.509 standard.
 *
 * [in] input: the X.509 formatted data containing a public key
 * [out] output: on success, the public key in raw format
 *
 * return:  On success, a positive number, size of decoded key
 *          ECDH_X509_FAIL if input cannot be decoded
 ****************************************************************************/
int ecdh_p256_decode_key_x509(const byte_array input, byte_array output) {
  if (input.size != (sizeof(asn1_der_header_p256) + SZ_ECDH_P256_PUBLIC_KEY))
    return ECDH_P256_X509_FAIL;
  if (output.size < SZ_ECDH_P256_PUBLIC_KEY)
    return ECDH_P256_X509_FAIL;
  if (memcmp(asn1_der_header_p256, input.data, sizeof(asn1_der_header_p256)) != 0)
    return ECDH_P256_X509_FAIL;
  memcpy(output.data, input.data + sizeof(asn1_der_header_p256), SZ_ECDH_P256_PUBLIC_KEY);
  return SZ_ECDH_P256_PUBLIC_KEY;
}



/****************************************************************
 * Zeroize memory - use this function to zero out sensitive data.
 *
 * This function shall be implemented in a way so that its
 * functionality will not be optimized away. the memset() call
 * gets special treatment by the code optimizer but if we wrap it
 * within a separate function like here, the code optimizer will
 * be unable to determine if skipping the memset will change the
 * program's function or not.
 *
 * For implementations where memset() is not available or must be
 * avoided at all costs, the classic C code is listed in comment.
 ****************************************************************/
void ecdh_p256_zeroize(void *s, size_t n) {
  /*------------------------------------------
   * Classic C implementation without memset()
   *------------------------------------------
  uint8_t volatile *p = s;
  while (n--) *p++ = 0;
  */
  memset(s, 0, n);
}



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
int ecdh_p256_random(byte_array output) {
#if defined(_WIN32)
  if (BCryptGenRandom(NULL, output.data, (ULONG)output.size,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    return ECDH_P256_RANDOM_FAIL;
  else
    return ECDH_P256_SUCCESS;
#elif defined(linux)
  return ECDH_P256_RANDOM_FAIL;
#else
  return ECDH_P256_RANDOM_FAIL;
#endif
}
