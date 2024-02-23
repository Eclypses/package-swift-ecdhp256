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
#include "platform.h"

#include <string.h>
#if defined(_WIN32)
#  include <bcrypt.h>
#elif defined(linux)
#  include "stdio.h"
#endif

#include "mtesupport_ecdh.h"



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
  FILE *rng = fopen("/dev/urandom", "rb");
  size_t result = fread(output.data, output.size, 1, rng);
  fclose(rng);
  return (result == 1) ? ECDH_P256_SUCCESS : ECDH_P256_RANDOM_FAIL;
#else
  return ECDH_P256_RANDOM_FAIL;
#endif
}
