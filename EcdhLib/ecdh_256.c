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
 *
 * CREDITS:
 * ========
 * The "dh-p256" package is heavily based on Manuel Pégourié-Gonnard's "p256-m"
 * project which has been published under the Apache-2.0 license. The original
 * project can be found here:
 *
 * https://github.com/mpg/p256-m
 *******************************************************************************/
#include "platform.h"

#include <string.h>

#include "mtesupport_ecdh.h"



/*****************************************************************************
 * Helpers to test constant-time behaviour with valgrind or MemSan.
 *
 * CT_POISON() is used for secret data. It marks the memory area as
 * uninitialised, so that any branch or pointer dereference that depends on it
 * (even indirectly) triggers a warning.
 * CT_UNPOISON() is used for public data; it marks the area as initialised.
 *
 * These are macros in order to avoid interfering with origin tracking.
 *****************************************************************************/
#if defined(CT_MEMSAN)

#include <sanitizer/msan_interface.h>
#define CT_POISON   __msan_allocated_memory
// void __msan_allocated_memory(const volatile void* data, size_t size);
#define CT_UNPOISON __msan_unpoison
// void __msan_unpoison(const volatile void *a, size_t size);

#elif defined(CT_VALGRIND)

#include <valgrind/memcheck.h>
#define CT_POISON   VALGRIND_MAKE_MEM_UNDEFINED
// VALGRIND_MAKE_MEM_UNDEFINED(_qzz_addr,_qzz_len)
#define CT_UNPOISON VALGRIND_MAKE_MEM_DEFINED
// VALGRIND_MAKE_MEM_DEFINED(_qzz_addr,_qzz_len)

#else

#define CT_POISON(p, sz)
#define CT_UNPOISON(p, sz)

#endif



/**********************************************************************
 *
 * Operations on fixed-width unsigned integers
 *
 * Represented using 32-bit limbs, least significant limb first.
 * That is: x = x[0] + 2^32 x[1] + ... + 2^224 x[7] for 256-bit.
 *
 **********************************************************************/



/*****************************
 * 256-bit set to 32-bit value
 *
 * in: x in [0, 2^32)
 * out: z = x
 *****************************/
static void u256_set32(uint32_t z[8], uint32_t x) {
  z[0] = x;
  ecdh_p256_zeroize(z + 1, (size_t)(8 - 1) * sizeof(uint32_t));
}



/***************************************************************************
 * 256-bit addition
 *
 * in: x, y in [0, 2^256)
 * out: z = (x + y) mod 2^256
 *      c = (x + y) div 2^256
 * That is, z + c * 2^256 = x + y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static uint32_t u256_add(uint32_t z[8],
                         const uint32_t x[8], const uint32_t y[8]) {
  uint32_t carry = 0;

  for (unsigned i = 0; i < 8; i++) {
    uint64_t sum = (uint64_t) carry + x[i] + y[i];
    z[i] = (uint32_t) sum;
    carry = (uint32_t) (sum >> 32);
  }
  return carry;
}



/***************************************************************************
 * 256-bit subtraction
 *
 * in: x, y in [0, 2^256)
 * out: z = (x - y) mod 2^256
 *      c = 0 if x >=y, 1 otherwise
 * That is, z = c * 2^256 + x - y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static uint32_t u256_sub(uint32_t z[8],
                         const uint32_t x[8], const uint32_t y[8]) {
  uint32_t carry = 0;
  uint64_t diff;

  for (unsigned i = 0; i < 8; i++) {
    diff = (uint64_t)x[i] - y[i] - carry;
    z[i] = (uint32_t)diff;
    carry = ~((uint32_t)(diff >> 32)) + 1;
  }
  return carry;
}



/**********************************************************************
 * 256-bit conditional assignment
 *
 * in: x in [0, 2^256)
 *     c in [0, 1]
 * out: z = x if c == 1, z unchanged otherwise
 *
 * Note: as a memory area, z must be either equal to x, or not overlap.
 **********************************************************************/
static void u256_cmov(uint32_t z[8], const uint32_t x[8], uint32_t c) {
  const uint32_t x_mask = ~c + 1;
  for (unsigned i = 0; i < 8; i++)
    z[i] = (z[i] & ~x_mask) | (x[i] & x_mask);
}



/**************************************************
 * 256-bit compare for equality
 *
 * in: x in [0, 2^256)
 *     y in [0, 2^256)
 * out: 0 if x == y, unspecified non-zero otherwise
 **************************************************/
static uint32_t u256_diff(const uint32_t x[8], const uint32_t y[8]) {
  uint32_t diff = 0;
  for (unsigned i = 0; i < 8; i++)
    diff |= x[i] ^ y[i];
  return diff;
}



/****************************************************************************
 * 32 x 32 -> 64-bit multiply-and-accumulate
 *
 * in: x, y, z, t in [0, 2^32)
 * out: x * y + z + t in [0, 2^64)
 *
 * Note: this computation cannot overflow.
 *
 * Note: this function has two pure-C implementations (depending on whether
 * MUL64_IS_CONSTANT_TIME).
 ****************************************************************************/
static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t);



#if defined(MUL64_IS_CONSTANT_TIME)

static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t) {
  return (uint64_t) x * y + z + t;
}

#else

static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t) {
  /* x = xl + 2**16 xh, y = yl + 2**16 yh */
  const uint16_t xl = (uint16_t) x;
  const uint16_t yl = (uint16_t) y;
  const uint16_t xh = x >> 16;
  const uint16_t yh = y >> 16;

  /* x*y = xl*yl + 2**16 (xh*yl + yl*yh) + 2**32 xh*yh
   *     = lo    + 2**16 (m1    + m2   ) + 2**32 hi    */
  const uint32_t lo = (uint32_t) xl * yl;
  const uint32_t m1 = (uint32_t) xh * yl;
  const uint32_t m2 = (uint32_t) xl * yh;
  const uint32_t hi = (uint32_t) xh * yh;

  #ifdef _MSC_VER
  /* It is OK that we'll lose bits when we shift m1 and m2.
   * Unfortunately Visual C keeps complaining about it.
   * We turn off the warnings using #pragmas. */
#pragma warning(push)
  #pragma warning(disable: 6297)
  #pragma warning(disable: 26451)
#endif
  uint64_t acc = lo + ((uint64_t)(hi + (m1 >> 16) + (m2 >> 16)) << 32);
  acc += m1 << 16;
  acc += m2 << 16;
#ifdef _MSC_VER
  #pragma warning(pop)
#endif
  acc += z;
  acc += t;

  return acc;
}

#endif /* MUL64_IS_CONSTANT_TIME */



/**********************************************************************
 * 288 + 32 x 256 -> 288-bit multiply and add
 *
 * in: x in [0, 2^32)
 *     y in [0, 2^256)
 *     z in [0, 2^288)
 * out: z_out = z_in + x * y mod 2^288
 *      c     = z_in + x * y div 2^288
 * That is, z_out + c * 2^288 = z_in + x * y
 *
 * Note: as a memory area, z must be either equal to y, or not overlap.
 *
 * This is a helper for Montgomery multiplication.
 **********************************************************************/
static uint32_t u288_muladd(uint32_t z[9], uint32_t x, const uint32_t y[8]) {
  uint32_t carry = 0;

#define U288_MULADD_STEP(i)                                   \
        do {                                                  \
          uint64_t prod = u32_muladd64(x, y[i], z[i], carry); \
          z[i] = (uint32_t) prod;                             \
          carry = (uint32_t) (prod >> 32);                    \
        } while (0)

  for (unsigned i = 0; i < 8; i++)
    U288_MULADD_STEP(i);

  uint64_t sum = (uint64_t) z[8] + carry;
  z[8] = (uint32_t) sum;
  carry = (uint32_t) (sum >> 32);
  return carry;
}



/*************************************************
 * 288-bit in-place right shift by 32 bits
 *
 * in: z in [0, 2^288)
 *     c in [0, 2^32)
 * out: z_out = z_in div 2^32 + c * 2^256
 *            = (z_in + c * 2^288) div 2^32
 *
 * This is a helper for Montgomery multiplication.
 *************************************************/
static void u288_rshift32(uint32_t z[9], uint32_t c) {
  for (unsigned i = 0; i < 8; i++)
    z[i] = z[i + 1];
  z[8] = c;
}



/**********************************************************
 * 256-bit import from big-endian bytes
 *
 * in: p = p0, ..., p31
 * out: z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 **********************************************************/
static void u256_from_bytes(uint32_t z[8], const uint8_t p[32]) {
  unsigned i, j;

  for (i = 0; i < 8; i++) {
    j = 4 * (7 - i);
    z[i] = ((uint32_t) p[j + 0] << 24) |
           ((uint32_t) p[j + 1] << 16) |
           ((uint32_t) p[j + 2] <<  8) |
           ((uint32_t) p[j + 3] <<  0);
  }
}



/**********************************************************
 * 256-bit export to big-endian bytes
 *
 * in: z in [0, 2^256)
 * out: p = p0, ..., p31 such that
 *      z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 **********************************************************/
static void u256_to_bytes(uint8_t p[32], const uint32_t z[8]) {
  unsigned i, j;

  for (i = 0; i < 8; i++) {
    j = 4 * (7 - i);
    p[j + 0] = (uint8_t) (z[i] >> 24);
    p[j + 1] = (uint8_t) (z[i] >> 16);
    p[j + 2] = (uint8_t) (z[i] >>  8);
    p[j + 3] = (uint8_t) (z[i] >>  0);
  }
}



/**********************************************************************
 *
 * Operations modulo a 256-bit prime m
 *
 * These are done in the Montgomery domain, that is x is represented by
 *  x * 2^256 mod m
 * Numbers need to be converted to that domain before computations,
 * and back from it afterwards.
 *
 * Inversion is computed using Fermat's little theorem.
 *
 * Assumptions on m:
 * - Montgomery operations require that m is odd.
 * - Fermat's little theorem require it to be a prime.
 * - m256_inv() further requires that m % 2^32 >= 2.
 * - m256_inv() also assumes that the value of m is not a secret.
 *
 * In practice operations are done modulo the curve's p and n,
 * both of which satisfy those assumptions.
 *
 **********************************************************************/



/*********************************************************
 * Data associated to a modulus for Montgomery operations.
 *
 * m in [0, 2^256) - the modulus itself, must be odd
 * R2 = 2^512 mod m
 * ni = -m^-1 mod 2^32
 *********************************************************/
typedef struct {
  uint32_t m[8];
  uint32_t R2[8];
  uint32_t ni;
} m256_mod;



/*****************************************************
 * Data for Montgomery operations modulo the curve's p
 *****************************************************/
static const m256_mod p256_p = {
  { /* the curve's p */
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
  },
  { /* 2^512 mod p */
    0x00000003, 0x00000000, 0xffffffff, 0xfffffffb,
    0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004,
  },
  0x00000001, /* -p^-1 mod 2^32 */
};



/*****************************************************
 * Data for Montgomery operations modulo the curve's n
 *****************************************************/
static const m256_mod p256_n = {
  { /* the curve's n */
    0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
  },
  { /* 2^512 mod n */
    0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c,
    0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94,
  },
  0xee00bc4f, /* -n^-1 mod 2^32 */
};



/***************************************************************************
 * Modular addition
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x + y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static void m256_add(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const m256_mod *mod) {
  uint32_t r[8];
  uint32_t carry_add = u256_add(z, x, y);
  uint32_t carry_sub = u256_sub(r, z, mod->m);
  /*------------------------------------------------
   * Need to subract m if:
   *   x + y >= 2^256 > m (that is, carry_add == 1)
   *   OR z >= m (that is, carry_sub == 0)
   *----------------------------------------------*/
  uint32_t use_sub = carry_add | (1 - carry_sub);
  u256_cmov(z, r, use_sub);
}



/***************************************************************************
 * Modular addition mod p
 *
 * in: x, y in [0, p)
 * out: z = (x + y) mod p, in [0, p)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static void m256_add_p(uint32_t z[8],
                       const uint32_t x[8], const uint32_t y[8]) {
  m256_add(z, x, y, &p256_p);
}



/***************************************************************************
 * Modular subtraction
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x - y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static void m256_sub(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const m256_mod *mod) {
  uint32_t r[8];
  uint32_t carry = u256_sub(z, x, y);
  u256_add(r, z, mod->m);
  /*--------------------------------------------------------
   * Need to add m if and only if x < y, that is carry == 1.
   * In that case z is in [2^256 - m + 1, 2^256 - 1], so the
   *------------------------------------------------------*/
  u256_cmov(z, r, carry);
}



/***************************************************************************
 * Modular subtraction mod p
 *
 * in: x, y in [0, p)
 * out: z = (x + y) mod p, in [0, p)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 ***************************************************************************/
static void m256_sub_p(uint32_t z[8],
                       const uint32_t x[8], const uint32_t y[8]) {
  m256_sub(z, x, y, &p256_p);
}



/****************************************************
 * Montgomery modular multiplication
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x * y) / 2^256 mod m, in [0, m)
 *
 * Note: as a memory area, z may overlap with x or y.
 ****************************************************/
static void m256_mul(uint32_t z[8],
                     const uint32_t x[8], const uint32_t y[8],
                     const m256_mod *mod) {
  /*----------------------------------------------------------
   * Algorithm 14.36 in Handbook of Applied Cryptography with:
   * b = 2^32, n = 8, R = 2^256
   *--------------------------------------------------------*/
  uint32_t m_prime = mod->ni;
  uint32_t a[9];

  ecdh_p256_zeroize(a, sizeof(a));
  for (unsigned i = 0; i < 8; i++) {
    /* the "mod 2^32" is implicit from the type */
    uint32_t u = (a[0] + x[i] * y[0]) * m_prime;
    /* a = (a + x[i] * y + u * m) div b */
    uint32_t c = u288_muladd(a, x[i], y);
    c += u288_muladd(a, u, mod->m);
    u288_rshift32(a, c);
  }

  /* a = a > m ? a - m : a */
  uint32_t carry_add = a[8];  /* 0 or 1 since a < 2m, see HAC Note 14.37 */
  uint32_t carry_sub = u256_sub(z, a, mod->m);
  uint32_t use_sub = carry_add | (1 - carry_sub);  /* see m256_add() */
  u256_cmov(z, a, 1 - use_sub);
}



/****************************************************
 * Montgomery modular multiplication modulo p.
 *
 * in: x, y in [0, p)
 * out: z = (x * y) / 2^256 mod p, in [0, p)
 *
 * Note: as a memory area, z may overlap with x or y.
 ****************************************************/
static void m256_mul_p(uint32_t z[8],
                       const uint32_t x[8], const uint32_t y[8]) {
  m256_mul(z, x, y, &p256_p);
}



/**************************************************
 * In-place conversion to Montgomery form
 *
 * in: z in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z_out = z_in * 2^256 mod m, in [0, m)
 **************************************************/
static void m256_prep(uint32_t z[8], const m256_mod *mod) {
  m256_mul(z, z, mod->R2, mod);
}



/******************************************************************
 * In-place conversion from Montgomery form
 *
 * in: z in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z_out = z_in / 2^256 mod m, in [0, m)
 * That is, z_in was z_actual * 2^256 mod m, and z_out is z_actual.
 ******************************************************************/
static void m256_done(uint32_t z[8], const m256_mod *mod) {
  uint32_t one[8];
  u256_set32(one, 1);
  m256_mul(z, z, one, mod);
}



/***************************************************************
 * Set to 32-bit value
 *
 * in: x in [0, 2^32)
 *     mod must point to a valid m256_mod structure
 * out: z = x * 2^256 mod m, in [0, m)
 * That is, z is set to the image of x in the Montgomery domain.
 ***************************************************************/
static void m256_set32(uint32_t z[8], uint32_t x, const m256_mod *mod) {
  u256_set32(z, x);
  m256_prep(z, mod);
}



/*********************************************************
 * Modular inversion in Montgomery form
 *
 * in: x in [0, m)
 *     mod must point to a valid m256_mod structure
 *     such that mod->m % 2^32 >= 2, assumed to be public.
 * out: z = x^-1 * 2^512 mod m if x != 0,
 *      z = 0 if x == 0
 * That is, if x = x_actual    * 2^256 mod m, then
 *             z = x_actual^-1 * 2^256 mod m
 *
 * Note: as a memory area, z may overlap with x.
 *********************************************************/
static void m256_inv(uint32_t z[8], const uint32_t x[8],
                     const m256_mod *mod) {
  /*------------------------------------------------------------------------
   * Use Fermat's little theorem to compute x^-1 as x^(m-2).
   *
   * Take advantage of the fact that both p's and n's least significant limb
   * is at least 2 to perform the subtraction on the flight (no carry).
   *
   * Use plain right-to-left binary exponentiation;
   * branches are OK as the exponent is not a secret.
   *----------------------------------------------------------------------*/
  uint32_t bitval[8];
  u256_cmov(bitval, x, 1);    /* copy x before writing to z */
  m256_set32(z, 1, mod);

  unsigned i = 0;
  uint32_t limb = mod->m[i] - 2;
  while (1) {
    for (unsigned j = 0; j < 32; j++) {
      if ((limb & 1) != 0)
        m256_mul(z, z, bitval, mod);
      m256_mul(bitval, bitval, bitval, mod);
      limb >>= 1;
    }
    if (i == 7)
      break;
    i++;
    limb = mod->m[i];
  }
}



/*******************************************************************
 * Import modular integer from bytes to Montgomery domain
 *
 * in: p = p0, ..., p32
 *     mod must point to a valid m256_mod structure
 * out: z = (p0 * 2^248 + ... + p31) * 2^256 mod m, in [0, m)
 *      return 0 if the number was already in [0, m), or -1.
 *      z may be incorrect and must be discared when -1 is returned.
 *******************************************************************/
static int m256_from_bytes(uint32_t z[8],
                           const uint8_t p[32], const m256_mod *mod) {
  u256_from_bytes(z, p);
  uint32_t t[8];
  uint32_t lt_m = u256_sub(t, z, mod->m);
  if (lt_m != 1)
    return -1;
  m256_prep(z, mod);
  return 0;
}



/********************************************************
 * Export modular integer from Montgomery domain to bytes
 *
 * in: z in [0, 2^256)
 *     mod must point to a valid m256_mod structure
 * out: p = p0, ..., p31 such that
 *      z = (p0 * 2^248 + ... + p31) * 2^256 mod m
 ********************************************************/
static void m256_to_bytes(uint8_t p[32],
                          const uint32_t z[8], const m256_mod *mod) {
  uint32_t zi[8];
  u256_cmov(zi, z, 1);
  m256_done(zi, mod);
  u256_to_bytes(p, zi);
}



/******************************************************************************
 *
 * Operations on curve points
 *
 * Points are represented in two coordinates system:
 *  - affine (x, y) - extended to represent 0 (see below)
 *  - jacobian (x:y:z)
 * In either case, coordinates are integers modulo p256_p and
 * are always represented in the Montgomery domain.
 *
 * For background on jacobian coordinates, see for example [GECC] 3.2.2:
 * - conversions go (x, y) -> (x:y:1) and (x:y:z) -> (x/z^2, y/z^3)
 * - the curve equation becomes y^2 = x^3 - 3 x z^4 + b z^6
 * - 0 (aka the origin aka point at infinity) is (x:y:0) with y^2 = x^3.
 * - point negation goes -(x:y:z) = (x:-y:z)
 *
 * Normally 0 (the point at infinity) can't be represented in affine
 * coordinates. However we extend affine coordinates with the convention that
 * (0, 0) (which is normally not a point on the curve) is interpreted as 0.
 *
 * References:
 * - [GECC]: Guide to Elliptic Curve Cryptography; Hankerson, Menezes,
 *   Vanstone; Springer, 2004.
 * - [CMO98]: Efficient Elliptic Curve Exponentiation Using Mixed Coordinates;
 *   Cohen, Miyaji, Ono; Springer, ASIACRYPT 1998.
 *   https://link.springer.com/content/pdf/10.1007/3-540-49649-1_6.pdf
 * - [RCB15]: Complete addition formulas for prime order elliptic curves;
 *   Renes, Costello, Batina; IACR e-print 2015-1060.
 *   https://eprint.iacr.org/2015/1060.pdf
 *
 *******************************************************************************/



/***********************************************************************
 * The curve's b parameter in the Short Weierstrass equation
 *  y^2 = x^3 - 3*x + b
 * Compared to the standard, this is converted to the Montgomery domain.
 ***********************************************************************/
static const uint32_t p256_b[8] = { /* b * 2^256 mod p */
                      0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd,
                      0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d,
};



/***************************************************************************
 * The curve's conventional base point G.
 * Compared to the standard, coordinates converted to the Montgomery domain.
 ***************************************************************************/
static const uint32_t p256_gx[8] = { /* G_x * 2^256 mod p */
                      0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc,
                      0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76,
};
static const uint32_t p256_gy[8] = { /* G_y * 2^256 mod p */
                      0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4,
                      0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18,
};



/*************************************************************************
 * Point-on-curve check - do the coordinates satisfy the curve's equation?
 *
 * in: x, y in [0, p)   (Montgomery domain)
 * out: 0 if the point lies on the curve and is not 0,
 *      unspecified non-zero otherwise
 *************************************************************************/
static uint32_t point_check(const uint32_t x[8], const uint32_t y[8]) {
  uint32_t lhs[8], rhs[8];

  /* lhs = y^2 */
  m256_mul_p(lhs, y, y);

  /* rhs = x^3 - 3x + b */
  m256_mul_p(rhs, x,   x);      /* x^2 */
  m256_mul_p(rhs, rhs, x);      /* x^3 */
  for (unsigned i = 0; i < 3; i++)
    m256_sub_p(rhs, rhs, x);  /* x^3 - 3x */
  m256_add_p(rhs, rhs, p256_b); /* x^3 - 3x + b */
  return u256_diff(lhs, rhs);
}



/**********************************************************************
 * In-place jacobian to affine coordinate conversion
 *
 * in: (x:y:z) must be on the curve (coordinates in Montegomery domain)
 * out: x_out = x_in / z_in^2   (Montgomery domain)
 *      y_out = y_in / z_in^3   (Montgomery domain)
 *      z_out unspecified, must be disregarded
 *
 * Note: if z is 0 (that is, the input point is 0), x_out = y_out = 0.
 **********************************************************************/
static void point_to_affine(uint32_t x[8], uint32_t y[8], uint32_t z[8]) {
  uint32_t t[8];

  m256_inv(z, z, &p256_p);    /* z = z^-1 */
  m256_mul_p(t, z, z);        /* t = z^-2 */
  m256_mul_p(x, x, t);        /* x = x * z^-2 */
  m256_mul_p(t, t, z);        /* t = z^-3 */
  m256_mul_p(y, y, t);        /* y = y * z^-3 */
}



/*********************************************************************
 * In-place point doubling in jacobian coordinates (Montgomery domain)
 *
 * in: P_in = (x:y:z), must be on the curve
 * out: (x:y:z) = P_out = 2 * P_in
 *********************************************************************/
static void point_double(uint32_t x[8], uint32_t y[8], uint32_t z[8]) {

  /*------------------------------------------------------------------------
   * This is formula 6 from [CMO98], cited as complete in [RCB15] (table 1).
   * Notations as in the paper, except u added and t ommited (it's x3).
   *----------------------------------------------------------------------*/
  uint32_t m[8], s[8], u[8];

  /* m = 3 * x^2 + a * z^4 = 3 * (x + z^2) * (x - z^2) */
  m256_mul_p(s, z, z);
  m256_add_p(m, x, s);
  m256_sub_p(u, x, s);
  m256_mul_p(s, m, u);
  m256_add_p(m, s, s);
  m256_add_p(m, m, s);

  /* s = 4 * x * y^2 */
  m256_mul_p(u, y, y);
  m256_add_p(u, u, u); /* u = 2 * y^2 (used below) */
  m256_mul_p(s, x, u);
  m256_add_p(s, s, s);

  /* u = 8 * y^4 (not named in the paper, first term of y3) */
  m256_mul_p(u, u, u);
  m256_add_p(u, u, u);

  /* x3 = t = m^2 - 2 * s */
  m256_mul_p(x, m, m);
  m256_sub_p(x, x, s);
  m256_sub_p(x, x, s);

  /* z3 = 2 * y * z */
  m256_mul_p(z, y, z);
  m256_add_p(z, z, z);

  /* y3 = -u + m * (s - t) */
  m256_sub_p(y, s, x);
  m256_mul_p(y, y, m);
  m256_sub_p(y, y, u);
}



/****************************************************************************
 * In-place point addition in jacobian-affine coordinates (Montgomery domain)
 *
 * in: P_in = (x1:y1:z1), must be on the curve and not 0
 *     Q = (x2, y2), must be on the curve and not P_in or -P_in or 0
 * out: P_out = (x1:y1:z1) = P_in + Q
 ****************************************************************************/
static void point_add(uint32_t x1[8], uint32_t y1[8], uint32_t z1[8],
                      const uint32_t x2[8], const uint32_t y2[8]) {
  /*------------------------------------------------------------------------
   * This is formula 5 from [CMO98], with z2 == 1 substituted. We use
   * intermediates with neutral names, and names from the paper in comments.
   *----------------------------------------------------------------------*/
  uint32_t t1[8], t2[8], t3[8];

  /* u1 = x1 and s1 = y1 (no computations) */

  /* t1 = u2 = x2 z1^2 */
  m256_mul_p(t1, z1, z1);
  m256_mul_p(t2, t1, z1);
  m256_mul_p(t1, t1, x2);

  /* t2 = s2 = y2 z1^3 */
  m256_mul_p(t2, t2, y2);

  /* t1 = h = u2 - u1 */
  m256_sub_p(t1, t1, x1); /* t1 = x2 * z1^2 - x1 */
  
  /* t2 = r = s2 - s1 */
  m256_sub_p(t2, t2, y1);

  /* z3 = z1 * h */
  m256_mul_p(z1, z1, t1);

  /* t1 = h^3 */
  m256_mul_p(t3, t1, t1);
  m256_mul_p(t1, t3, t1);

  /* t3 = x1 * h^2 */
  m256_mul_p(t3, t3, x1);

  /* x3 = r^2 - 2 * x1 * h^2 - h^3 */
  m256_mul_p(x1, t2, t2);
  m256_sub_p(x1, x1, t3);
  m256_sub_p(x1, x1, t3);
  m256_sub_p(x1, x1, t1);

  /* y3 = r * (x1 * h^2 - x3) - y1 h^3 */
  m256_sub_p(t3, t3, x1);
  m256_mul_p(t3, t3, t2);
  m256_mul_p(t1, t1, y1);
  m256_sub_p(y1, t3, t1);
}



/***************************************************************************
 * Import curve point from bytes
 *
 * in: p = (x, y) concatenated, fixed-width 256-bit big-endian integers
 * out: x, y in Mongomery domain
 *      return 0 if x and y are both in [0, p)
 *                  and (x, y) is on the curve and not 0
 *             unspecified non-zero otherwise.
 *      x and y are unspecified and must be discarded if returning non-zero.
 ***************************************************************************/
static int point_from_bytes(uint32_t x[8], uint32_t y[8], const uint8_t p[64]) {
  int rc;
  rc = m256_from_bytes(x, p, &p256_p);
  if (rc != 0)
    return rc;
  rc = m256_from_bytes(y, p + 32, &p256_p);
  if (rc != 0)
    return rc;
  return (int)point_check(x, y);
}



/***********************************************************************
 * Export curve point to bytes
 *
 * in: x, y affine coordinates of a point (Montgomery domain)
 *     must be on the curve and not 0
 * out: p = (x, y) concatenated, fixed-width 256-bit big-endian integers
 ***********************************************************************/
static void point_to_bytes(uint8_t p[64],
                           const uint32_t x[8], const uint32_t y[8]) {
  m256_to_bytes(p, x, &p256_p);
  m256_to_bytes(p + 32, y, &p256_p);
}



/******************************************************************************
 *
 * Scalar multiplication and other scalar-related operations
 *
 *******************************************************************************/



 /***********************************************************************
 * Scalar multiplication
 *
 * in: P = (px, py), affine (Montgomery), must be on the curve and not 0
 *     s in [1, n-1]
 * out: R = s * P = (rx, ry), affine coordinates (Montgomery).
 *
 * Note: as memory areas, none of the parameters may overlap.
 ***********************************************************************/
static void scalar_mult(uint32_t rx[8], uint32_t ry[8],
                        const uint32_t px[8], const uint32_t py[8],
                        const uint32_t s[8]) {

  /*------------------------------------------------------------------
   * We use a signed binary ladder, see for example slides 10-14 of
   * http://ecc2015.math.u-bordeaux1.fr/documents/hamburg.pdf but with
   * implicit recoding, and a different loop initialisation to avoid
   * feeding 0 to our addition formulas, as they don't support it.
   *----------------------------------------------------------------*/
  uint32_t s_odd[8], py_neg[8], py_use[8], rz[8];

  /*--------------------------------------------------------
   * Make s odd by replacing it with n - s if necessary.
   *
   * If s was odd, we'll have s_odd = s, and define P' = P.
   * Otherwise, we'll have s_odd = n - s and define P' = -P.
   *
   * Either way, we can compute s * P as s_odd * P'.
   *------------------------------------------------------*/
  u256_sub(s_odd, p256_n.m, s); /* no carry, result still in [1, n-1] */
  uint32_t negate = ~s[0] & 1;
  u256_cmov(s_odd, s, 1 - negate);

  /* Compute py_neg = - py mod p (that's the y coordinate of -P) */
  u256_set32(py_use, 0);
  m256_sub_p(py_neg, py_use, py);

  /* Initialize R = P' = (x:(-1)^negate * y:1) */
  u256_cmov(rx, px, 1);
  u256_cmov(ry, py, 1);
  m256_set32(rz, 1, &p256_p);
  u256_cmov(ry, py_neg, negate);

  /*-------------------------------------------------------------------------
   * For any odd number s_odd = b255 ... b1 1, we have
   *      s_odd = 2^255 + 2^254 sbit(b255) + ... + 2 sbit(b2) + sbit(b1)
   * writing
   *      sbit(b) = 2 * b - 1 = b ? 1 : -1
   *
   * Use that to compute s_odd * P' by repeating R = 2 * R +- P':
   *      s_odd * P' = 2 * ( ... (2 * P' + sbit(b255) P') ... ) + sbit(b1) P'
   *
   * The loop invariant is that when beginning an iteration we have
   *      R = s_i P'
   * with
   *      s_i = 2^(255-i) + 2^(254-i) sbit(b_255) + ...
   * where the sum has 256 - i terms.
   *
   * When updating R we need to make sure the input to point_add() is
   * neither 0 not +-P'. Since that input is 2 s_i P', it is sufficient to
   * see that 1 < 2 s_i < n-1. The lower bound is obvious since s_i is a
   * positive integer, and for the upper bound we distinguish three cases.
   *
   * If i > 1, then s_i < 2^254, so 2 s_i < 2^255 < n-1.
   * Otherwise, i == 1 and we have 2 s_i = s_odd - sbit(b1).
   *      If s_odd <= n-4, then 2 s_1 <= n-3.
   *      Otherwise, s_odd = n-2, and for this curve's value of n,
   *      we have b1 == 1, so sbit(b1) = 1 and 2 s_1 <= n-3.
   *-----------------------------------------------------------------------*/
  for (unsigned i = 255; i > 0; i--) {
    uint32_t bit = (s_odd[i / 32] >> i % 32) & 1;
    /* set (px, py_use) = sbit(bit) P' = sbit(bit) * (-1)^negate P */
    u256_cmov(py_use, py, bit ^ negate);
    u256_cmov(py_use, py_neg, (1 - bit) ^ negate);
    /* Update R = 2 * R +- P' */
    point_double(rx, ry, rz);
    point_add(rx, ry, rz, px, py_use);
  }
  point_to_affine(rx, ry, rz);
}



/**********************************************************
 * Scalar import from big-endian bytes
 *
 * in: p = p0, ..., p31
 * out: s = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 *      return 0 if s in [1, n-1],
 *            -1 otherwise.
 **********************************************************/
static int scalar_from_bytes(uint32_t s[8], const uint8_t p[32]) {
  u256_from_bytes(s, p);
  uint32_t r[8];
  uint32_t lt_n = u256_sub(r, s, p256_n.m);
  u256_set32(r, 1);
  uint32_t lt_1 = u256_sub(r, s, r);
  if (lt_n && !lt_1)
    return 0;
  return -1;
}



/*****************************************************************
 * Scalar generation, with public key
 *
 * out: sbytes the big-endian bytes representation of the scalar
 *      s its u256 representation
 *      x, y the affine coordinates of s * G (Montgomery domain)
 *      return 0 if OK, -1 on failure
 *      sbytes, s, x, y must be discarded when returning non-zero.
 *****************************************************************/
static int scalar_gen_with_pub(uint8_t sbytes[32], uint32_t s[8],
                               uint32_t x[8], uint32_t y[8],
                               ecdh_p256_get_entropy entropy_cb,
                               void *entropy_context) {

  /* generate a random valid scalar */
  int rc;
  unsigned nb_tried = 0;
  byte_array entropy = {32, sbytes};
  do {
    if (nb_tried++ >= 4)
      return -1;
    if (entropy_cb == NULL)
      rc = ecdh_p256_random(entropy);
    else
      rc = (*entropy_cb)(entropy_context, entropy);
    CT_POISON(sbytes, 32);
    if (rc != ECDH_P256_SUCCESS)
      return -1;
    rc = scalar_from_bytes(s, sbytes);
    CT_UNPOISON(&ret, sizeof ret);
  }
  while (rc != 0);
  /* compute and ouput the associated public key */
  scalar_mult(x, y, p256_gx, p256_gy, s);
  /* the associated public key is not a secret */
  CT_UNPOISON(x, 32);
  CT_UNPOISON(y, 32);
  return 0;
}






/******************************************************************************
 *
 * Public (exported) Functions
 *
 ******************************************************************************/


/********************************************************************************
 * ECDH/ECDSA generate key pair
 *
 * [in] none, draws from mte_generate_random()
 * [out] private_key: on success, holds the private key, as a big-endian integer
 * [out] public_key: on success, holds the public key, as two big-endian integers
 *
 * return:  ECDH_SUCCESS on success
 *          ECDH_RANDOM_FAILED on failure
 ********************************************************************************/
int ecdh_p256_create_keypair(byte_array *private_key,
                             byte_array *public_key,
                             ecdh_p256_get_entropy entropy_cb,
                             void *entropy_context) {
  uint32_t s[8], x[8], y[8];
  int rc;

  if ((private_key->size < SZ_ECDH_P256_PRIVATE_KEY) ||
      (public_key->size < SZ_ECDH_P256_PUBLIC_KEY))
    return ECDH_P256_MEMORY_FAIL;
  rc = scalar_gen_with_pub(private_key->data, s, x, y, entropy_cb, entropy_context);
  ecdh_p256_zeroize(s, sizeof s);
  if (rc != 0)
    return ECDH_P256_RANDOM_FAIL;
  point_to_bytes(public_key->data, x, y);
  private_key->size = SZ_ECDH_P256_PRIVATE_KEY;
  public_key->size = SZ_ECDH_P256_PUBLIC_KEY;
  return ECDH_P256_SUCCESS;
}



/****************************************************************************
 * ECDH compute shared secret
 *
 * [in] private_key: our private key as a big-endian integer
 * [in] public_key: the peer's public key, as two big-endian integers
 * [out] secret: on success, holds the shared secret, as a big-endian integer
 *
 * return:  P256_SUCCESS on success
 *          P256_INVALID_PRIVKEY if priv is invalid
 *          P256_INVALID_PUBKEY if pub is invalid
 ****************************************************************************/
int ecdh_p256_create_secret(const byte_array private_key,
                            const byte_array peer_public_key,
                            byte_array *secret) {
  CT_POISON(private_key, ECDH_PRIVATE_KEY_BYTES);
  uint32_t s[8], px[8], py[8], x[8], y[8];
  int rc;

  if ((private_key.size < SZ_ECDH_P256_PRIVATE_KEY) ||
      (peer_public_key.size < SZ_ECDH_P256_PUBLIC_KEY) ||
      (secret->size < SZ_ECDH_P256_SECRET_DATA))
    return ECDH_P256_MEMORY_FAIL;

  rc = scalar_from_bytes(s, private_key.data);
  CT_UNPOISON(&rc, sizeof rc);
  if (rc != 0) {
    rc = ECDH_P256_INVALID_PRIVKEY;
    goto cleanup;
  }
  rc = point_from_bytes(px, py, peer_public_key.data);
  if (rc != 0) {
    rc = ECDH_P256_INVALID_PUBKEY;
    goto cleanup;
  }
  scalar_mult(x, y, px, py, s);
  m256_to_bytes(secret->data, x, &p256_p);
  CT_UNPOISON(secret, ECDH_SECRET_DATA_BYTES);
  secret->size = SZ_ECDH_P256_SECRET_DATA;
  rc = ECDH_P256_SUCCESS;

cleanup:
  ecdh_p256_zeroize(s, sizeof(s));
  return rc;
}
