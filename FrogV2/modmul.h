#pragma once

#include "esp_bignum.h"

#include <string.h>
#include <sys/param.h>
#include "soc/hwcrypto_periph.h"
#include "esp_private/periph_ctrl.h"
#include "mbedtls/bignum.h"
#include "bignum_impl.h"
#include "soc/system_reg.h"
#include "soc/periph_defs.h"
#include "esp_crypto_lock.h"

#include "bignum_impl.h"
#include "soc/dport_access.h"



/* Convert bit count to word count
*/
static inline size_t bits_to_words(size_t bits)
{
  return (bits + 31) / 32;
}

/**

   There is a need for the value of integer N' such that B^-1(B-1)-N^-1N'=1,
   where B^-1(B-1) mod N=1. Actually, only the least significant part of
   N' is needed, hence the definition N0'=N' mod b. We reproduce below the
   simple algorithm from an article by Dusse and Kaliski to efficiently
   find N0' from N0 and b
*/
static mbedtls_mpi_uint modular_inverse(const mbedtls_mpi *M)
{
  int i;
  uint64_t t = 1;
  uint64_t two_2_i_minus_1 = 2;   /* 2^(i-1) */
  uint64_t two_2_i = 4;           /* 2^i */
  uint64_t N = M->MBEDTLS_PRIVATE(p[0]);

  for (i = 2; i <= 32; i++) {
    if ((mbedtls_mpi_uint) N * t % two_2_i >= two_2_i_minus_1) {
      t += two_2_i_minus_1;
    }

    two_2_i_minus_1 <<= 1;
    two_2_i <<= 1;
  }

  return (mbedtls_mpi_uint)(UINT32_MAX - t + 1);
}

/* Calculate Rinv = RR^2 mod M, where:

    R = b^n where b = 2^32, n=num_words,
    R = 2^N (where N=num_bits)
    RR = R^2 = 2^(2*N) (where N=num_bits=num_words*32)

   This calculation is computationally expensive (mbedtls_mpi_mod_mpi)
   so caller should cache the result where possible.

   DO NOT call this function while holding esp_mpi_enable_hardware_hw_op().

*/
static int calculate_rinv(mbedtls_mpi *Rinv, const mbedtls_mpi *M, int num_words)
{
  int ret;
  size_t num_bits = num_words * 32;
  mbedtls_mpi RR;
  mbedtls_mpi_init(&RR);
  MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&RR, num_bits * 2, 1));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(Rinv, &RR, M));

cleanup:
  mbedtls_mpi_free(&RR);

  return ret;
}







int esp_mpi_mul_mpi_mod(mbedtls_mpi *Z, const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M);

#define MAX_HW_WORDS 32

typedef struct {
  mbedtls_mpi M;
  mbedtls_mpi Rinv[MAX_HW_WORDS];
  mbedtls_mpi_uint Mprime;
} Modulus;

int esp_mpi_mul_mpi_mod_init(Modulus *mod, const mbedtls_mpi *M) {
  int ret = 0;
  size_t m_bits = mbedtls_mpi_bitlen(M);
  size_t m_words = bits_to_words(m_bits);
  size_t base_hw_words = esp_mpi_hardware_words(m_words);

  // Initialize M and Mprime
  mbedtls_mpi_init(&mod->M);
  MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&mod->M, M));
  mod->Mprime = modular_inverse(M);

  // Initialize and calculate Rinv for all possible hw_words
  for (size_t i = base_hw_words; i < (size_t)MIN((size_t)MAX_HW_WORDS, base_hw_words * 4); i++) {
    //        mbedtls_mpi_init(&mod->Rinv[i]);
    //        MBEDTLS_MPI_CHK(calculate_rinv(&mod->Rinv[i], M, i));
  }

cleanup:
  return ret;
}

int esp_mpi_mul_mpi_mod_rinv(mbedtls_mpi *Z, const mbedtls_mpi *X, const mbedtls_mpi *Y, Modulus *mod)
{
  int ret = 0;
  const mbedtls_mpi *M = &mod->M;

  size_t x_bits = mbedtls_mpi_bitlen(X);
  size_t y_bits = mbedtls_mpi_bitlen(Y);
  size_t m_bits = mbedtls_mpi_bitlen(M);
  size_t z_bits = MIN(m_bits, x_bits + y_bits);
  size_t x_words = bits_to_words(x_bits);
  size_t y_words = bits_to_words(y_bits);
  size_t m_words = bits_to_words(m_bits);
  size_t z_words = bits_to_words(z_bits);
  size_t hw_words = esp_mpi_hardware_words(MAX(x_words, MAX(y_words, m_words))); /* longest operand */

  // Ensure hw_words is within the precomputed range
  if (hw_words >= MAX_HW_WORDS) {
    return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
  }


  esp_mpi_enable_hardware_hw_op();


  const mbedtls_mpi *Rinv = &mod->Rinv[hw_words];  // Adjust index if hw_words starts from 1
  mbedtls_mpi_uint Mprime = mod->Mprime;
  // Load and start a (X * Y) mod M calculation
  esp_mpi_mul_mpi_mod_hw_op(X, Y, M, Rinv, Mprime, hw_words);
  MBEDTLS_MPI_CHK(mbedtls_mpi_grow(Z, z_words));
  esp_mpi_read_result_hw_op(Z, z_words);
  Z->MBEDTLS_PRIVATE(s) = X->MBEDTLS_PRIVATE(s) * Y->MBEDTLS_PRIVATE(s);

cleanup:
  esp_mpi_disable_hardware_hw_op();
  return ret;
}

// Function to free the Modulus structure
void esp_mpi_mul_mpi_mod_free(Modulus *mod) {
  mbedtls_mpi_free(&mod->M);
  for (size_t i = 0; i < MAX_HW_WORDS; i++) {
    mbedtls_mpi_free(&mod->Rinv[i]);
  }
}

Modulus recent_modulus = {0};

int mpi_mul_mpi_mod(mbedtls_mpi *Z, const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M) {
  if (recent_modulus.M.MBEDTLS_PRIVATE(p) == NULL) {
    esp_mpi_mul_mpi_mod_init(&recent_modulus, M);
  } else if (mbedtls_mpi_cmp_mpi(M, &recent_modulus.M) != 0) {
    esp_mpi_mul_mpi_mod_free(&recent_modulus);
    esp_mpi_mul_mpi_mod_init(&recent_modulus, M);
  }

  size_t x_bits = mbedtls_mpi_bitlen(X);
  size_t y_bits = mbedtls_mpi_bitlen(Y);
  size_t m_bits = mbedtls_mpi_bitlen(M);
  size_t z_bits = MIN(m_bits, x_bits + y_bits);
  size_t x_words = bits_to_words(x_bits);
  size_t y_words = bits_to_words(y_bits);
  size_t m_words = bits_to_words(m_bits);
  size_t z_words = bits_to_words(z_bits);
  size_t hw_words = esp_mpi_hardware_words(MAX(x_words, MAX(y_words, m_words))); /* longest operand */

  // Ensure hw_words is within the precomputed range
  if (hw_words >= MAX_HW_WORDS) {
    return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
  }

  if (recent_modulus.Rinv[hw_words].MBEDTLS_PRIVATE(p) == NULL) {
    mbedtls_mpi_init(&recent_modulus.Rinv[hw_words]);
    calculate_rinv(&recent_modulus.Rinv[hw_words], M, hw_words);
  }

  return esp_mpi_mul_mpi_mod_rinv(Z, X, Y, &recent_modulus);
}
