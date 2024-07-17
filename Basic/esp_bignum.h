
#ifndef __ESP_BIGNUM__
#define __ESP_BIGNUM__

#include <Arduino.h>


#if defined(ARDUINO_ESP32C3_DEV)

/*
   Multi-precision integer library
   ESP32 C3 hardware accelerated parts based on mbedTLS implementation

   SPDX-FileCopyrightText: The Mbed TLS Contributors

   SPDX-License-Identifier: Apache-2.0

   SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
*/
#include <string.h>
#include <sys/param.h>
#include "soc/hwcrypto_periph.h"
#include "esp_private/periph_ctrl.h"
#include "mbedtls/bignum.h"
#include "bignum_impl.h"
#include "soc/system_reg.h"
#include "soc/periph_defs.h"
#include "esp_crypto_lock.h"


size_t esp_mpi_hardware_words(size_t words)
{
  return words;
}

void esp_mpi_enable_hardware_hw_op( void )
{
  esp_crypto_mpi_lock_acquire();

  /* Enable RSA hardware */
  periph_module_enable(PERIPH_RSA_MODULE);

  REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

  while (REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
  }
  // Note: from enabling RSA clock to here takes about 1.3us

  REG_WRITE(RSA_INTERRUPT_REG, 0);
}

void esp_mpi_disable_hardware_hw_op( void )
{
  REG_SET_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

  /* Disable RSA hardware */
  periph_module_disable(PERIPH_RSA_MODULE);

  esp_crypto_mpi_lock_release();
}

void esp_mpi_interrupt_enable( bool enable )
{
  REG_WRITE(RSA_INTERRUPT_REG, enable);
}

void esp_mpi_interrupt_clear( void )
{
  REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}

/* Copy mbedTLS MPI bignum 'mpi' to hardware memory block at 'mem_base'.

   If num_words is higher than the number of words in the bignum then
   these additional words will be zeroed in the memory buffer.
*/
static inline void mpi_to_mem_block(uint32_t mem_base, const mbedtls_mpi *mpi, size_t num_words)
{
  uint32_t *pbase = (uint32_t *)mem_base;
  uint32_t copy_words = MIN(num_words, mpi->MBEDTLS_PRIVATE(n));

  /* Copy MPI data to memory block registers */
  for (int i = 0; i < copy_words; i++) {
    pbase[i] = mpi->MBEDTLS_PRIVATE(p)[i];
  }

  /* Zero any remaining memory block data */
  for (int i = copy_words; i < num_words; i++) {
    pbase[i] = 0;
  }
}

/* Read mbedTLS MPI bignum back from hardware memory block.

   Reads num_words words from block.
*/
static inline void mem_block_to_mpi(mbedtls_mpi *x, uint32_t mem_base, int num_words)
{

  /* Copy data from memory block registers */
  const size_t REG_WIDTH = sizeof(uint32_t);
  for (size_t i = 0; i < num_words; i++) {
    x->MBEDTLS_PRIVATE(p)[i] = REG_READ(mem_base + (i * REG_WIDTH));
  }
  /* Zero any remaining limbs in the bignum, if the buffer is bigger
     than num_words */
  for (size_t i = num_words; i < x->MBEDTLS_PRIVATE(n); i++) {
    x->MBEDTLS_PRIVATE(p)[i] = 0;
  }
}



/* Begin an RSA operation. op_reg specifies which 'START' register
   to write to.
*/
static inline void start_op(uint32_t op_reg)
{
  /* Clear interrupt status */
  REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

  /* Note: above REG_WRITE includes a memw, so we know any writes
     to the memory blocks are also complete. */

  REG_WRITE(op_reg, 1);
}

/* Wait for an RSA operation to complete.
*/
static inline void wait_op_complete(void)
{
  while (REG_READ(RSA_QUERY_INTERRUPT_REG) != 1)
  { }

  /* clear the interrupt */
  REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}


/* Read result from last MPI operation */
void esp_mpi_read_result_hw_op(mbedtls_mpi *Z, size_t z_words)
{
  wait_op_complete();
  mem_block_to_mpi(Z, RSA_MEM_Z_BLOCK_BASE, z_words);
}


/* Z = (X * Y) mod M

   Not an mbedTLS function
*/
void esp_mpi_mul_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  REG_WRITE(RSA_M_DASH_REG, Mprime);

  start_op(RSA_MOD_MULT_START_REG);
}

/* Z = (X ^ Y) mod M
*/
void esp_mpi_exp_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  size_t y_bits = mbedtls_mpi_bitlen(Y);

  REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  REG_WRITE(RSA_M_DASH_REG, Mprime);

  /* Enable acceleration options */
  REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
  REG_WRITE(RSA_SEARCH_ENABLE_REG, 1);
  REG_WRITE(RSA_SEARCH_POS_REG, y_bits - 1);

  /* Execute first stage montgomery multiplication */
  start_op(RSA_MODEXP_START_REG);

  REG_WRITE(RSA_SEARCH_ENABLE_REG, 0);
}


/* Z = X * Y */
void esp_mpi_mul_mpi_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* Copy X (right-extended) & Y (left-extended) to memory block */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Z_BLOCK_BASE + num_words * 4, Y, num_words);
  /* NB: as Y is left-extended, we don't zero the bottom words_mult words of Y block.
     This is OK for now because zeroing is done by hardware when we do esp_mpi_acquire_hardware().
  */
  REG_WRITE(RSA_LENGTH_REG, (num_words * 2 - 1));
  start_op(RSA_MULT_START_REG);
}



/**
   @brief Special-case of (X * Y), where we use hardware montgomery mod
   multiplication to calculate result where either A or B are >2048 bits so
   can't use the standard multiplication method.

*/
void esp_mpi_mult_mpi_failover_mod_mult_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* M = 2^num_words - 1, so block is entirely FF */
  for (int i = 0; i < num_words; i++) {
    REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, UINT32_MAX);
  }

  /* Mprime = 1 */
  REG_WRITE(RSA_M_DASH_REG, 1);
  REG_WRITE(RSA_LENGTH_REG, num_words - 1);

  /* Load X & Y */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);

  /* Rinv = 1, write first word */
  REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 1);

  /* Zero out rest of the Rinv words */
  for (int i = 1; i < num_words; i++) {
    REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
  }

  start_op(RSA_MOD_MULT_START_REG);
}

#elif defined(ARDUINO_ESP32S2_DEV)

/*
   Multi-precision integer library
   ESP32 S2 hardware accelerated parts based on mbedTLS implementation

   SPDX-FileCopyrightText: The Mbed TLS Contributors

   SPDX-License-Identifier: Apache-2.0

   SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
*/
#include "soc/hwcrypto_periph.h"
#include "esp_private/periph_ctrl.h"
#include <mbedtls/bignum.h>
#include "bignum_impl.h"
#include "soc/dport_reg.h"
#include "soc/periph_defs.h"
#include <sys/param.h>
#include "esp_crypto_lock.h"

size_t esp_mpi_hardware_words(size_t words)
{
  return words;
}

void esp_mpi_enable_hardware_hw_op( void )
{
  esp_crypto_mpi_lock_acquire();

  /* Enable RSA hardware */
  periph_module_enable(PERIPH_RSA_MODULE);

  DPORT_REG_CLR_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_MEM_PD);

  while (DPORT_REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
  }
  // Note: from enabling RSA clock to here takes about 1.3us

  REG_WRITE(RSA_INTERRUPT_REG, 0);
}

void esp_mpi_disable_hardware_hw_op( void )
{
  DPORT_REG_SET_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_PD);

  /* Disable RSA hardware */
  periph_module_disable(PERIPH_RSA_MODULE);

  esp_crypto_mpi_lock_release();
}

void esp_mpi_interrupt_enable( bool enable )
{
  REG_WRITE(RSA_INTERRUPT_REG, enable);
}

void esp_mpi_interrupt_clear( void )
{
  REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}

/* Copy mbedTLS MPI bignum 'mpi' to hardware memory block at 'mem_base'.

   If num_words is higher than the number of words in the bignum then
   these additional words will be zeroed in the memory buffer.
*/
static inline void mpi_to_mem_block(uint32_t mem_base, const mbedtls_mpi *mpi, size_t num_words)
{
  uint32_t *pbase = (uint32_t *)mem_base;
  uint32_t copy_words = MIN(num_words, mpi->MBEDTLS_PRIVATE(n));

  /* Copy MPI data to memory block registers */
  for (uint32_t i = 0; i < copy_words; i++) {
    pbase[i] = mpi->MBEDTLS_PRIVATE(p)[i];
  }

  /* Zero any remaining memory block data */
  for (uint32_t i = copy_words; i < num_words; i++) {
    pbase[i] = 0;
  }
}

/* Read mbedTLS MPI bignum back from hardware memory block.

   Reads num_words words from block.
*/
static inline void mem_block_to_mpi(mbedtls_mpi *x, uint32_t mem_base, int num_words)
{

  /* Copy data from memory block registers */
  esp_dport_access_read_buffer(x->MBEDTLS_PRIVATE(p), mem_base, num_words);
  /* Zero any remaining limbs in the bignum, if the buffer is bigger
     than num_words */
  for (size_t i = num_words; i < x->MBEDTLS_PRIVATE(n); i++) {
    x->MBEDTLS_PRIVATE(p)[i] = 0;
  }
}



/* Begin an RSA operation. op_reg specifies which 'START' register
   to write to.
*/
static inline void start_op(uint32_t op_reg)
{
  /* Clear interrupt status */
  DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

  /* Note: above REG_WRITE includes a memw, so we know any writes
     to the memory blocks are also complete. */

  DPORT_REG_WRITE(op_reg, 1);
}

/* Wait for an RSA operation to complete.
*/
static inline void wait_op_complete(void)
{
  while (DPORT_REG_READ(RSA_QUERY_INTERRUPT_REG) != 1)
  { }

  /* clear the interrupt */
  DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}


/* Read result from last MPI operation */
void esp_mpi_read_result_hw_op(mbedtls_mpi *Z, size_t z_words)
{
  wait_op_complete();
  mem_block_to_mpi(Z, RSA_MEM_Z_BLOCK_BASE, z_words);
}


/* Z = (X * Y) mod M

   Not an mbedTLS function
*/
void esp_mpi_mul_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  DPORT_REG_WRITE(RSA_M_DASH_REG, Mprime);

  start_op(RSA_MOD_MULT_START_REG);
}

/* Z = (X ^ Y) mod M
*/
void esp_mpi_exp_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  size_t y_bits = mbedtls_mpi_bitlen(Y);

  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  DPORT_REG_WRITE(RSA_M_DASH_REG, Mprime);

  /* Enable acceleration options */
  DPORT_REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
  DPORT_REG_WRITE(RSA_SEARCH_OPEN_REG, 1);
  DPORT_REG_WRITE(RSA_SEARCH_POS_REG, y_bits - 1);

  /* Execute first stage montgomery multiplication */
  start_op(RSA_MODEXP_START_REG);

  DPORT_REG_WRITE(RSA_SEARCH_OPEN_REG, 0);
}


/* Z = X * Y */
void esp_mpi_mul_mpi_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* Copy X (right-extended) & Y (left-extended) to memory block */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Z_BLOCK_BASE + num_words * 4, Y, num_words);
  /* NB: as Y is left-extended, we don't zero the bottom words_mult words of Y block.
     This is OK for now because zeroing is done by hardware when we do esp_mpi_acquire_hardware().
  */
  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words * 2 - 1));
  start_op(RSA_MULT_START_REG);
}



/**
   @brief Special-case of (X * Y), where we use hardware montgomery mod
   multiplication to calculate result where either A or B are >2048 bits so
   can't use the standard multiplication method.

*/
void esp_mpi_mult_mpi_failover_mod_mult_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* M = 2^num_words - 1, so block is entirely FF */
  for (size_t i = 0; i < num_words; i++) {
    DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, UINT32_MAX);
  }

  /* Mprime = 1 */
  DPORT_REG_WRITE(RSA_M_DASH_REG, 1);
  DPORT_REG_WRITE(RSA_LENGTH_REG, num_words - 1);

  /* Load X & Y */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);

  /* Rinv = 1, write first word */
  DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 1);

  /* Zero out rest of the Rinv words */
  for (size_t i = 1; i < num_words; i++) {
    DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
  }

  start_op(RSA_MOD_MULT_START_REG);
}

#elif defined(ARDUINO_ESP32S3_DEV)

/*
   Multi-precision integer library
   ESP32 S3 hardware accelerated parts based on mbedTLS implementation

   SPDX-FileCopyrightText: The Mbed TLS Contributors

   SPDX-License-Identifier: Apache-2.0

   SPDX-FileContributor: 2016-2022 Espressif Systems (Shanghai) CO LTD
*/
#include "soc/hwcrypto_periph.h"
#include "esp_private/periph_ctrl.h"
#include <mbedtls/bignum.h>
#include "bignum_impl.h"
#include "soc/dport_reg.h"
#include "soc/system_reg.h"
#include "soc/periph_defs.h"
#include <sys/param.h>
#include "esp_crypto_lock.h"

size_t esp_mpi_hardware_words(size_t words)
{
  return words;
}

void esp_mpi_enable_hardware_hw_op( void )
{
  esp_crypto_mpi_lock_acquire();

  /* Enable RSA hardware */
  periph_module_enable(PERIPH_RSA_MODULE);

  REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

  while (DPORT_REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
  }
  // Note: from enabling RSA clock to here takes about 1.3us

  REG_WRITE(RSA_INTERRUPT_REG, 0);

}

void esp_mpi_disable_hardware_hw_op( void )
{
  REG_SET_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);

  /* Disable RSA hardware */
  periph_module_disable(PERIPH_RSA_MODULE);

  esp_crypto_mpi_lock_release();
}

void esp_mpi_interrupt_enable( bool enable )
{
  REG_WRITE(RSA_INTERRUPT_REG, enable);
}

void esp_mpi_interrupt_clear( void )
{
  REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}

/* Copy mbedTLS MPI bignum 'mpi' to hardware memory block at 'mem_base'.

   If num_words is higher than the number of words in the bignum then
   these additional words will be zeroed in the memory buffer.
*/
static inline void mpi_to_mem_block(uint32_t mem_base, const mbedtls_mpi *mpi, size_t num_words)
{
  uint32_t *pbase = (uint32_t *)mem_base;
  uint32_t copy_words = MIN(num_words, mpi->MBEDTLS_PRIVATE(n));

  /* Copy MPI data to memory block registers */
  for (uint32_t i = 0; i < copy_words; i++) {
    pbase[i] = mpi->MBEDTLS_PRIVATE(p)[i];
  }

  /* Zero any remaining memory block data */
  for (uint32_t i = copy_words; i < num_words; i++) {
    pbase[i] = 0;
  }
}

/* Read mbedTLS MPI bignum back from hardware memory block.

   Reads num_words words from block.
*/
static inline void mem_block_to_mpi(mbedtls_mpi *x, uint32_t mem_base, int num_words)
{

  /* Copy data from memory block registers */
  esp_dport_access_read_buffer(x->MBEDTLS_PRIVATE(p), mem_base, num_words);
  /* Zero any remaining limbs in the bignum, if the buffer is bigger
     than num_words */
  for (size_t i = num_words; i < x->MBEDTLS_PRIVATE(n); i++) {
    x->MBEDTLS_PRIVATE(p)[i] = 0;
  }
}



/* Begin an RSA operation. op_reg specifies which 'START' register
   to write to.
*/
static inline void start_op(uint32_t op_reg)
{
  /* Clear interrupt status */
  DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

  /* Note: above REG_WRITE includes a memw, so we know any writes
     to the memory blocks are also complete. */

  DPORT_REG_WRITE(op_reg, 1);
}

/* Wait for an RSA operation to complete.
*/
static inline void wait_op_complete(void)
{
  while (DPORT_REG_READ(RSA_QUERY_INTERRUPT_REG) != 1)
  { }

  /* clear the interrupt */
  DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}


/* Read result from last MPI operation */
void esp_mpi_read_result_hw_op(mbedtls_mpi *Z, size_t z_words)
{
  wait_op_complete();
  mem_block_to_mpi(Z, RSA_MEM_Z_BLOCK_BASE, z_words);
}


/* Z = (X * Y) mod M

   Not an mbedTLS function
*/
void esp_mpi_mul_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  DPORT_REG_WRITE(RSA_M_DASH_REG, Mprime);

  start_op(RSA_MOD_MULT_START_REG);
}

/* Z = (X ^ Y) mod M
*/
void esp_mpi_exp_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  size_t y_bits = mbedtls_mpi_bitlen(Y);

  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);
  mpi_to_mem_block(RSA_MEM_M_BLOCK_BASE, M, num_words);
  mpi_to_mem_block(RSA_MEM_RB_BLOCK_BASE, Rinv, num_words);
  DPORT_REG_WRITE(RSA_M_DASH_REG, Mprime);

  /* Enable acceleration options */
  DPORT_REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
  DPORT_REG_WRITE(RSA_SEARCH_OPEN_REG, 1);
  DPORT_REG_WRITE(RSA_SEARCH_POS_REG, y_bits - 1);

  /* Execute first stage montgomery multiplication */
  start_op(RSA_MODEXP_START_REG);

  DPORT_REG_WRITE(RSA_SEARCH_OPEN_REG, 0);
}


/* Z = X * Y */
void esp_mpi_mul_mpi_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* Copy X (right-extended) & Y (left-extended) to memory block */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Z_BLOCK_BASE + num_words * 4, Y, num_words);
  /* NB: as Y is left-extended, we don't zero the bottom words_mult words of Y block.
     This is OK for now because zeroing is done by hardware when we do esp_mpi_acquire_hardware().
  */
  DPORT_REG_WRITE(RSA_LENGTH_REG, (num_words * 2 - 1));
  start_op(RSA_MULT_START_REG);
}



/**
   @brief Special-case of (X * Y), where we use hardware montgomery mod
   multiplication to calculate result where either A or B are >2048 bits so
   can't use the standard multiplication method.

*/
void esp_mpi_mult_mpi_failover_mod_mult_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* M = 2^num_words - 1, so block is entirely FF */
  for (size_t i = 0; i < num_words; i++) {
    DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + i * 4, UINT32_MAX);
  }

  /* Mprime = 1 */
  DPORT_REG_WRITE(RSA_M_DASH_REG, 1);
  DPORT_REG_WRITE(RSA_LENGTH_REG, num_words - 1);

  /* Load X & Y */
  mpi_to_mem_block(RSA_MEM_X_BLOCK_BASE, X, num_words);
  mpi_to_mem_block(RSA_MEM_Y_BLOCK_BASE, Y, num_words);

  /* Rinv = 1, write first word */
  DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 1);

  /* Zero out rest of the Rinv words */
  for (size_t i = 1; i < num_words; i++) {
    DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + i * 4, 0);
  }

  start_op(RSA_MOD_MULT_START_REG);
}

#elif defined(ARDUINO_ESP32C6_DEV)

/*
   Multi-precision integer library
   ESP32 C6 hardware accelerated parts based on mbedTLS implementation

   SPDX-FileCopyrightText: The Mbed TLS Contributors

   SPDX-License-Identifier: Apache-2.0

   SPDX-FileContributor: 2023 Espressif Systems (Shanghai) CO LTD
*/
#include <string.h>
#include <sys/param.h>
#include "soc/hwcrypto_periph.h"
#include "esp_private/periph_ctrl.h"
#include "mbedtls/bignum.h"
#include "bignum_impl.h"
#include "soc/pcr_reg.h"
#include "soc/periph_defs.h"
#include "soc/system_reg.h"
#include "esp_crypto_lock.h"


size_t esp_mpi_hardware_words(size_t words)
{
  return words;
}

void esp_mpi_enable_hardware_hw_op( void )
{
  esp_crypto_mpi_lock_acquire();

  /* Enable RSA hardware */
  periph_module_enable(PERIPH_RSA_MODULE);

  REG_CLR_BIT(PCR_RSA_PD_CTRL_REG, PCR_RSA_MEM_PD);

  while (REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
  }
  // Note: from enabling RSA clock to here takes about 1.3us

  REG_WRITE(RSA_INT_ENA_REG, 0);
}

void esp_mpi_disable_hardware_hw_op( void )
{
  REG_SET_BIT(PCR_RSA_PD_CTRL_REG, PCR_RSA_MEM_PD);

  /* Disable RSA hardware */
  periph_module_disable(PERIPH_RSA_MODULE);

  esp_crypto_mpi_lock_release();
}

void esp_mpi_interrupt_enable( bool enable )
{
  REG_WRITE(RSA_INT_ENA_REG, enable);
}

void esp_mpi_interrupt_clear( void )
{
  REG_WRITE(RSA_INT_CLR_REG, 1);
}

/* Copy mbedTLS MPI bignum 'mpi' to hardware memory block at 'mem_base'.

   If num_words is higher than the number of words in the bignum then
   these additional words will be zeroed in the memory buffer.
*/
static inline void mpi_to_mem_block(uint32_t mem_base, const mbedtls_mpi *mpi, size_t num_words)
{
  uint32_t *pbase = (uint32_t *)mem_base;
  uint32_t copy_words = MIN(num_words, mpi->MBEDTLS_PRIVATE(n));

  /* Copy MPI data to memory block registers */
  for (int i = 0; i < copy_words; i++) {
    pbase[i] = mpi->MBEDTLS_PRIVATE(p)[i];
  }

  /* Zero any remaining memory block data */
  for (int i = copy_words; i < num_words; i++) {
    pbase[i] = 0;
  }
}

/* Read mbedTLS MPI bignum back from hardware memory block.

   Reads num_words words from block.
*/
static inline void mem_block_to_mpi(mbedtls_mpi *x, uint32_t mem_base, int num_words)
{

  /* Copy data from memory block registers */
  const size_t REG_WIDTH = sizeof(uint32_t);
  for (size_t i = 0; i < num_words; i++) {
    x->MBEDTLS_PRIVATE(p)[i] = REG_READ(mem_base + (i * REG_WIDTH));
  }
  /* Zero any remaining limbs in the bignum, if the buffer is bigger
     than num_words */
  for (size_t i = num_words; i < x->MBEDTLS_PRIVATE(n); i++) {
    x->MBEDTLS_PRIVATE(p)[i] = 0;
  }
}



/* Begin an RSA operation. op_reg specifies which 'START' register
   to write to.
*/
static inline void start_op(uint32_t op_reg)
{
  /* Clear interrupt status */
  REG_WRITE(RSA_INT_CLR_REG, 1);

  /* Note: above REG_WRITE includes a memw, so we know any writes
     to the memory blocks are also complete. */

  REG_WRITE(op_reg, 1);
}

/* Wait for an RSA operation to complete.
*/
static inline void wait_op_complete(void)
{
  while (REG_READ(RSA_QUERY_IDLE_REG) != 1)
  { }

  /* clear the interrupt */
  REG_WRITE(RSA_INT_CLR_REG, 1);
}


/* Read result from last MPI operation */
void esp_mpi_read_result_hw_op(mbedtls_mpi *Z, size_t z_words)
{
  wait_op_complete();
  mem_block_to_mpi(Z, RSA_Z_MEM, z_words);
}


/* Z = (X * Y) mod M

   Not an mbedTLS function
*/
void esp_mpi_mul_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  REG_WRITE(RSA_MODE_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_X_MEM, X, num_words);
  mpi_to_mem_block(RSA_Y_MEM, Y, num_words);
  mpi_to_mem_block(RSA_M_MEM, M, num_words);
  mpi_to_mem_block(RSA_Z_MEM, Rinv, num_words);
  REG_WRITE(RSA_M_PRIME_REG, Mprime);

  start_op(RSA_SET_START_MODMULT_REG);
}

/* Z = (X ^ Y) mod M
*/
void esp_mpi_exp_mpi_mod_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, const mbedtls_mpi *M, const mbedtls_mpi *Rinv, mbedtls_mpi_uint Mprime, size_t num_words)
{
  size_t y_bits = mbedtls_mpi_bitlen(Y);

  REG_WRITE(RSA_MODE_REG, (num_words - 1));

  /* Load M, X, Rinv, Mprime (Mprime is mod 2^32) */
  mpi_to_mem_block(RSA_X_MEM, X, num_words);
  mpi_to_mem_block(RSA_Y_MEM, Y, num_words);
  mpi_to_mem_block(RSA_M_MEM, M, num_words);
  mpi_to_mem_block(RSA_Z_MEM, Rinv, num_words);
  REG_WRITE(RSA_M_PRIME_REG, Mprime);

  /* Enable acceleration options */
  REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
  REG_WRITE(RSA_SEARCH_ENABLE_REG, 1);
  REG_WRITE(RSA_SEARCH_POS_REG, y_bits - 1);

  /* Execute first stage montgomery multiplication */
  start_op(RSA_SET_START_MODEXP_REG);

  REG_WRITE(RSA_SEARCH_ENABLE_REG, 0);
}


/* Z = X * Y */
void esp_mpi_mul_mpi_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* Copy X (right-extended) & Y (left-extended) to memory block */
  mpi_to_mem_block(RSA_X_MEM, X, num_words);
  mpi_to_mem_block(RSA_Z_MEM + num_words * 4, Y, num_words);
  /* NB: as Y is left-exte, we don't zero the bottom words_mult words of Y block.
     This is OK for now bec zeroing is done by hardware when we do esp_mpi_acquire_hardware().
  */
  REG_WRITE(RSA_MODE_REG, (num_words * 2 - 1));
  start_op(RSA_SET_START_MULT_REG);
}



/**
   @brief Special-case of (X * Y), where we use hardware montgomery mod
   multiplication to calculate result where either A or B are >2048 bits so
   can't use the standard multiplication method.

*/
void esp_mpi_mult_mpi_failover_mod_mult_hw_op(const mbedtls_mpi *X, const mbedtls_mpi *Y, size_t num_words)
{
  /* M = 2^num_words - 1, so block is entirely FF */
  for (int i = 0; i < num_words; i++) {
    REG_WRITE(RSA_M_MEM + i * 4, UINT32_MAX);
  }

  /* Mprime = 1 */
  REG_WRITE(RSA_M_PRIME_REG, 1);
  REG_WRITE(RSA_MODE_REG, num_words - 1);

  /* Load X & Y */
  mpi_to_mem_block(RSA_X_MEM, X, num_words);
  mpi_to_mem_block(RSA_Y_MEM, Y, num_words);

  /* Rinv = 1, write first word */
  REG_WRITE(RSA_Z_MEM, 1);

  /* Zero out rest of the Rinv words */
  for (int i = 1; i < num_words; i++) {
    REG_WRITE(RSA_Z_MEM + i * 4, 0);
  }

  start_op(RSA_SET_START_MODMULT_REG);
}

#else

#define ESP_BIGNUM_UNAVAILABLE 1

#endif

#if !defined(ESP_BIGNUM_UNAVAILABLE)

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
    for (size_t i = base_hw_words; i < min((size_t) MAX_HW_WORDS, base_hw_words * 4); i++) {
        mbedtls_mpi_init(&mod->Rinv[i]);
        MBEDTLS_MPI_CHK(calculate_rinv(&mod->Rinv[i], M, i));
    }

cleanup:
    return ret;
}

int esp_mpi_mul_mpi_mod_rinv(mbedtls_mpi *Z, const mbedtls_mpi *X, const mbedtls_mpi *Y, const Modulus *mod)
{
    int ret = 0;
    const mbedtls_mpi *M = &mod->M;
    
    size_t x_bits = mbedtls_mpi_bitlen(X);
    size_t y_bits = mbedtls_mpi_bitlen(Y);
    size_t m_bits = mbedtls_mpi_bitlen(M);
    size_t z_bits = min(m_bits, x_bits + y_bits);
    size_t x_words = bits_to_words(x_bits);
    size_t y_words = bits_to_words(y_bits);
    size_t m_words = bits_to_words(m_bits);
    size_t z_words = bits_to_words(z_bits);
    size_t hw_words = esp_mpi_hardware_words(max(x_words, max(y_words, m_words))); /* longest operand */
    
    // Ensure hw_words is within the precomputed range
    if (hw_words >= MAX_HW_WORDS) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    esp_mpi_enable_hardware_hw_op();
    
    // Use the precomputed Rinv
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

#endif
#endif
