#pragma once


#include <mbedtls/bignum.h>
#include "poseidon.h"
#include "modmul.h"
#include "mbedtls/sha256.h"


void reverse_endianness(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size / 2; i++) {
    uint8_t temp = buffer[i];
    buffer[i] = buffer[size - 1 - i];
    buffer[size - 1 - i] = temp;
  }
}


String urlEncode(const String& input) {
  const char *hexChars = "0123456789ABCDEF";
  String output = "";

  for (int i = 0; i < input.length(); i++) {
    char c = input.charAt(i);
    if (isAlphaNumeric(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      output += c;
    } else {
      output += '%';
      output += hexChars[(c >> 4) & 0xF];
      output += hexChars[c & 0xF];
    }
  }

  return output;
}



String generateUUID() {
  const char* hexChars = "0123456789abcdef";
  String uuid = "";

  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      uuid += "-";
    } else if (i == 14) {
      uuid += "4"; // Version 4 UUID
    } else if (i == 19) {
      uuid += hexChars[esp_random() % 4 + 8]; // 8, 9, a, or b for variant
    } else {
      uuid += hexChars[esp_random() % 16];
    }
  }

  return uuid;
}


void sha256_hash_mpi(mbedtls_mpi *result, const char *input, size_t input_len) {
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0); // 0 for SHA-256
  mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)input, input_len);
  unsigned char key_hash[32];
  mbedtls_sha256_finish(&sha256_ctx, key_hash);
  mbedtls_sha256_free(&sha256_ctx);
  mbedtls_mpi_read_binary(result, key_hash, 32);
  mbedtls_mpi_shift_r(result, 8);
}




#include "mbedtls/bignum.h"
#include "esp_bignum.h"




// Define a struct for representing points in projective coordinates
typedef struct {
  mbedtls_mpi X;
  mbedtls_mpi Y;
  mbedtls_mpi Z;
} Point;

mbedtls_mpi Order, SubOrder, pm1d2;
mbedtls_mpi BjP, BjA, BjD;
Point Base8;
bool initialized_babyjub_constants = false;

void ensure_babyjub_constants(){
    if(!initialized_babyjub_constants){
        mbedtls_mpi_init(&BjP);
        mbedtls_mpi_read_string(&BjP, 10, "21888242871839275222246405745257275088548364400416034343698204186575808495617");

        mbedtls_mpi_init(&BjA);
        mbedtls_mpi_init(&BjD);
        mbedtls_mpi_lset(&BjA, 168700);
        mbedtls_mpi_lset(&BjD, 168696);

        mbedtls_mpi_init(&Base8.X); mbedtls_mpi_init(&Base8.Y); mbedtls_mpi_init(&Base8.Z);
        mbedtls_mpi_read_string(&Base8.X, 10, "5299619240641551281634865583518297030282874472190772894086521144482721001553");
        mbedtls_mpi_read_string(&Base8.Y, 10, "16950150798460657717958625567821834550301663161624707787222815936182638968203");
        mbedtls_mpi_lset(&Base8.Z, 1);

        mbedtls_mpi_read_string(&Order, 10, "21888242871839275222246405745257275088614511777268538073601725287587578984328");
        mbedtls_mpi_copy(&SubOrder, &Order);
        mbedtls_mpi_shift_r(&SubOrder, 3);

        mbedtls_mpi_read_string(&pm1d2, 10, "10944121435919637611123202872628637544274182200208017171849102093287904247808");
  
        initialized_babyjub_constants = true;
    }
}


static int ecp_normalize_bjxyz(const Point *P, Point *R)
{
  int ret = 0;
  mbedtls_mpi Zi;
  mbedtls_mpi_init(&Zi);

  if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
    mbedtls_mpi_lset(&R->X, 0);
    mbedtls_mpi_lset(&R->Y, 1);
    mbedtls_mpi_lset(&R->Z, 0);
  } else {
    ret = mbedtls_mpi_inv_mod(&Zi, &P->Z, &BjP);
    if (ret != 0) goto cleanup;

    mpi_mul_mpi_mod(&R->X, &P->X, &Zi, &BjP);
    mpi_mul_mpi_mod(&R->Y, &P->Y, &Zi, &BjP);
    mbedtls_mpi_lset(&R->Z, 1);
  }

cleanup:
  mbedtls_mpi_free(&Zi);
  return ret;
}

static int ecp_add_bjxyz(Point *R, const Point *P, const Point *Q)
{
  int ret = 0;
  mbedtls_mpi A, B, C, D, E, F, G, temp1, temp2;

  mbedtls_mpi_init(&A); mbedtls_mpi_init(&B); mbedtls_mpi_init(&C);
  mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&F);
  mbedtls_mpi_init(&G); mbedtls_mpi_init(&temp1); mbedtls_mpi_init(&temp2);

  // A = Z1 * Z2
  mpi_mul_mpi_mod(&A, &P->Z, &Q->Z, &BjP);

  // B = A^2
  mpi_mul_mpi_mod(&B, &A, &A, &BjP);

  // C = X1 * X2
  mpi_mul_mpi_mod(&C, &P->X, &Q->X, &BjP);

  // D = Y1 * Y2
  mpi_mul_mpi_mod(&D, &P->Y, &Q->Y, &BjP);

  // E = d * C * D
  mpi_mul_mpi_mod(&temp1, &C, &D, &BjP);
  mpi_mul_mpi_mod(&E, &temp1, &BjD, &BjP);

  // F = B - E
  mbedtls_mpi_sub_mpi(&F, &B, &E);
  mbedtls_mpi_mod_mpi(&F, &F, &BjP);

  // G = B + E
  mbedtls_mpi_add_mpi(&G, &B, &E);
  mbedtls_mpi_mod_mpi(&G, &G, &BjP);

  // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
  mbedtls_mpi_add_mpi(&temp1, &P->X, &P->Y);
  mbedtls_mpi_add_mpi(&temp2, &Q->X, &Q->Y);
  mpi_mul_mpi_mod(&R->X, &temp1, &temp2, &BjP);
  mbedtls_mpi_sub_mpi(&R->X, &R->X, &C);
  mbedtls_mpi_sub_mpi(&R->X, &R->X, &D);
  mpi_mul_mpi_mod(&temp1, &R->X, &F, &BjP);
  mpi_mul_mpi_mod(&R->X, &temp1, &A, &BjP);

  // Y3 = A * G * (D - a * C)
  mpi_mul_mpi_mod(&temp1, &BjA, &C, &BjP);
  mbedtls_mpi_sub_mpi(&R->Y, &D, &temp1);
  mbedtls_mpi_mod_mpi(&R->Y, &R->Y, &BjP);
  mpi_mul_mpi_mod(&temp1, &R->Y, &G, &BjP);
  mpi_mul_mpi_mod(&R->Y, &temp1, &A, &BjP);

  // Z3 = F * G
  mpi_mul_mpi_mod(&R->Z, &F, &G, &BjP);

  mbedtls_mpi_free(&A); mbedtls_mpi_free(&B); mbedtls_mpi_free(&C);
  mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&F);
  mbedtls_mpi_free(&G); mbedtls_mpi_free(&temp1); mbedtls_mpi_free(&temp2);

  return ret;
}

static int ecp_double_bjxyz(Point *R, const Point *P)
{
  int ret = 0;
  mbedtls_mpi B, C, D, E, F, J, temp1, temp2;

  mbedtls_mpi_init(&B); mbedtls_mpi_init(&C); mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E); mbedtls_mpi_init(&F); mbedtls_mpi_init(&J);
  mbedtls_mpi_init(&temp1); mbedtls_mpi_init(&temp2);

  // B = (X1 + Y1)^2
  mbedtls_mpi_add_mpi(&temp1, &P->X, &P->Y);
  mpi_mul_mpi_mod(&B, &temp1, &temp1, &BjP);

  // C = X1^2
  mpi_mul_mpi_mod(&C, &P->X, &P->X, &BjP);

  // D = Y1^2
  mpi_mul_mpi_mod(&D, &P->Y, &P->Y, &BjP);

  // E = a * C
  mpi_mul_mpi_mod(&E, &BjA, &C, &BjP);

  // F = E + D
  mbedtls_mpi_add_mpi(&F, &E, &D);
  mbedtls_mpi_mod_mpi(&F, &F, &BjP);

  // J = F - 2 * (Z1^2)
  mpi_mul_mpi_mod(&temp1, &P->Z, &P->Z, &BjP);
  mbedtls_mpi_mul_int(&temp2, &temp1, 2);
  mbedtls_mpi_sub_mpi(&J, &F, &temp2);
  mbedtls_mpi_mod_mpi(&J, &J, &BjP);

  // X3 = (B - C - D) * J
  mbedtls_mpi_sub_mpi(&temp1, &B, &C);
  mbedtls_mpi_sub_mpi(&temp1, &temp1, &D);
  mpi_mul_mpi_mod(&R->X, &temp1, &J, &BjP);

  // Y3 = F * (E - D)
  mbedtls_mpi_sub_mpi(&temp1, &E, &D);
  mpi_mul_mpi_mod(&R->Y, &temp1, &F, &BjP);

  // Z3 = F * J
  mpi_mul_mpi_mod(&R->Z, &F, &J, &BjP);

  mbedtls_mpi_free(&B); mbedtls_mpi_free(&C); mbedtls_mpi_free(&D);
  mbedtls_mpi_free(&E); mbedtls_mpi_free(&F); mbedtls_mpi_free(&J);
  mbedtls_mpi_free(&temp1); mbedtls_mpi_free(&temp2);

  return ret;
}





void multiply_bj(Point *result, const Point *pt, const mbedtls_mpi *n)
{
    Point R, RP, temp_result;
    mbedtls_mpi_init(&R.X); mbedtls_mpi_init(&R.Y); mbedtls_mpi_init(&R.Z);
    mbedtls_mpi_init(&RP.X); mbedtls_mpi_init(&RP.Y); mbedtls_mpi_init(&RP.Z);
    mbedtls_mpi_init(&temp_result.X); mbedtls_mpi_init(&temp_result.Y); mbedtls_mpi_init(&temp_result.Z);

    // Set R to zero point
    mbedtls_mpi_lset(&R.X, 0);
    mbedtls_mpi_lset(&R.Y, 1);
    mbedtls_mpi_lset(&R.Z, 1);

    // Copy input point to RP
    mbedtls_mpi_copy(&RP.X, &pt->X);
    mbedtls_mpi_copy(&RP.Y, &pt->Y);
    mbedtls_mpi_copy(&RP.Z, &pt->Z);

    // Montgomery ladder
    for (int i = mbedtls_mpi_bitlen(n) - 1; i >= 0; i--) {
        int bit = mbedtls_mpi_get_bit(n, i);
        
        if (bit) {
            ecp_add_bjxyz(&R, &R, &RP);
            ecp_double_bjxyz(&RP, &RP);
        } else {
            ecp_add_bjxyz(&RP, &RP, &R);
            ecp_double_bjxyz(&R, &R);
        }
    }

    // Normalize the result
    ecp_normalize_bjxyz(&R, &temp_result);

    
    mbedtls_mpi_mod_mpi(&temp_result.X, &temp_result.X, &BjP);
    mbedtls_mpi_mod_mpi(&temp_result.Y, &temp_result.Y, &BjP);


    // Copy normalized result to output
    mbedtls_mpi_copy(&result->X, &temp_result.X);
    mbedtls_mpi_copy(&result->Y, &temp_result.Y);
    mbedtls_mpi_copy(&result->Z, &temp_result.Z);

    // Clean up
    mbedtls_mpi_free(&R.X); mbedtls_mpi_free(&R.Y); mbedtls_mpi_free(&R.Z);
    mbedtls_mpi_free(&RP.X); mbedtls_mpi_free(&RP.Y); mbedtls_mpi_free(&RP.Z);
    mbedtls_mpi_free(&temp_result.X); mbedtls_mpi_free(&temp_result.Y); mbedtls_mpi_free(&temp_result.Z);
}
