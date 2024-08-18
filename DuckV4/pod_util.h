#ifndef __POD_UTIL__
#define __POD_UTIL__


#include <mbedtls/bignum.h>
#include "poseidon_constants.h"
#include "esp_bignum.h"
#include "mbedtls/sha256.h"


// Define a struct for representing points in projective coordinates
typedef struct {
  mbedtls_mpi X;
  mbedtls_mpi Y;
  mbedtls_mpi Z;
} Point;

mbedtls_mpi BjP, Order, SubOrder, BjA, BjD, pm1d2;
Point Base8;
Modulus Pmod;
mbedtls_mpi FIVE_BIGNUM;
mbedtls_mpi temp1, temp2, temp3, temp4, inv_result;
mbedtls_mpi x1y2, y1x2, x1x2, y1y2, BjDx1x2y1y2;



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

void cleanup_babyjub_constants() {
  mbedtls_mpi_free(&FIVE_BIGNUM);
  mbedtls_mpi_free(&pm1d2);
  mbedtls_mpi_free(&BjP);
  mbedtls_mpi_free(&Base8.X); mbedtls_mpi_free(&Base8.Y); mbedtls_mpi_free(&Base8.Z);

  mbedtls_mpi_free(&Order);
  mbedtls_mpi_free(&SubOrder); mbedtls_mpi_free(&BjA); mbedtls_mpi_free(&BjD);
}


// Initialize constants
void init_babyjub_constants(void) {

  mbedtls_mpi_init(&FIVE_BIGNUM);
  mbedtls_mpi_lset(&FIVE_BIGNUM, 5);

  mbedtls_mpi_init(&temp1); mbedtls_mpi_init(&temp2);
  mbedtls_mpi_init(&temp3); mbedtls_mpi_init(&temp4);
  mbedtls_mpi_init(&inv_result);
  mbedtls_mpi_init(&x1y2); mbedtls_mpi_init(&y1x2);
  mbedtls_mpi_init(&x1x2); mbedtls_mpi_init(&y1y2);
  mbedtls_mpi_init(&BjDx1x2y1y2);


  mbedtls_mpi_init(&BjP);
  mbedtls_mpi_init(&Order);
  mbedtls_mpi_init(&SubOrder);
  mbedtls_mpi_init(&BjA);
  mbedtls_mpi_init(&BjD);
  mbedtls_mpi_init(&pm1d2);

  mbedtls_mpi_read_string(&pm1d2, 10, "10944121435919637611123202872628637544274182200208017171849102093287904247808");


  mbedtls_mpi_read_string(&BjP, 10, "21888242871839275222246405745257275088548364400416034343698204186575808495617");
  mbedtls_mpi_read_string(&Order, 10, "21888242871839275222246405745257275088614511777268538073601725287587578984328");
  mbedtls_mpi_copy(&SubOrder, &Order);
  mbedtls_mpi_shift_r(&SubOrder, 3);


  mbedtls_mpi_lset(&BjA, 168700);
  mbedtls_mpi_lset(&BjD, 168696);

  mbedtls_mpi_init(&Base8.X); mbedtls_mpi_init(&Base8.Y); mbedtls_mpi_init(&Base8.Z);
  mbedtls_mpi_read_string(&Base8.X, 10, "5299619240641551281634865583518297030282874472190772894086521144482721001553");
  mbedtls_mpi_read_string(&Base8.Y, 10, "16950150798460657717958625567821834550301663161624707787222815936182638968203");
  mbedtls_mpi_lset(&Base8.Z, 1);

  esp_mpi_mul_mpi_mod_init(&Pmod, &BjP);
}





#if !defined(ESP_BIGNUM_UNAVAILABLE)

void poseidon(mbedtls_mpi *result, const mbedtls_mpi *inputs, size_t num_inputs) {
  mbedtls_mpi temp, RR;
  mbedtls_mpi state[MAX_INPUTS + 1], s2[MAX_INPUTS + 1];
  size_t t = num_inputs + 1;
  size_t coff = POSEIDON_C_OFF[t - 2];
  size_t moff = (2 * t * t * t - 3 * t * t + t - 6) / 6;

  mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&RR);

  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_init(&state[i]);
    mbedtls_mpi_init(&s2[i]);
  }

  // Initialize state
  mbedtls_mpi_lset(&state[0], 0);
  for (size_t i = 1; i < t; i++) {
    mbedtls_mpi_copy(&state[i], &inputs[i - 1]);
  }

  for (size_t r = 0; r < 8 + N_ROUNDS_P[t - 2]; r++) {
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_read_binary(&temp, POSEIDON_C[coff + r * t + i], 32);
      mbedtls_mpi_add_mpi(&state[i], &state[i], &temp);
      mbedtls_mpi_mod_mpi(&state[i], &state[i], &BjP);

      if (i == 0 || r < 4 || r >= 4 + N_ROUNDS_P[t - 2]) {
        mbedtls_mpi_exp_mod(&state[i], &state[i], &FIVE_BIGNUM, &BjP, &RR);
      }
    }

    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_lset(&s2[i], 0);
      for (size_t j = 0; j < t; j++) {
        mbedtls_mpi_read_binary(&temp, POSEIDON_M[moff + t * i + j], 32);
        esp_mpi_mul_mpi_mod_rinv(&temp, &temp, &state[j], &Pmod);
        mbedtls_mpi_add_mpi(&s2[i], &s2[i], &temp);
        mbedtls_mpi_mod_mpi(&s2[i], &s2[i], &BjP);
      }
    }
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_copy(&state[i], &s2[i]);
    }
  }

  mbedtls_mpi_copy(result, &state[0]);
  mbedtls_mpi_mod_mpi(result, result, &BjP);

  // Free allocated memory
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&RR);
  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_free(&state[i]);
    mbedtls_mpi_free(&s2[i]);
  }
}

#else



void poseidon(mbedtls_mpi *result, const mbedtls_mpi *inputs, size_t num_inputs) {
  mbedtls_mpi temp, RR;
  mbedtls_mpi state[MAX_INPUTS + 1], s2[MAX_INPUTS + 1];
  size_t t = num_inputs + 1;
  size_t coff = POSEIDON_C_OFF[t - 2];
  size_t moff = (2 * t * t * t - 3 * t * t + t - 6) / 6;

  mbedtls_mpi_init(&temp);
  mbedtls_mpi_init(&RR);

  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_init(&state[i]);
    mbedtls_mpi_init(&s2[i]);
  }

  // Initialize state
  mbedtls_mpi_lset(&state[0], 0);
  for (size_t i = 1; i < t; i++) {
    mbedtls_mpi_copy(&state[i], &inputs[i - 1]);
  }

  for (size_t r = 0; r < 8 + N_ROUNDS_P[t - 2]; r++) {
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_read_binary(&temp, POSEIDON_C[coff + r * t + i], 32);
      mbedtls_mpi_add_mpi(&state[i], &state[i], &temp);
      mbedtls_mpi_mod_mpi(&state[i], &state[i], &BjP);

      if (i == 0 || r < 4 || r >= 4 + N_ROUNDS_P[t - 2]) {
        mbedtls_mpi_exp_mod(&state[i], &state[i], &FIVE_BIGNUM, &BjP, &RR);
      }
    }

    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_lset(&s2[i], 0);
      for (size_t j = 0; j < t; j++) {
        mbedtls_mpi_read_binary(&temp, POSEIDON_M[moff + t * i + j], 32);
        mbedtls_mpi_mul_mpi(&temp2, &temp, &state[j]);
        mbedtls_mpi_mod_mpi(&temp2, &temp2, &BjP);
        mbedtls_mpi_add_mpi(&s2[i], &s2[i], &temp2);
        mbedtls_mpi_mod_mpi(&s2[i], &s2[i], &BjP);
      }
    }
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_copy(&state[i], &s2[i]);
    }
  }

  mbedtls_mpi_copy(result, &state[0]);
  mbedtls_mpi_mod_mpi(result, result, &BjP);

  // Free allocated memory
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&RR);
  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_free(&state[i]);
    mbedtls_mpi_free(&s2[i]);
  }
}

#endif



#if !defined(ESP_BIGNUM_UNAVAILABLE)


static int ecp_normalize_bjxyz(const Point *P, Point *R)
{
    int ret = 0;
    mbedtls_mpi Zi, temp;
    mbedtls_mpi_init(&Zi);
    mbedtls_mpi_init(&temp);

    if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
        mbedtls_mpi_lset(&R->X, 0);
        mbedtls_mpi_lset(&R->Y, 1);
        mbedtls_mpi_lset(&R->Z, 0);
    } else {
        ret = mbedtls_mpi_inv_mod(&Zi, &P->Z, &BjP);
        if (ret != 0) goto cleanup;

        esp_mpi_mul_mpi_mod_rinv(&R->X, &P->X, &Zi, &Pmod);
        esp_mpi_mul_mpi_mod_rinv(&R->Y, &P->Y, &Zi, &Pmod);
        mbedtls_mpi_lset(&R->Z, 1);
    }

cleanup:
    mbedtls_mpi_free(&Zi);
    mbedtls_mpi_free(&temp);
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
    esp_mpi_mul_mpi_mod_rinv(&A, &P->Z, &Q->Z, &Pmod);

    // B = A^2
    esp_mpi_mul_mpi_mod_rinv(&B, &A, &A, &Pmod);

    // C = X1 * X2
    esp_mpi_mul_mpi_mod_rinv(&C, &P->X, &Q->X, &Pmod);

    // D = Y1 * Y2
    esp_mpi_mul_mpi_mod_rinv(&D, &P->Y, &Q->Y, &Pmod);

    // E = d * C * D
    esp_mpi_mul_mpi_mod_rinv(&temp1, &C, &D, &Pmod);
    esp_mpi_mul_mpi_mod_rinv(&E, &temp1, &BjD, &Pmod);

    // F = B - E
    mbedtls_mpi_sub_mpi(&F, &B, &E);
    mbedtls_mpi_mod_mpi(&F, &F, &BjP);

    // G = B + E
    mbedtls_mpi_add_mpi(&G, &B, &E);
    mbedtls_mpi_mod_mpi(&G, &G, &BjP);

    // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
    mbedtls_mpi_add_mpi(&temp1, &P->X, &P->Y);
    mbedtls_mpi_add_mpi(&temp2, &Q->X, &Q->Y);
    esp_mpi_mul_mpi_mod_rinv(&R->X, &temp1, &temp2, &Pmod);
    mbedtls_mpi_sub_mpi(&R->X, &R->X, &C);
    mbedtls_mpi_sub_mpi(&R->X, &R->X, &D);
    esp_mpi_mul_mpi_mod_rinv(&temp1, &R->X, &F, &Pmod);
    esp_mpi_mul_mpi_mod_rinv(&R->X, &temp1, &A, &Pmod);

    // Y3 = A * G * (D - a * C)
    esp_mpi_mul_mpi_mod_rinv(&temp1, &BjA, &C, &Pmod);
    mbedtls_mpi_sub_mpi(&R->Y, &D, &temp1);
    mbedtls_mpi_mod_mpi(&R->Y, &R->Y, &BjP);
    esp_mpi_mul_mpi_mod_rinv(&temp1, &R->Y, &G, &Pmod);
    esp_mpi_mul_mpi_mod_rinv(&R->Y, &temp1, &A, &Pmod);

    // Z3 = F * G
    esp_mpi_mul_mpi_mod_rinv(&R->Z, &F, &G, &Pmod);

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
    esp_mpi_mul_mpi_mod_rinv(&B, &temp1, &temp1, &Pmod);

    // C = X1^2
    esp_mpi_mul_mpi_mod_rinv(&C, &P->X, &P->X, &Pmod);

    // D = Y1^2
    esp_mpi_mul_mpi_mod_rinv(&D, &P->Y, &P->Y, &Pmod);

    // E = a * C
    esp_mpi_mul_mpi_mod_rinv(&E, &BjA, &C, &Pmod);

    // F = E + D
    mbedtls_mpi_add_mpi(&F, &E, &D);
    mbedtls_mpi_mod_mpi(&F, &F, &BjP);

    // J = F - 2 * (Z1^2)
    esp_mpi_mul_mpi_mod_rinv(&temp1, &P->Z, &P->Z, &Pmod);
    mbedtls_mpi_mul_int(&temp2, &temp1, 2);
    mbedtls_mpi_sub_mpi(&J, &F, &temp2);
    mbedtls_mpi_mod_mpi(&J, &J, &BjP);

    // X3 = (B - C - D) * J
    mbedtls_mpi_sub_mpi(&temp1, &B, &C);
    mbedtls_mpi_sub_mpi(&temp1, &temp1, &D);
    esp_mpi_mul_mpi_mod_rinv(&R->X, &temp1, &J, &Pmod);

    // Y3 = F * (E - D)
    mbedtls_mpi_sub_mpi(&temp1, &E, &D);
    esp_mpi_mul_mpi_mod_rinv(&R->Y, &temp1, &F, &Pmod);

    // Z3 = F * J
    esp_mpi_mul_mpi_mod_rinv(&R->Z, &F, &J, &Pmod);

    mbedtls_mpi_free(&B); mbedtls_mpi_free(&C); mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E); mbedtls_mpi_free(&F); mbedtls_mpi_free(&J);
    mbedtls_mpi_free(&temp1); mbedtls_mpi_free(&temp2);

    return ret;
}

#else



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

    mbedtls_mpi_mul_mpi(&R->X, &P->X, &Zi);
    mbedtls_mpi_mod_mpi(&R->X, &R->X, &BjP);

    mbedtls_mpi_mul_mpi(&R->Y, &P->Y, &Zi);
    mbedtls_mpi_mod_mpi(&R->Y, &R->Y, &BjP);

    mbedtls_mpi_lset(&R->Z, 1);
  }

cleanup:
  mbedtls_mpi_free(&Zi);
  return ret;
}


static int ecp_add_bjxyz(Point *R, const Point *P, const Point *Q)
{
  int ret = 0;
  mbedtls_mpi A, B, C, D, E, F, G;

  mbedtls_mpi_init(&A); mbedtls_mpi_init(&B); mbedtls_mpi_init(&C);
  mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&F);
  mbedtls_mpi_init(&G);

  // A = Z1 * Z2
  mbedtls_mpi_mul_mpi(&A, &P->Z, &Q->Z);
  mbedtls_mpi_mod_mpi(&A, &A, &BjP);

  // B = A^2
  mbedtls_mpi_mul_mpi(&B, &A, &A);
  mbedtls_mpi_mod_mpi(&B, &B, &BjP);

  // C = X1 * X2
  mbedtls_mpi_mul_mpi(&C, &P->X, &Q->X);
  mbedtls_mpi_mod_mpi(&C, &C, &BjP);

  // D = Y1 * Y2
  mbedtls_mpi_mul_mpi(&D, &P->Y, &Q->Y);
  mbedtls_mpi_mod_mpi(&D, &D, &BjP);

  // E = d * C * D
  mbedtls_mpi_mul_mpi(&E, &C, &D);
  mbedtls_mpi_mul_mpi(&E, &E, &BjD);
  mbedtls_mpi_mod_mpi(&E, &E, &BjP);

  // F = B - E
  mbedtls_mpi_sub_mpi(&F, &B, &E);
  mbedtls_mpi_mod_mpi(&F, &F, &BjP);

  // G = B + E
  mbedtls_mpi_add_mpi(&G, &B, &E);
  mbedtls_mpi_mod_mpi(&G, &G, &BjP);

  // X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D)
  mbedtls_mpi_add_mpi(&temp1, &P->X, &P->Y);
  mbedtls_mpi_add_mpi(&temp2, &Q->X, &Q->Y);
  mbedtls_mpi_mul_mpi(&R->X, &temp1, &temp2);
  mbedtls_mpi_sub_mpi(&R->X, &R->X, &C);
  mbedtls_mpi_sub_mpi(&R->X, &R->X, &D);
  mbedtls_mpi_mul_mpi(&R->X, &R->X, &F);
  mbedtls_mpi_mul_mpi(&R->X, &R->X, &A);
  mbedtls_mpi_mod_mpi(&R->X, &R->X, &BjP);

  // Y3 = A * G * (D - a * C)
  mbedtls_mpi_mul_mpi(&R->Y, &BjA, &C);
  mbedtls_mpi_sub_mpi(&R->Y, &D, &R->Y);
  mbedtls_mpi_mul_mpi(&R->Y, &R->Y, &G);
  mbedtls_mpi_mul_mpi(&R->Y, &R->Y, &A);
  mbedtls_mpi_mod_mpi(&R->Y, &R->Y, &BjP);

  // Z3 = F * G
  mbedtls_mpi_mul_mpi(&R->Z, &F, &G);
  mbedtls_mpi_mod_mpi(&R->Z, &R->Z, &BjP);

  mbedtls_mpi_free(&A); mbedtls_mpi_free(&B); mbedtls_mpi_free(&C);
  mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&F);
  mbedtls_mpi_free(&G);

  return ret;
}

static int ecp_double_bjxyz(Point *R, const Point *P)
{
  int ret = 0;
  mbedtls_mpi A, B, C, D, E, F, J;

  mbedtls_mpi_init(&A); mbedtls_mpi_init(&B); mbedtls_mpi_init(&C);
  mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&F);
  mbedtls_mpi_init(&J);

  // B = (X1 + Y1)^2
  mbedtls_mpi_add_mpi(&B, &P->X, &P->Y);
  mbedtls_mpi_mul_mpi(&B, &B, &B);
  mbedtls_mpi_mod_mpi(&B, &B, &BjP);

  // C = X1^2
  mbedtls_mpi_mul_mpi(&C, &P->X, &P->X);
  mbedtls_mpi_mod_mpi(&C, &C, &BjP);

  // D = Y1^2
  mbedtls_mpi_mul_mpi(&D, &P->Y, &P->Y);
  mbedtls_mpi_mod_mpi(&D, &D, &BjP);

  // E = a * C
  mbedtls_mpi_mul_mpi(&E, &BjA, &C);
  mbedtls_mpi_mod_mpi(&E, &E, &BjP);

  // F = E + D
  mbedtls_mpi_add_mpi(&F, &E, &D);
  mbedtls_mpi_mod_mpi(&F, &F, &BjP);

  // J = F - 2 * (Z1^2)
  mbedtls_mpi_mul_mpi(&J, &P->Z, &P->Z);
  mbedtls_mpi_mul_int(&J, &J, 2);
  mbedtls_mpi_sub_mpi(&J, &F, &J);
  mbedtls_mpi_mod_mpi(&J, &J, &BjP);

  // X3 = (B - C - D) * J
  mbedtls_mpi_sub_mpi(&R->X, &B, &C);
  mbedtls_mpi_sub_mpi(&R->X, &R->X, &D);
  mbedtls_mpi_mul_mpi(&R->X, &R->X, &J);
  mbedtls_mpi_mod_mpi(&R->X, &R->X, &BjP);

  // Y3 = F * (E - D)
  mbedtls_mpi_sub_mpi(&R->Y, &E, &D);
  mbedtls_mpi_mul_mpi(&R->Y, &R->Y, &F);
  mbedtls_mpi_mod_mpi(&R->Y, &R->Y, &BjP);

  // Z3 = F * J
  mbedtls_mpi_mul_mpi(&R->Z, &F, &J);
  mbedtls_mpi_mod_mpi(&R->Z, &R->Z, &BjP);

  mbedtls_mpi_free(&A); mbedtls_mpi_free(&B); mbedtls_mpi_free(&C);
  mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&F);
  mbedtls_mpi_free(&J);

  return ret;
}



#endif


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



#endif
