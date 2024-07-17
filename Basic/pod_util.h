#ifndef __POD_UTIL__
#define __POD_UTIL__


#include <mbedtls/bignum.h>
#include "poseidon_constants.h"
#include "esp_bignum.h"
#include "mbedtls/sha256.h"

// Define a struct for representing points
typedef struct {
  mbedtls_mpi x;
  mbedtls_mpi y;
} Point;

mbedtls_mpi P, Order, SubOrder, BjA, BjD, pm1d2;
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
  mbedtls_mpi_free(&Base8.x); mbedtls_mpi_free(&Base8.y);
  mbedtls_mpi_free(&P); mbedtls_mpi_free(&Order);
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

  
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&Order);
  mbedtls_mpi_init(&SubOrder);
  mbedtls_mpi_init(&BjA);
  mbedtls_mpi_init(&BjD);
  mbedtls_mpi_init(&pm1d2);

  mbedtls_mpi_read_string(&pm1d2, 10, "10944121435919637611123202872628637544274182200208017171849102093287904247808");
  mbedtls_mpi_read_string(&P, 10, "21888242871839275222246405745257275088548364400416034343698204186575808495617");
  mbedtls_mpi_read_string(&Order, 10, "21888242871839275222246405745257275088614511777268538073601725287587578984328");
  mbedtls_mpi_copy(&SubOrder, &Order);
  mbedtls_mpi_shift_r(&SubOrder, 3);
  mbedtls_mpi_lset(&BjA, 168700);
  mbedtls_mpi_lset(&BjD, 168696);

  mbedtls_mpi_init(&Base8.x); mbedtls_mpi_init(&Base8.y);
  mbedtls_mpi_read_string(&Base8.x, 10, "5299619240641551281634865583518297030282874472190772894086521144482721001553");
  mbedtls_mpi_read_string(&Base8.y, 10, "16950150798460657717958625567821834550301663161624707787222815936182638968203");

  esp_mpi_mul_mpi_mod_init(&Pmod, &P);
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
      mbedtls_mpi_mod_mpi(&state[i], &state[i], &P);

      if (i == 0 || r < 4 || r >= 4 + N_ROUNDS_P[t - 2]) {
        mbedtls_mpi_exp_mod(&state[i], &state[i], &FIVE_BIGNUM, &P, &RR);
      }
    }

    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_lset(&s2[i], 0);
      for (size_t j = 0; j < t; j++) {
        mbedtls_mpi_read_binary(&temp, POSEIDON_M[moff + t * i + j], 32);
        esp_mpi_mul_mpi_mod_rinv(&temp, &temp, &state[j], &Pmod);
        mbedtls_mpi_add_mpi(&s2[i], &s2[i], &temp);
        mbedtls_mpi_mod_mpi(&s2[i], &s2[i], &P);
      }
    }
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_copy(&state[i], &s2[i]);
    }
  }

  mbedtls_mpi_copy(result, &state[0]);
  mbedtls_mpi_mod_mpi(result, result, &P);

  // Free allocated memory
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&RR);
  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_free(&state[i]);
    mbedtls_mpi_free(&s2[i]);
  }
}


void add_bj(Point *result, const Point *p1, const Point *p2) {
  // Calculate and store x1y2 and y1x2
  esp_mpi_mul_mpi_mod_rinv(&x1y2, &p1->x, &p2->y, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&y1x2, &p1->y, &p2->x, &Pmod);

  // Calculate x3 = ((x1y2 + y1x2) % P) * inv((1 + BjD x1 x2 y1 y2) % P, P)
  mbedtls_mpi_add_mpi(&temp3, &x1y2, &y1x2);
  mbedtls_mpi_mod_mpi(&temp3, &temp3, &P);

  // Calculate x1x2 and y1y2
  esp_mpi_mul_mpi_mod_rinv(&x1x2, &p1->x, &p2->x, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&y1y2, &p1->y, &p2->y, &Pmod);

  // Calculate BjDx1x2y1y2
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &y1y2, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&BjDx1x2y1y2, &temp1, &BjD, &Pmod);

  // Calculate (1 + BjD x1 x2 y1 y2) % P
  mbedtls_mpi_add_int(&temp1, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp1, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->x, &temp3, &inv_result, &Pmod);

  // Calculate y3 = ((y1y2 - BjAx1x2) % P) * inv((P + 1 - BjDx1x2y1y2) % P, P)
  esp_mpi_mul_mpi_mod_rinv(&temp2, &x1x2, &BjA, &Pmod);
  mbedtls_mpi_sub_mpi(&temp4, &y1y2, &temp2);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);

  // Reuse BjDx1x2y1y2 to calculate (P + 1 - BjDx1x2y1y2) % P
  mbedtls_mpi_sub_mpi(&temp1, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp2, &temp1, 1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp2, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->y, &temp4, &inv_result, &Pmod);
}

void double_bj(Point *result, const Point *p) {
  // Calculate x^2, y^2, and xy
  esp_mpi_mul_mpi_mod_rinv(&x1x2, &p->x, &p->x, &Pmod);  // x^2
  esp_mpi_mul_mpi_mod_rinv(&y1y2, &p->y, &p->y, &Pmod);  // y^2
  esp_mpi_mul_mpi_mod_rinv(&x1y2, &p->x, &p->y, &Pmod);  // xy

  // Calculate BjDx^2y^2
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &y1y2, &Pmod);
  esp_mpi_mul_mpi_mod_rinv(&BjDx1x2y1y2, &temp1, &BjD, &Pmod);

  // Calculate x3 = (2xy % P) * inv((1 + BjDx^2y^2) % P, P)
  mbedtls_mpi_add_mpi(&temp1, &x1y2, &x1y2);  // temp1 = 2xy
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);
  mbedtls_mpi_add_int(&temp2, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp2, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->x, &temp1, &inv_result, &Pmod);

  // Calculate y3 = ((y^2 - BjAx^2) % P) * inv((P + 1 - BjDx^2y^2) % P, P)
  esp_mpi_mul_mpi_mod_rinv(&temp1, &x1x2, &BjA, &Pmod);
  mbedtls_mpi_sub_mpi(&temp2, &y1y2, &temp1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
  mbedtls_mpi_sub_mpi(&temp3, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp4, &temp3, 1);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp4, &P);
  esp_mpi_mul_mpi_mod_rinv(&result->y, &temp2, &inv_result, &Pmod);
}



// Scalar multiplication on Baby Jubjub curve (corrected iterative version)
void multiply_bj(Point *result, const Point *pt, const mbedtls_mpi *n) {
  Point R, T;
  mbedtls_mpi_init(&R.x); mbedtls_mpi_init(&R.y);
  mbedtls_mpi_init(&T.x); mbedtls_mpi_init(&T.y);

  // Initialize R as the input point
  mbedtls_mpi_copy(&R.x, &pt->x);
  mbedtls_mpi_copy(&R.y, &pt->y);

  // Initialize T as the point at infinity (0, 1)
  mbedtls_mpi_lset(&T.x, 0);
  mbedtls_mpi_lset(&T.y, 1);

  // Iterate through each bit of n, from least significant to most
  for (int i = 0; i < mbedtls_mpi_bitlen(n); i++) {
    // If the current bit of n is 1, add R to T
    if (mbedtls_mpi_get_bit(n, i)) {
      add_bj(&T, &T, &R);
    }
    double_bj(&R, &R);
  }

  // Copy the result to the output
  mbedtls_mpi_copy(&result->x, &T.x);
  mbedtls_mpi_copy(&result->y, &T.y);

  // Clean up
  mbedtls_mpi_free(&R.x); mbedtls_mpi_free(&R.y);
  mbedtls_mpi_free(&T.x); mbedtls_mpi_free(&T.y);
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
      mbedtls_mpi_mod_mpi(&state[i], &state[i], &P);

      if (i == 0 || r < 4 || r >= 4 + N_ROUNDS_P[t - 2]) {
        mbedtls_mpi_exp_mod(&state[i], &state[i], &FIVE_BIGNUM, &P, &RR);
      }
    }

    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_lset(&s2[i], 0);
      for (size_t j = 0; j < t; j++) {
        mbedtls_mpi_read_binary(&temp, POSEIDON_M[moff + t * i + j], 32);
        mbedtls_mpi_mul_mpi(&temp2, &temp, &state[j]);
        mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
        mbedtls_mpi_add_mpi(&s2[i], &s2[i], &temp2);
        mbedtls_mpi_mod_mpi(&s2[i], &s2[i], &P);
      }
    }
    for (size_t i = 0; i < t; i++) {
      mbedtls_mpi_copy(&state[i], &s2[i]);
    }
  }

  mbedtls_mpi_copy(result, &state[0]);
  mbedtls_mpi_mod_mpi(result, result, &P);

  // Free allocated memory
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&RR);
  for (size_t i = 0; i < t; i++) {
    mbedtls_mpi_free(&state[i]);
    mbedtls_mpi_free(&s2[i]);
  }
}


// 7509ms for multiply
void add_bj(Point *result, const Point *p1, const Point *p2) {
  // Calculate and store x1y2 and y1x2
  mbedtls_mpi_mul_mpi(&x1y2, &p1->x, &p2->y);
  mbedtls_mpi_mul_mpi(&y1x2, &p1->y, &p2->x);

  // Calculate x3 = ((x1y2 + y1x2) % P) * inv((1 + BjD x1 x2 y1 y2) % P, P)
  mbedtls_mpi_add_mpi(&temp3, &x1y2, &y1x2);
  mbedtls_mpi_mod_mpi(&temp3, &temp3, &P);

  // Calculate x1x2 and y1y2
  mbedtls_mpi_mul_mpi(&x1x2, &p1->x, &p2->x);
  mbedtls_mpi_mul_mpi(&y1y2, &p1->y, &p2->y);

  // Calculate BjDx1x2y1y2
  mbedtls_mpi_mul_mpi(&temp1, &x1x2, &y1y2);
  mbedtls_mpi_mul_mpi(&BjDx1x2y1y2, &temp1, &BjD);

  // Calculate (1 + BjD x1 x2 y1 y2) % P
  mbedtls_mpi_add_int(&temp1, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp1, &P);
  mbedtls_mpi_mul_mpi(&result->x, &temp3, &inv_result);
  mbedtls_mpi_mod_mpi(&result->x, &result->x, &P);

  // Calculate y3 = ((y1y2 - BjAx1x2) % P) * inv((P + 1 - BjDx1x2y1y2) % P, P)
  mbedtls_mpi_mul_mpi(&temp2, &x1x2, &BjA);
  mbedtls_mpi_sub_mpi(&temp4, &y1y2, &temp2);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);

  // Reuse BjDx1x2y1y2 to calculate (P + 1 - BjDx1x2y1y2) % P
  mbedtls_mpi_sub_mpi(&temp1, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp2, &temp1, 1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);

  mbedtls_mpi_inv_mod(&inv_result, &temp2, &P);
  mbedtls_mpi_mul_mpi(&result->y, &temp4, &inv_result);
  mbedtls_mpi_mod_mpi(&result->y, &result->y, &P);

}


void double_bj(Point *result, const Point *p) {
  // Calculate x^2, y^2, and xy
  mbedtls_mpi_mul_mpi(&x1x2, &p->x, &p->x);
  mbedtls_mpi_mod_mpi(&x1x2, &x1x2, &P);  // x^2
  mbedtls_mpi_mul_mpi(&y1y2, &p->y, &p->y);
  mbedtls_mpi_mod_mpi(&y1y2, &y1y2, &P);  // y^2
  mbedtls_mpi_mul_mpi(&x1y2, &p->x, &p->y);
  mbedtls_mpi_mod_mpi(&x1y2, &x1y2, &P);  // xy

  // Calculate BjDx^2y^2
  mbedtls_mpi_mul_mpi(&temp1, &x1x2, &y1y2);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);
  mbedtls_mpi_mul_mpi(&BjDx1x2y1y2, &temp1, &BjD);
  mbedtls_mpi_mod_mpi(&BjDx1x2y1y2, &BjDx1x2y1y2, &P);

  // Calculate x3 = (2xy % P) * inv((1 + BjDx^2y^2) % P, P)
  mbedtls_mpi_lset(&temp1, 2);
  mbedtls_mpi_mul_mpi(&temp2, &temp1, &x1y2);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);  // temp2 = 2xy % P
  mbedtls_mpi_add_int(&temp1, &BjDx1x2y1y2, 1);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp1, &P);
  mbedtls_mpi_mul_mpi(&result->x, &temp2, &inv_result);
  mbedtls_mpi_mod_mpi(&result->x, &result->x, &P);

  // Calculate y3 = ((y^2 - BjAx^2) % P) * inv((P + 1 - BjDx^2y^2) % P, P)
  mbedtls_mpi_mul_mpi(&temp1, &x1x2, &BjA);
  mbedtls_mpi_mod_mpi(&temp1, &temp1, &P);
  mbedtls_mpi_sub_mpi(&temp2, &y1y2, &temp1);
  mbedtls_mpi_mod_mpi(&temp2, &temp2, &P);
  mbedtls_mpi_sub_mpi(&temp3, &P, &BjDx1x2y1y2);
  mbedtls_mpi_add_int(&temp4, &temp3, 1);
  mbedtls_mpi_mod_mpi(&temp4, &temp4, &P);
  mbedtls_mpi_inv_mod(&inv_result, &temp4, &P);
  mbedtls_mpi_mul_mpi(&result->y, &temp2, &inv_result);
  mbedtls_mpi_mod_mpi(&result->y, &result->y, &P);
}


// Scalar multiplication on Baby Jubjub curve (corrected iterative version)
void multiply_bj(Point *result, const Point *pt, const mbedtls_mpi *n) {
  Point R, T;
  mbedtls_mpi_init(&R.x); mbedtls_mpi_init(&R.y);
  mbedtls_mpi_init(&T.x); mbedtls_mpi_init(&T.y);

  // Initialize R as the input point
  mbedtls_mpi_copy(&R.x, &pt->x);
  mbedtls_mpi_copy(&R.y, &pt->y);

  // Initialize T as the point at infinity (0, 1)
  mbedtls_mpi_lset(&T.x, 0);
  mbedtls_mpi_lset(&T.y, 1);

  // Iterate through each bit of n, from least significant to most
  for (int i = 0; i < mbedtls_mpi_bitlen(n); i++) {
    // If the current bit of n is 1, add R to T
    if (mbedtls_mpi_get_bit(n, i)) {
      add_bj(&T, &T, &R);
    }
    double_bj(&R, &R);
  }

  // Copy the result to the output
  mbedtls_mpi_copy(&result->x, &T.x);
  mbedtls_mpi_copy(&result->y, &T.y);

  // Clean up
  mbedtls_mpi_free(&R.x); mbedtls_mpi_free(&R.y);
  mbedtls_mpi_free(&T.x); mbedtls_mpi_free(&T.y);
}

#endif

#endif
