// Cryptographic_execution.cpp
#include <relic.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>

// Convert a chrono duration to seconds (double)
static double to_seconds(std::chrono::high_resolution_clock::duration d) {
  return std::chrono::duration<double>(d).count();
}

// Hash arbitrary bytes to a bn_t modulo 'order'
static void hash_to_zn(bn_t out, const uint8_t *data, size_t len, const bn_t order) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(data, len, digest);
  bn_read_bin(out, digest, SHA256_DIGEST_LENGTH);
  bn_mod_basic(out, out, order);
}

int main() {
  // 1) Initialize RELIC
  if (core_init() != RLC_OK) {
    std::cerr << "RELIC initialization failed\n";
    return 1;
  }
  ep_param_set_any_pairf();

  // 2) Fetch the group order
  bn_t order;
  bn_new(order);
  ep_curve_get_ord(order);

  // 3) Prepare some constants
  const int ITER_HASH_G1  = 1000000;
  const int ITER_HASH_G2  = 1000000;
  const int ITER_INV      = 1000000;
  const int ITER_EXP      = 1000000;
  const int ITER_RAND     = 1000000;
  const int ITER_PAIRING  = 1000000;
  const int ITER_SMUL     = 1000000;
  const int ITER_ADD      = 1000000;
  const int ITER_HASH_ZN  = 1000000;

  // For SHA-256 → ℤₚ
  const char *MSG = "example data for hashing";
  size_t MSG_LEN = std::strlen(MSG);

  // === 1. Hash → G1 ===
  std::vector<double> times_hashG1;
  times_hashG1.reserve(ITER_HASH_G1);
  double total_hashG1 = 0.0;

  for (int i = 0; i < ITER_HASH_G1; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    ep_t P; ep_new(P);
    // ep_map: hash-to-curve on G1
    ep_map(P, (const uint8_t*)MSG, MSG_LEN);
    auto t1 = std::chrono::high_resolution_clock::now();
    ep_free(P);
    double sec = to_seconds(t1 - t0);
    times_hashG1.push_back(sec);
    total_hashG1 += sec;
  }
  std::cout
    << "Average Hashing to G1 over " << ITER_HASH_G1
    << " iterations: " << (total_hashG1 / ITER_HASH_G1) << " seconds\n"
    << "Total Hashing to G1 execution time over " << ITER_HASH_G1
    << " iterations: " << total_hashG1 << " seconds\n\n";

  // === 2. Hash → G2 ===
  std::vector<double> times_hashG2;
  times_hashG2.reserve(ITER_HASH_G2);
  double total_hashG2 = 0.0;

  for (int i = 0; i < ITER_HASH_G2; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    ep2_t Q; ep2_new(Q);
    // ep2_map: hash-to-curve on G2
    ep2_map(Q, (const uint8_t*)MSG, MSG_LEN);
    auto t1 = std::chrono::high_resolution_clock::now();
    ep2_free(Q);
    double sec = to_seconds(t1 - t0);
    times_hashG2.push_back(sec);
    total_hashG2 += sec;
  }
  std::cout
    << "Average Hashing to G2 over " << ITER_HASH_G2
    << " iterations: " << (total_hashG2 / ITER_HASH_G2) << " seconds\n"
    << "Total Hashing to G2 execution time over " << ITER_HASH_G2
    << " iterations: " << total_hashG2 << " seconds\n\n";

  // === 3. Modular Inverse in Zp ===
  std::vector<double> times_inv;
  times_inv.reserve(ITER_INV);
  double total_inv = 0.0;

  // pick a random base
  bn_t base; bn_new(base);
  bn_rand_mod(base, order);

  for (int i = 0; i < ITER_INV; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bn_t inv; bn_new(inv);
    bn_mod_inv(inv, base, order);
    auto t1 = std::chrono::high_resolution_clock::now();
    bn_free(inv);
    double sec = to_seconds(t1 - t0);
    times_inv.push_back(sec);
    total_inv += sec;
  }
  std::cout
    << "Average Modular Inverse time over " << ITER_INV
    << " iterations: " << (total_inv / ITER_INV) << " seconds\n"
    << "Total Modular Inverse execution time over " << ITER_INV
    << " iterations: " << total_inv << " seconds\n\n";

  // === 4. Modular Exponentiation in Zp ===
  std::vector<double> times_exp;
  times_exp.reserve(ITER_EXP);
  double total_exp = 0.0;

  // pick random exponent
  bn_t exp_bn; bn_new(exp_bn);
  bn_rand_mod(exp_bn, order);

  for (int i = 0; i < ITER_EXP; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bn_t out; bn_new(out);
    // bn_mxp macro: out = base^exp_bn mod order
    bn_mxp(out, base, exp_bn, order);
    auto t1 = std::chrono::high_resolution_clock::now();
    bn_free(out);
    double sec = to_seconds(t1 - t0);
    times_exp.push_back(sec);
    total_exp += sec;
  }
  std::cout
    << "Average Modular Exponentiation time over " << ITER_EXP
    << " iterations: " << (total_exp / ITER_EXP) << " seconds\n"
    << "Total Modular Exponentiation execution time over " << ITER_EXP
    << " iterations: " << total_exp << " seconds\n\n";

  // === 5. Random Scalar Generation ===
  std::vector<double> times_rand;
  times_rand.reserve(ITER_RAND);
  double total_rand = 0.0;

  for (int i = 0; i < ITER_RAND; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bn_t r; bn_new(r);
    bn_rand_mod(r, order);
    auto t1 = std::chrono::high_resolution_clock::now();
    bn_free(r);
    double sec = to_seconds(t1 - t0);
    times_rand.push_back(sec);
    total_rand += sec;
  }
  std::cout
    << "Average Random Scalar time over " << ITER_RAND
    << " iterations: " << (total_rand / ITER_RAND) << " seconds\n"
    << "Total Random Scalar execution time over " << ITER_RAND
    << " iterations: " << total_rand << " seconds\n\n";

  // === 6. Bilinear Pairing ===
  std::vector<double> times_pair;
  times_pair.reserve(ITER_PAIRING);
  double total_pair = 0.0;

  // prepare pairing inputs
  ep_t  h1;  ep_new(h1);  ep_curve_get_gen(h1);
  ep2_t g2;  ep2_new(g2); ep2_curve_get_gen(g2);
  bn_t  gamma; bn_new(gamma); bn_rand_mod(gamma, order);
  ep2_t w;  ep2_new(w);  ep2_mul(w, g2, gamma);

  for (int i = 0; i < ITER_PAIRING; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    gt_t e; gt_new(e);
    pc_map(e, h1, w);
    auto t1 = std::chrono::high_resolution_clock::now();
    gt_free(e);
    double sec = to_seconds(t1 - t0);
    times_pair.push_back(sec);
    total_pair += sec;
  }
  std::cout
    << "Average pairing time over " << ITER_PAIRING
    << " iterations: " << (total_pair / ITER_PAIRING) << " seconds\n"
    << "Total Pairing execution time over " << ITER_PAIRING
    << " iterations: " << total_pair << " seconds\n\n";

  // === 7. Scalar Multiplication in G1 ===
  std::vector<double> times_smul;
  times_smul.reserve(ITER_SMUL);
  double total_smul = 0.0;

  for (int i = 0; i < ITER_SMUL; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    ep_t R; ep_new(R);
    ep_mul(R, h1, gamma);
    auto t1 = std::chrono::high_resolution_clock::now();
    ep_free(R);
    double sec = to_seconds(t1 - t0);
    times_smul.push_back(sec);
    total_smul += sec;
  }
  std::cout
    << "Average Scalar multiplication time over " << ITER_SMUL
    << " iterations: " << (total_smul / ITER_SMUL) << " seconds\n"
    << "Total Scalar multiplication execution time over " << ITER_SMUL
    << " iterations: " << total_smul << " seconds\n\n";

  // === 8. Point Addition in G1 ===
  std::vector<double> times_add;
  times_add.reserve(ITER_ADD);
  double total_add = 0.0;

  for (int i = 0; i < ITER_ADD; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    ep_t R; ep_new(R);
    ep_add(R, h1, h1);
    auto t1 = std::chrono::high_resolution_clock::now();
    ep_free(R);
    double sec = to_seconds(t1 - t0);
    times_add.push_back(sec);
    total_add += sec;
  }
  std::cout
    << "Average Point Addition time over " << ITER_ADD
    << " iterations: " << (total_add / ITER_ADD) << " seconds\n"
    << "Total Point Addition execution time over " << ITER_ADD
    << " iterations: " << total_add << " seconds\n\n";

  // === 9. SHA-256 → Zp ===
  std::vector<double> times_hashZn;
  times_hashZn.reserve(ITER_HASH_ZN);
  double total_hashZn = 0.0;

  for (int i = 0; i < ITER_HASH_ZN; i++) {
    auto t0 = std::chrono::high_resolution_clock::now();
    bn_t z; bn_new(z);
    hash_to_zn(z, (const uint8_t*)MSG, MSG_LEN, order);
    auto t1 = std::chrono::high_resolution_clock::now();
    bn_free(z);
    double sec = to_seconds(t1 - t0);
    times_hashZn.push_back(sec);
    total_hashZn += sec;
  }
  std::cout
    << "Average Hashing time over " << ITER_HASH_ZN
    << " iterations: " << (total_hashZn / ITER_HASH_ZN) << " seconds\n"
    << "Total Hashing execution time over " << ITER_HASH_ZN
    << " iterations: " << total_hashZn << " seconds\n\n";

  // 4) Clean up RELIC
  core_clean();
  return 0;
}
