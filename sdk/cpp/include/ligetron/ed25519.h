/*
 * copyright (c) 2026 Soundness Labs Ltd.
 *
 * licensed under the apache license, version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * you may obtain a copy of the license at
 *
 *     http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 */

#ifndef __LIGETRON_ED25519__
#define __LIGETRON_ED25519__

#include <cstdio>
#include <ligetron/bn254fr_class.h>
#include <ligetron/vbn254fr_class.h>
#include <stddef.h>
#include <stdint.h>
#include <string>

namespace ligetron {

// ======================================================================
// ed25519
// ======================================================================
struct ed25519 {
  uint8_t bytes[32];

  ed25519();
  void set_from_bytes(const uint8_t *in, size_t len);
  void set_from_decimal(const std::string &decimal);
  void to_bytes(uint8_t *out) const;
  static std::string le32_to_decimal(const uint8_t *bytes);

  // Ed25519 curve constants
  const static ed25519 field_modulus();      // q = 2^255 - 19
  const static ed25519 scalar_field_order(); // r = curve order
  const static ed25519 coeff_a();            // a = -1
  const static ed25519 coeff_d();            // d = -121665/121666
  const static ed25519 generator_x();        // Generator point X coordinate
  const static ed25519 generator_y();        // Generator point Y coordinate
  const static ed25519 cofactor();           // COFACTOR = 8
  const static ed25519 cofactor_inv();       // COFACTOR_INV (mod r)

  void print_hex() const;
  void print_dec() const;
};

// ======================================================================
// ed25519_emulated
// ======================================================================
// Emulated representation of ed25519 (non-native field arithmetic) over bn254
// (native) using 3 limbs where each limb has 85 bits.
struct ed25519_emulated {
  const static size_t NUM_LIMBS = 3;
  const static size_t BITS_PER_LIMB = 85;
  const static size_t MODULUS_BIT_SIZE = 255;

  const static ed25519_emulated field_modulus();

  bn254fr_class
      limbs[NUM_LIMBS]; // Limbs in big-endian order (highest limb first)
  size_t num_additions; // Track additions for reduction decisions
  bool is_normalized;   // Whether the representation is fully reduced

  void set_from_hex(const char *hex_string);
  void set_from_bytes(const uint8_t *bytes, size_t len);
  void to_bytes(uint8_t *bytes) const;

  static void to_limbs(const ed25519 &target, bn254fr_class limbs[NUM_LIMBS]);
  static void to_limbs_bn254(bn254fr_class &target,
                             bn254fr_class limbs[NUM_LIMBS]);
  static ed25519 from_limbs(const bn254fr_class limbs[NUM_LIMBS]);

  // Reconstruct a value from 3 limbs in base 2^85 (big-endian limb order).
  // out = limbs[0]*base^2 + limbs[1]*base + limbs[2], where base = 2^85 (mod
  // p).
  // Obtain the target field element value of a emulated field element
  static ed25519 to_ed25519(const ed25519_emulated &emulated);

  static ed25519_emulated to_emulated(const ed25519 &target);

  const static ed25519_emulated zero();
  const static ed25519_emulated one();
  const static ed25519_emulated two();
  const static ed25519_emulated three();

  // Ed25519 generator point coordinates (as BN254 field elements)
  // in extended coordinates (X, Y, Z, T) = (X, Y, Z, X * Y / Z)
  const static ed25519_emulated generator_x(); // Generator point X coordinate
  const static ed25519_emulated generator_y(); // Generator point Y coordinate
  const static ed25519_emulated generator_z(); // Generator point Z coordinate
  const static ed25519_emulated generator_t(); // Generator point T = X * Y / Z

  ed25519_emulated add(const ed25519_emulated &other) const;
  ed25519_emulated sub(const ed25519_emulated &other) const;
  ed25519_emulated mul(const ed25519_emulated &other) const;
  ed25519_emulated mul_k(const ed25519_emulated &other) const;

  ed25519_emulated negate() const;
  ed25519_emulated inverse() const;
  ed25519_emulated square() const;

  ed25519_emulated reduce(const ed25519_emulated &elem) const;

  void print_limbs_hex(const char *label = nullptr) const;
  void print_limbs_dec(const char *label = nullptr) const;
  void debug_print_limbs(const char *label = nullptr) const;
  void debug_print_value(const char *label = nullptr) const;
}; // struct ed25519_emulated
//
// ======================================================================
// ed25519_point
// ======================================================================
// Extended coordinates for Ed25519 points (X, Y, Z, T) where T = X * Y/Z
//
struct ed25519_point {
  ed25519_emulated x, y, z, t;

  ed25519_point();
  ed25519_point(const ed25519_emulated &x, const ed25519_emulated &y,
                const ed25519_emulated &z, const ed25519_emulated &t);

  static ed25519_point zero();
  static ed25519_point generator();

  static ed25519_point point_add(const ed25519_point &p1,
                                 const ed25519_point &p2);
  static ed25519_point point_double(const ed25519_point &p);
  static ed25519_point point_negate(const ed25519_point &p);

static ed25519_point scalar_mul(const ed25519_point &p,
                                  const ed25519 &scalar);
  
  // Optimized scalar multiplication for generator point
  static ed25519_point scalar_mul_generator(const ed25519 &scalar);
  
  // Montgomery ladder for constant-time scalar multiplication
  static ed25519_point scalar_mul_montgomery(const ed25519_point &p,
                                            const ed25519 &scalar);
  
  // Precomputed generator multiples for windowed multiplication
  static const ed25519_point* get_generator_table();

  void to_affine(ed25519_emulated &affine_x, ed25519_emulated &affine_y) const;

  void debug_print(const char *label = nullptr) const;
}; // struct ed25519_point

} // namespace ligetron

#endif // __LIGETRON_ED25519__