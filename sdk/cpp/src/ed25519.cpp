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

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ligetron/ed25519.h>
#include <vector>
/*
ed25519 is the emulated field for the ed25519 curve over bn254.
It is defined as the field of 2^252 + 27742317777372353535851937790883648493.
It is represented as a 3-limb big-endian representation in base 2^85.
The limbs are stored in the limbs array.
The num_additions field tracks the number of additions done over this gadget,
using which the gadget decides when to reduce.
The is_normalized field tracks whether the limb representation is the normal
form (using only the bits specified in the parameters, and the representation
is strictly within the range of bn254fr_class).
*/


namespace ligetron {
// ======================================================================
// ed25519
// ======================================================================
ed25519::ed25519() {
  for (size_t i = 0; i < 32; ++i)
    bytes[i] = 0;
}

void ed25519::set_from_bytes(const uint8_t *in, size_t len) {
  // Expect big-endian input up to 32 bytes; store as 32 bytes little-endian in
  // bytes
  for (size_t i = 0; i < 32; ++i)
    bytes[i] = 0;
  if (!in || len == 0)
    return;
  size_t n = (len > 32) ? 32 : len;
  for (size_t i = 0; i < n; ++i) {
    // place msb first into end of buffer
    bytes[i] = in[n - 1 - i];
  }
}

void ed25519::set_from_decimal(const std::string &decimal) {
  for (int i = 0; i < 32; ++i) {
    bytes[i] = 0;
  }

  if (decimal == "0" || decimal.empty()) {
    return;
  }

  for (char c : decimal) {
    if (c < '0' || c > '9') {
      return;
    }
  }

  std::vector<uint8_t> result(32, 0);
  std::string current = decimal;

  int byte_index = 0;
  while (!current.empty() && byte_index < 32) {
    std::string quotient;
    uint32_t remainder = 0;

    for (char digit : current) {
      remainder = remainder * 10 + (digit - '0');
      if (!quotient.empty() || remainder >= 256) {
        quotient.push_back('0' + (remainder / 256));
        remainder %= 256;
      }
    }

    result[byte_index] = static_cast<uint8_t>(remainder);
    byte_index++;

    current = quotient;
  }

  ed25519 field_mod = ed25519::field_modulus();

  bool need_reduction = false;
  for (int i = 31; i >= 0; --i) {
    if (result[i] > field_mod.bytes[i]) {
      need_reduction = true;
      break;
    } else if (result[i] < field_mod.bytes[i]) {
      break;
    }
  }

  if (need_reduction) {
    int16_t borrow = 0;
    for (int i = 0; i < 32; ++i) {
      int16_t diff = result[i] - field_mod.bytes[i] - borrow;
      if (diff < 0) {
        diff += 256;
        borrow = 1;
      } else {
        borrow = 0;
      }
      result[i] = static_cast<uint8_t>(diff);
    }
  }

  for (int i = 0; i < 32; ++i) {
    bytes[i] = result[i];
  }
}

void ed25519::to_bytes(uint8_t *out) const {
  // Return 32 bytes little-endian
  for (size_t i = 0; i < 32; ++i)
    out[i] = bytes[i];
}

// Convert 32-byte little-endian buffer to decimal string
std::string ed25519::le32_to_decimal(const uint8_t *bytes) {
  std::vector<uint8_t> n(bytes, bytes + 32); // little-endian
  std::string digits;
  // Remove leading zeros check
  auto is_zero = [&]() {
    for (int i = 0; i < 32; ++i)
      if (n[i] != 0)
        return false;
    return true;
  };
  if (is_zero())
    return std::string("0");
  while (!is_zero()) {
    uint32_t carry = 0;
    for (int i = 31; i >= 0; --i) {
      uint32_t cur = (carry << 8) | n[i];
      n[i] = static_cast<uint8_t>(cur / 10u);
      carry = cur % 10u;
    }
    digits.push_back(static_cast<char>('0' + carry));
  }
  std::reverse(digits.begin(), digits.end());
  return digits;
}

/*
Ed25519 curve constants implementation
These values are taken from Arkworks ED25519 implementation:
https://github.com/arkworks-rs/algebra/blob/851d4680491ed97fb09b5410893c2e12377b2bec/curves/ed25519/src/curves/mod.rs

Field modulus: q = 2^255 - 19 =
57896044618658097711785492504343953926634992332820282019728792003956564819949
In hex (big-endian):
0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
*/
const ed25519 ed25519::field_modulus() {
  ed25519 p;
  // Little-endian representation of 2^255 - 19
  p.bytes[0] = 0xed;
  p.bytes[1] = 0xff;
  p.bytes[2] = 0xff;
  p.bytes[3] = 0xff;
  p.bytes[4] = 0xff;
  p.bytes[5] = 0xff;
  p.bytes[6] = 0xff;
  p.bytes[7] = 0xff;
  p.bytes[8] = 0xff;
  p.bytes[9] = 0xff;
  p.bytes[10] = 0xff;
  p.bytes[11] = 0xff;
  p.bytes[12] = 0xff;
  p.bytes[13] = 0xff;
  p.bytes[14] = 0xff;
  p.bytes[15] = 0xff;
  p.bytes[16] = 0xff;
  p.bytes[17] = 0xff;
  p.bytes[18] = 0xff;
  p.bytes[19] = 0xff;
  p.bytes[20] = 0xff;
  p.bytes[21] = 0xff;
  p.bytes[22] = 0xff;
  p.bytes[23] = 0xff;
  p.bytes[24] = 0xff;
  p.bytes[25] = 0xff;
  p.bytes[26] = 0xff;
  p.bytes[27] = 0xff;
  p.bytes[28] = 0xff;
  p.bytes[29] = 0xff;
  p.bytes[30] = 0xff;
  p.bytes[31] = 0x7f;
  return p;
}

/*
Scalar field order: r =
7237005577332262213973186563042994240857116359379907606001950938285454250989
In hex (big-endian):
0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
*/
const ed25519 ed25519::scalar_field_order() {
  ed25519 r;
  // Little-endian representation
  r.bytes[0] = 0xed;
  r.bytes[1] = 0xd3;
  r.bytes[2] = 0xf5;
  r.bytes[3] = 0x5c;
  r.bytes[4] = 0x1a;
  r.bytes[5] = 0x63;
  r.bytes[6] = 0x12;
  r.bytes[7] = 0x58;
  r.bytes[8] = 0xd6;
  r.bytes[9] = 0x9c;
  r.bytes[10] = 0xf7;
  r.bytes[11] = 0xa2;
  r.bytes[12] = 0xde;
  r.bytes[13] = 0xf9;
  r.bytes[14] = 0xde;
  r.bytes[15] = 0x14;
  r.bytes[16] = 0x00;
  r.bytes[17] = 0x00;
  r.bytes[18] = 0x00;
  r.bytes[19] = 0x00;
  r.bytes[20] = 0x00;
  r.bytes[21] = 0x00;
  r.bytes[22] = 0x00;
  r.bytes[23] = 0x00;
  r.bytes[24] = 0x00;
  r.bytes[25] = 0x00;
  r.bytes[26] = 0x00;
  r.bytes[27] = 0x00;
  r.bytes[28] = 0x00;
  r.bytes[29] = 0x00;
  r.bytes[30] = 0x00;
  r.bytes[31] = 0x10;
  return r;
}

/*
Coefficient A: a = -1 (mod p)
-1 mod p = p - 1 = 2^255 - 20
In hex (big-endian):
0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
*/
const ed25519 ed25519::coeff_a() {
  ed25519 a;
  // Little-endian representation of -1 mod p
  a.bytes[0] = 0xec;
  a.bytes[1] = 0xff;
  a.bytes[2] = 0xff;
  a.bytes[3] = 0xff;
  a.bytes[4] = 0xff;
  a.bytes[5] = 0xff;
  a.bytes[6] = 0xff;
  a.bytes[7] = 0xff;
  a.bytes[8] = 0xff;
  a.bytes[9] = 0xff;
  a.bytes[10] = 0xff;
  a.bytes[11] = 0xff;
  a.bytes[12] = 0xff;
  a.bytes[13] = 0xff;
  a.bytes[14] = 0xff;
  a.bytes[15] = 0xff;
  a.bytes[16] = 0xff;
  a.bytes[17] = 0xff;
  a.bytes[18] = 0xff;
  a.bytes[19] = 0xff;
  a.bytes[20] = 0xff;
  a.bytes[21] = 0xff;
  a.bytes[22] = 0xff;
  a.bytes[23] = 0xff;
  a.bytes[24] = 0xff;
  a.bytes[25] = 0xff;
  a.bytes[26] = 0xff;
  a.bytes[27] = 0xff;
  a.bytes[28] = 0xff;
  a.bytes[29] = 0xff;
  a.bytes[30] = 0xff;
  a.bytes[31] = 0x7f;
  return a;
}

/*
Coefficient D: d = -121665/121666 =
37095705934669439343138083508754565189542113879843219016388785533085940283555
In hex (big-endian):
0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
*/
const ed25519 ed25519::coeff_d() {
  ed25519 d;
  // Little-endian representation
  d.bytes[0] = 0xa3;
  d.bytes[1] = 0x78;
  d.bytes[2] = 0x59;
  d.bytes[3] = 0x13;
  d.bytes[4] = 0xca;
  d.bytes[5] = 0x4d;
  d.bytes[6] = 0xeb;
  d.bytes[7] = 0x75;
  d.bytes[8] = 0xab;
  d.bytes[9] = 0xd8;
  d.bytes[10] = 0x41;
  d.bytes[11] = 0x41;
  d.bytes[12] = 0x4d;
  d.bytes[13] = 0x0a;
  d.bytes[14] = 0x70;
  d.bytes[15] = 0x00;
  d.bytes[16] = 0x98;
  d.bytes[17] = 0xe8;
  d.bytes[18] = 0x79;
  d.bytes[19] = 0x77;
  d.bytes[20] = 0x79;
  d.bytes[21] = 0x40;
  d.bytes[22] = 0xc7;
  d.bytes[23] = 0x8c;
  d.bytes[24] = 0x73;
  d.bytes[25] = 0xfe;
  d.bytes[26] = 0x6f;
  d.bytes[27] = 0x2b;
  d.bytes[28] = 0xee;
  d.bytes[29] = 0x6c;
  d.bytes[30] = 0x03;
  d.bytes[31] = 0x52;
  return d;
}

/*
Generator X coordinate:
15112221349535400772501151409588531511454012693041857206046113283949847762202
In hex (big-endian):
0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
*/
const ed25519 ed25519::generator_x() {
  ed25519 gx;
  // Little-endian representation
  gx.bytes[0] = 0x1a;
  gx.bytes[1] = 0xd5;
  gx.bytes[2] = 0x25;
  gx.bytes[3] = 0x8f;
  gx.bytes[4] = 0x60;
  gx.bytes[5] = 0x2d;
  gx.bytes[6] = 0x56;
  gx.bytes[7] = 0xc9;
  gx.bytes[8] = 0xb2;
  gx.bytes[9] = 0xa7;
  gx.bytes[10] = 0x25;
  gx.bytes[11] = 0x95;
  gx.bytes[12] = 0x60;
  gx.bytes[13] = 0xc7;
  gx.bytes[14] = 0x2c;
  gx.bytes[15] = 0x69;
  gx.bytes[16] = 0x5c;
  gx.bytes[17] = 0xdc;
  gx.bytes[18] = 0xd6;
  gx.bytes[19] = 0xfd;
  gx.bytes[20] = 0x31;
  gx.bytes[21] = 0xe2;
  gx.bytes[22] = 0xa4;
  gx.bytes[23] = 0xc0;
  gx.bytes[24] = 0xfe;
  gx.bytes[25] = 0x53;
  gx.bytes[26] = 0x6e;
  gx.bytes[27] = 0xcd;
  gx.bytes[28] = 0xd3;
  gx.bytes[29] = 0x36;
  gx.bytes[30] = 0x69;
  gx.bytes[31] = 0x21;
  return gx;
}

/*
Generator Y coordinate:
46316835694926478169428394003475163141307993866256225615783033603165251855960
In hex (big-endian):
0x6666666666666666666666666666666666666666666666666666666666666658
*/
const ed25519 ed25519::generator_y() {
  ed25519 gy;
  // Little-endian representation (this is 4/5 mod p)
  gy.bytes[0] = 0x58;
  gy.bytes[1] = 0x66;
  gy.bytes[2] = 0x66;
  gy.bytes[3] = 0x66;
  gy.bytes[4] = 0x66;
  gy.bytes[5] = 0x66;
  gy.bytes[6] = 0x66;
  gy.bytes[7] = 0x66;
  gy.bytes[8] = 0x66;
  gy.bytes[9] = 0x66;
  gy.bytes[10] = 0x66;
  gy.bytes[11] = 0x66;
  gy.bytes[12] = 0x66;
  gy.bytes[13] = 0x66;
  gy.bytes[14] = 0x66;
  gy.bytes[15] = 0x66;
  gy.bytes[16] = 0x66;
  gy.bytes[17] = 0x66;
  gy.bytes[18] = 0x66;
  gy.bytes[19] = 0x66;
  gy.bytes[20] = 0x66;
  gy.bytes[21] = 0x66;
  gy.bytes[22] = 0x66;
  gy.bytes[23] = 0x66;
  gy.bytes[24] = 0x66;
  gy.bytes[25] = 0x66;
  gy.bytes[26] = 0x66;
  gy.bytes[27] = 0x66;
  gy.bytes[28] = 0x66;
  gy.bytes[29] = 0x66;
  gy.bytes[30] = 0x66;
  gy.bytes[31] = 0x66;
  return gy;
}

// Cofactor: 8
const ed25519 ed25519::cofactor() {
  ed25519 h;
  memset(h.bytes, 0, 32);
  h.bytes[0] = 8; // Little-endian representation of 8
  return h;
}

/*
Cofactor inverse (mod r):
2713877091499598330239944961141122840321418634767465352250731601857045344121
In hex (big-endian):
0x06000000000000000000000000000000053bda402fffe5bfeffffffff00000001
*/
const ed25519 ed25519::cofactor_inv() {
  ed25519 hinv;
  // Little-endian representation
  hinv.bytes[0] = 0x01;
  hinv.bytes[1] = 0x00;
  hinv.bytes[2] = 0x00;
  hinv.bytes[3] = 0x00;
  hinv.bytes[4] = 0xff;
  hinv.bytes[5] = 0xff;
  hinv.bytes[6] = 0xff;
  hinv.bytes[7] = 0xff;
  hinv.bytes[8] = 0xfe;
  hinv.bytes[9] = 0x5b;
  hinv.bytes[10] = 0xff;
  hinv.bytes[11] = 0x2f;
  hinv.bytes[12] = 0x40;
  hinv.bytes[13] = 0xa4;
  hinv.bytes[14] = 0xbd;
  hinv.bytes[15] = 0x53;
  hinv.bytes[16] = 0x00;
  hinv.bytes[17] = 0x00;
  hinv.bytes[18] = 0x00;
  hinv.bytes[19] = 0x00;
  hinv.bytes[20] = 0x00;
  hinv.bytes[21] = 0x00;
  hinv.bytes[22] = 0x00;
  hinv.bytes[23] = 0x00;
  hinv.bytes[24] = 0x00;
  hinv.bytes[25] = 0x00;
  hinv.bytes[26] = 0x00;
  hinv.bytes[27] = 0x00;
  hinv.bytes[28] = 0x00;
  hinv.bytes[29] = 0x00;
  hinv.bytes[30] = 0x00;
  hinv.bytes[31] = 0x06;
  return hinv;
}

// ===== ed25519_emulated generator functions =====
const ed25519_emulated ed25519_emulated::field_modulus() {
  ed25519_emulated modulus;
  to_limbs(ed25519::field_modulus(), modulus.limbs);
  return modulus;
}

// Ed25519 generator X coordinate as BN254 field elements
const ed25519_emulated ed25519_emulated::generator_x() {
  ed25519_emulated gx;
  // Use the actual Ed25519 generator X coordinate and convert to limbs
  ed25519 generator_x_actual = ed25519::generator_x();
  to_limbs(generator_x_actual, gx.limbs);
  gx.num_additions = 0;
  gx.is_normalized = true;
  return gx;
}

// Ed25519 generator Y coordinate as BN254 field elements
const ed25519_emulated ed25519_emulated::generator_y() {
  ed25519_emulated gy;
  // Use the actual Ed25519 generator Y coordinate and convert to limbs
  ed25519 generator_y_actual = ed25519::generator_y();
  to_limbs(generator_y_actual, gy.limbs);
  gy.num_additions = 0;
  gy.is_normalized = true;
  return gy;
}

// Ed25519 generator Z coordinate as BN254 field elements
const ed25519_emulated ed25519_emulated::generator_z() {
  ed25519_emulated gz;
  // Z = 1, stored as [0, 0, 1] in big-endian limbs
  gz.limbs[0] = bn254fr_class(0);
  gz.limbs[1] = bn254fr_class(0);
  gz.limbs[2] = bn254fr_class(1);
  gz.num_additions = 0;
  gz.is_normalized = true;
  return gz;
}

// Ed25519 generator T coordinate as BN254 field elements
// T = X*Y/Z (extended coordinates)
const ed25519_emulated ed25519_emulated::generator_t() {
  ed25519_emulated gt;
  // Compute T = X*Y/Z using emulated arithmetic
  ed25519_emulated gx = generator_x();
  ed25519_emulated gy = generator_y();
  ed25519_emulated gz = generator_z();

  // T = X*Y/Z = X*Y (since Z=1 for the generator)
  gt = gx.mul(gy);
  gt.num_additions = 0; // Reset since this is a constant
  gt.is_normalized = true;
  return gt;
}

// ===== ed25519_emulated =====

const ed25519_emulated ed25519_emulated::zero() {
  ed25519_emulated p;
  // 0 in base 2^85 limbs: [0, 0, 0] (big-endian limbs)
  p.limbs[0] = bn254fr_class(0);
  p.limbs[1] = bn254fr_class(0);
  p.limbs[2] = bn254fr_class(0);
  p.num_additions = 0;
  p.is_normalized = true;
  return p;
}

const ed25519_emulated ed25519_emulated::one() {
  ed25519_emulated p;
  // 1 in base 2^85 limbs: [0, 0, 1] (big-endian limbs, 1 goes in LSB)
  p.limbs[0] = bn254fr_class(0);
  p.limbs[1] = bn254fr_class(0);
  p.limbs[2] = bn254fr_class(1);
  p.num_additions = 0;
  p.is_normalized = true;
  return p;
}

const ed25519_emulated ed25519_emulated::two() {
  ed25519_emulated p;
  // 2 in base 2^85 limbs: [0, 0, 2] (big-endian limbs, 2 goes in LSB)
  p.limbs[0] = bn254fr_class(0);
  p.limbs[1] = bn254fr_class(0);
  p.limbs[2] = bn254fr_class(2);
  p.num_additions = 0;
  p.is_normalized = true;
  return p;
}

const ed25519_emulated ed25519_emulated::three() {
  ed25519_emulated p;
  // 3 in base 2^85 limbs: [0, 0, 3] (big-endian limbs, 3 goes in LSB)
  p.limbs[0] = bn254fr_class(0);
  p.limbs[1] = bn254fr_class(0);
  p.limbs[2] = bn254fr_class(3);
  p.num_additions = 0;
  p.is_normalized = true;
  return p;
}

// ===== Field Arithmetic Operations =====

ed25519_emulated ed25519_emulated::to_emulated(const ed25519 &target) {
  ed25519_emulated emulated;
  bn254fr_class limbs[ed25519_emulated::NUM_LIMBS];

  to_limbs(target, limbs);

  for (size_t i = 0; i < ed25519_emulated::NUM_LIMBS; ++i) {
    emulated.limbs[i] = limbs[i];
  }

  emulated.num_additions = 0;
  emulated.is_normalized = true;
  return emulated;
}

ed25519 ed25519_emulated::to_ed25519(const ed25519_emulated &emulated) {
  // Direct inverse of to_limbs
  // Reconstruct the 32-byte little-endian representation from the 3 limbs

  ed25519 target;
  for (int i = 0; i < 32; ++i) {
    target.bytes[i] = 0;
  }

  // Process each limb and reconstruct the bits
  for (int limb_idx = 0; limb_idx < ed25519_emulated::NUM_LIMBS; ++limb_idx) {
    // Get the limb value (remember: limb 0 is MSB, limb 2 is LSB)
    // In to_limbs we did: limbs[NUM_LIMBS - 1 - limb_idx] =
    // limb_value So to reverse: limb_value = limbs[NUM_LIMBS - 1 - limb_idx]
    int actual_limb_idx = ed25519_emulated::NUM_LIMBS - 1 - limb_idx;
    const bn254fr_class &limb_value = emulated.limbs[actual_limb_idx];

    // Extract bits from this limb
    bn254fr_class limb_bits[256];
    // For the last limb (limb_idx = 2), we need to extract 86 bits instead of
    // 85
    int bits_to_extract = (limb_idx == 2) ? ed25519_emulated::BITS_PER_LIMB + 1
                                          : ed25519_emulated::BITS_PER_LIMB;
    const_cast<bn254fr_class &>(limb_value).to_bits(limb_bits, bits_to_extract);

    // Place these bits back into the target bytes
    int start_bit = limb_idx * ed25519_emulated::BITS_PER_LIMB;

    // For the last limb (limb_idx = 2), we need to handle the extra bit (bit
    // 255)
    int bits_to_process = ed25519_emulated::BITS_PER_LIMB;
    if (limb_idx == 2) {
      bits_to_process =
          ed25519_emulated::BITS_PER_LIMB + 1; // Handle bits 170-255 (86 bits)
    }

    for (int bit_offset = 0; bit_offset < bits_to_process; ++bit_offset) {
      int global_bit_idx = start_bit + bit_offset;

      // Check if this bit index is within the 256-bit range (0-255)
      if (global_bit_idx >= 256) {
        break;
      }

      // If this bit is set in the limb
      if ((limb_bits[bit_offset].get_u64() & 1) != 0) {
        // Set the corresponding bit in the target bytes (little-endian)
        int byte_idx = global_bit_idx / 8;
        int bit_in_byte = global_bit_idx % 8;

        if (byte_idx < 32) {
          target.bytes[byte_idx] |= (1 << bit_in_byte);
        }
      }
    }
  }

  return target;
}

void ed25519_emulated::to_bytes(uint8_t *bytes) const {
  ed25519 target = to_ed25519(*this);
  target.to_bytes(bytes);
}

/*
decomposition into three 85-bit limbs:
limbs[2] = x mod 2^85
limbs[1] = (x >> 85) mod 2^85
limbs[0] = (x >> 170) mod 2^85
Note: We intentionally ignore bit 255; this matches a pure 3x85-bit split.
*/
static inline void copy_bits_le(const uint8_t *src, int start_bit, int bit_len,
                                uint8_t *out_bytes, int out_len) {
  for (int i = 0; i < out_len; ++i)
    out_bytes[i] = 0;
  for (int i = 0; i < bit_len; ++i) {
    int src_bit = start_bit + i;
    int src_byte = src_bit / 8;
    int src_off = src_bit % 8;
    uint8_t bit = (src[src_byte] >> src_off) & 1u;
    int dst_byte = i / 8;
    int dst_off = i % 8;
    out_bytes[dst_byte] |= (bit << dst_off);
  }
}

void ed25519_emulated::to_limbs_bn254(
    bn254fr_class &target, bn254fr_class limbs[ed25519_emulated::NUM_LIMBS]) {
  // printf("DEBUG to_limbs_bn254\n");
  bn254fr_class bits[254];

  for (size_t i = 0; i < ed25519_emulated::NUM_LIMBS; ++i)
    limbs[i] = bn254fr_class(0);

  // printf("target: ");
  // target.print_hex();
  // target.print_dec();
  // printf("\n");
  // Convert field element to 32-byte little-endian representation
  ed25519 v;
  for (int i = 0; i < 32; ++i)
    v.bytes[i] = 0;
  target.to_bits(bits, 254);
  // for (int i = 0; i < 254; ++i) {
  //   printf("%d", bits[i].get_u64() & 1u);
  // }
  // printf("\n");
  for (int i = 0; i < 254; ++i) {
    if ((bits[i].get_u64() & 1u) != 0) {
      int byte_idx = i / 8;
      int bit_in_byte = i % 8;
      if (byte_idx < 32)
        v.bytes[byte_idx] |= (1u << bit_in_byte);
    }
  }

  // Reuse byte-based splitter
  ed25519_emulated::to_limbs(v, limbs);
}

void ed25519_emulated::to_limbs(
    const ed25519 &target, bn254fr_class limbs[ed25519_emulated::NUM_LIMBS]) {
  for (size_t i = 0; i < ed25519_emulated::NUM_LIMBS; ++i)
    limbs[i] = bn254fr_class(0);

  bool is_zero = true;
  for (int i = 0; i < 32; ++i) {
    if (target.bytes[i] != 0) {
      is_zero = false;
      break;
    }
  }
  if (is_zero)
    return;

  const int bits_per_limb =
      static_cast<int>(ed25519_emulated::BITS_PER_LIMB); // 85
  const int out_len = (bits_per_limb + 7) / 8;           // 11 bytes

  uint8_t buf[16]; // enough for 11 bytes

  // LSB chunk: bits [0..84]
  copy_bits_le(target.bytes, 0, bits_per_limb, buf, out_len);
  bn254fr_class l0;
  l0.set_bytes_little(buf, out_len);

  // Middle chunk: bits [85..169]
  copy_bits_le(target.bytes, bits_per_limb, bits_per_limb, buf, out_len);
  bn254fr_class l1;
  l1.set_bytes_little(buf, out_len);

  // MSB chunk: bits [170..254] (ignoring bit 255)
  copy_bits_le(target.bytes, 2 * bits_per_limb, bits_per_limb, buf, out_len);
  bn254fr_class l2;
  l2.set_bytes_little(buf, out_len);

  // Store in big-endian limb order
  limbs[0] = l2; // MSB
  limbs[1] = l1;
  limbs[2] = l0; // LSB
}

// Reconstruct ed25519 value from three 85-bit limbs in big-endian limb order:
// x = limbs[2] + (limbs[1] << 85) + (limbs[0] << 170)
ed25519 ed25519_emulated::from_limbs(
    const bn254fr_class limbs[ed25519_emulated::NUM_LIMBS]) {
  ed25519 out;
  for (int i = 0; i < 32; ++i)
    out.bytes[i] = 0;

  const int bits_per_limb = 85;
  const int NUM_LIMBS = 3;

  for (int limb_idx = 0; limb_idx < NUM_LIMBS; ++limb_idx) {
    const bn254fr_class &limb_value = limbs[limb_idx];
    bn254fr_class limb_bits[256];
    const_cast<bn254fr_class &>(limb_value).to_bits(limb_bits, bits_per_limb);

    // Place bits: limb 0 -> start 170, limb 1 -> start 85, limb 2 -> start 0
    int start_bit = (NUM_LIMBS - 1 - limb_idx) * bits_per_limb;

    for (int bit_offset = 0; bit_offset < bits_per_limb; ++bit_offset) {
      if ((limb_bits[bit_offset].get_u64() & 1u) == 0)
        continue;
      int global_bit_idx = start_bit + bit_offset;
      if (global_bit_idx >= 256)
        break;
      int byte_idx = global_bit_idx / 8;
      int bit_in_byte = global_bit_idx % 8;
      if (byte_idx < 32)
        out.bytes[byte_idx] |= (1u << bit_in_byte);
    }
  }

  return out;
}

ed25519_emulated ed25519_emulated::add(const ed25519_emulated &other) const {
  ed25519_emulated sum;
  // Limb-wise addition (big-endian limb order)
  for (size_t i = 0; i < ed25519_emulated::NUM_LIMBS; ++i) {
    bn254fr_class s;
    bn254fr_class a = this->limbs[i];
    bn254fr_class b = other.limbs[i];
    addmod(s, a, b);
    sum.limbs[i] = s;
  }
  bn254fr_class this_limb = this->limbs[0];
  bn254fr_class other_limb = other.limbs[0];

  bn254fr_class sum_limb;
  bn254fr_class one(1), two(2);
  addmod(sum_limb, one, two);

  bn254fr_class two_pow_250(
      "180925139433306555349329664076074856020734351040063381"
      "3116524750123642650624",
      10);
  bn254fr_class two_pow_253("14474011154664524427946373126085988481658748083205"
                            "070504932198000989141204992",
                            10);
  bn254fr_class base("38685626227668133590597632", 10);
  if (sum.limbs[0] >= base || sum.limbs[1] >= base || sum.limbs[2] >= base) {
    sum.num_additions = sum.num_additions + 1;
    sum.is_normalized = false;
  }
  // Use lazy reduction - only reduce when necessary
  sum.num_additions = this->num_additions + other.num_additions + 1;
  if (sum.num_additions >= 169) {
    return this->reduce(sum);
  }
  
  return sum;
}

ed25519_emulated ed25519_emulated::mul(const ed25519_emulated &other) const {
  // Map to LSB-first temporaries
  bn254fr_class a0 = this->limbs[2]; // LSB
  bn254fr_class a1 = this->limbs[1];
  bn254fr_class a2 = this->limbs[0]; // MSB
  bn254fr_class b0 = other.limbs[2];
  bn254fr_class b1 = other.limbs[1];
  bn254fr_class b2 = other.limbs[0];

  bn254fr_class nineteen(19);

  // Accumulate directly into three limbs
  bn254fr_class r0(0), r1(0), r2(0);
  bn254fr_class t, u, v;

  // res[0] += a0*b0
  mulmod(t, a0, b0);
  r0 = t;

  // res[1] += a0*b1
  mulmod(t, a0, b1);
  addmod(u, r1, t);
  r1 = u;

  // res[2] += a0*b2
  mulmod(t, a0, b2);
  addmod(u, r2, t);
  r2 = u;

  // res[1] += a1*b0
  mulmod(t, a1, b0);
  addmod(u, r1, t);
  r1 = u;

  // res[2] += a1*b1
  mulmod(t, a1, b1);
  addmod(u, r2, t);
  r2 = u;

  // res[0] += a1*b2*19
  mulmod(t, a1, b2);
  mulmod(v, t, nineteen);
  addmod(u, r0, v);
  r0 = u;

  // res[2] += a2*b0
  mulmod(t, a2, b0);
  addmod(u, r2, t);
  r2 = u;

  // res[0] += a2*b1*19
  mulmod(t, a2, b1);
  mulmod(v, t, nineteen);
  addmod(u, r0, v);
  r0 = u;

  // res[1] += a2*b2*19
  mulmod(t, a2, b2);
  mulmod(v, t, nineteen);
  addmod(u, r1, v);
  r1 = u;

  ed25519_emulated pre;
  pre.limbs[0] = r2; // MSB
  pre.limbs[1] = r1;
  pre.limbs[2] = r0; // LSB

  return this->reduce(pre);
}

ed25519_emulated ed25519_emulated::mul_k(const ed25519_emulated &other) const {
  // Map to LSB-first temporaries
  bn254fr_class a0 = this->limbs[2]; // LSB
  bn254fr_class a1 = this->limbs[1];
  bn254fr_class a2 = this->limbs[0]; // MSB
  bn254fr_class b0 = other.limbs[2];
  bn254fr_class b1 = other.limbs[1];
  bn254fr_class b2 = other.limbs[0];

  bn254fr_class nineteen(19);
  bn254fr_class t, u;

  // Karatsuba 3x3
  bn254fr_class m00, m11, m22, m02, m01, m12;
  mulmod(m00, a0, b0);
  mulmod(m11, a1, b1);
  mulmod(m22, a2, b2);

  bn254fr_class a0a2, b0b2;
  addmod(a0a2, a0, a2);
  addmod(b0b2, b0, b2);
  mulmod(m02, a0a2, b0b2);

  bn254fr_class a0a1, b0b1;
  addmod(a0a1, a0, a1);
  addmod(b0b1, b0, b1);
  mulmod(m01, a0a1, b0b1);

  bn254fr_class a1a2, b1b2;
  addmod(a1a2, a1, a2);
  addmod(b1b2, b1, b2);
  mulmod(m12, a1a2, b1b2);

  // Cross terms
  bn254fr_class c01, c02, c12;
  // c01 = m01 - m00 - m11
  submod(t, m01, m00); // t = m01 - m00
  submod(c01, t, m11);
  // c02 = m02 - m00 - m22
  submod(t, m02, m00);
  submod(c02, t, m22);
  // c12 = m12 - m11 - m22
  submod(t, m12, m11);
  submod(c12, t, m22);

  // Assemble result limbs in base 2^85 using 2^255 ≡ 19 folding
  bn254fr_class r0, r1, r2;
  // r0 = m00 + 19*c12
  bn254fr_class k0;
  mulmod(k0, c12, nineteen);
  addmod(r0, m00, k0);
  // r1 = c01 + 19*m22
  bn254fr_class k1;
  mulmod(k1, m22, nineteen);
  addmod(r1, c01, k1);
  // r2 = m11 + c02
  addmod(r2, m11, c02);

  // Pack into big-endian limb order for reduce
  ed25519_emulated pre;
  pre.limbs[0] = r2; // MSB
  pre.limbs[1] = r1;
  pre.limbs[2] = r0; // LSB

  return this->reduce(pre);
}

ed25519_emulated ed25519_emulated::sub(const ed25519_emulated &other) const {
  bn254fr_class a0 = this->limbs[2]; // LSB
  bn254fr_class a1 = this->limbs[1];
  bn254fr_class a2 = this->limbs[0]; // MSB
  bn254fr_class b0 = other.limbs[2];
  bn254fr_class b1 = other.limbs[1];
  bn254fr_class b2 = other.limbs[0];

  // Modulus limbs (big-endian in struct). Map to LSB-first p0..p2
  ed25519_emulated p = ed25519_emulated::field_modulus();
  bn254fr_class p0 = p.limbs[2];
  bn254fr_class p1 = p.limbs[1];
  bn254fr_class p2 = p.limbs[0];

  // For each limb i, while b_i > a_i, add modulus limbs to a
  bn254fr_class t;
  // i = 0
  while (b0 > a0) {
    addmod(t, a0, p0);
    a0 = t;
    addmod(t, a1, p1);
    a1 = t;
    addmod(t, a2, p2);
    a2 = t;
  }
  // i = 1
  while (b1 > a1) {
    addmod(t, a0, p0);
    a0 = t;
    addmod(t, a1, p1);
    a1 = t;
    addmod(t, a2, p2);
    a2 = t;
  }
  // i = 2
  while (b2 > a2) {
    addmod(t, a0, p0);
    a0 = t;
    addmod(t, a1, p1);
    a1 = t;
    addmod(t, a2, p2);
    a2 = t;
  }

  // Now subtract per limb
  bn254fr_class r0, r1, r2;
  submod(r0, a0, b0);
  submod(r1, a1, b1);
  submod(r2, a2, b2);

  // Pack back to big-endian and reduce
  ed25519_emulated pre;
  pre.limbs[0] = r2; // MSB
  pre.limbs[1] = r1;
  pre.limbs[2] = r0; // LSB

  pre.num_additions = pre.num_additions + 1;
  pre.is_normalized = false;

  if (pre.num_additions >= 169) {
    return this->reduce(pre);
  }
  return pre;
}

ed25519_emulated ed25519_emulated::negate() const {
  ed25519_emulated zero = ed25519_emulated::zero();
  return zero.sub(*this);
}

// Compute inverse of an emulated field element using Fermat's Little Theorem
// For prime p: a^(p-1) ≡ 1 (mod p), so a^(p-2) ≡ a^(-1) (mod p)
ed25519_emulated ed25519_emulated::inverse() const {
  if (this->limbs[0].eqz() && this->limbs[1].eqz() && this->limbs[2].eqz()) {
    return ed25519_emulated::zero();
  }

  // Compute p - 2 where p = 2^255 - 19
  // p - 2 = 2^255 - 19 - 2 = 2^255 - 21
  ed25519 p_minus_2;
  // Start with p = 2^255 - 19
  p_minus_2.bytes[0] = 0xeb; // 0xed - 2 = 0xeb
  for (int i = 1; i < 31; i++) {
    p_minus_2.bytes[i] = 0xff;
  }
  p_minus_2.bytes[31] = 0x7f;

  // Use square-and-multiply algorithm to compute a^(p-2) mod p
  ed25519_emulated result = ed25519_emulated::one();
  ed25519_emulated base = *this;

  // Process bits of p-2 from LSB to MSB
  for (int byte_idx = 0; byte_idx < 32; byte_idx++) {
    uint8_t byte = p_minus_2.bytes[byte_idx];
    for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
      if (byte & (1 << bit_idx)) {
        result = result.mul(base);
      }
      // Don't square on the last iteration
      if (byte_idx != 31 || bit_idx != 7) {
        base = base.mul(base);
      }
    }
  }

  return result;
}

ed25519_emulated ed25519_emulated::square() const { return this->mul(*this); }

ed25519_emulated ed25519_emulated::reduce(const ed25519_emulated &elem) const {
  bn254fr_class res0 = elem.limbs[2];
  bn254fr_class res1 = elem.limbs[1];
  bn254fr_class res2 = elem.limbs[0];
  bn254fr_class base("38685626227668133590597632", 10);
  bn254fr_class nineteen("19", 10);
  bn254fr_class tmp;

  // Repeat until all three limbs are strictly < 2^85
  while ((res0 >= base) || (res1 >= base) || (res2 >= base)) {
    // Decompose each limb into three 85-bit chunks
    bn254fr_class a0, a1, a2; // from res0
    bn254fr_class b0, b1, b2; // from res1
    bn254fr_class c0, c1, c2; // from res2
    if (res0 < base) {
      a0 = res0;
      a1 = bn254fr_class(0);
      a2 = bn254fr_class(0);
    } else {
      bn254fr_class limb[3];
      ed25519_emulated::to_limbs_bn254(res0, limb);
      a0 = limb[2];
      a1 = limb[1];
      a2 = limb[0];
    }
    if (res1 < base) {
      b0 = res1;
      b1 = bn254fr_class(0);
      b2 = bn254fr_class(0);
    } else {
      bn254fr_class limb[3];
      ed25519_emulated::to_limbs_bn254(res1, limb);
      b0 = limb[2];
      b1 = limb[1];
      b2 = limb[0];
    }
    if (res2 < base) {
      c0 = res2;
      c1 = bn254fr_class(0);
      c2 = bn254fr_class(0);
    } else {
      // printf("res2 >= base\n");
      bn254fr_class limb[3];
      ed25519_emulated::to_limbs_bn254(res2, limb);
      c0 = limb[2];
      c1 = limb[1];
      c2 = limb[0];
    }

    // Start with res = limb0 decomposition
    res0 = a0; // LSB
    res1 = a1; // MID
    res2 = a2; // MSB

    // Fold limb1 parts
    addmod(tmp, res1, b0); // res1 += limb1_low
    res1 = tmp;
    addmod(tmp, res2, b1); // res2 += limb1_mid
    res2 = tmp;
    bn254fr_class b2x19;
    mulmod(b2x19, b2, nineteen); // res0 += limb1_high * 19
    addmod(tmp, res0, b2x19);
    res0 = tmp;

    // Fold limb2 parts
    addmod(tmp, res2, c0); // res2 += limb2_low
    res2 = tmp;
    bn254fr_class c1x19;
    mulmod(c1x19, c1, nineteen); // res0 += limb2_mid * 19
    addmod(tmp, res0, c1x19);
    res0 = tmp;
    bn254fr_class c2x19;
    mulmod(c2x19, c2, nineteen); // res1 += limb2_high * 19
    addmod(tmp, res1, c2x19);
    res1 = tmp;
  }

  // Return in big-endian limb order
  ed25519_emulated out;
  out.limbs[0] = res2; // MSB
  out.limbs[1] = res1; // MID
  out.limbs[2] = res0; // LSB
  out.num_additions = 0;
  out.is_normalized = true;
  return out;
}
// ======================================================
// ===== ed25519_point =====
// ======================================================
ed25519_point::ed25519_point() {
  // In extended coordinates: (0, 1, 1, 0) where T = X*Y/Z = 0*1/1 = 0
  x = ed25519_emulated::zero();
  y = ed25519_emulated::one();  // Identity point has y=1
  z = ed25519_emulated::one();  // Z should be 1, not 0!
  t = ed25519_emulated::zero(); // T = X*Y/Z = 0*1/1 = 0
}

ed25519_point::ed25519_point(const ed25519_emulated &x,
                             const ed25519_emulated &y,
                             const ed25519_emulated &z,
                             const ed25519_emulated &t)
    : x(x), y(y), z(z), t(t) {}

// Identity point (0, 1, 1, 0) in extended coordinates
ed25519_point ed25519_point::zero() { return ed25519_point(); }

// Generator point in extended coordinates
ed25519_point ed25519_point::generator() {
  return ed25519_point(
      ed25519_emulated::generator_x(), ed25519_emulated::generator_y(),
      ed25519_emulated::generator_z(), ed25519_emulated::generator_t());
}

/*
Point addition using twisted Edwards formulae
Twisted Edwards curve point addition in extended coordinates
Curve equation: ax² + y² = 1 + dx²y² where a = -1, d = -121665/121666
Extended coordinates: (X, Y, Z, T) where T = XY/Z
Twisted Edwards formula for P3 = P1 + P2:
X3 = (X1Y2 + X2Y1)(Z1Z2 - dT1T2)
Y3 = (Y1Y2 + X1X2)(Z1Z2 + dT1T2)  [since a = -1, so Y1Y2 - aX1X2 = Y1Y2 +
X1X2] Z3 = (Z1Z2 - dT1T2)(Z1Z2 + dT1T2) T3 = (X1Y2 + X2Y1)(Y1Y2 + X1X2)
*/
ed25519_point ed25519_point::point_add(const ed25519_point &p1,
                                       const ed25519_point &p2) {
  // Compute all intermediate products
  ed25519_emulated X1X2 = p1.x.mul(p2.x); // X1 * X2
  ed25519_emulated Y1Y2 = p1.y.mul(p2.y); // Y1 * Y2
  ed25519_emulated X1Y2 = p1.x.mul(p2.y); // X1 * Y2
  ed25519_emulated X2Y1 = p2.x.mul(p1.y); // X2 * Y1
  ed25519_emulated T1T2 = p1.t.mul(p2.t); // T1 * T2
  ed25519_emulated Z1Z2 = p1.z.mul(p2.z); // Z1 * Z2

  // Get curve constant d
  ed25519 d_coeff = ed25519::coeff_d();
  ed25519_emulated d = ed25519_emulated::to_emulated(d_coeff);

  // Compute dT1T2
  ed25519_emulated dT1T2 = T1T2.mul(d);

  // Compute Z1Z2 - dT1T2 and Z1Z2 + dT1T2
  ed25519_emulated Z1Z2_minus_dT1T2 = Z1Z2.sub(dT1T2);
  ed25519_emulated Z1Z2_plus_dT1T2 = Z1Z2.add(dT1T2);

  // Compute X1Y2 + X2Y1
  ed25519_emulated X1Y2_plus_X2Y1 = X1Y2.add(X2Y1);

  // Compute Y1Y2 + X1X2 (since a = -1, this is Y1Y2 - aX1X2)
  ed25519_emulated Y1Y2_plus_X1X2 = Y1Y2.add(X1X2);

  // Compute final coordinates using complete formula
  // Compute X3 = (X1Y2 + X2Y1)(Z1Z2 - dT1T2)
  ed25519_emulated x3 = X1Y2_plus_X2Y1.mul(Z1Z2_minus_dT1T2);

  // Compute Y3 = (Y1Y2 + X1X2)(Z1Z2 + dT1T2)
  ed25519_emulated y3 = Y1Y2_plus_X1X2.mul(Z1Z2_plus_dT1T2);

  // Compute Z3 = (Z1Z2 - dT1T2)(Z1Z2 + dT1T2)
  ed25519_emulated z3 = Z1Z2_minus_dT1T2.mul(Z1Z2_plus_dT1T2);

  // Compute T3 = (X1Y2 + X2Y1)(Y1Y2 + X1X2)
  ed25519_emulated t3 = X1Y2_plus_X2Y1.mul(Y1Y2_plus_X1X2);

  ed25519_point result(x3, y3, z3, t3);
  return result;
}

ed25519_point ed25519_point::point_double(const ed25519_point &p) {
  // Extended Edwards doubling (a = -1) with T = X*Y/Z
  const ed25519_emulated &X = p.x;
  const ed25519_emulated &Y = p.y;
  const ed25519_emulated &Z = p.z;

  ed25519_emulated A = X.mul_k(X);                      // A = X^2
  ed25519_emulated B = Y.mul_k(Y);                      // B = Y^2
  ed25519_emulated ZZ = Z.mul_k(Z);                     // ZZ = Z^2
  ed25519_emulated C = ZZ.add(ZZ);                      // C = 2*Z^2
  ed25519_emulated D = A.negate();                      // D = -X^2
  ed25519_emulated XY = X.add(Y);                      // D = -X^2
  ed25519_emulated XYXY = XY.mul_k(XY);              // XYXY = (X+Y)^2 
  ed25519_emulated E = XYXY.sub(A).sub(B);              // E = (X+Y)^2 - A - B
  ed25519_emulated G = D.add(B);                        // G = -X^2 + Y^2
  ed25519_emulated F = G.sub(C);                        // F = G - 2Z^2
  ed25519_emulated H = D.sub(B);                        // H = -X^2 - Y^2

  ed25519_emulated X2 = E.mul(F); // X2 = E * F
  ed25519_emulated Y2 = G.mul(H); // Y2 = G * H
  ed25519_emulated Z2 = F.mul(G); // Z2 = F * G
  ed25519_emulated T2 = E.mul(H); // T2 = E * H

  return ed25519_point(X2, Y2, Z2, T2);
}

// Point negation for Ed25519 curve
// For twisted Edwards curves: -(X, Y, Z, T) = (-X, Y, Z, -T)
ed25519_point ed25519_point::point_negate(const ed25519_point &p) {
  // Negate X and T coordinates, keep Y and Z unchanged
  // This follows the standard Ed25519 point negation formula
  ed25519_emulated neg_x = p.x.negate();
  ed25519_emulated neg_t = p.t.negate();

  ed25519_point result(neg_x, p.y, p.z, neg_t);

  return result;
}

ed25519_point ed25519_point::scalar_mul(const ed25519_point &p,
                                        const ed25519 &scalar) {
  ed25519_emulated scalar_emul = ed25519_emulated::to_emulated(scalar);
  int max_idx = 255;
  // 4-bit fixed-window scalar multiplication with simple per-call precompute
  // Table size: 16 (0..15), store multiples of p: [1P,2P,...,15P], 0 unused
  ed25519_point table[16];
  table[0] = ed25519_point::zero();
  table[1] = p;
  for (int i = 2; i < 16; ++i) {
    if ((i & 1) == 0) {
      // table[i] = ed25519_point::point_add(table[i >> 1], table[i >> 1]);
      table[i] = ed25519_point::point_double(table[i >> 1]);
    } else {
      table[i] = ed25519_point::point_add(table[i - 1], p);
    }
  }

  // Extract scalar bits LSB-first into 255-bit array
  bool bits[max_idx];
  for (int bit_idx = 0; bit_idx < max_idx; ++bit_idx) {
    int limb_idx = 2 - (bit_idx / 85);
    int bit_in_limb = bit_idx % 85;
    bits[bit_idx] = false;
    if (limb_idx >= 0 && limb_idx < 3) {
      bn254fr_class limb_value = scalar_emul.limbs[limb_idx];
      bn254fr_class bit_array[85];
      limb_value.to_bits(bit_array, 85);
      bits[bit_idx] = (bit_array[bit_in_limb].get_u64() & 1) != 0;
    }
  }

  ed25519_point acc = ed25519_point::zero();
  // Process from MSB window to LSB window: windows of 4 bits
  for (int w = ((max_idx + 3) / 4) - 1; w >= 0; --w) {
    // 4 doublings between windows
    for (int d = 0; d < 4; ++d) {
      // acc = ed25519_point::point_add(acc, acc);
      acc = ed25519_point::point_double(acc);
    }
    // Gather window value (LSB-first bits array)
    int start_bit = w * 4;
    int val = 0;
    for (int b = 3; b >= 0; --b) {
      val <<= 1;
      int idx = start_bit + b;
      if (idx < max_idx && bits[idx])
        val |= 1;
    }
    if (val != 0) {
      acc = ed25519_point::point_add(acc, table[val]);
    }
  }

  return acc;
}

// Precomputed generator multiples for 5-bit windowed multiplication
// Table contains [G, 2G, 3G, ..., 31G] for 5-bit windows
static ed25519_point generator_table[32];
static bool generator_table_initialized = false;

void initialize_generator_table() {
  if (generator_table_initialized) return;
  
  ed25519_point G = ed25519_point::generator();
  
  // Initialize table[0] as zero point
  generator_table[0] = ed25519_point::zero();
  
  // Initialize table[1] as generator
  generator_table[1] = G;
  
  // Compute multiples using efficient doubling and addition
  for (int i = 2; i < 32; ++i) {
    if ((i & 1) == 0) {
      // Even index: double the half-index point
      generator_table[i] = ed25519_point::point_double(generator_table[i >> 1]);
    } else {
      // Odd index: add G to the previous point
      generator_table[i] = ed25519_point::point_add(generator_table[i - 1], G);
    }
  }
  
  generator_table_initialized = true;
}

const ed25519_point* ed25519_point::get_generator_table() {
  initialize_generator_table();
  return generator_table;
}

// Optimized scalar multiplication specifically for generator point
ed25519_point ed25519_point::scalar_mul_generator(const ed25519 &scalar) {
  initialize_generator_table();
  
  ed25519_emulated scalar_emul = ed25519_emulated::to_emulated(scalar);
  
  // Extract scalar bits LSB-first
  bool bits[255];
  for (int bit_idx = 0; bit_idx < 255; ++bit_idx) {
    int limb_idx = 2 - (bit_idx / 85);
    int bit_in_limb = bit_idx % 85;
    bits[bit_idx] = false;
    if (limb_idx >= 0 && limb_idx < 3) {
      bn254fr_class limb_value = scalar_emul.limbs[limb_idx];
      bn254fr_class bit_array[85];
      limb_value.to_bits(bit_array, 85);
      bits[bit_idx] = (bit_array[bit_in_limb].get_u64() & 1) != 0;
    }
  }
  
  ed25519_point acc = ed25519_point::zero();
  
  // 5-bit windowed multiplication (more efficient than 4-bit)
  for (int w = 50; w >= 0; --w) { // 255 bits / 5 bits = 51 windows
    // 5 doublings between windows
    for (int d = 0; d < 5; ++d) {
      acc = ed25519_point::point_double(acc);
    }
    
    // Gather 5-bit window value
    int start_bit = w * 5;
    int val = 0;
    for (int b = 4; b >= 0; --b) {
      val <<= 1;
      int idx = start_bit + b;
      if (idx < 255 && bits[idx]) {
        val |= 1;
      }
    }
    
    if (val != 0) {
      acc = ed25519_point::point_add(acc, generator_table[val]);
    }
  }
  
  return acc;
}

// Montgomery ladder for constant-time scalar multiplication
ed25519_point ed25519_point::scalar_mul_montgomery(const ed25519_point &p,
                                                   const ed25519 &scalar) {
  ed25519_emulated scalar_emul = ed25519_emulated::to_emulated(scalar);
  
  // Extract scalar bits LSB-first
  bool bits[255];
  for (int bit_idx = 0; bit_idx < 255; ++bit_idx) {
    int limb_idx = 2 - (bit_idx / 85);
    int bit_in_limb = bit_idx % 85;
    bits[bit_idx] = false;
    if (limb_idx >= 0 && limb_idx < 3) {
      bn254fr_class limb_value = scalar_emul.limbs[limb_idx];
      bn254fr_class bit_array[85];
      limb_value.to_bits(bit_array, 85);
      bits[bit_idx] = (bit_array[bit_in_limb].get_u64() & 1) != 0;
    }
  }
  
  // Montgomery ladder: R0 = O (infinity), R1 = P
  ed25519_point R0 = ed25519_point::zero();
  ed25519_point R1 = p;
  
  // Process bits from MSB to LSB for constant-time behavior
  for (int i = 254; i >= 0; --i) {
    if (bits[i]) {
      // bit is 1: R0 = R0 + R1, R1 = 2*R1
      R0 = ed25519_point::point_add(R0, R1);
      R1 = ed25519_point::point_double(R1);
    } else {
      // bit is 0: R1 = R0 + R1, R0 = 2*R0
      R1 = ed25519_point::point_add(R0, R1);
      R0 = ed25519_point::point_double(R0);
    }
  }
  
  return R0;
}

void ed25519_point::debug_print(const char *label) const {
  if (label)
    std::printf("%s\n", label);
  std::printf("ed25519_point (extended coordinates):\n");
  x.debug_print_limbs("  X:");
  y.debug_print_limbs("  Y:");
  z.debug_print_limbs("  Z:");
  t.debug_print_limbs("  T:");
}

// Convert extended coordinates to affine coordinates (x, y) = (X/Z, Y/Z)
void ed25519_point::to_affine(ed25519_emulated &affine_x,
                              ed25519_emulated &affine_y) const {
  // Check if Z is zero (point at infinity)
  if (z.limbs[0].eqz() && z.limbs[1].eqz() && z.limbs[2].eqz()) {
    affine_x = ed25519_emulated::zero();
    affine_y = ed25519_emulated::zero();
    return;
  }

  ed25519_emulated z_inv = z.inverse();
  affine_x = x.mul(z_inv);
  affine_y = y.mul(z_inv);
}

void ed25519::print_hex() const {
  std::printf("0x");
  for (int i = 31; i >= 0; --i)
    std::printf("%02x", bytes[i]);
  std::printf("\n");
}
void ed25519::print_dec() const {
  std::string decimal = le32_to_decimal(bytes);
  std::printf("%s\n", decimal.c_str());
}

} // namespace ligetron