/*
 * Copyright (C) 2026 Soundness Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ligetron/api.h>
#include <ligetron/ed25519.h>
#include <ligetron/sha512.h>
#include <vector>

using namespace ligetron;



static std::string bytes_to_decimal(const unsigned char *bytes, int len) {
  std::vector<int> digits;
  digits.push_back(0);
  for (int i = 0; i < len; i++) {
    int carry = bytes[i];
    for (size_t j = 0; j < digits.size(); j++) {
      long long value = (long long)digits[j] * 256 + carry;
      digits[j] = (int)(value % 10);
      carry = (int)(value / 10);
    }
    while (carry > 0) {
      digits.push_back(carry % 10);
      carry /= 10;
    }
  }
  std::string result;
  bool leading = true;
  for (int i = (int)digits.size() - 1; i >= 0; i--) {
    if (leading && digits[i] == 0) {
      continue;
    }
    leading = false;
    result.push_back((char)('0' + digits[i]));
  }
  if (result.empty()) {
    result = "0";
  }
  return result;
}

static std::string bytes_to_decimal_reversed(const unsigned char *bytes,
                                             int len) {
  unsigned char tmp[256];
  if (len > 256)
    len = 256;
  for (int i = 0; i < len; i++) {
    tmp[i] = bytes[len - 1 - i];
  }
  return bytes_to_decimal(tmp, len);
}


void pk_verify(const unsigned char *pk, const unsigned char *seed) {
  unsigned char h[64];
  sha512(h, seed, 32);

  unsigned char a[32];
  memcpy(a, h, 32);
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;

  // Reverse bytes to match bytes_to_decimal_reversed behavior
  unsigned char a_reversed[32];
  for (int i = 0; i < 32; i++) {
    a_reversed[i] = a[31-i];
  }
  
  // Direct byte-to-field conversion (eliminates decimal conversion)
  ed25519 sk;
  sk.set_from_bytes(a_reversed, 32);
  
  ed25519_point generator = ed25519_point::generator();
  ed25519_point computed_public_key_point = 
      ed25519_point::scalar_mul(generator, sk);

  // Rest of verification
  ed25519_emulated x_emul, y_emul;
  computed_public_key_point.to_affine(x_emul, y_emul);
  ed25519 x = ed25519_emulated::to_ed25519(x_emul);
  ed25519 y = ed25519_emulated::to_ed25519(y_emul);

  unsigned char computed_pk[32];
  y.to_bytes(computed_pk);
  unsigned char x_le[32];
  x.to_bytes(x_le);
  unsigned char x_lsb = x_le[0] & 1;
  computed_pk[31] &= 0x7F;
  computed_pk[31] |= (x_lsb << 7);

  for (int i = 0; i < 32; i++) {
    assert_zero(computed_pk[i] - pk[i]);
  }
}


void hx_verify(const unsigned char *hx, const unsigned char *msg,
               const unsigned char *seed, int msg_len) {
  // hx = SHA-512(msg||seed)
  const int hash_input_len = msg_len + 32;
  unsigned char hash_input[hash_input_len];
  int current_pos = 0;
  memcpy(hash_input + current_pos, msg, msg_len);
  current_pos += msg_len;
  memcpy(hash_input + current_pos, seed, 32);

  unsigned char computed_hx[64];
  sha512(computed_hx, hash_input, hash_input_len);

  for (int i = 0; i < 64; i++) {
    assert_zero(computed_hx[i] - hx[i]);
  }
}

int main(int argc, char *argv[]) {
  // Private input
  const unsigned char *seed = (const unsigned char *)argv[1];
  // Public inputs
  const unsigned char *pk = (const unsigned char *)argv[2];
  const unsigned char *msg = (const unsigned char *)argv[3];
  const unsigned char *hx = (const unsigned char *)argv[4];

  int args_len[argc];
  args_len_get(argv, args_len);
  const int msg_len = args_len[3];

  pk_verify(pk, seed);
  hx_verify(hx, msg, seed, msg_len);

  return 0;
}