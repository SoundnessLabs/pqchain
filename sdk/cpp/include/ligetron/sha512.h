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

#ifndef __SHA512__
#define __SHA512__

#include <stdint.h>
#include <ligetron/apidef.h>

extern "C" void sha512(unsigned char *out, const unsigned char* in, int len);
extern "C" void hmac_sha512(unsigned char *out, const unsigned char *key, int key_len, const unsigned char *data, int data_len);

#endif