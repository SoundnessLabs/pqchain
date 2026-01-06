<p align="center">
  <a href="https://soundness.xyz" target="_blank">
    <img src="https://soundness-xyz.notion.site/image/attachment%3Aa4df3045-521c-41da-a0ef-ad89d7b2852e%3Abacf94a6-5284-4794-b5ec-5a8844affca7.png?table=block&id=262cb720-3e2b-80ee-af44-e4101aab1819&spaceId=2b0fa06f-b360-4628-a423-b7731e622496&width=1420&userId=&cache=v2" alt="Soundness Labs Logo" width="400">
  </a>
</p>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/license-Apache_2.0-blue" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/build-success-green" alt="Build"></a>
  <a href="https://github.com/SoundnessLabs"><img src="https://img.shields.io/badge/GitHub-SoundnessLabs-181717?logo=github" alt="GitHub"></a>
  <a href="https://soundness.xyz"><img src="https://img.shields.io/badge/Website-soundness.xyz-purple" alt="Website"></a>
</p>

# PQChain: Post-Quantum EdDSA Verification Circuit

**By [Soundness Labs](https://soundness.xyz)**

PQChain is an open-source implementation of a post-quantum secure zero-knowledge proof system for EdDSA key ownership. It enables users to prove ownership of Ed25519 keys through their deterministic seed, facilitating seamless post-quantum migration for modern blockchains without changing addresses.

---

## Table of Contents

- [Introduction](#introduction)
- [Why PQChain?](#why-pqchain)
- [Technical Approach](#technical-approach)
- [Repository Structure](#repository-structure)
- [Prerequisites and Setup](#prerequisites-and-setup)
- [Building the Project](#building-the-project)
- [Running the Prover and Verifier](#running-the-prover-and-verifier)
- [Circuit Arguments](#circuit-arguments)
- [Performance Benchmarks](#performance-benchmarks)
- [Live Demo](#live-demo)
- [License](#license)
- [About Soundness Labs](#about-soundness-labs)

---

## Introduction

Quantum computers pose an existential threat to elliptic curve cryptography. Shor's algorithm can recover private keys from public keys in polynomial time, putting billions of dollars in blockchain assets at risk. EdDSA-based chains (Sui, Solana, Near, and others) have a structural advantage: keys are deterministically derived from a seed via RFC 8032, enabling zero-knowledge proofs of ownership without exposing the private scalar.

PQChain leverages this property to create a backward-compatible post-quantum migration path. Users can prove they control an EdDSA keypair by demonstrating knowledge of the underlying seed—all without revealing the seed itself or changing their on-chain address.

This implementation builds upon the [Ligetron zkVM](https://github.com/ligeroinc/ligero-prover) (v1.1.0), extending it with:
- Complete Ed25519 curve arithmetic via non-native field emulation
- SHA-512 implementation for RFC 8032-compliant key derivation
- A ZK circuit proving seed-to-public-key consistency

**Base Commit:**
```
commit fd06e438cf84de6d9c30243e0feec858c9b16bf8
Author: release-bot <releases@ligero-inc.com>
Date:   Sun Oct 5 04:00:15 2025 +0000
    Release v1.1.0
```

---

## Why PQChain?

### The Post-Quantum Imperative

- **Shor's Algorithm**: Can break ECDSA/EdDSA in polynomial time once large-scale quantum computers exist
- **Harvest Now, Decrypt Later**: Adversaries may already be collecting encrypted data and signed transactions for future decryption
- **Regulatory Pressure**: NIST mandates post-quantum migration for critical systems by 2035; many enterprises need solutions now

### Why Ligetron?

We selected the Ligetron zkVM as our proving backend for several reasons:

| Feature | Benefit |
|---------|---------|
| **Post-Quantum Security** | Based on hash-based commitments resistant to quantum attacks |
| **Space Efficiency** | Streaming memory architecture enables proving on resource-constrained devices |
| **Client-Side Proving** | Compiles to WebAssembly for browser-based proof generation via WebGPU |
| **No Trusted Setup** | Transparent setup eliminates trusted third parties |

### The Non-Native Arithmetic Challenge

Ed25519 operates over a prime field (2²⁵⁵ - 19) that lacks sufficient roots of unity for efficient FFT operations. Ligetron requires FFT-friendly fields with smooth-order multiplicative subgroups (specifically BN254). 

**Our Solution**: We implement non-native field arithmetic, decomposing Ed25519 field elements into three 85-bit limbs that fit within the BN254 scalar field. This enables emulated arithmetic with careful carry and overflow handling, at the cost of increased constraint count (~70% of our circuit).

---

## Technical Approach

### Circuit Relation

The ZK circuit proves the following relation:

```
R = { (pk, msg, hx) | ∃ seed such that
      pk = HashToScalar(SHA-512(seed)[:32]) · G
      ∧ hx = SHA-512(msg || seed) }
```

Where:
- `seed` is the 32-byte EdDSA private seed (secret witness)
- `pk` is the 32-byte Ed25519 public key (public input)
- `msg` is the 32-byte message (public input)
- `hx` is the 64-byte hash commitment (public input)
- `G` is the Ed25519 generator point

### What the Circuit Proves

1. **Public Key Derivation**: The provided public key was correctly derived from the secret seed following RFC 8032
2. **Hash Commitment**: Knowledge of the seed via `hx = SHA-512(msg || seed)`

This enables a user to authorize post-quantum transactions or key rotations by proving seed ownership, without ever revealing the seed or the derived private scalar.

### Non-Native Field Emulation

Ed25519 field elements (255 bits) are represented as vectors of three BN254 field elements:

```
element = limbs[2] + limbs[1] × 2⁸⁵ + limbs[0] × 2¹⁷⁰
```

Key implementation details:
- **Lazy Reduction**: Additions accumulate without immediate modular reduction
- **Modular Folding**: Multiplication uses 2²⁵⁵ ≡ 19 (mod p) for efficient reduction
- **Extended Edwards Coordinates**: Point operations use (X, Y, Z, T) representation for complete addition formulas

---

## Repository Structure

Files added to the base Ligetron v1.1.0 release:

```
sdk/cpp/
├── examples/
│   ├── PQChain/
│   │   └── pqchain.cpp          # Main ZK circuit implementation
│   └── CMakeLists.txt           # Updated to compile pqchain circuit
├── include/
│   └── ligetron/
│       ├── ed25519.h            # Ed25519 emulated arithmetic header
│       └── sha512.h             # SHA-512 header
└── src/
    ├── ed25519.cpp              # Ed25519 non-native field arithmetic
    └── sha512.cpp               # SHA-512 implementation
```

### File Descriptions

| File | Lines | Description |
|------|-------|-------------|
| `pqchain.cpp` | ~120 | ZK circuit verifying EdDSA public key derivation and hash commitment |
| `ed25519.cpp` | ~1,400 | Complete Ed25519 implementation: field emulation, point arithmetic, scalar multiplication |
| `ed25519.h` | ~150 | Defines `ed25519`, `ed25519_emulated`, and `ed25519_point` structures |
| `sha512.cpp` | ~100 | SHA-512 and HMAC-SHA-512 for RFC 8032 key derivation |
| `sha512.h` | ~20 | SHA-512 function declarations |

---

## Prerequisites and Setup

Follow the standard Ligetron setup instructions for your platform.

> **Note**: Setup instructions are adapted from the [Ligetron zkVM documentation](https://github.com/ligeroinc/ligero-prover).

<details>
<summary><b>macOS Setup</b></summary>

Install [Homebrew](https://brew.sh/) if not already installed:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install dependencies:

```bash
brew install cmake gmp mpfr libomp llvm boost
```
</details>

<details>
<summary><b>Ubuntu Setup</b></summary>

Update your system:

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

Install dependencies:

```bash
sudo apt-get install g++ libgmp-dev libtbb-dev cmake libssl-dev libboost-all-dev git -y
```

Install X11 libraries:

```bash
sudo apt install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libx11-xcb-dev
```

Install g++ 13:

```bash
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-13
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 20
sudo update-alternatives --set g++ "/usr/bin/g++-13"
```

Install Vulkan:

```bash
sudo apt install libvulkan1 vulkan-tools
```

Upgrade CMake:

```bash
sudo apt remove --purge cmake && sudo apt autoremove
sudo apt install -y software-properties-common lsb-release wget gpg
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null
sudo apt update && sudo apt install cmake
```

Install NVIDIA drivers (if applicable):

```bash
sudo apt purge nvidia*
sudo apt install nvidia-driver-535 nvidia-dkms-535 nvidia-utils-535
sudo reboot
```

Install OpenGL:

```bash
sudo apt install mesa-common-dev libgl1-mesa-dev
```
</details>

### Build WebGPU (Dawn)

```bash
git clone https://dawn.googlesource.com/dawn
cd dawn/
git checkout cec4482eccee45696a7c0019e750c77f101ced04
mkdir release && cd release
cmake -DDAWN_FETCH_DEPENDENCIES=ON -DDAWN_BUILD_MONOLITHIC_LIBRARY=STATIC -DDAWN_ENABLE_INSTALL=ON -DCMAKE_BUILD_TYPE=Release ..
make -j
make install
```

### Build WebAssembly Binary Toolkit

```bash
git clone https://github.com/WebAssembly/wabt.git
cd wabt
git submodule update --init
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=g++-13 ..  # Ubuntu
# cmake -DCMAKE_CXX_COMPILER=clang++ ..  # macOS
make -j
sudo make install
```

---

## Building the Project

### Clone the Repository

```bash
git clone https://github.com/SoundnessLabs/pqchain.git
cd pqchain
```

### Build Native Prover/Verifier

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j
```

### Build the C++ SDK (includes PQChain circuit)

```bash
cd sdk/cpp
mkdir build && cd build
emcmake cmake ..
make -j
```

This produces `sdk/cpp/build/examples/pqchain.wasm`.

---

## Running the Prover and Verifier

### Generate a Proof

From the `build` directory:

```bash
./webgpu_prover '{
  "program": "../sdk/cpp/build/examples/pqchain.wasm",
  "shader-path": "../shader",
  "packing": 8192,
  "private-indices": [1],
  "args": [
    {"hex": "0574b75998ea6340a30096cc3b681347edae548ad43ce731873cf3b94b1b6d2d"},
    {"hex": "d7e347f6f9b6a9f19460ac13d40bff77eb910a73d51d1eb4dc0dc950dd12c5da"},
    {"hex": "5468697320697320612074657374206d65737361676500000000000000000000"},
    {"hex": "cca8dcd0056ec5245982179a6916bbc6e4232dd58260c3bb73859021530d7f1c2dcb514dc23b6a4e0c45dac43bcc7dab05ce14fdc17fd466a772678c1cc268d5"}
  ]
}'
```

### Verify the Proof

The verifier uses obscured (zeroed) private inputs:

```bash
./webgpu_verifier '{
  "program": "../sdk/cpp/build/examples/pqchain.wasm",
  "shader-path": "../shader",
  "packing": 8192,
  "private-indices": [1],
  "args": [
    {"hex": "0000000000000000000000000000000000000000000000000000000000000000"},
    {"hex": "d7e347f6f9b6a9f19460ac13d40bff77eb910a73d51d1eb4dc0dc950dd12c5da"},
    {"hex": "5468697320697320612074657374206d65737361676500000000000000000000"},
    {"hex": "cca8dcd0056ec5245982179a6916bbc6e4232dd58260c3bb73859021530d7f1c2dcb514dc23b6a4e0c45dac43bcc7dab05ce14fdc17fd466a772678c1cc268d5"}
  ]
}'
```

---

## Circuit Arguments

| Index | Field | Type | Size | Privacy | Description |
|-------|-------|------|------|---------|-------------|
| 1 | `seed` | hex | 32 bytes | **PRIVATE** | EdDSA seed (secret witness) |
| 2 | `pk` | hex | 32 bytes | Public | Expected Ed25519 public key |
| 3 | `msg` | hex | 32 bytes | Public | Message (zero-padded) |
| 4 | `hx` | hex | 64 bytes | Public | Hash commitment SHA-512(msg ‖ seed) |

### JSON Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `program` | string | ✓ | — | Path to the WASM circuit |
| `shader-path` | string | | `"./shader"` | Path to GPU shaders |
| `packing` | int | | 8192 | FFT packing size |
| `private-indices` | [int] | | [] | Indices of private arguments (1-indexed) |
| `args` | [object] | | [] | Circuit arguments |
| `gpu-threads` | int | | packing | Number of GPU threads |

---

## Performance Benchmarks

**Platform**: MacBook Pro M4 (12 cores, 24 GB RAM)  
**Methodology**: Average over 100 runs

| Metric | Value |
|--------|-------|
| **Proving Time** | 5.4 seconds |
| **Verification Time** | 2.3 seconds |
| **Proof Size** | 5.4 MB |
| **Memory Usage** | 34 MB |
| **Linear Constraints** | 331,238 |
| **Quadratic Constraints** | 4,592,987 |
| **Total Constraints** | 4,924,225 |

### Constraint Breakdown

| Component | Constraints | Percentage |
|-----------|-------------|------------|
| Non-native field emulation & scalar multiplication | ~3.4M | ~70% |
| SHA-512 operations | ~1.0M | ~20% |
| Other (comparisons, assertions) | ~0.5M | ~10% |

---

## Live Demo

Try PQChain directly in your browser—no installation required.

### **[Launch Demo →](https://soundness-pq-hub-qyf1.vercel.app/)**

### Features

- **100% Client-Side**: All proof generation happens in your browser via WebGPU
- **Zero Data Transmission**: Private keys never leave your device
- **Wallet Integration**: Connect Slush or Phantom wallets (TESTNET only)
- **Real-Time Metrics**: Watch constraint generation and proving stages live

### Requirements

- Chrome 113+ or Edge 113+ with WebGPU enabled
- GPU with WebGPU/Vulkan/Metal support
- 4GB+ VRAM recommended

### Demo Workflow

1. Navigate to the demo URL
2. Accept the security disclaimer
3. Connect a testnet wallet (Slush or Phantom)
4. Scroll to "Proof Generation"
5. Click "Generate Proof"
6. View timing breakdown and proof output

### Security Notice

> **This demo is for TESTNET only.** Never use mainnet wallets or real assets. Private keys are displayed for educational purposes. Create fresh test accounts and delete them after use.

---

## Troubleshooting

<details>
<summary><b>Build Issues</b></summary>

**CMake cannot find dependencies**
- Ensure all prerequisites are installed
- Check that paths are correctly set in environment variables

**Compilation errors with g++**
- Verify g++ 13 is installed: `g++ --version`
- Set as default: `sudo update-alternatives --set g++ /usr/bin/g++-13`

**WebGPU initialization fails**
- Install/update GPU drivers
- Verify Vulkan support: `vulkaninfo`
</details>

<details>
<summary><b>Runtime Issues</b></summary>

**Proof generation hangs**
- Reduce packing size (try 4096)
- Close other GPU-intensive applications

**"Out of memory" error**
- Use a smaller packing size
- Ensure sufficient GPU VRAM (4GB+ recommended)

**WebGPU not available in browser**
- Use Chrome 113+ or Edge 113+
- Enable at `chrome://flags/#enable-unsafe-webgpu`
</details>

<details>
<summary><b>Verification Failures</b></summary>

**Proof verification fails**
- Ensure public inputs match exactly between prover and verifier
- Verify hash commitment: `hx = SHA-512(msg || seed)`
- Check that private-indices match
</details>

---

### Development Setup

```bash
git clone https://github.com/SoundnessLabs/pqchain.git
cd pqchain
# Follow build instructions above
```

---

## License

Licensed under the Apache License, Version 2.0.

```
Copyright 2023-2025 Soundness Labs Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## About Soundness Labs

<p align="center">
  <a href="https://soundness.xyz">
    <img src="https://framerusercontent.com/images/Dd9qT2d3jy0lfqDeIhP7vMLRic.png?scale-down-to=512&width=2531&height=616" alt="Soundness Labs" width="300">
  </a>
</p>

**[Soundness Labs](https://soundness.xyz)** is a post-quantum cryptography company focused on blockchain security infrastructure. We build quantum-ready solutions that protect digital assets against future cryptographic threats.

### Connect With Us

- **Website**: [soundness.xyz](https://soundness.xyz)
- **GitHub**: [github.com/SoundnessLabs](https://github.com/SoundnessLabs)
- **Twitter/X**: [@SoundnessLabs](https://twitter.com/SoundnessLabs)

---

<p align="center">
  <b>Built by Soundness Labs</b><br>
  <i>Towards building a Sound Internet</i>
</p>