# Quantum Privacy Guard (QPG)

**Post-quantum cryptographic CLI tool built on [Open Quantum Safe (liboqs)](https://openquantumsafe.org/).**

QPG provides:

- **Key Encapsulation (KEM)** — ML-KEM / Kyber and all other liboqs-supported KEM algorithms.
- **Digital Signatures** — ML-DSA / Dilithium, Falcon, SPHINCS+, and more.
- **Hybrid file encryption** — Ephemeral KEM encapsulation → SHA-256 key derivation → AES-256-GCM.
- **Forward secrecy** — Every encryption uses a fresh ephemeral KEM key pair; shared secrets are never reused.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building](#building)
3. [Usage](#usage)
4. [Supported Algorithms](#supported-algorithms)
5. [Key Storage Format](#key-storage-format)
6. [Security](#security)
7. [Project Structure](#project-structure)
8. [Testing](#testing)
9. [Contributing](#contributing)
10. [License](#license)

---

## Prerequisites

| Dependency | Minimum version |
|------------|-----------------|
| C compiler | C11-capable (GCC ≥ 7, Clang ≥ 5) |
| CMake      | ≥ 3.0 |
| liboqs     | ≥ 0.8.0 |
| OpenSSL    | ≥ 1.1.0 (for AES-256-GCM) |

Install liboqs from source or via your package manager:

```bash
# Build liboqs from source (example)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc) && sudo make install
```

---

## Building

```bash
git clone https://github.com/yourusername/quantum-privacy-guard.git
cd quantum-privacy-guard

mkdir build && cd build
cmake ..
make
```

Optional: install system-wide:

```bash
sudo make install
```

Build with tests:

```bash
cmake -DBUILD_TESTS=ON ..
make
ctest --output-on-failure
```

---

## Usage

### Generate a KEM key pair

```bash
qpg --gen-key \
    --algorithm ML-KEM-768 \
    --public-key pub.key \
    --private-key priv.key
```

### Encrypt a file

```bash
qpg --encrypt \
    --public-key pub.key \
    --input secret.txt \
    --output secret.enc
```

### Decrypt a file

```bash
qpg --decrypt \
    --private-key priv.key \
    --input secret.enc \
    --output secret.txt
```

### Generate a signature key pair

```bash
qpg --gen-key \
    --algorithm ML-DSA-65 \
    --type sig \
    --public-key sig_pub.key \
    --private-key sig_priv.key
```

### Sign a file

```bash
qpg --sign \
    --private-key sig_priv.key \
    --input document.pdf \
    --output document.sig
```

### Verify a signature

```bash
qpg --verify \
    --public-key sig_pub.key \
    --input document.pdf \
    --signature document.sig
```

### List supported algorithms

```bash
qpg --list-algorithms
```

### Help

```bash
qpg --help
```

---

## Supported Algorithms

QPG dynamically queries liboqs at runtime for all enabled algorithms. Run `qpg --list-algorithms` or `qpg --help` for the full list on your build.

**Common KEM algorithms:**

| Algorithm | NIST Level | Notes |
|-----------|-----------|-------|
| ML-KEM-512 | 1 | FIPS 203 (Kyber) |
| ML-KEM-768 | 3 | FIPS 203 (Kyber) — recommended |
| ML-KEM-1024 | 5 | FIPS 203 (Kyber) |

**Common signature algorithms:**

| Algorithm | NIST Level | Notes |
|-----------|-----------|-------|
| ML-DSA-44 | 2 | FIPS 204 (Dilithium) |
| ML-DSA-65 | 3 | FIPS 204 (Dilithium) — recommended |
| ML-DSA-87 | 5 | FIPS 204 (Dilithium) |
| Falcon-512 | 1 | Compact signatures |
| Falcon-1024 | 5 | Compact signatures |
| SPHINCS+-SHA2-128f-simple | 1 | Hash-based (conservative) |

> **Note:** Algorithm availability depends on your liboqs build configuration.

---

## Key Storage Format

Keys are stored in a compact binary format with a metadata header:

```
[QPG\x01]          4 bytes — magic
[key_type]         1 byte  — KEM_PUB / KEM_PRIV / SIG_PUB / SIG_PRIV
[algo_name_len]    2 bytes — big-endian
[algo_name]        N bytes — algorithm identifier (no NUL)
[key_data_len]     4 bytes — big-endian
[key_data]         M bytes — raw key material
```

---

## Security

### Implemented safeguards

- **Secure random generation** via `OQS_randombytes()` (system CSPRNG).
- **Memory zeroization** of all private keys, shared secrets, and symmetric keys after use (volatile memset to prevent dead-store elimination).
- **AES-256-GCM authenticated encryption** — tampering is detected.
- **Constant-time comparison** for signature verification paths.
- **Ephemeral KEM encapsulation** — each encryption generates a fresh shared secret (forward secrecy).
- **Strict validation** of all file formats, key types, and algorithm compatibility.

### ⚠️ Security Disclaimer

> Post-quantum cryptographic algorithms are under active standardisation and research.
> While QPG implements them using the well-audited liboqs library, **use this tool at your own risk** for production workloads.
> No formal security audit has been performed on this codebase.
> Always keep your private keys secure and back them up.

---

## Project Structure

```
quantum-privacy-guard/
├── CMakeLists.txt           CMake build configuration
├── LICENSE                  MIT License
├── README.md                This file
├── include/
│   ├── qpg.h               Master header — constants, error codes
│   ├── crypto.h             KEM, SIG, and AES function declarations
│   ├── cli.h                CLI argument parsing types and functions
│   └── utils.h              Utility functions and serialisation helpers
├── src/
│   ├── main.c               Entry point
│   ├── cli.c                GNU-style argument parser and dispatcher
│   ├── crypto_kem.c         KEM keypair generation, encrypt, decrypt
│   ├── crypto_sig.c         SIG keypair generation, sign, verify
│   ├── encryption.c         AES-256-GCM encrypt/decrypt, SHA-256 KDF
│   ├── file_io.c            File read/write, key-file serialisation
│   └── utils.c              Secure zero, base64, error logging
└── tests/
    ├── CMakeLists.txt        Test build rules
    └── test_qpg.c            KEM round-trip, SIG, tamper, bad-algo tests
```

---

## Testing

```bash
cd build
cmake -DBUILD_TESTS=ON ..
make
ctest --output-on-failure
```

The test suite covers:

1. **KEM round-trip** — generate keypair → encrypt → decrypt → compare.
2. **SIG round-trip** — generate keypair → sign → verify.
3. **Invalid signature detection** — tampered message must be rejected.
4. **Unsupported algorithm** — nonsense algorithm names must fail cleanly.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Write tests for new functionality.
4. Ensure all tests pass (`ctest`).
5. Open a pull request with a clear description.

Coding standards:

- C11 with `-Wall -Wextra -Wpedantic`.
- No memory leaks (test with Valgrind / ASan).
- Zeroize all secret material before freeing.
- Check every return value from liboqs and OpenSSL.

---

## License

QPG is licensed under the [MIT License](LICENSE).

```
Copyright (c) 2023 SalahDin Rezk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```
