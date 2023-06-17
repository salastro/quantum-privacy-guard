# Quantum Privacy Guard (QPG)

Quantum Privacy Guard (QPG) is a modern cryptography tool designed to provide secure communication and data storage using post-quantum cryptographic algorithms. QPG is written in C and utilizes the Open Quantum Safe (OQS) library, which is an open-source collection of quantum-resistant cryptographic algorithms.

## Features

- Post-quantum key encapsulation and digital signature algorithms
- Secure communication channels with forward secrecy
- Encryption and decryption of files and messages
- Easy-to-use command-line interface
- Cross-platform compatibility

## Prerequisites

Before you can build and use QPG, you will need the following dependencies installed on your system:

- C compiler (e.g., GCC or Clang)
- CMake (version 3.0 or higher)
- liboqs (version 0.8.0 or higher)

## Building QPG

1. Clone the repository:

```
git clone https://github.com/yourusername/quantum-privacy-guard.git
cd quantum-privacy-guard
```

2. Create a build directory:

```
mkdir build
cd build
```

3. Run CMake and compile the project:

```
cmake ..
make
```

4. (Optional) Install QPG on your system:

```
sudo make install
```

## Usage

After building QPG, you can use the command-line interface to encrypt, decrypt, sign, and verify messages and files. Here are some basic examples:

- Generate a key pair:

```
qpg --gen-key --algorithm [ALGORITHM] --public-key [PUBLIC_KEY_FILE] --private-key [PRIVATE_KEY_FILE]
```

- Encrypt a message or file:

```
qpg --encrypt --public-key [PUBLIC_KEY_FILE] --input [INPUT_FILE] --output [OUTPUT_FILE]
```

- Decrypt a message or file:

```
qpg --decrypt --private-key [PRIVATE_KEY_FILE] --input [INPUT_FILE] --output [OUTPUT_FILE]
```

- Sign a message or file:

```
qpg --sign --private-key [PRIVATE_KEY_FILE] --input [INPUT_FILE] --output [OUTPUT_FILE]
```

- Verify a message or file:

```
qpg --verify --public-key [PUBLIC_KEY_FILE] --input [INPUT_FILE]
```

For a full list of options and supported algorithms, run `qpg --help`.

## Contributing

We welcome contributions to QPG, whether it's in the form of bug reports, feature requests, or code contributions. Please follow the [contributing guidelines](CONTRIBUTING.md) to get started.

## License

QPG is licensed under the [MIT License](LICENSE).
