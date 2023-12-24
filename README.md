# Encryption Tool in Rust

## Overview

This Rust-based encryption tool provides a secure and straightforward way to encrypt and decrypt files using various encryption algorithms, including AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.

## Caution
Use this for educational purposes only

## Table of Contents

- [Installation](#installation)
- [Building](#building)
- [Usage](#usage)
  - [Encrypt](#encryption)
  - [Decrypt](#decryption)

## Installation

Ensure you have Rust installed on your system. You can install Rust by following the instructions on [Rust's official website](https://www.rust-lang.org/tools/install).

Clone the repository:

```bash
git clone https://github.com/Typical-User0/file_encryptor.git
cd file_encryptor
```

## Building
```bash
cargo build --release
```

## Usage
### Encryption
```bash
./target/release/crypt encrypt aes128-gcm secret.txt secret.enc
./target/release/crypt encrypt aes256-gcm secret.txt secret.enc
./target/release/crypt encrypt chacha20-poly1305 secret.txt secret.enc
```
### Decryption
```bash
./target/release/crypt decrypt secret.enc decrypted.txt
```
