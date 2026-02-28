/*
 * Quantum Privacy Guard – Cryptographic operations.
 */

#ifndef QPG_CRYPTO_H
#define QPG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ── KEM operations (crypto_kem.c) ───────────────────────────────────────── */

/**
 * Generate a KEM key pair and write the keys to disk.
 *
 * @param algorithm   liboqs KEM algorithm name (e.g. "ML-KEM-768").
 * @param pub_file    Output path for the public key.
 * @param priv_file   Output path for the private (secret) key.
 * @return QPG_SUCCESS or a negative error code.
 */
int qpg_generate_kem_keypair(const char *algorithm,
                             const char *pub_file,
                             const char *priv_file);

/**
 * Encrypt a file using KEM-based hybrid encryption.
 *
 * Flow: ephemeral KEM encapsulation → SHA-256 key derivation → AES-256-GCM.
 *
 * @param pub_file    Path to the recipient's KEM public key.
 * @param input_file  Path to the plaintext input.
 * @param output_file Path to the encrypted output.
 */
int qpg_encrypt_with_kem(const char *pub_file,
                         const char *input_file,
                         const char *output_file);

/**
 * Decrypt a file that was encrypted with qpg_encrypt_with_kem().
 *
 * @param priv_file   Path to the KEM private key.
 * @param input_file  Path to the encrypted input.
 * @param output_file Path to the plaintext output.
 */
int qpg_decrypt_with_kem(const char *priv_file,
                         const char *input_file,
                         const char *output_file);

/** Print all enabled KEM algorithms to stdout. */
void qpg_list_kem_algorithms(void);

/* ── Signature operations (crypto_sig.c) ─────────────────────────────────── */

/**
 * Generate a signature key pair and write the keys to disk.
 *
 * @param algorithm   liboqs SIG algorithm name (e.g. "ML-DSA-65").
 * @param pub_file    Output path for the public key.
 * @param priv_file   Output path for the private (secret) key.
 */
int qpg_generate_sig_keypair(const char *algorithm,
                             const char *pub_file,
                             const char *priv_file);

/**
 * Sign a file.
 *
 * @param priv_file  Path to the SIG private key.
 * @param input_file Path to the message/file to sign.
 * @param sig_file   Output path for the detached signature.
 */
int qpg_sign(const char *priv_file,
             const char *input_file,
             const char *sig_file);

/**
 * Verify a detached signature.
 *
 * @param pub_file   Path to the SIG public key.
 * @param input_file Path to the signed message/file.
 * @param sig_file   Path to the detached signature.
 * @return QPG_SUCCESS if valid, QPG_ERROR_VERIFY_FAIL otherwise.
 */
int qpg_verify(const char *pub_file,
               const char *input_file,
               const char *sig_file);

/** Print all enabled SIG algorithms to stdout. */
void qpg_list_sig_algorithms(void);

/* ── Symmetric encryption helpers (encryption.c) ────────────────────────── */

/**
 * AES-256-GCM encrypt.
 *
 * @param key            32-byte symmetric key.
 * @param plaintext      Input data.
 * @param plaintext_len  Length of input data.
 * @param iv             [out] 12-byte IV (randomly generated inside).
 * @param ciphertext     [out] Output buffer (>= plaintext_len bytes).
 * @param ciphertext_len [out] Length of produced ciphertext.
 * @param tag            [out] 16-byte authentication tag.
 */
int qpg_aes256gcm_encrypt(const uint8_t *key,
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *iv,
                          uint8_t *ciphertext, size_t *ciphertext_len,
                          uint8_t *tag);

/**
 * AES-256-GCM decrypt.
 *
 * @param key            32-byte symmetric key.
 * @param ciphertext     Encrypted data.
 * @param ciphertext_len Length of encrypted data.
 * @param iv             12-byte IV.
 * @param tag            16-byte authentication tag.
 * @param plaintext      [out] Output buffer (>= ciphertext_len bytes).
 * @param plaintext_len  [out] Length of produced plaintext.
 */
int qpg_aes256gcm_decrypt(const uint8_t *key,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *iv,
                          const uint8_t *tag,
                          uint8_t *plaintext, size_t *plaintext_len);

/**
 * Derive a 32-byte key from a shared secret using SHA-256.
 */
int qpg_derive_key_sha256(const uint8_t *shared_secret, size_t secret_len,
                          uint8_t *derived_key);

#endif /* QPG_CRYPTO_H */
