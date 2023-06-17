#ifndef QPG_CRYPTO_H
#define QPG_CRYPTO_H

/**
 * Generates a key pair using the specified algorithm and saves the public and
 * private keys to the specified files.
 *
 * @param algorithm The name of the algorithm to use for key generation.
 * @param public_key_file The file path to save the public key.
 * @param private_key_file The file path to save the private key.
 * @return 0 on success, non-zero on error.
 */
int qpg_generate_keypair(const char *algorithm, const char *public_key_file,
                         const char *private_key_file);

/**
 * Encrypts a message or file using the public key and saves the encrypted
 * output to the specified file.
 *
 * @param public_key_file The file path of the public key.
 * @param input_file The file path of the input message or file.
 * @param output_file The file path to save the encrypted output.
 * @return 0 on success, non-zero on error.
 */
int qpg_encrypt(const char *public_key_file, const char *input_file,
                const char *output_file);

/**
 * Decrypts a message or file using the private key and saves the decrypted
 * output to the specified file.
 *
 * @param private_key_file The file path of the private key.
 * @param input_file The file path of the encrypted input message or file.
 * @param output_file The file path to save the decrypted output.
 * @return 0 on success, non-zero on error.
 */
int qpg_decrypt(const char *private_key_file, const char *input_file,
                const char *output_file);

/**
 * Signs a message or file using the private key and saves the signature to the
 * specified file.
 *
 * @param private_key_file The file path of the private key.
 * @param input_file The file path of the input message or file.
 * @param signature_file The file path to save the generated signature.
 * @return 0 on success, non-zero on error.
 */
int qpg_sign(const char *private_key_file, const char *input_file,
             const char *signature_file);

/**
 * Verifies the signature of a message or file using the public key and displays
 * the result.
 *
 * @param public_key_file The file path of the public key.
 * @param input_file The file path of the input message or file.
 * @param signature_file The file path of the signature to verify.
 * @return 0 if the signature is valid, non-zero otherwise.
 */
int qpg_verify(const char *public_key_file, const char *input_file,
               const char *signature_file);

#endif // QPG_CRYPTO_H
