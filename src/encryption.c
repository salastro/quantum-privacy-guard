/*
 * Quantum Privacy Guard – Symmetric encryption (AES-256-GCM) and key
 * derivation via OpenSSL.
 */

#include "qpg.h"

#include <openssl/evp.h>
#include <oqs/oqs.h>
#include <string.h>

/* ── AES-256-GCM encrypt ─────────────────────────────────────────────────── */

int qpg_aes256gcm_encrypt(const uint8_t *key,
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *iv,
                          uint8_t *ciphertext, size_t *ciphertext_len,
                          uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return QPG_ERROR_CRYPTO;

    int ret = QPG_ERROR_CRYPTO;
    int len = 0;

    /* Generate a random 12-byte IV using the OQS CSPRNG. */
    OQS_randombytes(iv, QPG_AES_IV_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            QPG_AES_IV_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, (int)plaintext_len) != 1)
        goto cleanup;
    *ciphertext_len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto cleanup;
    *ciphertext_len += (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            QPG_AES_TAG_LEN, tag) != 1)
        goto cleanup;

    ret = QPG_SUCCESS;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── AES-256-GCM decrypt ─────────────────────────────────────────────────── */

int qpg_aes256gcm_decrypt(const uint8_t *key,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          const uint8_t *iv,
                          const uint8_t *tag,
                          uint8_t *plaintext, size_t *plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return QPG_ERROR_CRYPTO;

    int ret = QPG_ERROR_CRYPTO;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            QPG_AES_IV_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(ctx, plaintext, &len,
                          ciphertext, (int)ciphertext_len) != 1)
        goto cleanup;
    *plaintext_len = (size_t)len;

    /* Set the expected tag before finalising. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            QPG_AES_TAG_LEN, (void *)tag) != 1)
        goto cleanup;

    /* EVP_DecryptFinal_ex returns 0 if the tag does not match. */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        goto cleanup;
    *plaintext_len += (size_t)len;

    ret = QPG_SUCCESS;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── SHA-256 key derivation ──────────────────────────────────────────────── */

int qpg_derive_key_sha256(const uint8_t *shared_secret, size_t secret_len,
                          uint8_t *derived_key)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return QPG_ERROR_CRYPTO;

    int ret = QPG_ERROR_CRYPTO;
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto cleanup;
    if (EVP_DigestUpdate(ctx, shared_secret, secret_len) != 1)
        goto cleanup;
    if (EVP_DigestFinal_ex(ctx, derived_key, &md_len) != 1)
        goto cleanup;

    ret = QPG_SUCCESS;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}
