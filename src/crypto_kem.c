/*
 * Quantum Privacy Guard – KEM-based key encapsulation and hybrid encryption.
 *
 * Encryption flow
 * ───────────────
 * 1.  Read the recipient's KEM public key.
 * 2.  OQS_KEM_encaps() → ephemeral ciphertext + shared secret.
 * 3.  Derive a 32-byte AES key from the shared secret (SHA-256).
 * 4.  AES-256-GCM encrypt the plaintext.
 * 5.  Serialise: magic ‖ algo ‖ KEM-ct ‖ IV ‖ tag ‖ AES-ct.
 * 6.  Wipe every secret buffer.
 */

#include "qpg.h"

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Key-pair generation ─────────────────────────────────────────────────── */

int qpg_generate_kem_keypair(const char *algorithm,
                             const char *pub_file,
                             const char *priv_file)
{
    OQS_KEM *kem = OQS_KEM_new(algorithm);
    if (!kem)
    {
        qpg_log_error("Unsupported KEM algorithm: %s", algorithm);
        return QPG_ERROR_UNSUPPORTED;
    }

    int ret = QPG_ERROR_MEMORY;
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);

    if (!pk || !sk)
    {
        qpg_log_error("Memory allocation failed");
        goto cleanup;
    }

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS)
    {
        qpg_log_error("KEM keypair generation failed");
        ret = QPG_ERROR_CRYPTO;
        goto cleanup;
    }

    ret = qpg_write_key_file(pub_file, QPG_KEY_TYPE_KEM_PUBLIC,
                             algorithm, pk, kem->length_public_key);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Failed to write public key to %s", pub_file);
        goto cleanup;
    }

    ret = qpg_write_key_file(priv_file, QPG_KEY_TYPE_KEM_PRIVATE,
                             algorithm, sk, kem->length_secret_key);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Failed to write private key to %s", priv_file);
        goto cleanup;
    }

    qpg_log_info("KEM keypair generated (%s)", algorithm);
    qpg_log_info("  Public key  → %s (%zu bytes)", pub_file,
                 kem->length_public_key);
    qpg_log_info("  Private key → %s (%zu bytes)", priv_file,
                 kem->length_secret_key);

cleanup:
    if (sk)
    {
        qpg_secure_zero(sk, kem->length_secret_key);
        free(sk);
    }
    free(pk);
    OQS_KEM_free(kem);
    return ret;
}

/* ── Encrypt ─────────────────────────────────────────────────────────────── */

/*
 * Encrypted-file wire format
 * ──────────────────────────
 * Offset  Size  Field
 * 0       4     Magic "QPGE"
 * 4       2     algo_name_len  (big-endian)
 * 6       N     algo_name      (no NUL)
 * 6+N     4     kem_ct_len     (big-endian)
 * 10+N    M     kem_ciphertext
 * 10+N+M  12    AES IV
 * 22+N+M  16    AES-GCM tag
 * 38+N+M  …     AES ciphertext
 */

int qpg_encrypt_with_kem(const char *pub_file,
                         const char *input_file,
                         const char *output_file)
{
    int ret = QPG_ERROR;

    /* Buffers that must be freed / zeroed. */
    uint8_t *pk_data = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *kem_ct = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *aes_ct = NULL;
    uint8_t *outbuf = NULL;
    OQS_KEM *kem = NULL;

    uint8_t aes_key[QPG_AES_KEY_LEN];
    uint8_t iv[QPG_AES_IV_LEN];
    uint8_t tag[QPG_AES_TAG_LEN];

    char algorithm[QPG_MAX_ALGO_NAME];
    uint8_t key_type = 0;
    size_t pk_len = 0, pt_len = 0, aes_ct_len = 0;

    /* 1. Read public key -------------------------------------------------- */
    ret = qpg_read_key_file(pub_file, &key_type, algorithm,
                            sizeof(algorithm), &pk_data, &pk_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read public key from %s", pub_file);
        goto cleanup;
    }
    if (key_type != QPG_KEY_TYPE_KEM_PUBLIC)
    {
        qpg_log_error("Key file %s is not a KEM public key", pub_file);
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 2. Initialise KEM --------------------------------------------------- */
    kem = OQS_KEM_new(algorithm);
    if (!kem)
    {
        qpg_log_error("Unsupported KEM algorithm: %s", algorithm);
        ret = QPG_ERROR_UNSUPPORTED;
        goto cleanup;
    }
    if (pk_len != kem->length_public_key)
    {
        qpg_log_error("Public key length mismatch (got %zu, expected %zu)",
                      pk_len, kem->length_public_key);
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 3. KEM encapsulation ------------------------------------------------ */
    kem_ct = malloc(kem->length_ciphertext);
    shared_secret = malloc(kem->length_shared_secret);
    if (!kem_ct || !shared_secret)
    {
        ret = QPG_ERROR_MEMORY;
        goto cleanup;
    }

    if (OQS_KEM_encaps(kem, kem_ct, shared_secret, pk_data) != OQS_SUCCESS)
    {
        qpg_log_error("KEM encapsulation failed");
        ret = QPG_ERROR_CRYPTO;
        goto cleanup;
    }

    /* 4. Derive AES key --------------------------------------------------- */
    ret = qpg_derive_key_sha256(shared_secret, kem->length_shared_secret,
                                aes_key);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Key derivation failed");
        goto cleanup;
    }

    /* 5. Read plaintext --------------------------------------------------- */
    ret = qpg_read_file(input_file, &plaintext, &pt_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read input file %s", input_file);
        goto cleanup;
    }

    /* 6. AES-256-GCM encrypt ---------------------------------------------- */
    aes_ct = malloc(pt_len + 16); /* GCM never expands, but be safe */
    if (!aes_ct)
    {
        ret = QPG_ERROR_MEMORY;
        goto cleanup;
    }

    ret = qpg_aes256gcm_encrypt(aes_key, plaintext, pt_len,
                                iv, aes_ct, &aes_ct_len, tag);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("AES-256-GCM encryption failed");
        goto cleanup;
    }

    /* 7. Serialise -------------------------------------------------------- */
    {
        size_t algo_len = strlen(algorithm);
        size_t header = QPG_ENC_MAGIC_LEN + 2 + algo_len + 4 +
                        kem->length_ciphertext +
                        QPG_AES_IV_LEN + QPG_AES_TAG_LEN;
        size_t total = header + aes_ct_len;

        outbuf = malloc(total);
        if (!outbuf)
        {
            ret = QPG_ERROR_MEMORY;
            goto cleanup;
        }

        uint8_t *p = outbuf;

        memcpy(p, QPG_ENC_MAGIC, QPG_ENC_MAGIC_LEN);
        p += QPG_ENC_MAGIC_LEN;
        qpg_write_be16(p, (uint16_t)algo_len);
        p += 2;
        memcpy(p, algorithm, algo_len);
        p += algo_len;
        qpg_write_be32(p, (uint32_t)kem->length_ciphertext);
        p += 4;
        memcpy(p, kem_ct, kem->length_ciphertext);
        p += kem->length_ciphertext;
        memcpy(p, iv, QPG_AES_IV_LEN);
        p += QPG_AES_IV_LEN;
        memcpy(p, tag, QPG_AES_TAG_LEN);
        p += QPG_AES_TAG_LEN;
        memcpy(p, aes_ct, aes_ct_len);
        p += aes_ct_len;

        ret = qpg_write_file(output_file, outbuf, total);
        if (ret != QPG_SUCCESS)
            qpg_log_error("Cannot write encrypted output to %s", output_file);
        else
            qpg_log_info("Encrypted %s → %s (%zu bytes)", input_file,
                         output_file, total);
    }

cleanup:
    qpg_secure_zero(aes_key, sizeof(aes_key));
    qpg_secure_zero(iv, sizeof(iv));
    if (shared_secret)
    {
        qpg_secure_zero(shared_secret,
                        kem ? kem->length_shared_secret : 0);
        free(shared_secret);
    }
    free(kem_ct);
    free(pk_data);
    free(plaintext);
    free(aes_ct);
    free(outbuf);
    if (kem)
        OQS_KEM_free(kem);
    return ret;
}

/* ── Decrypt ─────────────────────────────────────────────────────────────── */

int qpg_decrypt_with_kem(const char *priv_file,
                         const char *input_file,
                         const char *output_file)
{
    int ret = QPG_ERROR;

    uint8_t *sk_data = NULL;
    uint8_t *enc_data = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *plaintext = NULL;
    OQS_KEM *kem = NULL;

    uint8_t aes_key[QPG_AES_KEY_LEN];
    char sk_algo[QPG_MAX_ALGO_NAME];
    uint8_t sk_type = 0;
    size_t sk_len = 0, enc_len = 0;

    /* 1. Read private key ------------------------------------------------- */
    ret = qpg_read_key_file(priv_file, &sk_type, sk_algo,
                            sizeof(sk_algo), &sk_data, &sk_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read private key from %s", priv_file);
        goto cleanup;
    }
    if (sk_type != QPG_KEY_TYPE_KEM_PRIVATE)
    {
        qpg_log_error("Key file %s is not a KEM private key", priv_file);
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 2. Read encrypted file ---------------------------------------------- */
    ret = qpg_read_file(input_file, &enc_data, &enc_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read encrypted file %s", input_file);
        goto cleanup;
    }

    /* 3. Parse header ----------------------------------------------------- */
    {
        const uint8_t *p = enc_data;
        const uint8_t *end = enc_data + enc_len;

        if ((size_t)(end - p) < QPG_ENC_MAGIC_LEN + 2)
        {
            qpg_log_error("Encrypted file too short");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        if (memcmp(p, QPG_ENC_MAGIC, QPG_ENC_MAGIC_LEN) != 0)
        {
            qpg_log_error("Invalid encrypted file (bad magic)");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        p += QPG_ENC_MAGIC_LEN;

        uint16_t algo_len = qpg_read_be16(p);
        p += 2;
        if (algo_len == 0 || algo_len >= QPG_MAX_ALGO_NAME ||
            (size_t)(end - p) < algo_len)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        char enc_algo[QPG_MAX_ALGO_NAME];
        memcpy(enc_algo, p, algo_len);
        enc_algo[algo_len] = '\0';
        p += algo_len;

        /* Verify algorithm match. */
        if (strcmp(enc_algo, sk_algo) != 0)
        {
            qpg_log_error("Algorithm mismatch: file uses %s, "
                          "key is %s",
                          enc_algo, sk_algo);
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }

        if ((size_t)(end - p) < 4)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        uint32_t kem_ct_len = qpg_read_be32(p);
        p += 4;

        if ((size_t)(end - p) < kem_ct_len)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        const uint8_t *kem_ct = p;
        p += kem_ct_len;

        if ((size_t)(end - p) < QPG_AES_IV_LEN + QPG_AES_TAG_LEN)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        const uint8_t *iv = p;
        p += QPG_AES_IV_LEN;
        const uint8_t *tag = p;
        p += QPG_AES_TAG_LEN;

        const uint8_t *aes_ct = p;
        size_t aes_ct_len = (size_t)(end - p);

        /* 4. Initialise KEM ----------------------------------------------- */
        kem = OQS_KEM_new(enc_algo);
        if (!kem)
        {
            qpg_log_error("Unsupported KEM algorithm: %s", enc_algo);
            ret = QPG_ERROR_UNSUPPORTED;
            goto cleanup;
        }
        if (sk_len != kem->length_secret_key)
        {
            qpg_log_error("Private key length mismatch");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        if (kem_ct_len != kem->length_ciphertext)
        {
            qpg_log_error("KEM ciphertext length mismatch");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }

        /* 5. KEM decapsulation -------------------------------------------- */
        shared_secret = malloc(kem->length_shared_secret);
        if (!shared_secret)
        {
            ret = QPG_ERROR_MEMORY;
            goto cleanup;
        }

        if (OQS_KEM_decaps(kem, shared_secret, kem_ct, sk_data) !=
            OQS_SUCCESS)
        {
            qpg_log_error("KEM decapsulation failed");
            ret = QPG_ERROR_CRYPTO;
            goto cleanup;
        }

        /* 6. Derive AES key ----------------------------------------------- */
        ret = qpg_derive_key_sha256(shared_secret,
                                    kem->length_shared_secret, aes_key);
        if (ret != QPG_SUCCESS)
        {
            goto cleanup;
        }

        /* 7. AES-256-GCM decrypt ------------------------------------------ */
        plaintext = malloc(aes_ct_len + 1);
        if (!plaintext)
        {
            ret = QPG_ERROR_MEMORY;
            goto cleanup;
        }

        size_t pt_len = 0;
        ret = qpg_aes256gcm_decrypt(aes_key, aes_ct, aes_ct_len,
                                    iv, tag, plaintext, &pt_len);
        if (ret != QPG_SUCCESS)
        {
            qpg_log_error("Decryption failed (authentication error)");
            goto cleanup;
        }

        /* 8. Write output ------------------------------------------------- */
        ret = qpg_write_file(output_file, plaintext, pt_len);
        if (ret != QPG_SUCCESS)
            qpg_log_error("Cannot write decrypted output to %s", output_file);
        else
            qpg_log_info("Decrypted %s → %s (%zu bytes)", input_file,
                         output_file, pt_len);
    }

cleanup:
    qpg_secure_zero(aes_key, sizeof(aes_key));
    if (shared_secret)
    {
        qpg_secure_zero(shared_secret,
                        kem ? kem->length_shared_secret : 0);
        free(shared_secret);
    }
    if (sk_data)
    {
        qpg_secure_zero(sk_data, sk_len);
        free(sk_data);
    }
    free(enc_data);
    free(plaintext);
    if (kem)
        OQS_KEM_free(kem);
    return ret;
}

/* ── List enabled KEM algorithms ─────────────────────────────────────────── */

void qpg_list_kem_algorithms(void)
{
    int count = OQS_KEM_alg_count();
    for (int i = 0; i < count; i++)
    {
        const char *name = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(name))
            printf("  [KEM] %s\n", name);
    }
}
