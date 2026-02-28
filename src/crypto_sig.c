/*
 * Quantum Privacy Guard – Digital signature operations.
 *
 * Signature-file wire format
 * ──────────────────────────
 * Offset  Size  Field
 * 0       4     Magic "QPGS"
 * 4       2     algo_name_len  (big-endian)
 * 6       N     algo_name      (no NUL)
 * 6+N     4     sig_data_len   (big-endian)
 * 10+N    M     sig_data
 */

#include "qpg.h"

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Key-pair generation ─────────────────────────────────────────────────── */

int qpg_generate_sig_keypair(const char *algorithm,
                             const char *pub_file,
                             const char *priv_file)
{
    OQS_SIG *sig = OQS_SIG_new(algorithm);
    if (!sig)
    {
        qpg_log_error("Unsupported signature algorithm: %s", algorithm);
        return QPG_ERROR_UNSUPPORTED;
    }

    int ret = QPG_ERROR_MEMORY;
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);

    if (!pk || !sk)
    {
        qpg_log_error("Memory allocation failed");
        goto cleanup;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)
    {
        qpg_log_error("Signature keypair generation failed");
        ret = QPG_ERROR_CRYPTO;
        goto cleanup;
    }

    ret = qpg_write_key_file(pub_file, QPG_KEY_TYPE_SIG_PUBLIC,
                             algorithm, pk, sig->length_public_key);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Failed to write public key to %s", pub_file);
        goto cleanup;
    }

    ret = qpg_write_key_file(priv_file, QPG_KEY_TYPE_SIG_PRIVATE,
                             algorithm, sk, sig->length_secret_key);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Failed to write private key to %s", priv_file);
        goto cleanup;
    }

    qpg_log_info("Signature keypair generated (%s)", algorithm);
    qpg_log_info("  Public key  → %s (%zu bytes)", pub_file,
                 sig->length_public_key);
    qpg_log_info("  Private key → %s (%zu bytes)", priv_file,
                 sig->length_secret_key);

cleanup:
    if (sk)
    {
        qpg_secure_zero(sk, sig->length_secret_key);
        free(sk);
    }
    free(pk);
    OQS_SIG_free(sig);
    return ret;
}

/* ── Sign ────────────────────────────────────────────────────────────────── */

int qpg_sign(const char *priv_file,
             const char *input_file,
             const char *sig_file)
{
    int ret = QPG_ERROR;

    uint8_t *sk_data = NULL;
    uint8_t *message = NULL;
    uint8_t *sig_data = NULL;
    uint8_t *outbuf = NULL;
    OQS_SIG *sig = NULL;

    char algorithm[QPG_MAX_ALGO_NAME];
    uint8_t key_type = 0;
    size_t sk_len = 0, msg_len = 0;

    /* 1. Read private key ------------------------------------------------- */
    ret = qpg_read_key_file(priv_file, &key_type, algorithm,
                            sizeof(algorithm), &sk_data, &sk_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read private key from %s", priv_file);
        goto cleanup;
    }
    if (key_type != QPG_KEY_TYPE_SIG_PRIVATE)
    {
        qpg_log_error("Key file %s is not a signature private key", priv_file);
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 2. Initialise SIG --------------------------------------------------- */
    sig = OQS_SIG_new(algorithm);
    if (!sig)
    {
        qpg_log_error("Unsupported signature algorithm: %s", algorithm);
        ret = QPG_ERROR_UNSUPPORTED;
        goto cleanup;
    }
    if (sk_len != sig->length_secret_key)
    {
        qpg_log_error("Private key length mismatch");
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 3. Read input ------------------------------------------------------- */
    ret = qpg_read_file(input_file, &message, &msg_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read input file %s", input_file);
        goto cleanup;
    }

    /* 4. Sign ------------------------------------------------------------- */
    sig_data = malloc(sig->length_signature);
    if (!sig_data)
    {
        ret = QPG_ERROR_MEMORY;
        goto cleanup;
    }

    size_t actual_sig_len = 0;
    if (OQS_SIG_sign(sig, sig_data, &actual_sig_len,
                     message, msg_len, sk_data) != OQS_SUCCESS)
    {
        qpg_log_error("Signing failed");
        ret = QPG_ERROR_CRYPTO;
        goto cleanup;
    }

    /* 5. Serialise -------------------------------------------------------- */
    {
        size_t algo_len = strlen(algorithm);
        size_t total = QPG_SIG_MAGIC_LEN + 2 + algo_len + 4 +
                       actual_sig_len;

        outbuf = malloc(total);
        if (!outbuf)
        {
            ret = QPG_ERROR_MEMORY;
            goto cleanup;
        }

        uint8_t *p = outbuf;
        memcpy(p, QPG_SIG_MAGIC, QPG_SIG_MAGIC_LEN);
        p += QPG_SIG_MAGIC_LEN;
        qpg_write_be16(p, (uint16_t)algo_len);
        p += 2;
        memcpy(p, algorithm, algo_len);
        p += algo_len;
        qpg_write_be32(p, (uint32_t)actual_sig_len);
        p += 4;
        memcpy(p, sig_data, actual_sig_len);
        p += actual_sig_len;

        ret = qpg_write_file(sig_file, outbuf, total);
        if (ret != QPG_SUCCESS)
            qpg_log_error("Cannot write signature to %s", sig_file);
        else
            qpg_log_info("Signed %s → %s (%zu bytes)", input_file,
                         sig_file, actual_sig_len);
    }

cleanup:
    if (sk_data)
    {
        qpg_secure_zero(sk_data, sk_len);
        free(sk_data);
    }
    free(message);
    free(sig_data);
    free(outbuf);
    if (sig)
        OQS_SIG_free(sig);
    return ret;
}

/* ── Verify ──────────────────────────────────────────────────────────────── */

int qpg_verify(const char *pub_file,
               const char *input_file,
               const char *sig_file)
{
    int ret = QPG_ERROR;

    uint8_t *pk_data = NULL;
    uint8_t *message = NULL;
    uint8_t *sig_raw = NULL;
    OQS_SIG *sig = NULL;

    char pk_algo[QPG_MAX_ALGO_NAME];
    uint8_t key_type = 0;
    size_t pk_len = 0, msg_len = 0, sig_raw_len = 0;

    /* 1. Read public key -------------------------------------------------- */
    ret = qpg_read_key_file(pub_file, &key_type, pk_algo,
                            sizeof(pk_algo), &pk_data, &pk_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read public key from %s", pub_file);
        goto cleanup;
    }
    if (key_type != QPG_KEY_TYPE_SIG_PUBLIC)
    {
        qpg_log_error("Key file %s is not a signature public key", pub_file);
        ret = QPG_ERROR_FORMAT;
        goto cleanup;
    }

    /* 2. Read signature file ---------------------------------------------- */
    ret = qpg_read_file(sig_file, &sig_raw, &sig_raw_len);
    if (ret != QPG_SUCCESS)
    {
        qpg_log_error("Cannot read signature file %s", sig_file);
        goto cleanup;
    }

    /* 3. Parse signature header ------------------------------------------- */
    {
        const uint8_t *p = sig_raw;
        const uint8_t *end = sig_raw + sig_raw_len;

        if ((size_t)(end - p) < QPG_SIG_MAGIC_LEN + 2)
        {
            qpg_log_error("Signature file too short");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        if (memcmp(p, QPG_SIG_MAGIC, QPG_SIG_MAGIC_LEN) != 0)
        {
            qpg_log_error("Invalid signature file (bad magic)");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        p += QPG_SIG_MAGIC_LEN;

        uint16_t algo_len = qpg_read_be16(p);
        p += 2;
        if (algo_len == 0 || algo_len >= QPG_MAX_ALGO_NAME ||
            (size_t)(end - p) < algo_len)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        char sig_algo[QPG_MAX_ALGO_NAME];
        memcpy(sig_algo, p, algo_len);
        sig_algo[algo_len] = '\0';
        p += algo_len;

        if (strcmp(sig_algo, pk_algo) != 0)
        {
            qpg_log_error("Algorithm mismatch: signature uses %s, "
                          "key is %s",
                          sig_algo, pk_algo);
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }

        if ((size_t)(end - p) < 4)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        uint32_t sd_len = qpg_read_be32(p);
        p += 4;
        if ((size_t)(end - p) < sd_len)
        {
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }
        const uint8_t *sd = p;

        /* 4. Initialise SIG ----------------------------------------------- */
        sig = OQS_SIG_new(sig_algo);
        if (!sig)
        {
            qpg_log_error("Unsupported signature algorithm: %s", sig_algo);
            ret = QPG_ERROR_UNSUPPORTED;
            goto cleanup;
        }
        if (pk_len != sig->length_public_key)
        {
            qpg_log_error("Public key length mismatch");
            ret = QPG_ERROR_FORMAT;
            goto cleanup;
        }

        /* 5. Read message ------------------------------------------------- */
        ret = qpg_read_file(input_file, &message, &msg_len);
        if (ret != QPG_SUCCESS)
        {
            qpg_log_error("Cannot read input file %s", input_file);
            goto cleanup;
        }

        /* 6. Verify ------------------------------------------------------- */
        if (OQS_SIG_verify(sig, message, msg_len,
                           sd, sd_len, pk_data) != OQS_SUCCESS)
        {
            qpg_log_error("Signature verification FAILED");
            ret = QPG_ERROR_VERIFY_FAIL;
            goto cleanup;
        }

        qpg_log_info("Signature verification OK");
        ret = QPG_SUCCESS;
    }

cleanup:
    free(pk_data);
    free(message);
    free(sig_raw);
    if (sig)
        OQS_SIG_free(sig);
    return ret;
}

/* ── List enabled signature algorithms ───────────────────────────────────── */

void qpg_list_sig_algorithms(void)
{
    int count = OQS_SIG_alg_count();
    for (int i = 0; i < count; i++)
    {
        const char *name = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(name))
            printf("  [SIG] %s\n", name);
    }
}
