/*
 * Quantum Privacy Guard – File I/O and key-file serialisation.
 *
 * Key-file wire format
 * ────────────────────
 * Offset  Size  Field
 * 0       4     Magic "QPG\x01"
 * 4       1     key_type
 * 5       2     algo_name_len  (big-endian, no NUL)
 * 7       N     algo_name
 * 7+N     4     key_data_len   (big-endian)
 * 11+N    M     key_data
 */

#include "qpg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Generic file read ───────────────────────────────────────────────────── */

int qpg_read_file(const char *path, uint8_t **data, size_t *len)
{
    if (!path || !data || !len)
        return QPG_ERROR_INVALID_ARGS;

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        qpg_log_error("Cannot open file: %s", path);
        return QPG_ERROR_FILE_IO;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return QPG_ERROR_FILE_IO;
    }
    long size = ftell(fp);
    if (size < 0)
    {
        fclose(fp);
        return QPG_ERROR_FILE_IO;
    }
    rewind(fp);

    *data = malloc((size_t)size);
    if (!*data)
    {
        fclose(fp);
        return QPG_ERROR_MEMORY;
    }

    size_t n = fread(*data, 1, (size_t)size, fp);
    fclose(fp);

    if (n != (size_t)size)
    {
        free(*data);
        *data = NULL;
        return QPG_ERROR_FILE_IO;
    }

    *len = n;
    return QPG_SUCCESS;
}

/* ── Generic file write ──────────────────────────────────────────────────── */

int qpg_write_file(const char *path, const uint8_t *data, size_t len)
{
    if (!path || !data)
        return QPG_ERROR_INVALID_ARGS;

    FILE *fp = fopen(path, "wb");
    if (!fp)
    {
        qpg_log_error("Cannot open file for writing: %s", path);
        return QPG_ERROR_FILE_IO;
    }

    size_t n = fwrite(data, 1, len, fp);
    fclose(fp);

    if (n != len)
        return QPG_ERROR_FILE_IO;
    return QPG_SUCCESS;
}

/* ── Write key file ──────────────────────────────────────────────────────── */

int qpg_write_key_file(const char *path, uint8_t key_type,
                       const char *algorithm,
                       const uint8_t *key_data, size_t key_len)
{
    if (!path || !algorithm || !key_data)
        return QPG_ERROR_INVALID_ARGS;

    size_t algo_len = strlen(algorithm);
    if (algo_len == 0 || algo_len > 0xFFFF)
        return QPG_ERROR_INVALID_ARGS;

    /*
     * Header: magic(4) + type(1) + algo_len(2) + algo(N) + key_len(4) + key(M)
     */
    size_t total = QPG_KEY_MAGIC_LEN + 1 + 2 + algo_len + 4 + key_len;

    uint8_t *buf = malloc(total);
    if (!buf)
        return QPG_ERROR_MEMORY;

    uint8_t *p = buf;

    memcpy(p, QPG_KEY_MAGIC, QPG_KEY_MAGIC_LEN);
    p += QPG_KEY_MAGIC_LEN;
    *p++ = key_type;
    qpg_write_be16(p, (uint16_t)algo_len);
    p += 2;
    memcpy(p, algorithm, algo_len);
    p += algo_len;
    qpg_write_be32(p, (uint32_t)key_len);
    p += 4;
    memcpy(p, key_data, key_len);
    p += key_len;

    int ret = qpg_write_file(path, buf, total);

    /* Zeroize the buffer if it contained a private key. */
    if (key_type == QPG_KEY_TYPE_KEM_PRIVATE ||
        key_type == QPG_KEY_TYPE_SIG_PRIVATE)
    {
        qpg_secure_zero(buf, total);
    }

    free(buf);
    return ret;
}

/* ── Read key file ───────────────────────────────────────────────────────── */

int qpg_read_key_file(const char *path,
                      uint8_t *key_type,
                      char *algorithm, size_t algo_buf_len,
                      uint8_t **key_data, size_t *key_len)
{
    if (!path || !key_type || !algorithm || !key_data || !key_len)
        return QPG_ERROR_INVALID_ARGS;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int ret = qpg_read_file(path, &raw, &raw_len);
    if (ret != QPG_SUCCESS)
        return ret;

    const uint8_t *p = raw;
    const uint8_t *end = raw + raw_len;

    /* Minimum: magic(4) + type(1) + algo_len(2) + key_len(4) = 11 */
    if (raw_len < 11)
    {
        ret = QPG_ERROR_FORMAT;
        goto fail;
    }

    /* Magic */
    if (memcmp(p, QPG_KEY_MAGIC, QPG_KEY_MAGIC_LEN) != 0)
    {
        qpg_log_error("Invalid key file (bad magic): %s", path);
        ret = QPG_ERROR_FORMAT;
        goto fail;
    }
    p += QPG_KEY_MAGIC_LEN;

    /* Key type */
    *key_type = *p++;

    /* Algorithm name */
    uint16_t alen = qpg_read_be16(p);
    p += 2;
    if (alen == 0 || alen >= algo_buf_len || (size_t)(end - p) < alen)
    {
        ret = QPG_ERROR_FORMAT;
        goto fail;
    }
    memcpy(algorithm, p, alen);
    algorithm[alen] = '\0';
    p += alen;

    /* Key data */
    if ((size_t)(end - p) < 4)
    {
        ret = QPG_ERROR_FORMAT;
        goto fail;
    }
    uint32_t klen = qpg_read_be32(p);
    p += 4;

    if ((size_t)(end - p) < klen)
    {
        ret = QPG_ERROR_FORMAT;
        goto fail;
    }

    *key_data = malloc(klen);
    if (!*key_data)
    {
        ret = QPG_ERROR_MEMORY;
        goto fail;
    }

    memcpy(*key_data, p, klen);
    *key_len = klen;

    free(raw);
    return QPG_SUCCESS;

fail:
    free(raw);
    return ret;
}
