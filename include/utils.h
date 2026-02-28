/*
 * Quantum Privacy Guard – Utility functions.
 */

#ifndef QPG_UTILS_H
#define QPG_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* ── Memory safety ───────────────────────────────────────────────────────── */

/** Secure-zero a memory region (not optimised away by the compiler). */
void qpg_secure_zero(void *ptr, size_t len);

/* ── Constant-time comparison ────────────────────────────────────────────── */

/**
 * Compare two buffers in constant time.
 * @return 0 if equal, non-zero otherwise.
 */
int qpg_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

/* ── File I/O (file_io.c) ───────────────────────────────────────────────── */

/**
 * Read an entire file into a heap-allocated buffer.
 * Caller must free(*data) when done.
 */
int qpg_read_file(const char *path, uint8_t **data, size_t *len);

/**
 * Write a buffer to a file (binary mode, truncates existing).
 */
int qpg_write_file(const char *path, const uint8_t *data, size_t len);

/* ── Key file I/O (file_io.c) ───────────────────────────────────────────── */

/**
 * Write a key file with the QPG metadata header.
 *
 * Format:
 *   [QPG\x01]          4 bytes magic
 *   [key_type]         1 byte
 *   [algo_name_len]    2 bytes big-endian
 *   [algo_name]        N bytes (no NUL)
 *   [key_data_len]     4 bytes big-endian
 *   [key_data]         M bytes
 */
int qpg_write_key_file(const char *path, uint8_t key_type,
                       const char *algorithm,
                       const uint8_t *key_data, size_t key_len);

/**
 * Read a key file written by qpg_write_key_file().
 *
 * @param algorithm   [out] Buffer of at least @a algo_buf_len bytes.
 * @param key_data    [out] Heap-allocated; caller must free.
 */
int qpg_read_key_file(const char *path,
                      uint8_t *key_type,
                      char *algorithm, size_t algo_buf_len,
                      uint8_t **key_data, size_t *key_len);

/* ── Base64 helpers (utils.c) ────────────────────────────────────────────── */

/**
 * Base64-encode binary data.  Caller must free(*output).
 */
int qpg_base64_encode(const uint8_t *input, size_t input_len,
                      char **output, size_t *output_len);

/**
 * Base64-decode a string.  Caller must free(*output).
 */
int qpg_base64_decode(const char *input, size_t input_len,
                      uint8_t **output, size_t *output_len);

/* ── Error formatting (utils.c) ──────────────────────────────────────────── */

/** Return a human-readable string for a QPG error code. */
const char *qpg_strerror(int error_code);

/** Print an error message to stderr (printf-style). */
void qpg_log_error(const char *fmt, ...);

/** Print an informational message to stdout (printf-style). */
void qpg_log_info(const char *fmt, ...);

/* ── Inline serialisation helpers ────────────────────────────────────────── */

static inline void qpg_write_be16(uint8_t *buf, uint16_t v)
{
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v);
}

static inline uint16_t qpg_read_be16(const uint8_t *buf)
{
    return (uint16_t)((uint16_t)buf[0] << 8 | buf[1]);
}

static inline void qpg_write_be32(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)(v);
}

static inline uint32_t qpg_read_be32(const uint8_t *buf)
{
    return (uint32_t)buf[0] << 24 | (uint32_t)buf[1] << 16 |
           (uint32_t)buf[2] << 8 | (uint32_t)buf[3];
}

#endif /* QPG_UTILS_H */
