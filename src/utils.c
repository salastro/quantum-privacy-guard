/*
 * Quantum Privacy Guard – Utility functions.
 *
 * • Secure memory zeroization
 * • Constant-time comparison
 * • Base64 encode / decode
 * • Error formatting and logging
 */

#include "qpg.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Secure memory zeroization ───────────────────────────────────────────── */

/*
 * Use a volatile function-pointer trick so the compiler cannot optimise
 * the memset away.  C11's optional memset_s would also work but is not
 * universally available.
 */
static void *(*const volatile memset_func)(void *, int, size_t) = memset;

void qpg_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0)
        memset_func(ptr, 0, len);
}

/* ── Constant-time comparison ────────────────────────────────────────────── */

int qpg_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return (int)diff;
}

/* ── Base64 encoding / decoding ──────────────────────────────────────────── */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int qpg_base64_encode(const uint8_t *input, size_t input_len,
                      char **output, size_t *output_len)
{
    if (!input || !output || !output_len)
        return QPG_ERROR_INVALID_ARGS;

    size_t olen = 4 * ((input_len + 2) / 3);
    *output = malloc(olen + 1);
    if (!*output)
        return QPG_ERROR_MEMORY;

    size_t j = 0;
    for (size_t i = 0; i < input_len;)
    {
        uint32_t a = i < input_len ? input[i++] : 0;
        uint32_t b = i < input_len ? input[i++] : 0;
        uint32_t c = i < input_len ? input[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        (*output)[j++] = b64_table[(triple >> 18) & 0x3F];
        (*output)[j++] = b64_table[(triple >> 12) & 0x3F];
        (*output)[j++] = b64_table[(triple >> 6) & 0x3F];
        (*output)[j++] = b64_table[triple & 0x3F];
    }

    /* Pad */
    size_t mod = input_len % 3;
    if (mod == 1)
    {
        (*output)[j - 1] = '=';
        (*output)[j - 2] = '=';
    }
    else if (mod == 2)
    {
        (*output)[j - 1] = '=';
    }

    (*output)[j] = '\0';
    *output_len = j;
    return QPG_SUCCESS;
}

static inline int b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

int qpg_base64_decode(const char *input, size_t input_len,
                      uint8_t **output, size_t *output_len)
{
    if (!input || !output || !output_len)
        return QPG_ERROR_INVALID_ARGS;
    if (input_len % 4 != 0)
        return QPG_ERROR_FORMAT;

    size_t olen = (input_len / 4) * 3;
    if (input_len > 0 && input[input_len - 1] == '=')
        olen--;
    if (input_len > 1 && input[input_len - 2] == '=')
        olen--;

    *output = malloc(olen);
    if (!*output)
        return QPG_ERROR_MEMORY;

    size_t j = 0;
    for (size_t i = 0; i < input_len; i += 4)
    {
        int a = b64_decode_char(input[i]);
        int b = b64_decode_char(input[i + 1]);
        int c = (input[i + 2] == '=') ? 0 : b64_decode_char(input[i + 2]);
        int d = (input[i + 3] == '=') ? 0 : b64_decode_char(input[i + 3]);

        if (a < 0 || b < 0 || c < 0 || d < 0)
        {
            free(*output);
            *output = NULL;
            return QPG_ERROR_FORMAT;
        }

        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                          ((uint32_t)c << 6) | (uint32_t)d;

        if (j < olen)
            (*output)[j++] = (uint8_t)(triple >> 16);
        if (j < olen)
            (*output)[j++] = (uint8_t)(triple >> 8);
        if (j < olen)
            (*output)[j++] = (uint8_t)(triple);
    }

    *output_len = olen;
    return QPG_SUCCESS;
}

/* ── Error formatting ────────────────────────────────────────────────────── */

const char *qpg_strerror(int code)
{
    switch (code)
    {
    case QPG_SUCCESS:
        return "Success";
    case QPG_ERROR:
        return "General error";
    case QPG_ERROR_INVALID_ARGS:
        return "Invalid arguments";
    case QPG_ERROR_FILE_IO:
        return "File I/O error";
    case QPG_ERROR_CRYPTO:
        return "Cryptographic error";
    case QPG_ERROR_MEMORY:
        return "Memory allocation failed";
    case QPG_ERROR_UNSUPPORTED:
        return "Unsupported algorithm";
    case QPG_ERROR_VERIFY_FAIL:
        return "Verification failed";
    case QPG_ERROR_FORMAT:
        return "Invalid file format";
    default:
        return "Unknown error";
    }
}

void qpg_log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[QPG ERROR] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void qpg_log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[QPG] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}
