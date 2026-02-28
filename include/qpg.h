/*
 * Quantum Privacy Guard (QPG)
 * Post-quantum cryptographic CLI tool built on Open Quantum Safe (liboqs).
 *
 * Copyright (c) 2023 SalahDin Rezk
 * Licensed under the MIT License.
 */

#ifndef QPG_H
#define QPG_H

/* ── Version ─────────────────────────────────────────────────────────────── */

#define QPG_VERSION_MAJOR 1
#define QPG_VERSION_MINOR 0
#define QPG_VERSION_PATCH 0
#define QPG_VERSION_STRING "1.0.0"

/* ── Error codes ─────────────────────────────────────────────────────────── */

#define QPG_SUCCESS 0
#define QPG_ERROR -1
#define QPG_ERROR_INVALID_ARGS -2
#define QPG_ERROR_FILE_IO -3
#define QPG_ERROR_CRYPTO -4
#define QPG_ERROR_MEMORY -5
#define QPG_ERROR_UNSUPPORTED -6
#define QPG_ERROR_VERIFY_FAIL -7
#define QPG_ERROR_FORMAT -8

/* ── Key-file format constants ───────────────────────────────────────────── */

#define QPG_KEY_MAGIC "QPG\x01"
#define QPG_KEY_MAGIC_LEN 4

#define QPG_KEY_TYPE_KEM_PUBLIC 0x01
#define QPG_KEY_TYPE_KEM_PRIVATE 0x02
#define QPG_KEY_TYPE_SIG_PUBLIC 0x03
#define QPG_KEY_TYPE_SIG_PRIVATE 0x04

/* ── Encrypted-file format constants ─────────────────────────────────────── */

#define QPG_ENC_MAGIC "QPGE"
#define QPG_ENC_MAGIC_LEN 4

/* ── Signature-file format constants ─────────────────────────────────────── */

#define QPG_SIG_MAGIC "QPGS"
#define QPG_SIG_MAGIC_LEN 4

/* ── AES-256-GCM parameters ──────────────────────────────────────────────── */

#define QPG_AES_KEY_LEN 32
#define QPG_AES_IV_LEN 12
#define QPG_AES_TAG_LEN 16

/* ── Maximum algorithm name length ───────────────────────────────────────── */

#define QPG_MAX_ALGO_NAME 256

/* ── Convenience includes ────────────────────────────────────────────────── */

#include "crypto.h"
#include "cli.h"
#include "utils.h"

#endif /* QPG_H */
