/*
 * Quantum Privacy Guard – Test suite.
 *
 * Tests:
 *   1. KEM: generate keypair → encrypt → decrypt → compare content.
 *   2. SIG: generate keypair → sign → verify.
 *   3. Invalid-signature detection (tampered message).
 *   4. Unsupported-algorithm rejection.
 */

#include "qpg.h"

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Simple test harness ─────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg)             \
    do                                     \
    {                                      \
        tests_run++;                       \
        if (!(cond))                       \
        {                                  \
            printf("  FAIL: %s\n", (msg)); \
            tests_failed++;                \
        }                                  \
        else                               \
        {                                  \
            printf("  PASS: %s\n", (msg)); \
            tests_passed++;                \
        }                                  \
    } while (0)

/* ── Find first enabled KEM / SIG algorithm ──────────────────────────────── */

static const char *find_kem_algorithm(void)
{
    for (int i = 0; i < OQS_KEM_alg_count(); i++)
    {
        const char *name = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(name))
            return name;
    }
    return NULL;
}

static const char *find_sig_algorithm(void)
{
    for (int i = 0; i < OQS_SIG_alg_count(); i++)
    {
        const char *name = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(name))
            return name;
    }
    return NULL;
}

/* ── Temporary file paths ────────────────────────────────────────────────── */

#define TMP_PUB_KEY "/tmp/qpg_test_pub.key"
#define TMP_PRIV_KEY "/tmp/qpg_test_priv.key"
#define TMP_INPUT "/tmp/qpg_test_input.bin"
#define TMP_ENCRYPTED "/tmp/qpg_test_encrypted.bin"
#define TMP_DECRYPTED "/tmp/qpg_test_decrypted.bin"
#define TMP_SIG_PUB_KEY "/tmp/qpg_test_sig_pub.key"
#define TMP_SIG_PRIV_KEY "/tmp/qpg_test_sig_priv.key"
#define TMP_SIG_INPUT "/tmp/qpg_test_sig_input.bin"
#define TMP_SIGNATURE "/tmp/qpg_test_signature.bin"

/* ── Test 1: KEM encrypt / decrypt round-trip ────────────────────────────── */

static void test_kem_encrypt_decrypt(void)
{
    printf("\n=== Test: KEM Encrypt / Decrypt ===\n");

    const char *alg = find_kem_algorithm();
    TEST_ASSERT(alg != NULL, "Found an enabled KEM algorithm");
    if (!alg)
        return;
    printf("  Using: %s\n", alg);

    /* Generate keypair. */
    int rc = qpg_generate_kem_keypair(alg, TMP_PUB_KEY, TMP_PRIV_KEY);
    TEST_ASSERT(rc == QPG_SUCCESS, "Generate KEM keypair");

    /* Write test plaintext. */
    const char *msg = "Hello, Quantum World! "
                      "This is a QPG round-trip test with AES-256-GCM.";
    rc = qpg_write_file(TMP_INPUT, (const uint8_t *)msg, strlen(msg));
    TEST_ASSERT(rc == QPG_SUCCESS, "Write test input");

    /* Encrypt. */
    rc = qpg_encrypt_with_kem(TMP_PUB_KEY, TMP_INPUT, TMP_ENCRYPTED);
    TEST_ASSERT(rc == QPG_SUCCESS, "Encrypt with KEM");

    /* Decrypt. */
    rc = qpg_decrypt_with_kem(TMP_PRIV_KEY, TMP_ENCRYPTED, TMP_DECRYPTED);
    TEST_ASSERT(rc == QPG_SUCCESS, "Decrypt with KEM");

    /* Compare. */
    uint8_t *dec = NULL;
    size_t dec_len = 0;
    rc = qpg_read_file(TMP_DECRYPTED, &dec, &dec_len);
    TEST_ASSERT(rc == QPG_SUCCESS, "Read decrypted output");
    TEST_ASSERT(dec_len == strlen(msg), "Decrypted length matches");
    TEST_ASSERT(dec && memcmp(dec, msg, strlen(msg)) == 0,
                "Decrypted content matches original");
    free(dec);
}

/* ── Test 2: SIG sign / verify ───────────────────────────────────────────── */

static void test_sig_sign_verify(void)
{
    printf("\n=== Test: SIG Sign / Verify ===\n");

    const char *alg = find_sig_algorithm();
    TEST_ASSERT(alg != NULL, "Found an enabled SIG algorithm");
    if (!alg)
        return;
    printf("  Using: %s\n", alg);

    /* Generate keypair. */
    int rc = qpg_generate_sig_keypair(alg, TMP_SIG_PUB_KEY, TMP_SIG_PRIV_KEY);
    TEST_ASSERT(rc == QPG_SUCCESS, "Generate SIG keypair");

    /* Write test message. */
    const char *msg = "Message to be signed by QPG.";
    rc = qpg_write_file(TMP_SIG_INPUT, (const uint8_t *)msg, strlen(msg));
    TEST_ASSERT(rc == QPG_SUCCESS, "Write test input");

    /* Sign. */
    rc = qpg_sign(TMP_SIG_PRIV_KEY, TMP_SIG_INPUT, TMP_SIGNATURE);
    TEST_ASSERT(rc == QPG_SUCCESS, "Sign message");

    /* Verify. */
    rc = qpg_verify(TMP_SIG_PUB_KEY, TMP_SIG_INPUT, TMP_SIGNATURE);
    TEST_ASSERT(rc == QPG_SUCCESS, "Verify valid signature");
}

/* ── Test 3: Invalid signature detection ─────────────────────────────────── */

static void test_invalid_signature(void)
{
    printf("\n=== Test: Invalid Signature Detection ===\n");

    /* Tamper with the input file. */
    const char *tampered = "This message has been tampered with!";
    int rc = qpg_write_file(TMP_SIG_INPUT,
                            (const uint8_t *)tampered, strlen(tampered));
    TEST_ASSERT(rc == QPG_SUCCESS, "Write tampered input");

    /* Verification must fail. */
    rc = qpg_verify(TMP_SIG_PUB_KEY, TMP_SIG_INPUT, TMP_SIGNATURE);
    TEST_ASSERT(rc != QPG_SUCCESS, "Reject tampered message");
}

/* ── Test 4: Unsupported algorithm ───────────────────────────────────────── */

static void test_unsupported_algorithm(void)
{
    printf("\n=== Test: Unsupported Algorithm ===\n");

    int rc = qpg_generate_kem_keypair("NONEXISTENT-KEM-42",
                                      "/tmp/qpg_fake_pub.key",
                                      "/tmp/qpg_fake_priv.key");
    TEST_ASSERT(rc != QPG_SUCCESS, "Reject unsupported KEM algorithm");

    rc = qpg_generate_sig_keypair("NONEXISTENT-SIG-42",
                                  "/tmp/qpg_fake_pub.key",
                                  "/tmp/qpg_fake_priv.key");
    TEST_ASSERT(rc != QPG_SUCCESS, "Reject unsupported SIG algorithm");
}

/* ── Cleanup ─────────────────────────────────────────────────────────────── */

static void cleanup_test_files(void)
{
    remove(TMP_PUB_KEY);
    remove(TMP_PRIV_KEY);
    remove(TMP_INPUT);
    remove(TMP_ENCRYPTED);
    remove(TMP_DECRYPTED);
    remove(TMP_SIG_PUB_KEY);
    remove(TMP_SIG_PRIV_KEY);
    remove(TMP_SIG_INPUT);
    remove(TMP_SIGNATURE);
    remove("/tmp/qpg_fake_pub.key");
    remove("/tmp/qpg_fake_priv.key");
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("==============================\n");
    printf("  QPG Test Suite  v%s\n", QPG_VERSION_STRING);
    printf("==============================\n");

    test_kem_encrypt_decrypt();
    test_sig_sign_verify();
    test_invalid_signature();
    test_unsupported_algorithm();

    cleanup_test_files();

    printf("\n==============================\n");
    printf("  Results: %d / %d passed", tests_passed, tests_run);
    if (tests_failed)
        printf(", %d FAILED", tests_failed);
    printf("\n==============================\n");

    return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
