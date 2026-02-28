/*
 * Quantum Privacy Guard – CLI argument parsing and command dispatch.
 */

#include "qpg.h"

#include <getopt.h>
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Long-option codes (> 255 to avoid collisions with ASCII chars) ──────── */

enum
{
    OPT_GEN_KEY = 256,
    OPT_ENCRYPT,
    OPT_DECRYPT,
    OPT_SIGN,
    OPT_VERIFY,
    OPT_HELP,
    OPT_VERSION,
    OPT_LIST_ALGORITHMS,
    OPT_ALGORITHM,
    OPT_PUBLIC_KEY,
    OPT_PRIVATE_KEY,
    OPT_INPUT,
    OPT_OUTPUT,
    OPT_SIGNATURE,
    OPT_TYPE
};

static struct option long_options[] = {
    {"gen-key", no_argument, NULL, OPT_GEN_KEY},
    {"encrypt", no_argument, NULL, OPT_ENCRYPT},
    {"decrypt", no_argument, NULL, OPT_DECRYPT},
    {"sign", no_argument, NULL, OPT_SIGN},
    {"verify", no_argument, NULL, OPT_VERIFY},
    {"help", no_argument, NULL, OPT_HELP},
    {"version", no_argument, NULL, OPT_VERSION},
    {"list-algorithms", no_argument, NULL, OPT_LIST_ALGORITHMS},
    {"algorithm", required_argument, NULL, OPT_ALGORITHM},
    {"public-key", required_argument, NULL, OPT_PUBLIC_KEY},
    {"private-key", required_argument, NULL, OPT_PRIVATE_KEY},
    {"input", required_argument, NULL, OPT_INPUT},
    {"output", required_argument, NULL, OPT_OUTPUT},
    {"signature", required_argument, NULL, OPT_SIGNATURE},
    {"type", required_argument, NULL, OPT_TYPE},
    {NULL, 0, NULL, 0}};

/* ── Argument parser ─────────────────────────────────────────────────────── */

int qpg_parse_args(int argc, char *argv[], qpg_args_t *args)
{
    if (argc < 2)
    {
        qpg_print_help();
        return QPG_ERROR_INVALID_ARGS;
    }

    int opt;
    int option_index = 0;

    /* Reset getopt state (useful in tests). */
    optind = 1;

    while ((opt = getopt_long(argc, argv, "", long_options,
                              &option_index)) != -1)
    {
        switch (opt)
        {
        /* ── Commands ──────────────────────────────────────────────── */
        case OPT_GEN_KEY:
            args->command = QPG_CMD_GEN_KEY;
            break;
        case OPT_ENCRYPT:
            args->command = QPG_CMD_ENCRYPT;
            break;
        case OPT_DECRYPT:
            args->command = QPG_CMD_DECRYPT;
            break;
        case OPT_SIGN:
            args->command = QPG_CMD_SIGN;
            break;
        case OPT_VERIFY:
            args->command = QPG_CMD_VERIFY;
            break;
        case OPT_HELP:
            args->command = QPG_CMD_HELP;
            break;
        case OPT_VERSION:
            args->command = QPG_CMD_VERSION;
            break;
        case OPT_LIST_ALGORITHMS:
            args->command = QPG_CMD_LIST_ALGORITHMS;
            break;

        /* ── Options ───────────────────────────────────────────────── */
        case OPT_ALGORITHM:
            args->algorithm = optarg;
            break;
        case OPT_PUBLIC_KEY:
            args->public_key_file = optarg;
            break;
        case OPT_PRIVATE_KEY:
            args->private_key_file = optarg;
            break;
        case OPT_INPUT:
            args->input_file = optarg;
            break;
        case OPT_OUTPUT:
            args->output_file = optarg;
            break;
        case OPT_SIGNATURE:
            args->signature_file = optarg;
            break;

        case OPT_TYPE:
            if (strcmp(optarg, "kem") == 0)
                args->type = QPG_TYPE_KEM;
            else if (strcmp(optarg, "sig") == 0)
                args->type = QPG_TYPE_SIG;
            else
            {
                qpg_log_error("Unknown key type '%s'. Use 'kem' or 'sig'.",
                              optarg);
                return QPG_ERROR_INVALID_ARGS;
            }
            break;

        default:
            qpg_print_help();
            return QPG_ERROR_INVALID_ARGS;
        }
    }

    return QPG_SUCCESS;
}

/* ── Command dispatch ────────────────────────────────────────────────────── */

int qpg_dispatch(const qpg_args_t *args)
{
    switch (args->command)
    {

    /* ── Help / version ────────────────────────────────────────────── */
    case QPG_CMD_HELP:
        qpg_print_help();
        return QPG_SUCCESS;

    case QPG_CMD_VERSION:
        qpg_print_version();
        return QPG_SUCCESS;

    case QPG_CMD_LIST_ALGORITHMS:
        qpg_list_kem_algorithms();
        qpg_list_sig_algorithms();
        return QPG_SUCCESS;

    /* ── Key generation ────────────────────────────────────────────── */
    case QPG_CMD_GEN_KEY:
        if (!args->algorithm || !args->public_key_file ||
            !args->private_key_file)
        {
            qpg_log_error("--gen-key requires --algorithm, "
                          "--public-key, and --private-key.");
            return QPG_ERROR_INVALID_ARGS;
        }

        if (args->type == QPG_TYPE_KEM)
            return qpg_generate_kem_keypair(args->algorithm,
                                            args->public_key_file,
                                            args->private_key_file);
        if (args->type == QPG_TYPE_SIG)
            return qpg_generate_sig_keypair(args->algorithm,
                                            args->public_key_file,
                                            args->private_key_file);

        /* Auto-detect: try KEM first, then SIG. */
        {
            OQS_KEM *kem = OQS_KEM_new(args->algorithm);
            if (kem)
            {
                OQS_KEM_free(kem);
                return qpg_generate_kem_keypair(args->algorithm,
                                                args->public_key_file,
                                                args->private_key_file);
            }
            OQS_SIG *sig = OQS_SIG_new(args->algorithm);
            if (sig)
            {
                OQS_SIG_free(sig);
                return qpg_generate_sig_keypair(args->algorithm,
                                                args->public_key_file,
                                                args->private_key_file);
            }
        }
        qpg_log_error("Unsupported or unknown algorithm: %s", args->algorithm);
        return QPG_ERROR_UNSUPPORTED;

    /* ── Encrypt ───────────────────────────────────────────────────── */
    case QPG_CMD_ENCRYPT:
        if (!args->public_key_file || !args->input_file ||
            !args->output_file)
        {
            qpg_log_error("--encrypt requires --public-key, "
                          "--input, and --output.");
            return QPG_ERROR_INVALID_ARGS;
        }
        return qpg_encrypt_with_kem(args->public_key_file,
                                    args->input_file,
                                    args->output_file);

    /* ── Decrypt ───────────────────────────────────────────────────── */
    case QPG_CMD_DECRYPT:
        if (!args->private_key_file || !args->input_file ||
            !args->output_file)
        {
            qpg_log_error("--decrypt requires --private-key, "
                          "--input, and --output.");
            return QPG_ERROR_INVALID_ARGS;
        }
        return qpg_decrypt_with_kem(args->private_key_file,
                                    args->input_file,
                                    args->output_file);

    /* ── Sign ──────────────────────────────────────────────────────── */
    case QPG_CMD_SIGN:
        if (!args->private_key_file || !args->input_file ||
            !args->output_file)
        {
            qpg_log_error("--sign requires --private-key, "
                          "--input, and --output.");
            return QPG_ERROR_INVALID_ARGS;
        }
        return qpg_sign(args->private_key_file,
                        args->input_file,
                        args->output_file);

    /* ── Verify ────────────────────────────────────────────────────── */
    case QPG_CMD_VERIFY:
        if (!args->public_key_file || !args->input_file ||
            !args->signature_file)
        {
            qpg_log_error("--verify requires --public-key, "
                          "--input, and --signature.");
            return QPG_ERROR_INVALID_ARGS;
        }
        return qpg_verify(args->public_key_file,
                          args->input_file,
                          args->signature_file);

    /* ── No command ────────────────────────────────────────────────── */
    case QPG_CMD_NONE:
    default:
        qpg_print_help();
        return QPG_ERROR_INVALID_ARGS;
    }
}

/* ── Help / version output ───────────────────────────────────────────────── */

void qpg_print_version(void)
{
    printf("Quantum Privacy Guard (QPG) v%s\n", QPG_VERSION_STRING);
    printf("Built against liboqs.\n");
}

void qpg_print_help(void)
{
    qpg_print_version();
    printf("\nUsage: qpg <command> [options]\n");

    printf("\nCommands:\n");
    printf("  --gen-key            Generate a key pair\n");
    printf("  --encrypt            Encrypt a file\n");
    printf("  --decrypt            Decrypt a file\n");
    printf("  --sign               Sign a file\n");
    printf("  --verify             Verify a signature\n");
    printf("  --list-algorithms    List all supported algorithms\n");
    printf("  --help               Show this help message\n");
    printf("  --version            Show version information\n");

    printf("\nOptions:\n");
    printf("  --algorithm <name>   Algorithm name (for --gen-key)\n");
    printf("  --type <kem|sig>     Key type (optional, auto-detected)\n");
    printf("  --public-key <file>  Public key file path\n");
    printf("  --private-key <file> Private key file path\n");
    printf("  --input <file>       Input file path\n");
    printf("  --output <file>      Output file path\n");
    printf("  --signature <file>   Signature file (for --verify)\n");

    printf("\nExamples:\n");
    printf("  # Generate a KEM key pair\n");
    printf("  qpg --gen-key --algorithm ML-KEM-768 "
           "--public-key pub.key --private-key priv.key\n\n");

    printf("  # Encrypt a file\n");
    printf("  qpg --encrypt --public-key pub.key "
           "--input secret.txt --output secret.enc\n\n");

    printf("  # Decrypt a file\n");
    printf("  qpg --decrypt --private-key priv.key "
           "--input secret.enc --output secret.txt\n\n");

    printf("  # Generate a signature key pair\n");
    printf("  qpg --gen-key --algorithm ML-DSA-65 --type sig "
           "--public-key sig_pub.key --private-key sig_priv.key\n\n");

    printf("  # Sign a file\n");
    printf("  qpg --sign --private-key sig_priv.key "
           "--input document.pdf --output document.sig\n\n");

    printf("  # Verify a signature\n");
    printf("  qpg --verify --public-key sig_pub.key "
           "--input document.pdf --signature document.sig\n");

    printf("\nSupported KEM algorithms:\n");
    qpg_list_kem_algorithms();

    printf("\nSupported signature algorithms:\n");
    qpg_list_sig_algorithms();

    printf("\nSecurity notice:\n");
    printf("  Post-quantum algorithms are under active standardisation.\n");
    printf("  Use at your own risk for production workloads.\n");
}
