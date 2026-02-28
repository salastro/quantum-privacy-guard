/*
 * Quantum Privacy Guard – Command-line interface.
 */

#ifndef QPG_CLI_H
#define QPG_CLI_H

/* ── Command identifiers ─────────────────────────────────────────────────── */

typedef enum
{
    QPG_CMD_NONE = 0,
    QPG_CMD_GEN_KEY,
    QPG_CMD_ENCRYPT,
    QPG_CMD_DECRYPT,
    QPG_CMD_SIGN,
    QPG_CMD_VERIFY,
    QPG_CMD_HELP,
    QPG_CMD_VERSION,
    QPG_CMD_LIST_ALGORITHMS
} qpg_command_t;

/* ── Key-type selector ───────────────────────────────────────────────────── */

typedef enum
{
    QPG_TYPE_AUTO = 0, /* auto-detect from algorithm name */
    QPG_TYPE_KEM,
    QPG_TYPE_SIG
} qpg_key_type_t;

/* ── Parsed arguments ────────────────────────────────────────────────────── */

typedef struct
{
    qpg_command_t command;
    qpg_key_type_t type;
    const char *algorithm;
    const char *public_key_file;
    const char *private_key_file;
    const char *input_file;
    const char *output_file;
    const char *signature_file;
} qpg_args_t;

/**
 * Parse command-line arguments into a qpg_args_t structure.
 * Returns QPG_SUCCESS on success.
 */
int qpg_parse_args(int argc, char *argv[], qpg_args_t *args);

/**
 * Dispatch the parsed command to the appropriate handler.
 */
int qpg_dispatch(const qpg_args_t *args);

/** Print full help text (usage, examples, supported algorithms). */
void qpg_print_help(void);

/** Print version string. */
void qpg_print_version(void);

#endif /* QPG_CLI_H */
