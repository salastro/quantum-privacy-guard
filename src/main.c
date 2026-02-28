/*
 * Quantum Privacy Guard – Entry point.
 *
 * Delegates all work to the CLI parser and dispatcher.
 */

#include "qpg.h"

#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    qpg_args_t args;
    memset(&args, 0, sizeof(args));

    int ret = qpg_parse_args(argc, argv, &args);
    if (ret != QPG_SUCCESS)
        return EXIT_FAILURE;

    ret = qpg_dispatch(&args);

    return (ret == QPG_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
