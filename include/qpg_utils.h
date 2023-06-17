#ifndef QPG_UTILS_H
#define QPG_UTILS_H

#include <stddef.h>

/**
 * Reads the entire contents of a file into a buffer.
 *
 * @param file_path The file path of the file to read.
 * @param data A pointer to an unsigned char pointer that will hold the data.
 * @param data_len A pointer to a size_t variable that will store the length of
 * the data.
 * @return 0 on success, non-zero on error.
 */
int read_file(const char *file_path, unsigned char **data, size_t *data_len);

/**
 * Writes the given data to a file.
 *
 * @param file_path The file path of the file to write.
 * @param data A pointer to the data to be written.
 * @param data_len The length of the data to be written.
 * @return 0 on success, non-zero on error.
 */
int write_file(const char *file_path, const unsigned char *data,
               size_t data_len);

#endif // QPG_UTILS_H
