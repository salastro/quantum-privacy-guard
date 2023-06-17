#include "qpg_utils.h"
#include <stdio.h>
#include <stdlib.h>

int read_file(const char *file_path, unsigned char **data, size_t *data_len) {
  FILE *file = fopen(file_path, "rb");
  if (file == NULL) {
    perror("Error opening file");
    return 1;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  *data = (unsigned char *)malloc(file_size);
  if (*data == NULL) {
    perror("Error allocating memory");
    fclose(file);
    return 1;
  }

  size_t bytes_read = fread(*data, 1, file_size, file);
  fclose(file);

  if (bytes_read != file_size) {
    perror("Error reading file");
    free(*data);
    return 1;
  }

  *data_len = bytes_read;
  return 0;
}

int write_file(const char *file_path, const unsigned char *data,
               size_t data_len) {
  FILE *file = fopen(file_path, "wb");
  if (file == NULL) {
    perror("Error opening file");
    return 1;
  }

  size_t bytes_written = fwrite(data, 1, data_len, file);
  fclose(file);

  if (bytes_written != data_len) {
    perror("Error writing file");
    return 1;
  }

  return 0;
}
