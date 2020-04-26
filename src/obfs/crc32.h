#ifndef _OBFS_CRC32_H
#define _OBFS_CRC32_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void init_crc32_table(void);

uint32_t crc32_imp(const unsigned char *buffer, size_t size);

void fillcrc32to(const unsigned char *buffer, size_t size, unsigned char *outbuffer);

void fillcrc32(unsigned char *buffer, size_t size);

void filladler32(unsigned char *buffer, size_t size);

bool checkadler32(const unsigned char *buffer, size_t size);

#endif // _OBFS_CRC32_H
