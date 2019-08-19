#include <stdlib.h>
#include <stdbool.h>
#include "crc32.h"

static uint32_t crc32_table[256] = {0};
static bool crc32_table_init = false;

void init_crc32_table(void) {
    uint32_t c, i, j;
    if (crc32_table_init) {
        return;
    }
    if (crc32_table[0] == 0) {
        for (i = 0; i < 256; i++) {
            c = i;
            for (j = 0; j < 8; j++) {
                if (c & 1) {
                    c = 0xedb88320L ^ (c >> 1);
                } else {
                    c = c >> 1;
                }
            }
            crc32_table[i] = c;
        }
    }
    crc32_table_init = true;
}

uint32_t crc32_imp(unsigned char *buffer, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    size_t i;
    init_crc32_table();
    for (i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

void fillcrc32to(unsigned char *buffer, size_t size, unsigned char *outbuffer) {
    uint32_t crc = 0xFFFFFFFF;
    size_t i;
    init_crc32_table();
    for (i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
    }
    crc ^= 0xFFFFFFFF;
    outbuffer[0] = (unsigned char)crc;
    outbuffer[1] = (unsigned char)(crc >> 8);
    outbuffer[2] = (unsigned char)(crc >> 16);
    outbuffer[3] = (unsigned char)(crc >> 24);
}

void fillcrc32(unsigned char *buffer, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    size_t i;
    init_crc32_table();
    size -= 4;
    for (i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
    }
    buffer += size;
    buffer[0] = (unsigned char)crc;
    buffer[1] = (unsigned char)(crc >> 8);
    buffer[2] = (unsigned char)(crc >> 16);
    buffer[3] = (unsigned char)(crc >> 24);
}

void adler32_short(unsigned char *buffer, size_t size, uint32_t *a, uint32_t *b) {
    size_t i = 0;
    for (i = 0; i < size; i++) {
        *a += buffer[i];
        *b += *a;
    }
    *a %= 65521;
    *b %= 65521;
}

#define NMAX 5552
uint32_t adler32(unsigned char *buffer, size_t size) {
    uint32_t a = 1;
    uint32_t b = 0;
    while ( size >= NMAX ) {
        adler32_short(buffer, NMAX, &a, &b);
        buffer += NMAX;
        size -= NMAX;
    }
    adler32_short(buffer, size, &a, &b);
    return (b << 16) + a;
}
#undef NMAX

void filladler32(unsigned char *buffer, size_t size) {
    uint32_t checksum;
    size -= 4;
    checksum = adler32(buffer, size);
    buffer += size;
    buffer[0] = (unsigned char)checksum;
    buffer[1] = (unsigned char)(checksum >> 8);
    buffer[2] = (unsigned char)(checksum >> 16);
    buffer[3] = (unsigned char)(checksum >> 24);
}

bool checkadler32(unsigned char *buffer, size_t size) {
    uint32_t checksum;
    size -= 4;
    checksum = adler32(buffer, size);
    buffer += size;
    return checksum == (((uint32_t)buffer[3] << 24)
            | ((uint32_t)buffer[2] << 16)
            | ((uint32_t)buffer[1] << 8)
            | (uint32_t)buffer[0]);
}

