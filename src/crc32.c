static uint32_t crc32_table[256] = {0};

void init_crc32_table(void) {
    uint32_t c, i, j;
    if (crc32_table[0] == 0) {
        for (i = 0; i < 256; i++) {
            c = i;
            for (j = 0; j < 8; j++) {
                if (c & 1)
                    c = 0xedb88320L ^ (c >> 1);
                else
                    c = c >> 1;
            }
            crc32_table[i] = c;
        }
    }
}

uint32_t crc32(unsigned char *buffer, unsigned int size) {
    uint32_t crc = 0xFFFFFFFF;
    unsigned int i;
    for (i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

void fillcrc32(unsigned char *buffer, unsigned int size) {
    uint32_t crc = 0xFFFFFFFF;
    unsigned int i;
    size -= 4;
    for (i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
    }
    buffer += size;
    buffer[0] = crc;
    buffer[1] = crc >> 8;
    buffer[2] = crc >> 16;
    buffer[3] = crc >> 24;
}

static uint64_t shift128plus_s[2] = {0x10000000, 0xFFFFFFFF};

uint64_t xorshift128plus(void) {
    uint64_t x = shift128plus_s[0];
    uint64_t const y = shift128plus_s[1];
    shift128plus_s[0] = y;
    x ^= x << 23; // a
    x ^= x >> 17; // b
    x ^= y ^ (y >> 26); // c
    shift128plus_s[1] = x;
    return x + y;
}

