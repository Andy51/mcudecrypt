#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <malloc.h>
#include <string.h>

/* http://stackoverflow.com/a/31488147 */
uint32_t rotr32(uint32_t n, unsigned int c)
{
    const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);

    assert((c <= mask) && "rotate by type width or more");
    c &= mask;  // avoid undef behaviour with NDEBUG.  0 overhead for most types / compilers
    return (n >> c) | (n << ((-(int)c)&mask));
}

#define GETNIBBLE(value_, index_) (((value_) >> ((index_)*4)) & 0xF)

uint8_t fMoveTable[] =
{
    0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3,
    0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
    0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
    0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
    0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
    0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
    0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
    0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC
};

uint32_t fMove(uint32_t value)
{
    uint8_t nibble;
    uint32_t result = 0;

    for (int i = 0; i < 8; i++)
    {
        nibble = GETNIBBLE(value, i);
        result |= fMoveTable[0x10 * i + nibble] << i*4;
    }
    return rotr32(result, 21);
}


unsigned char g_JieMi2permutations[] =
{
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0
};

int dencry_data(uint32_t *data0, uint32_t *data1, uint32_t *key)
{
    uint32_t fresult;
    uint32_t accu;
    uint32_t tmp;
    int i = 31;

    do
    {
        fresult = fMove(key[g_JieMi2permutations[i]] + *data0);
        accu = fresult ^ *data1;
        *data1 = *data0;
        *data0 = accu;
    } while (--i >= 0);

    tmp = *data1;
    *data1 = accu;
    *data0 = tmp;

    return 1;

}

int gost_dec(unsigned int *data, unsigned int *key)
{
    dencry_data(&data[0], &data[1], key);
    return 1;
}

static unsigned int g_JieMi2encryptionKey[16] =
{
    0x4F4C5544, 0x434D474E, 0x47373555, 0x30303030,
    0x47474747, 0x47474747, 0x33333333, 0x33333333,
    0x36363636, 0x36363636, 0x39393939, 0x39393939,
    0x42424242, 0x42424242, 0x49494949, 0x49494949
};

void Data_JieMi2(unsigned int *data)
{
    gost_dec(data, g_JieMi2encryptionKey);
}

int decrypt(unsigned char *data, size_t *dataSize)
{
    size_t encryptedSize = ((*dataSize - 16) & 0xFFFFFFC0) - 64 + 16;
    unsigned int checksum = 0;

    printf("Encrypted data size: 0x%X (%d)\n", encryptedSize, encryptedSize);

    /* Verify checksum */
    for(size_t i = 0; i < encryptedSize; i++) {
        checksum += data[i];
    }

    if (checksum != *(unsigned int*)&data[encryptedSize]) {
        puts(" * ERROR: checksum mismatch, file damaged?\n");
        return 1;
    }

    printf("Checksum: 0x%X match\n", checksum);

    for(size_t i = 0; i < encryptedSize; i += 8) {
        Data_JieMi2((unsigned int*)&data[i]);
    }

    *dataSize = encryptedSize;

    return 0;
}

int usage(void)
{
    puts("MCU decryption utility v1.0\n"
         "Usage: mcudecrypt INPUT OUTPUT\n"
         "    INPUT: path to hesi_mcu.bin\n"
         "    OUTPUT: path where decrypted file will be written\n");
    return 1;
}

int main(int argc, char **argv)
{
    FILE *fd;
    const char *filename;
    size_t filesize;
    unsigned char *buf;

    if (argc < 3) {
        return usage();
    }
    filename = argv[1];
    fd = fopen(filename, "rb");
    if (fd == NULL) {
        printf(" * ERROR: File %s not found\n", filename);
        return 1;
    }

    fseek(fd, 0, SEEK_END);
    filesize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    buf = (unsigned char*)malloc(filesize);
    fread(buf, filesize, 1, fd);
    fclose(fd);

    decrypt(buf, &filesize);

    fd = fopen(argv[2], "wb");
    if (fd == NULL) {
        printf(" * ERROR: Could not open output file\n");
        return 1;
    }

    fwrite(buf, filesize, 1, fd);
    fclose(fd);

    puts("Done.\n");

    return 0;
}
