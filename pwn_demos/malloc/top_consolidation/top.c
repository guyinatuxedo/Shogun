#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x80


void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *chunk3;

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE1);

    chunk0[-1] = (CHUNK_SIZE0 + CHUNK_SIZE1) + 0x20 + 0x1;

    free(chunk0);

    chunk2 = malloc(CHUNK_SIZE0);
    chunk3 = malloc(CHUNK_SIZE0);
}
