#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100

void main() {
    char *chunk0,
            *chunk1;
    long data[10];

    printf("%p\n", &data);

    chunk0 = malloc(CHUNK_SIZE0);
    free(chunk0);
    malloc(CHUNK_SIZE0);
}


