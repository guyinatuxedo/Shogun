#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x50

void main() {
    int i;
    long *tcache_chunks[7];
    long *fastbin_chunk0,
            *fastbin_chunk1,
            *fastbin_chunk2,
            *reallocated_chunk0,
            *reallocated_chunk1,
            *reallocated_chunk2;

    printf("So this time around, our goal is to get malloc to allocate the same fastbin chunk multiple times.\n");
    printf("This will be done via executing a fastbin double free.\n");
    printf("Which is when we free the same chunk twice, and insert it into the fastbin.\n");
    printf("There is a check to catch chunks being inserted into the fastbin multiple times (double free).\n");
    printf("However, it will only check if the chunk being inserted is the same as the fastbin head chunk.\n");
    printf("So if we just free a chunk in between, we can free the same chunk twice.\n");
    printf("Also, since printf uses memory allocation, I will not use printf until the end, to avoid issues.\n\n");

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    fastbin_chunk0 = malloc(CHUNK_SIZE);
    fastbin_chunk1 = malloc(CHUNK_SIZE);
    fastbin_chunk2 = malloc(CHUNK_SIZE);


    malloc(CHUNK_SIZE);

    for (i = 0; i < 7; i++) {
        free(tcache_chunks[i]);
    }

    free(fastbin_chunk0);
    free(fastbin_chunk1);
    free(fastbin_chunk0);

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    reallocated_chunk0 = malloc(CHUNK_SIZE);
    reallocated_chunk1 = malloc(CHUNK_SIZE);
    reallocated_chunk2 = malloc(CHUNK_SIZE);

    printf("Reallocated Chunk 0:\t%p\n", reallocated_chunk0);
    printf("Reallocated Chunk 1:\t%p\n", reallocated_chunk1);
    printf("Reallocated Chunk 2:\t%p\n\n", reallocated_chunk2);

    printf("Malloc allocated the same chunk multiple times?\t%s\n", (reallocated_chunk0 == reallocated_chunk2) ? "True" : "False");

}
