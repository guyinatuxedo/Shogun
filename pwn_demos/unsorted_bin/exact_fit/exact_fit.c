#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x80
#define CHUNK_EXPANDED_ALLOCATION_SIZE 0x470

// CHUNK_REMAINDER1 is 0x40
#define CHUNK_REMAINDER1 CHUNK_SIZE1 - (CHUNK_EXPANDED_ALLOCATION_SIZE - CHUNK_SIZE0) + 0x10

void main() {
    long *chunk0,
            *chunk1,
            *overlapping_chunk,
            *overlapping_chunk_end;

    printf("So the goal this time, is we will try to allocate partially overlapping chunks.\n");
    printf("This will be done leveraging the unsorted bin's exact fit allocation.\n");
    printf("We will free the chunk prior to the chunk we wish to allocate overlapping memory with.\n");
    printf("When we free it, we will need to have it inserted into the unsorted bin.\n");
    printf("We will then overwrite the size of the freed unsorted bin chunk, to expand it into the adjacent chunk.\n");
    printf("We put a fake heap chunk header in the adjacent chunk we just expanded into, right after the newly expanded chunk (to pass some checks).\n");
    printf("Then we will simply allocate a chunk the exact size of the expanded chunk.\n");
    printf("We will then have a chunk that overlaps partially with the allocated chunk.\n");
    printf("We are effectively just expanding the size of a freed unsorted bin chunk, so when it gets allocated, it should also include subsequent memory.\n\n");

    printf("Let's start off by allocating two chunks.\n\n");

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE1);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n\n", chunk1);

    printf("So we have two chunks, chunk0 of size 0x%lx, and chunk1 of size 0x%lx\n", CHUNK_SIZE0, CHUNK_SIZE1);
    printf("Let's free chunk0 and have it be inserted into the unsorted bin.\n\n");

    free(chunk0);

    printf("Now that chunk0 is freed, we will now do the preparation to allocate the overlapping chunk.\n");
    printf("Again, we will simply expand the size of chunk0, 0x50 bytes into chunk1, then reallocate chunk0.\n");
    printf("This first means, we will have to change the size value in the chunk0 header, from 0x%lx, to 0x%lx.\n\n", (CHUNK_SIZE0+0x10), (CHUNK_EXPANDED_ALLOCATION_SIZE+0x10));

    chunk0[-1] = CHUNK_EXPANDED_ALLOCATION_SIZE+0x10;

    printf("Next up, the unsorted bin will check the size value of chunk0 against the prev_size of the next chunk.\n");
    printf("So we will have to create a fake chunk header there, with a prev_size value that matches the expanded size.\n");
    printf("For the size of this fake chunk header, I put 0x%lx, since that will encompass the rest of this chunk, and lineup with the following chunk.\n", CHUNK_REMAINDER1);
    printf("This should help prevent potential heap check failures later on.\n\n");

    chunk1[8] = CHUNK_EXPANDED_ALLOCATION_SIZE+0x10;
    chunk1[9] = CHUNK_REMAINDER1;

    printf("Now that we have done the setup, we should be able to allocate the expanded chunk.\n");
    printf("This should partially overlap with chunk1.\n\n");

    overlapping_chunk = malloc(CHUNK_EXPANDED_ALLOCATION_SIZE);
    overlapping_chunk_end = (long *)((long)overlapping_chunk + CHUNK_EXPANDED_ALLOCATION_SIZE + 0x10);

    printf("Overlapping Chunk Begin:\t%p\n", overlapping_chunk);
    printf("Overlapping Chunk End:\t%p\n", overlapping_chunk_end);
    printf("Chunk1:\t%p\n\n", chunk1);

    printf("Does it overlap?:\t%s\n", ((overlapping_chunk < chunk1) && (chunk1 < overlapping_chunk_end)) ? "True" : "Falase");
}
