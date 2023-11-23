#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100

void main() {
    long *chunk;
    long fake_chunk[4];

    printf("So our goal here, is to show how we can create fake chunks.\n");
    printf("We can create a fake chunk, with chunk metadata similar to that of a real chunk.\n");
    printf("We can go ahead and free that fake chunk, to insert it into the heap.\n");
    printf("This way, we can free a chunk of memory not actually in the heap.\n");
    printf("We will be making a fake chunk on the stack.\n\n");

    printf("Fake Chunk Being Made At:\t%p\n\n", &fake_chunk[2]);

    printf("Now we have to write the chunk metadata.\n");
    printf("We will mark the size as 0x111.\n");
    printf("We want to be able to allocate the chunk via requesting a chunk size of 0x100.\n");
    printf("A 0x110 byte chunk will be able to give us the 0x100 bytes, plus 0x10 byte heap header.\n");
    printf("The 0x1 is for the PREV_INUSE bit flag of the size value.\n");
    printf("For the prev_size, we are going write 0x00 to it.\n");
    printf("We will also null out the first 0x10 bytes of the chunk, even though we don't need to.\n");
    printf("Now let's write the heap values!\n\n");

    fake_chunk[0] = 0x00;
    fake_chunk[1] = 0x111;
    fake_chunk[2] = 0x00;
    fake_chunk[3] = 0x00;

    printf("Value @ %p:\t0x%lx\n", &fake_chunk[0], fake_chunk[0]);
    printf("Value @ %p:\t0x%lx\n", &fake_chunk[1], fake_chunk[1]);
    printf("Value @ %p:\t0x%lx\n", &fake_chunk[2], fake_chunk[2]);
    printf("Value @ %p:\t0x%lx\n\n", &fake_chunk[3], fake_chunk[3]);

    printf("Now let's go ahead and free the chunk!\n");

    free(&fake_chunk[2]);

    printf("Now that we freed it!\n");
    printf("Based on the value we set for the size, we will need to request 0x100 bytes.\n\n");

    chunk = malloc(CHUNK_SIZE0);

    printf("Allocated Chunk:\t%p\n\n", chunk);

    printf("As we've seen, we were able to create a fake heap chunk on the stack.\n");
    printf("We were able to free it, insert it into the tcache, and reallocate it.\n");
}


