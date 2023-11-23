#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100


void main() {
    long *chunk0;

    printf("So the purpose of this, is we want to introduce a double free bug.\n");
    printf("This is when we will free a chunk twice, to hopefully insert it multiple times into the heap bins.\n");
    printf("Now, for some of the bins, like tcache/fastbin, there are checks to hopefully catch it.\n");
    printf("When a check detects a double free, the program ends.\n");
    printf("Here we will see an instance where a check detects a double free.\n");
    printf("Now let's allocate a chunk.\n\n");

    chunk0 = malloc(CHUNK_SIZE0);

    printf("Chunk allocated at:\t%p\n\n", chunk0);

    printf("Now let's free it, to insert it into the tcache.\n\n");

    free(chunk0);

    printf("Now how does the tcache detect double frees?\n");
    printf("It does this, by writing a value to a specific offset in the chunk.\n");
    printf("This value is known as the tcache key, and it is set at offset `0x08` in the user data section of the chunk.\n");
    printf("Then when malloc attempts to insert a new chunk into the tcache, it sees if it has the tcache key value set.\n");
    printf("If it does, it know the chunk is already present in the tcache, and flags it as a double free.\n\n");

    printf("We see here, the tcache key is 0x%lx\n\n", *(chunk0 + 1));

    printf("Now let's free the chunk again, and fail the double free chunk!\n");

    free(chunk0);

    printf("This printf should never run, because  we fail the tcache double free check.\n");
}

