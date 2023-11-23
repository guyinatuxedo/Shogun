#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100


void main() {
    long *chunk0;

    printf("So the purpose of this, is we want to actually pull off a tcache double free successfully.\n");
    printf("Double frees can be helpful with heap exploitation.");
    printf("This is because a lot of heap exploitation revolves around editing the data of freed chunks.\n");
    printf("By having a chunk inserted multiple times into the heap bins, you can allocate one copy of it, while it is still in a heap bin.\n");
    printf("In many instances this will lead to you being able to edit a freed heap bin chunk.\n");
    printf("Let's allocate a chunk, which will later be freed twice!.\n\n");

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

    printf("So to pass this check, we will simply overwrite the tcache key of the chunk with a different value.\n\n");

    *(chunk0 + 1) = 0x0000000000000000;

    printf("We see here, the tcache key is 0x%lx\n\n", *(chunk0 + 1));

    printf("Now let's free the chunk again!\n");

    free(chunk0);

    printf("Now we have freed the same chunk twice.\n");
    printf("We will be able to allocate it twice now!\n\n");

    printf("Chunk Allocation 0:\t%p\n", malloc(CHUNK_SIZE0));
    printf("Chunk Allocation 1:\t%p\n", malloc(CHUNK_SIZE0));
}
