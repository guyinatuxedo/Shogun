#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x1100
#define CHUNK_SIZE1 0x20

void main() {
   char *chunk0,
      *chunk1,
      *chunk2,
      *chunk3;

   chunk0 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk1 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk2 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk3 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);

   free(chunk0);
   free(chunk1);
   free(chunk2);

   malloc(CHUNK_SIZE0 + 0x10);

   free(chunk3);

   malloc(CHUNK_SIZE0 - 0x10);
}
