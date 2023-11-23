#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x500
#define CHUNK_SIZE1 0x600
#define CHUNK_SIZE2 0x20

void main() {
	char *chunk0,
		*chunk1,
		*chunk2,
		*chunk3,
		*chunk4,
		*chunk5,
		*chunk6,
		*chunk7;

	chunk0 = malloc(CHUNK_SIZE0);
	chunk1 = malloc(CHUNK_SIZE2);
	chunk2 = malloc(CHUNK_SIZE0);
	chunk3 = malloc(CHUNK_SIZE2);
	chunk4 = malloc(CHUNK_SIZE1);
	chunk5 = malloc(CHUNK_SIZE2);
	chunk6 = malloc(CHUNK_SIZE0);
	chunk7 = malloc(CHUNK_SIZE2);

	free(chunk0);
	free(chunk2);
	free(chunk4);
	free(chunk6);

	malloc(CHUNK_SIZE1);
}
