#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x10
#define CHUNK_SIZE1 0x100
#define CHUNK_SIZE2 0x400

void main() {
	char *chunk0,
		*chunk1,
		*chunk2,
		*chunk3,
		*chunk4,
		*chunk5;

	chunk0 = malloc(CHUNK_SIZE0);
	chunk1 = malloc(CHUNK_SIZE0);
	chunk2 = malloc(CHUNK_SIZE1);
	chunk3 = malloc(CHUNK_SIZE1);
	chunk4 = malloc(CHUNK_SIZE2);
	chunk5 = malloc(CHUNK_SIZE2);

	free(chunk0);
	free(chunk2);
	free(chunk4);

	free(chunk1);
	free(chunk3);
	free(chunk5);

	malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	malloc(CHUNK_SIZE2);

	malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	malloc(CHUNK_SIZE2);
}
