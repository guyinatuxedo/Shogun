#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x800
#define CHUNK_SIZE1 0x20
#define CHUNK_SIZE2 0x900
#define CHUNK_SIZE3 0x200

void main() {
	char *chunk0,
		 *chunk1;

	chunk0 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk1 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);

	free(chunk0);
	free(chunk1);

	malloc(CHUNK_SIZE2);

	malloc(CHUNK_SIZE3);
	malloc(CHUNK_SIZE3);
}
