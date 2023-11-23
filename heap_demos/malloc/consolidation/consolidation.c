#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420

void main() {
	char *chunk0,
		*chunk1,
		*chunk2,
		*chunk3,
		*chunk4,
		*chunk5;

	chunk0 = malloc(CHUNK_SIZE);
	chunk1 = malloc(CHUNK_SIZE);
	chunk2 = malloc(CHUNK_SIZE);
	chunk3 = malloc(CHUNK_SIZE);
	chunk4 = malloc(CHUNK_SIZE);
	chunk5 = malloc(CHUNK_SIZE);

	// Free chunks for backwards consolidation
	free(chunk0);
	free(chunk1);

	// Free chunks for forwards consolidation
	free(chunk4);
	free(chunk3);
}
