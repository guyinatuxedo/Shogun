#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x40
#define CHUNK_SIZE1 0x50
#define CHUNK_SIZE2 0x60

#define MAX_TCACHE_BIN_SIZE 7

void main() {
	char *tcache_chunks0[MAX_TCACHE_BIN_SIZE];
	char *tcache_chunks1[MAX_TCACHE_BIN_SIZE];
	char *tcache_chunks2[MAX_TCACHE_BIN_SIZE];

	char *chunk0,
		*chunk1,
		*chunk2,
		*chunk3,
		*chunk4,
		*chunk5;
	int i;

	for (i = 0; i < MAX_TCACHE_BIN_SIZE; i++) {
		tcache_chunks0[i] = malloc(CHUNK_SIZE0);
		tcache_chunks1[i] = malloc(CHUNK_SIZE1);
		tcache_chunks2[i] = malloc(CHUNK_SIZE2);
	}

	chunk0 = malloc(CHUNK_SIZE0);
	chunk1 = malloc(CHUNK_SIZE0);
	chunk2 = malloc(CHUNK_SIZE1);
	chunk3 = malloc(CHUNK_SIZE1);
	chunk4 = malloc(CHUNK_SIZE2);

	for (i = 0; i < MAX_TCACHE_BIN_SIZE; i++) {
		free(tcache_chunks0[i]);
		free(tcache_chunks1[i]);
		free(tcache_chunks2[i]);
	}

	free(chunk0);
	free(chunk1);
	free(chunk2);
	free(chunk3);	
	free(chunk4);

	malloc(0x500);
}
