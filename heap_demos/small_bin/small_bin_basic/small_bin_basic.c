#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x200
#define CHUNK_SIZE1 0x20
#define CHUNK_SIZE2 0x600

void main() {
	char *chunk0,
		*chunk1,
		*chunk2,
		*chunk3,
		*chunk4,
		*chunk5,
		*chunk6,
		*chunk7,
		*chunk8,
		*chunk9,
		*chunk10;

	puts("\n\nLet's fill up the tcache!\n\n");

	chunk0 = malloc(CHUNK_SIZE0);
	chunk1 = malloc(CHUNK_SIZE0);
	chunk2 = malloc(CHUNK_SIZE0);
	chunk3 = malloc(CHUNK_SIZE0);
	chunk4 = malloc(CHUNK_SIZE0);
	chunk5 = malloc(CHUNK_SIZE0);
	chunk6 = malloc(CHUNK_SIZE0);
	chunk7 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk8 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk9 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk10 = malloc(CHUNK_SIZE2);
	malloc(CHUNK_SIZE1);

	free(chunk0);
	free(chunk1);
	free(chunk2);
	free(chunk3);
	free(chunk4);
	free(chunk5);
	free(chunk6);

	puts("\n\nThe tcache has been filled up! Let's insert chunks into the unsorted bin now!\n\n");

	free(chunk7);
	free(chunk8);
	free(chunk9);

	puts("\n\nLet's empty the tcache now, so we can allocated chunks from the small bin\n\n");

	for (int i = 0; i < 7; i++) {
		malloc(CHUNK_SIZE0);
	}

	puts("\n\nLet's allocate our first chunk from the small bin!\n\n");

	malloc(CHUNK_SIZE0 - 0x10);

	puts("\n\nLet's insert another chunk into the unsorted bin (not small bin size)!\n\n");

	free(chunk10);

	puts("\n\nLet's allocate our second chunk from the small bin!\n\n");

	malloc(CHUNK_SIZE0);
}
