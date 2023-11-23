#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420

void main() {
	char *chunk;

	malloc(CHUNK_SIZE);
	
	chunk = malloc(CHUNK_SIZE);

	free(chunk);
}