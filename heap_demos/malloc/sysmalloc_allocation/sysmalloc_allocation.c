#include <stdlib.h>

#define CHUNK_SIZE 0x10000

void main() {
	malloc(0x10);
	
	malloc(CHUNK_SIZE);
	malloc(CHUNK_SIZE);
	malloc(CHUNK_SIZE);
}

