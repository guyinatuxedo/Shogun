#include <stdlib.h>

#define CHUNK_SIZE 0x10000

void main() {
	char *ptrs[100];
	int i;

	for (i = 0; i < 10; i++) {
		ptrs[i] = malloc(CHUNK_SIZE);
	}
	
	for (i = 0; i < 9; i++) {
		free(ptrs[i]);
	}

	free(ptrs[9]);
}

