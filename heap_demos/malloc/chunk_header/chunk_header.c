#include <stdlib.h>

void main() {
	char *chunk0,
			*chunk1,
			*chunk2,
			*chunk3;


	chunk0 = malloc(0x50);
	chunk1 = malloc(0x50);
	chunk2 = malloc(0x500);
	chunk3 = malloc(0x500);


	free(chunk0);
	free(chunk2);
}
