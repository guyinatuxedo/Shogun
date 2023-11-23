#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

unsigned int get_uint(void) {
	char buf[20];

	fgets(buf, sizeof(buf) - 1, stdin);
	puts("");
	return (unsigned int)atoi(buf);
}

void main(void) {
	char *chunk0,
			*chunk1,
			*target_chunk,
			*free_ptr,
			*alloc_ptr;

	unsigned long index, allocation_size;

	chunk0 = malloc(0x500);
	target_chunk = malloc(0x100);
	chunk1 = malloc(0x500);

	memset(chunk0, 0x00, 0x500);
	memset(target_chunk, 0x00, 0x100);
	memset(chunk1, 0x00, 0x500);

	printf("Chunk0: %p\n\n", chunk0);
	
	puts("Chunk0 Contents:");
	read(0, chunk0, 0x50);

	puts("Chunk1 Contents:");
	read(0, chunk1, 0x50);

	puts("Index?");
	index = get_uint();

	if ((index < 0) || (index > 0x50)) {
		puts("Index is out of range.\n");
		return;
	}

	free_ptr = (char *)((unsigned long)chunk0 + index);

	free(free_ptr);

	puts("Size of the chunk allocation?");
	allocation_size = get_uint();

	if ((allocation_size < 1) || (allocation_size > 0x800)) {
		puts("Size is out of range.\n");
		return;
	}

	alloc_ptr = malloc(allocation_size);

	puts("Allocation Chunk Contents.");
	read(0, alloc_ptr, allocation_size);

	if (*((int *)target_chunk) == 0xdeadbeef) {
		puts("You solved the chall!\n");
	}

}