#include <stdio.h>
#include <stdlib.h>
#include "chall-00.h"

char *chunks[10];
unsigned int chunk_sizes[10];

void main(void) {
	unsigned int menu_choice;

	while (1 == 1) {
		puts("Menu:\n1.) Allocate New Chunk\n2.) View Chunk\n3.) Edit Chunk\n4.) Free Chunk\n5.) Remove Chunk\n");
		puts("Please enter menu choice:");
		menu_choice = get_uint();

		if (menu_choice == ALLOCATE) {
			allocate_chunk();
		}

		else if (menu_choice == VIEW) {
			view_chunk();
		}

		else if (menu_choice == EDIT) {
			edit_chunk();
		}

		else if (menu_choice == FREE) {
			free_chunk();
		}

		else if (menu_choice == REMOVE) {
			remove_chunk();
		}		

		else if (menu_choice == SECRET) {
			secret();
		}		

		else {
			printf("Unknown Menu Choice: %d\n", menu_choice);	
		}
	}
}

void you_win(void) {
	puts("Call this function to win!");

	puts("\n\nYou Win\n\n");
}

unsigned int get_uint(void) {
	char buf[20];

	fgets(buf, sizeof(buf) - 1, stdin);
	puts("");
	return (unsigned int)atoi(buf);
}

unsigned int get_chunk_idx(void) {
	unsigned chunk_idx;
	char *chunk;

	puts("Which chunk idx would you like?");
	chunk_idx = get_uint();


	if ((chunk_idx <= MAX_CHUNK_IDX)) {
		printf("You choose idx: %u\n\n", chunk_idx);
	}

	else {
		puts("Bad Chunk IDX\n");
		return -1;
	}

	chunk = chunks[chunk_idx];

	if (chunk == NULL) {
		puts("Chunk doesn't exist.\n");
		return -1;
	}

	else {
		return chunk_idx;
	}

}

void allocate_chunk(void) {
	unsigned int new_chunk_size, chunk_idx;
	char *new_chunk;

	puts("Allocating a new chunk!\n");

	printf("Enter the chunk size between 0x%x-0x%x:\n", 
		MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);

	new_chunk_size = get_uint();

	if ((new_chunk_size > MIN_CHUNK_SIZE) && (new_chunk_size < MAX_CHUNK_SIZE)) {
		printf("Chunk Size: 0x%x\n\n", new_chunk_size);
	}

	else {
		puts("You have inputed a bad chunks size.\n");
		return;
	}

	puts("Which chunk spot would you like to allocate?");
	chunk_idx = get_uint();

	if ((chunk_idx < MAX_CHUNK_IDX)) {
		printf("Choosen chunk idx: 0x%x\n\n", chunk_idx);
	}

	else {
		puts("Bad Chunk IDX\n");
		return;
	}

	if (chunks[chunk_idx] != NULL) {
		puts("Chunk already exists there!\n");
		return;
	}

	new_chunk = malloc(new_chunk_size);
	chunks[chunk_idx] = new_chunk;
	chunk_sizes[chunk_idx] = new_chunk_size;

	puts("Chunk has been allocated!\n");

}

void view_chunk(void) {
	unsigned int chunk_idx;
	char *chunk;

	puts("Viewing a chunk!\n");

	chunk_idx = get_chunk_idx();
	if (chunk_idx == -1) {
		puts("Your chunk idx is invalid.\n");
		return;
	}

	chunk = chunks[chunk_idx];

	printf("Chunk Contents: %s\x0d\x0a\n", chunk);
}

void edit_chunk(void) {
	unsigned int chunk_idx, chunk_size;
	char *chunk;

	puts("Editing a chunk!\n");

	chunk_idx = get_chunk_idx();
	if (chunk_idx == -1) {
		puts("Your chunk idx is invalid.\n");
		return;
	}

	chunk = chunks[chunk_idx];
	chunk_size = chunk_sizes[chunk_idx];

	puts("Please input new chunk content:\n");

	fgets(chunk, chunk_size, stdin);

	puts("\nChunk has been edited!\n");
}

void free_chunk(void) {
	unsigned int chunk_idx;
	char *chunk;

	puts("Freeing a chunk!\n");

	chunk_idx = get_chunk_idx();
	if (chunk_idx == -1) {
		puts("Your chunk idx is invalid.\n");
		return;
	}

	chunk = chunks[chunk_idx];
	free(chunk);

	puts("Chunk has been freed!\n");
}

void remove_chunk(void) {
	unsigned int chunk_idx;

	puts("Removing a chunk!\n");

	chunk_idx = get_chunk_idx();
	if (chunk_idx == -1) {
		puts("Your chunk idx is invalid.\n");
		return;
	}

	chunks[chunk_idx] = NULL;
	chunk_sizes[chunk_idx] = 0x00;

	puts("Chunk has been removed!\n");
}

void secret(void) {
	unsigned int chunk_idx, choice;
	char *chunk;
	char buf[20];

	chunk_idx = get_chunk_idx();
	if (chunk_idx == -1) {
		puts("Your chunk idx is invalid.");
		return;
	}

	chunk = chunks[chunk_idx];

	puts("Choice?");

	fgets(buf, sizeof(buf) - 1, stdin);
	choice = (unsigned int)atoi(buf);

	if (choice == 0xd3) {
		*((unsigned int **)chunk) = (&choice);
	}

	else if (choice == 0x83) {
		*((void (**)(void))chunk) = (&secret);
	}
}