# Exact Fit Allocation

So the goal here is once again we will be trying to allocate partially overlapping chunks. This time around, we will be doing so via expanding the size of an unsorted bin chunk, into an adjacent heap chunk we wish to allocate partially overlapping data into. Then, we will allocate that expanded chunk.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x80
#define CHUNK_EXPANDED_ALLOCATION_SIZE 0x470

// CHUNK_REMAINDER1 is 0x40
#define CHUNK_REMAINDER1 CHUNK_SIZE1 - (CHUNK_EXPANDED_ALLOCATION_SIZE - CHUNK_SIZE0) + 0x10

void main() {
    long *chunk0,
            *chunk1,
            *overlapping_chunk,
            *overlapping_chunk_end;

    printf("So the goal this time, is we will try to allocate partially overlapping chunks.\n");
    printf("This will be done leveraging the unsorted bin's exact fit allocation.\n");
    printf("We will free the chunk prior to the chunk we wish to allocate overlapping memory with.\n");
    printf("When we free it, we will need to have it inserted into the unsorted bin.\n");
    printf("We will then overwrite the size of the freed unsorted bin chunk, to expand it into the adjacent chunk.\n");
    printf("We put a fake heap chunk header in the adjacent chunk we just expanded into, right after the newly expanded chunk (to pass some checks).\n");
    printf("Then we will simply allocate a chunk the exact size of the expanded chunk.\n");
    printf("We will then have a chunk that overlaps partially with the allocated chunk.\n");
    printf("We are effectively just expanding the size of a freed unsorted bin chunk, so when it gets allocated, it should also include subsequent memory.\n\n");

    printf("Let's start off by allocating two chunks.\n\n");

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE1);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n\n", chunk1);

    printf("So we have two chunks, chunk0 of size 0x%lx, and chunk1 of size 0x%lx\n", CHUNK_SIZE0, CHUNK_SIZE1);
    printf("Let's free chunk0 and have it be inserted into the unsorted bin.\n\n");

    free(chunk0);

    printf("Now that chunk0 is freed, we will now do the preparation to allocate the overlapping chunk.\n");
    printf("Again, we will simply expand the size of chunk0, 0x50 bytes into chunk1, then reallocate chunk0.\n");
    printf("This first means, we will have to change the size value in the chunk0 header, from 0x%lx, to 0x%lx.\n\n", (CHUNK_SIZE0+0x10), (CHUNK_EXPANDED_ALLOCATION_SIZE+0x10));

    chunk0[-1] = CHUNK_EXPANDED_ALLOCATION_SIZE+0x10;

    printf("Next up, the unsorted bin will check the size value of chunk0 against the prev_size of the next chunk.\n");
    printf("So we will have to create a fake chunk header there, with a prev_size value that matches the expanded size.\n");
    printf("For the size of this fake chunk header, I put 0x%lx, since that will encompass the rest of this chunk, and lineup with the following chunk.\n", CHUNK_REMAINDER1);
    printf("This should help prevent potential heap check failures later on.\n\n");

    chunk1[8] = CHUNK_EXPANDED_ALLOCATION_SIZE+0x10;
    chunk1[9] = CHUNK_REMAINDER1;

    printf("Now that we have done the setup, we should be able to allocate the expanded chunk.\n");
    printf("This should partially overlap with chunk1.\n\n");

    overlapping_chunk = malloc(CHUNK_EXPANDED_ALLOCATION_SIZE);
    overlapping_chunk_end = (long *)((long)overlapping_chunk + CHUNK_EXPANDED_ALLOCATION_SIZE + 0x10);

    printf("Overlapping Chunk Begin:\t%p\n", overlapping_chunk);
    printf("Overlapping Chunk End:\t%p\n", overlapping_chunk_end);
    printf("Chunk1:\t%p\n\n", chunk1);

    printf("Does it overlap?:\t%s\n", ((overlapping_chunk < chunk1) && (chunk1 < overlapping_chunk_end)) ? "True" : "Falase");
}
```

## Walkthrough

So this process is going to be a bit simpler than previous techniques that produce more or less the same result.

The first thing we will have to do is free a chunk and have it inserted into the unsorted bin, that is adjacent to the chunk which we want to allocate again.

The second thing that we will need to do, is expand the size of the freed unsorted bin chunk, to expand it into the adjacent chunk, and contain the data which we want to overlap.

The third thing we will need to do is put a fake heap chunk header right after our expanded heap chunk, and put in heap metadata to match our expanded chunk. Also for this, I will put the size of the fake heap chunk to line up with the next actual heap chunk (help prevent potential issues).

Then we will simply request from malloc, a chunk that is the exact size of the expanded unsorted bin chunk. It will get allocated, and just like that, we will have allocated the same block of memory twice.

In this context, we will start off with two chunks, one of size `0x430` and the other of size `0x90`. We will expand the `0x430` chunk `0x50` bytes. So we will set the size of the `0x430` chunk, to `0x480`. Then in the `0x90` chunk, `0x50` bytes after the actual heap chunk header, we will make a fake heap chunk header. We will set its `prev_size` to `0x480`, and the chunk size to `0x40`. Then, we will just allocate a chunk size of `0x480`, which will give us the overlapping chunk.

Let's see this in action. First off, let's see the two chunks after I have freed `chunk0`:

```
$   gdb ./exact_fit
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
Reading symbols from ./exact_fit...
(No debugging symbols found in ./exact_fit)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>: endbr64
   0x00000000000011ad <+4>: push   rbp
   0x00000000000011ae <+5>: mov rbp,rsp
   0x00000000000011b1 <+8>: sub rsp,0x20
   0x00000000000011b5 <+12>:    lea rax,[rip+0xe4c]     # 0x2008
   0x00000000000011bc <+19>:    mov rdi,rax
   0x00000000000011bf <+22>:    call   0x1090 <puts@plt>
   0x00000000000011c4 <+27>:    lea rax,[rip+0xe8d]     # 0x2058
   0x00000000000011cb <+34>:    mov rdi,rax
   0x00000000000011ce <+37>:    call   0x1090 <puts@plt>
   0x00000000000011d3 <+42>:    lea rax,[rip+0xec6]     # 0x20a0
   0x00000000000011da <+49>:    mov rdi,rax
   0x00000000000011dd <+52>:    call   0x1090 <puts@plt>
   0x00000000000011e2 <+57>:    lea rax,[rip+0xf0f]     # 0x20f8
   0x00000000000011e9 <+64>:    mov rdi,rax
   0x00000000000011ec <+67>:    call   0x1090 <puts@plt>
   0x00000000000011f1 <+72>:    lea rax,[rip+0xf50]     # 0x2148
   0x00000000000011f8 <+79>:    mov rdi,rax
   0x00000000000011fb <+82>:    call   0x1090 <puts@plt>
   0x0000000000001200 <+87>:    lea rax,[rip+0xfa9]     # 0x21b0
   0x0000000000001207 <+94>:    mov rdi,rax
   0x000000000000120a <+97>:    call   0x1090 <puts@plt>
   0x000000000000120f <+102>:   lea rax,[rip+0x102a]        # 0x2240
   0x0000000000001216 <+109>:   mov rdi,rax
   0x0000000000001219 <+112>:   call   0x1090 <puts@plt>
   0x000000000000121e <+117>:   lea rax,[rip+0x106b]        # 0x2290
   0x0000000000001225 <+124>:   mov rdi,rax
   0x0000000000001228 <+127>:   call   0x1090 <puts@plt>
   0x000000000000122d <+132>:   lea rax,[rip+0x10ac]        # 0x22e0
   0x0000000000001234 <+139>:   mov rdi,rax
   0x0000000000001237 <+142>:   call   0x1090 <puts@plt>
   0x000000000000123c <+147>:   lea rax,[rip+0x112d]        # 0x2370
   0x0000000000001243 <+154>:   mov rdi,rax
   0x0000000000001246 <+157>:   call   0x1090 <puts@plt>
   0x000000000000124b <+162>:   mov edi,0x420
   0x0000000000001250 <+167>:   call   0x10b0 <malloc@plt>
   0x0000000000001255 <+172>:   mov QWORD PTR [rbp-0x20],rax
   0x0000000000001259 <+176>:   mov edi,0x80
   0x000000000000125e <+181>:   call   0x10b0 <malloc@plt>
   0x0000000000001263 <+186>:   mov QWORD PTR [rbp-0x18],rax
   0x0000000000001267 <+190>:   mov rax,QWORD PTR [rbp-0x20]
   0x000000000000126b <+194>:   mov rsi,rax
   0x000000000000126e <+197>:   lea rax,[rip+0x1126]        # 0x239b
   0x0000000000001275 <+204>:   mov rdi,rax
   0x0000000000001278 <+207>:   mov eax,0x0
   0x000000000000127d <+212>:   call   0x10a0 <printf@plt>
   0x0000000000001282 <+217>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001286 <+221>:   mov rsi,rax
   0x0000000000001289 <+224>:   lea rax,[rip+0x1117]        # 0x23a7
   0x0000000000001290 <+231>:   mov rdi,rax
   0x0000000000001293 <+234>:   mov eax,0x0
   0x0000000000001298 <+239>:   call   0x10a0 <printf@plt>
   0x000000000000129d <+244>:   mov edx,0x80
   0x00000000000012a2 <+249>:   mov esi,0x420
   0x00000000000012a7 <+254>:   lea rax,[rip+0x110a]        # 0x23b8
   0x00000000000012ae <+261>:   mov rdi,rax
   0x00000000000012b1 <+264>:   mov eax,0x0
   0x00000000000012b6 <+269>:   call   0x10a0 <printf@plt>
   0x00000000000012bb <+274>:   lea rax,[rip+0x113e]        # 0x2400
   0x00000000000012c2 <+281>:   mov rdi,rax
   0x00000000000012c5 <+284>:   call   0x1090 <puts@plt>
   0x00000000000012ca <+289>:   mov rax,QWORD PTR [rbp-0x20]
   0x00000000000012ce <+293>:   mov rdi,rax
   0x00000000000012d1 <+296>:   call   0x1080 <free@plt>
   0x00000000000012d6 <+301>:   lea rax,[rip+0x116b]        # 0x2448
   0x00000000000012dd <+308>:   mov rdi,rax
   0x00000000000012e0 <+311>:   call   0x1090 <puts@plt>
   0x00000000000012e5 <+316>:   lea rax,[rip+0x11bc]        # 0x24a8
   0x00000000000012ec <+323>:   mov rdi,rax
   0x00000000000012ef <+326>:   call   0x1090 <puts@plt>
   0x00000000000012f4 <+331>:   mov edx,0x480
   0x00000000000012f9 <+336>:   mov esi,0x430
   0x00000000000012fe <+341>:   lea rax,[rip+0x120b]        # 0x2510
   0x0000000000001305 <+348>:   mov rdi,rax
   0x0000000000001308 <+351>:   mov eax,0x0
   0x000000000000130d <+356>:   call   0x10a0 <printf@plt>
   0x0000000000001312 <+361>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001316 <+365>:   sub rax,0x8
   0x000000000000131a <+369>:   mov QWORD PTR [rax],0x480
   0x0000000000001321 <+376>:   lea rax,[rip+0x1250]        # 0x2578
   0x0000000000001328 <+383>:   mov rdi,rax
   0x000000000000132b <+386>:   call   0x1090 <puts@plt>
   0x0000000000001330 <+391>:   lea rax,[rip+0x12a9]        # 0x25e0
   0x0000000000001337 <+398>:   mov rdi,rax
   0x000000000000133a <+401>:   call   0x1090 <puts@plt>
   0x000000000000133f <+406>:   mov esi,0x40
   0x0000000000001344 <+411>:   lea rax,[rip+0x1305]        # 0x2650
   0x000000000000134b <+418>:   mov rdi,rax
   0x000000000000134e <+421>:   mov eax,0x0
   0x0000000000001353 <+426>:   call   0x10a0 <printf@plt>
   0x0000000000001358 <+431>:   lea rax,[rip+0x1381]        # 0x26e0
   0x000000000000135f <+438>:   mov rdi,rax
   0x0000000000001362 <+441>:   call   0x1090 <puts@plt>
   0x0000000000001367 <+446>:   mov rax,QWORD PTR [rbp-0x18]
   0x000000000000136b <+450>:   add rax,0x40
   0x000000000000136f <+454>:   mov QWORD PTR [rax],0x480
   0x0000000000001376 <+461>:   mov rax,QWORD PTR [rbp-0x18]
   0x000000000000137a <+465>:   add rax,0x48
   0x000000000000137e <+469>:   mov QWORD PTR [rax],0x40
   0x0000000000001385 <+476>:   lea rax,[rip+0x139c]        # 0x2728
   0x000000000000138c <+483>:   mov rdi,rax
   0x000000000000138f <+486>:   call   0x1090 <puts@plt>
   0x0000000000001394 <+491>:   lea rax,[rip+0x13e5]        # 0x2780
   0x000000000000139b <+498>:   mov rdi,rax
   0x000000000000139e <+501>:   call   0x1090 <puts@plt>
   0x00000000000013a3 <+506>:   mov edi,0x470
   0x00000000000013a8 <+511>:   call   0x10b0 <malloc@plt>
   0x00000000000013ad <+516>:   mov QWORD PTR [rbp-0x10],rax
   0x00000000000013b1 <+520>:   mov rax,QWORD PTR [rbp-0x10]
   0x00000000000013b5 <+524>:   add rax,0x480
   0x00000000000013bb <+530>:   mov QWORD PTR [rbp-0x8],rax
   0x00000000000013bf <+534>:   mov rax,QWORD PTR [rbp-0x10]
   0x00000000000013c3 <+538>:   mov rsi,rax
   0x00000000000013c6 <+541>:   lea rax,[rip+0x13df]        # 0x27ac
   0x00000000000013cd <+548>:   mov rdi,rax
   0x00000000000013d0 <+551>:   mov eax,0x0
   0x00000000000013d5 <+556>:   call   0x10a0 <printf@plt>
   0x00000000000013da <+561>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000013de <+565>:   mov rsi,rax
   0x00000000000013e1 <+568>:   lea rax,[rip+0x13e1]        # 0x27c9
   0x00000000000013e8 <+575>:   mov rdi,rax
   0x00000000000013eb <+578>:   mov eax,0x0
   0x00000000000013f0 <+583>:   call   0x10a0 <printf@plt>
   0x00000000000013f5 <+588>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000013f9 <+592>:   mov rsi,rax
   0x00000000000013fc <+595>:   lea rax,[rip+0xfa4]     # 0x23a7
   0x0000000000001403 <+602>:   mov rdi,rax
   0x0000000000001406 <+605>:   mov eax,0x0
   0x000000000000140b <+610>:   call   0x10a0 <printf@plt>
   0x0000000000001410 <+615>:   mov rax,QWORD PTR [rbp-0x10]
   0x0000000000001414 <+619>:   cmp rax,QWORD PTR [rbp-0x18]
   0x0000000000001418 <+623>:   jae 0x142d <main+644>
   0x000000000000141a <+625>:   mov rax,QWORD PTR [rbp-0x18]
   0x000000000000141e <+629>:   cmp rax,QWORD PTR [rbp-0x8]
   0x0000000000001422 <+633>:   jae 0x142d <main+644>
   0x0000000000001424 <+635>:   lea rax,[rip+0x13b9]        # 0x27e4
   0x000000000000142b <+642>:   jmp 0x1434 <main+651>
   0x000000000000142d <+644>:   lea rax,[rip+0x13b5]        # 0x27e9
   0x0000000000001434 <+651>:   mov rsi,rax
   0x0000000000001437 <+654>:   lea rax,[rip+0x13b2]        # 0x27f0
   0x000000000000143e <+661>:   mov rdi,rax
   0x0000000000001441 <+664>:   mov eax,0x0
   0x0000000000001446 <+669>:   call   0x10a0 <printf@plt>
   0x000000000000144b <+674>:   nop
   0x000000000000144c <+675>:   leave  
   0x000000000000144d <+676>:   ret    
End of assembler dump.
gef➤  b *main+172
Breakpoint 1 at 0x1255
gef➤  b *main+301
Breakpoint 2 at 0x12d6
gef➤  b *main+511
Breakpoint 3 at 0x13a8
gef➤  b *main+516
Breakpoint 4 at 0x13ad
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/unsorted_bin/exact_fit/exact_fit
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So the goal this time, is we will try to allocate partially overlapping chunks.
This will be done leveraging the unsorted bin's exact fit allocation.
We will free the chunk prior to the chunk we wish to allocate overlapping memory with.
When we free it, we will need to have it inserted into the unsorted bin.
We will then overwrite the size of the freed unsorted bin chunk, to expand it into the adjacent chunk.
We put a fake heap chunk header in the adjacent chunk we just expanded into, right after the newly expanded chunk (to pass some checks).
Then we will simply allocate a chunk the exact size of the expanded chunk.
We will then have a chunk that overlaps partially with the allocated chunk.
We are effectively just expanding the size of a freed unsorted bin chunk, so when it gets allocated, it should also include subsequent memory.

Let's start off by allocating two chunks.


Breakpoint 1, 0x0000555555555255 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x431           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfa0  →  0x00007fffffffe3c9  →  0x000034365f363878 ("x86_64"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559ad0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x0000555555555255  →  <main+172> mov QWORD PTR [rbp-0x20], rax
$r8 : 0x0            
$r9 : 0x00005555555596b0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559ad0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/unsorted_bin/ex[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00007fffffffe3c9  →  0x000034365f363878 ("x86_64"?)   ← $rsp
0x00007fffffffdfa8│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfb0│+0x0010: 0x0000000000001000
0x00007fffffffdfb8│+0x0018: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0x00005555555551a9  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555246 <main+157>    call   0x555555555090 <puts@plt>
   0x55555555524b <main+162>    mov edi, 0x420
   0x555555555250 <main+167>    call   0x5555555550b0 <malloc@plt>
 → 0x555555555255 <main+172>    mov QWORD PTR [rbp-0x20], rax
   0x555555555259 <main+176>    mov edi, 0x80
   0x55555555525e <main+181>    call   0x5555555550b0 <malloc@plt>
   0x555555555263 <main+186>    mov QWORD PTR [rbp-0x18], rax
   0x555555555267 <main+190>    mov rax, QWORD PTR [rbp-0x20]
   0x55555555526b <main+194>    mov rsi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exact_fit", stopped 0x555555555255 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555255 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555596b0
gef➤  c
Continuing.
Chunk0: 0x5555555596b0
Chunk1: 0x555555559ae0

So we have two chunks, chunk0 of size 0x420, and chunk1 of size 0x80
Let's free chunk0 and have it be inserted into the unsorted bin.


Breakpoint 2, 0x00005555555552d6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x41            
$rdx   : 0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$rsp   : 0x00007fffffffdfa0  →  0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555552d6  →  <main+301> lea rax, [rip+0x116b]        # 0x555555556448
$r8 : 0x0            
$r9 : 0x00007fffffffde76  →  0x3bdcd95511003038 ("80"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/unsorted_bin/ex[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000  ← $rsp
0x00007fffffffdfa8│+0x0008: 0x0000555555559ae0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0010: 0x0000000000001000
0x00007fffffffdfb8│+0x0018: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0x00005555555551a9  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ca <main+289>    mov rax, QWORD PTR [rbp-0x20]
   0x5555555552ce <main+293>    mov rdi, rax
   0x5555555552d1 <main+296>    call   0x555555555080 <free@plt>
 → 0x5555555552d6 <main+301>    lea rax, [rip+0x116b]       # 0x555555556448
   0x5555555552dd <main+308>    mov rdi, rax
   0x5555555552e0 <main+311>    call   0x555555555090 <puts@plt>
   0x5555555552e5 <main+316>    lea rax, [rip+0x11bc]       # 0x5555555564a8
   0x5555555552ec <main+323>    mov rdi, rax
   0x5555555552ef <main+326>    call   0x555555555090 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exact_fit", stopped 0x5555555552d6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x5555555596a0
0x5555555596a0: 0x0 0x431
0x5555555596b0: 0x7ffff7e19ce0  0x7ffff7e19ce0
0x5555555596c0: 0x0 0x0
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x0
0x555555559760: 0x0 0x0
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
0x5555555597f0: 0x0 0x0
0x555555559800: 0x0 0x0
0x555555559810: 0x0 0x0
0x555555559820: 0x0 0x0
0x555555559830: 0x0 0x0
0x555555559840: 0x0 0x0
0x555555559850: 0x0 0x0
0x555555559860: 0x0 0x0
0x555555559870: 0x0 0x0
0x555555559880: 0x0 0x0
0x555555559890: 0x0 0x0
0x5555555598a0: 0x0 0x0
0x5555555598b0: 0x0 0x0
0x5555555598c0: 0x0 0x0
0x5555555598d0: 0x0 0x0
0x5555555598e0: 0x0 0x0
0x5555555598f0: 0x0 0x0
0x555555559900: 0x0 0x0
0x555555559910: 0x0 0x0
0x555555559920: 0x0 0x0
0x555555559930: 0x0 0x0
0x555555559940: 0x0 0x0
0x555555559950: 0x0 0x0
0x555555559960: 0x0 0x0
0x555555559970: 0x0 0x0
0x555555559980: 0x0 0x0
0x555555559990: 0x0 0x0
0x5555555599a0: 0x0 0x0
0x5555555599b0: 0x0 0x0
0x5555555599c0: 0x0 0x0
0x5555555599d0: 0x0 0x0
0x5555555599e0: 0x0 0x0
0x5555555599f0: 0x0 0x0
0x555555559a00: 0x0 0x0
0x555555559a10: 0x0 0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x0
0x555555559a50: 0x0 0x0
0x555555559a60: 0x0 0x0
0x555555559a70: 0x0 0x0
0x555555559a80: 0x0 0x0
0x555555559a90: 0x0 0x0
0x555555559aa0: 0x0 0x0
0x555555559ab0: 0x0 0x0
0x555555559ac0: 0x0 0x0
0x555555559ad0: 0x430   0x90
0x555555559ae0: 0x0 0x0
0x555555559af0: 0x0 0x0
0x555555559b00: 0x0 0x0
0x555555559b10: 0x0 0x0
0x555555559b20: 0x0 0x0
0x555555559b30: 0x0 0x0
0x555555559b40: 0x0 0x0
0x555555559b50: 0x0 0x0
0x555555559b60: 0x0 0x204a1
0x555555559b70: 0x0 0x0
0x555555559b80: 0x0 0x0
0x555555559b90: 0x0 0x0
0x555555559ba0: 0x0 0x0
0x555555559bb0: 0x0 0x0
0x555555559bc0: 0x0 0x0
0x555555559bd0: 0x0 0x0
0x555555559be0: 0x0 0x0
0x555555559bf0: 0x0 0x0
0x555555559c00: 0x0 0x0
0x555555559c10: 0x0 0x0
0x555555559c20: 0x0 0x0
0x555555559c30: 0x0 0x0
0x555555559c40: 0x0 0x0
0x555555559c50: 0x0 0x0
0x555555559c60: 0x0 0x0
0x555555559c70: 0x0 0x0
0x555555559c80: 0x0 0x0
0x555555559c90: 0x0 0x0
0x555555559ca0: 0x0 0x0
0x555555559cb0: 0x0 0x0
0x555555559cc0: 0x0 0x0
0x555555559cd0: 0x0 0x0
```

So we see our two chunks, at `0x5555555596a0` and `0x555555559ad0`. We see that the first chunk has been freed. Let's see what it looks like after we have expanded the first chunk into the second chunk:

```
gef➤  c
Continuing.
Now that chunk0 is freed, we will now do the preparation to allocate the overlapping chunk.
Again, we will simply expand the size of chunk0, 0x50 bytes into chunk1, then reallocate chunk0.
This first means, we will have to change the size value in the chunk0 header, from 0x430, to 0x480.

Next up, the unsorted bin will check the size value of chunk0 against the prev_size of the next chunk.
So we will have to create a fake chunk header there, with a prev_size value that matches the expanded size.
For the size of this fake chunk header, I put 0x40, since that will encompass the rest of this chunk, and lineup with the following chunk.
This should help prevent potential heap check failures later on.

Now that we have done the setup, we should be able to allocate the expanded chunk.
This should partially overlap with chunk1.


Breakpoint 3, 0x00005555555553a8 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x2c            
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a77  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdfa0  →  0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x470           
$rip   : 0x00005555555553a8  →  <main+511> call 0x5555555550b0 <malloc@plt>
$r8 : 0x0            
$r9 : 0x00007fffffffde76  →  0x3bdcd95511003034 ("40"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/unsorted_bin/ex[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000  ← $rsp
0x00007fffffffdfa8│+0x0008: 0x0000555555559ae0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0010: 0x0000000000001000
0x00007fffffffdfb8│+0x0018: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0x00005555555551a9  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555539b <main+498>    mov rdi, rax
   0x55555555539e <main+501>    call   0x555555555090 <puts@plt>
   0x5555555553a3 <main+506>    mov edi, 0x470
 → 0x5555555553a8 <main+511>    call   0x5555555550b0 <malloc@plt>
   ↳  0x5555555550b0 <malloc@plt+0>   endbr64
    0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fd0 <malloc@got.plt>
    0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550c0 <_start+0>       endbr64
    0x5555555550c4 <_start+4>       xor ebp, ebp
    0x5555555550c6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000470,
   $rsi = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exact_fit", stopped 0x5555555553a8 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553a8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x5555555596a0
0x5555555596a0: 0x0 0x480
0x5555555596b0: 0x7ffff7e19ce0  0x7ffff7e19ce0
0x5555555596c0: 0x0 0x0
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x0
0x555555559760: 0x0 0x0
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
0x5555555597f0: 0x0 0x0
0x555555559800: 0x0 0x0
0x555555559810: 0x0 0x0
0x555555559820: 0x0 0x0
0x555555559830: 0x0 0x0
0x555555559840: 0x0 0x0
0x555555559850: 0x0 0x0
0x555555559860: 0x0 0x0
0x555555559870: 0x0 0x0
0x555555559880: 0x0 0x0
0x555555559890: 0x0 0x0
0x5555555598a0: 0x0 0x0
0x5555555598b0: 0x0 0x0
0x5555555598c0: 0x0 0x0
0x5555555598d0: 0x0 0x0
0x5555555598e0: 0x0 0x0
0x5555555598f0: 0x0 0x0
0x555555559900: 0x0 0x0
0x555555559910: 0x0 0x0
0x555555559920: 0x0 0x0
0x555555559930: 0x0 0x0
0x555555559940: 0x0 0x0
0x555555559950: 0x0 0x0
0x555555559960: 0x0 0x0
0x555555559970: 0x0 0x0
0x555555559980: 0x0 0x0
0x555555559990: 0x0 0x0
0x5555555599a0: 0x0 0x0
0x5555555599b0: 0x0 0x0
0x5555555599c0: 0x0 0x0
0x5555555599d0: 0x0 0x0
0x5555555599e0: 0x0 0x0
0x5555555599f0: 0x0 0x0
0x555555559a00: 0x0 0x0
0x555555559a10: 0x0 0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x0
0x555555559a50: 0x0 0x0
0x555555559a60: 0x0 0x0
0x555555559a70: 0x0 0x0
0x555555559a80: 0x0 0x0
0x555555559a90: 0x0 0x0
0x555555559aa0: 0x0 0x0
0x555555559ab0: 0x0 0x0
0x555555559ac0: 0x0 0x0
0x555555559ad0: 0x430   0x90
0x555555559ae0: 0x0 0x0
0x555555559af0: 0x0 0x0
0x555555559b00: 0x0 0x0
0x555555559b10: 0x0 0x0
0x555555559b20: 0x480   0x40
0x555555559b30: 0x0 0x0
0x555555559b40: 0x0 0x0
0x555555559b50: 0x0 0x0
0x555555559b60: 0x0 0x204a1
0x555555559b70: 0x0 0x0
0x555555559b80: 0x0 0x0
0x555555559b90: 0x0 0x0
0x555555559ba0: 0x0 0x0
0x555555559bb0: 0x0 0x0
0x555555559bc0: 0x0 0x0
0x555555559bd0: 0x0 0x0
0x555555559be0: 0x0 0x0
0x555555559bf0: 0x0 0x0
0x555555559c00: 0x0 0x0
0x555555559c10: 0x0 0x0
0x555555559c20: 0x0 0x0
0x555555559c30: 0x0 0x0
0x555555559c40: 0x0 0x0
0x555555559c50: 0x0 0x0
0x555555559c60: 0x0 0x0
0x555555559c70: 0x0 0x0
0x555555559c80: 0x0 0x0
0x555555559c90: 0x0 0x0
0x555555559ca0: 0x0 0x0
0x555555559cb0: 0x0 0x0
0x555555559cc0: 0x0 0x0
0x555555559cd0: 0x0 0x0
```

So we see that the size value at `0x5555555596a8` got expanded from `0x431` to `0x480` (I forgot to consider the `prev_inuse` flag, but it doesn't appear to matter in this situation). We also see that the fake chunk has been made at `0x555555559b20`. Now let's allocate the chunk via requesting a size of `0x470`:

```
gef➤  p $rdi
$2 = 0x470
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555553ad in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x41            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfa0  →  0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x0             
$rip   : 0x00005555555553ad  →  <main+516> mov QWORD PTR [rbp-0x10], rax
$r8 : 0x0            
$r9 : 0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$r10   : 0x0000555555559b20  →  0x0000000000000480
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/unsorted_bin/ex[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555596b0  →  0x00007ffff7e19ce0  →  0x0000555555559b60  →  0x0000000000000000  ← $rsp
0x00007fffffffdfa8│+0x0008: 0x0000555555559ae0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0010: 0x0000000000001000
0x00007fffffffdfb8│+0x0018: 0x00005555555550c0  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0x00005555555551a9  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555539e <main+501>    call   0x555555555090 <puts@plt>
   0x5555555553a3 <main+506>    mov edi, 0x470
   0x5555555553a8 <main+511>    call   0x5555555550b0 <malloc@plt>
 → 0x5555555553ad <main+516>    mov QWORD PTR [rbp-0x10], rax
   0x5555555553b1 <main+520>    mov rax, QWORD PTR [rbp-0x10]
   0x5555555553b5 <main+524>    add rax, 0x480
   0x5555555553bb <main+530>    mov QWORD PTR [rbp-0x8], rax
   0x5555555553bf <main+534>    mov rax, QWORD PTR [rbp-0x10]
   0x5555555553c3 <main+538>    mov rsi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exact_fit", stopped 0x5555555553ad in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553ad → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x5555555596b0
gef➤  x/200g 0x5555555596a0
0x5555555596a0: 0x0 0x480
0x5555555596b0: 0x7ffff7e19ce0  0x7ffff7e19ce0
0x5555555596c0: 0x0 0x0
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x0
0x555555559760: 0x0 0x0
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
0x5555555597f0: 0x0 0x0
0x555555559800: 0x0 0x0
0x555555559810: 0x0 0x0
0x555555559820: 0x0 0x0
0x555555559830: 0x0 0x0
0x555555559840: 0x0 0x0
0x555555559850: 0x0 0x0
0x555555559860: 0x0 0x0
0x555555559870: 0x0 0x0
0x555555559880: 0x0 0x0
0x555555559890: 0x0 0x0
0x5555555598a0: 0x0 0x0
0x5555555598b0: 0x0 0x0
0x5555555598c0: 0x0 0x0
0x5555555598d0: 0x0 0x0
0x5555555598e0: 0x0 0x0
0x5555555598f0: 0x0 0x0
0x555555559900: 0x0 0x0
0x555555559910: 0x0 0x0
0x555555559920: 0x0 0x0
0x555555559930: 0x0 0x0
0x555555559940: 0x0 0x0
0x555555559950: 0x0 0x0
0x555555559960: 0x0 0x0
0x555555559970: 0x0 0x0
0x555555559980: 0x0 0x0
0x555555559990: 0x0 0x0
0x5555555599a0: 0x0 0x0
0x5555555599b0: 0x0 0x0
0x5555555599c0: 0x0 0x0
0x5555555599d0: 0x0 0x0
0x5555555599e0: 0x0 0x0
0x5555555599f0: 0x0 0x0
0x555555559a00: 0x0 0x0
0x555555559a10: 0x0 0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x0
0x555555559a50: 0x0 0x0
0x555555559a60: 0x0 0x0
0x555555559a70: 0x0 0x0
0x555555559a80: 0x0 0x0
0x555555559a90: 0x0 0x0
0x555555559aa0: 0x0 0x0
0x555555559ab0: 0x0 0x0
0x555555559ac0: 0x0 0x0
0x555555559ad0: 0x430   0x90
0x555555559ae0: 0x0 0x0
0x555555559af0: 0x0 0x0
0x555555559b00: 0x0 0x0
0x555555559b10: 0x0 0x0
0x555555559b20: 0x480   0x41
0x555555559b30: 0x0 0x0
0x555555559b40: 0x0 0x0
0x555555559b50: 0x0 0x0
0x555555559b60: 0x0 0x204a1
0x555555559b70: 0x0 0x0
0x555555559b80: 0x0 0x0
0x555555559b90: 0x0 0x0
0x555555559ba0: 0x0 0x0
0x555555559bb0: 0x0 0x0
0x555555559bc0: 0x0 0x0
0x555555559bd0: 0x0 0x0
0x555555559be0: 0x0 0x0
0x555555559bf0: 0x0 0x0
0x555555559c00: 0x0 0x0
0x555555559c10: 0x0 0x0
0x555555559c20: 0x0 0x0
0x555555559c30: 0x0 0x0
0x555555559c40: 0x0 0x0
0x555555559c50: 0x0 0x0
0x555555559c60: 0x0 0x0
0x555555559c70: 0x0 0x0
0x555555559c80: 0x0 0x0
0x555555559c90: 0x0 0x0
0x555555559ca0: 0x0 0x0
0x555555559cb0: 0x0 0x0
0x555555559cc0: 0x0 0x0
0x555555559cd0: 0x0 0x0
gef➤  c
Continuing.
Overlapping Chunk Begin:    0x5555555596b0
Overlapping Chunk End:  0x555555559b30
Chunk1: 0x555555559ae0

Does it overlap?:   True
[Inferior 1 (process 5956) exited with code 027]
```

So we see, we were able to reallocate the expanded `0x5555555596a0` chunk, which overlaps with the `0x555555559b20` chunk.
