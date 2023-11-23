## unsorted bin basic

So, in this instance, we will be showing the basics of the `unsorted bin`. We will be showing insertions, and removals into the `unsorted bin`.

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x500
#define CHUNK_SIZE1 0x600
#define CHUNK_SIZE2 0x20

void main() {
   char *chunk0,
      *chunk1,
      *chunk2,
      *chunk3,
      *chunk4,
      *chunk5,
      *chunk6,
      *chunk7;

   chunk0 = malloc(CHUNK_SIZE0);
   chunk1 = malloc(CHUNK_SIZE2);
   chunk2 = malloc(CHUNK_SIZE0);
   chunk3 = malloc(CHUNK_SIZE2);
   chunk4 = malloc(CHUNK_SIZE1);
   chunk5 = malloc(CHUNK_SIZE2);
   chunk6 = malloc(CHUNK_SIZE0);
   chunk7 = malloc(CHUNK_SIZE2);

   free(chunk0);
   free(chunk2);
   free(chunk4);
   free(chunk6);

   malloc(CHUNK_SIZE1);
}

```

#### unsorted bin basic walkthrough

So a few things about the unsorted bin. Newly freed chunks that are not inserted into either the tcache or fastbin (or consolidated into another chunk), are inserted into the unsorted bin. The unsorted bin acts in some ways, as a catch all for chunks that are not picked up by another chunk recycling mechanism. When a new chunk needs to be allocated, and it can't get a chunk from either the fastbin, tcache, or smallbin, it will attempt allocation from the unsorted bin.

This process will probably seem a little weird, in comparison to the others. First off, it will iterate through each chunk of the unsorted bin (starting from the tail, working towards the head). As it does, it will get removed. If it is an exact size fit for the allocation size, it will allocate the chunk. Insertions are made at the head of the doubly linked list (which the unsorted bin is one), and removals occur at the tail. If it isn't an exact fit, it will insert the chunk into either the corresponding small or large bin for the appropriate size (there is also the potential for it to end up in the tcache, if the corresponding tcache bin is empty).

The unsorted bin iteration (so removal of unsorted bin chunks), only happens when there is a malloc call that reaches the unsorted bin allocation. If while iterating through the unsorted bin, it finds a chunk suitable for allocation, it will stop the iteration. However if it doesn't, it will clear out the unsorted bin, and attempt allocation from either the small or large bins (looking for the "next best size" chunk).

Looking at the code above, we see we are allocating chunks of sizes `0x500/0x600/0x20`. The `0x20` chunks will be to simply split up the larger chunks, so we don't have to worry about any possible consolidation. The `0x500/0x600` byte chunks will be what we insert into the unsorted bin (they are this size, so they don't get inserted into either the tcache / fastbin).

Looking at the code, I start off with allocating my chunks (each `0x500/0x600` byte chunk has a `0x20` byte chunk in between to seperate). I then free my larger chunks, starting with two `0x500` byte chunks, one `0x600` byte chunk, then finally another `0x500` byte chunks. Since unsorted bin insertions happen at the head, and looking at the order of frees, this will be the order of chunks in the unsorted bin after the freeing happens:

```
Head
chunk6 -> 0x500
chunk4 -> 0x600
chunk2 -> 0x500
chunk0 -> 0x500
Tail
```

Then we see, we will allocate a chunk of size `0x600`. We have a chunk of the exact same size in the unsorted bin, so we can expect it to do an exact fit allocation of that chunk. However the unsorted bin allocation begins at the tail, so with `chunk0`, moving towards the head. In order to reach `chunk4`, it will have to go through `chunk0`, and then `chunk2`, before finally ending up with `chunk4`. Since once it gets to `chunk4` it will be able to allocate a chunk and stop the unsorted bin iteration, `chunk6` will remain in the unsorted bin.

Let's see this in action, first let's see the addresses for chunks `0/2/4/6`:

```
$  gdb ./unsorted_bin_basic 
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
Reading symbols from ./unsorted_bin_basic...
(No debugging symbols found in ./unsorted_bin_basic)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:   endbr64 
   0x000000000000116d <+4>:   push   rbp
   0x000000000000116e <+5>:   mov    rbp,rsp
   0x0000000000001171 <+8>:   sub    rsp,0x40
   0x0000000000001175 <+12>:  mov    edi,0x500
   0x000000000000117a <+17>:  call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:  mov    QWORD PTR [rbp-0x40],rax
   0x0000000000001183 <+26>:  mov    edi,0x20
   0x0000000000001188 <+31>:  call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:  mov    QWORD PTR [rbp-0x38],rax
   0x0000000000001191 <+40>:  mov    edi,0x500
   0x0000000000001196 <+45>:  call   0x1070 <malloc@plt>
   0x000000000000119b <+50>:  mov    QWORD PTR [rbp-0x30],rax
   0x000000000000119f <+54>:  mov    edi,0x20
   0x00000000000011a4 <+59>:  call   0x1070 <malloc@plt>
   0x00000000000011a9 <+64>:  mov    QWORD PTR [rbp-0x28],rax
   0x00000000000011ad <+68>:  mov    edi,0x600
   0x00000000000011b2 <+73>:  call   0x1070 <malloc@plt>
   0x00000000000011b7 <+78>:  mov    QWORD PTR [rbp-0x20],rax
   0x00000000000011bb <+82>:  mov    edi,0x20
   0x00000000000011c0 <+87>:  call   0x1070 <malloc@plt>
   0x00000000000011c5 <+92>:  mov    QWORD PTR [rbp-0x18],rax
   0x00000000000011c9 <+96>:  mov    edi,0x500
   0x00000000000011ce <+101>: call   0x1070 <malloc@plt>
   0x00000000000011d3 <+106>: mov    QWORD PTR [rbp-0x10],rax
   0x00000000000011d7 <+110>: mov    edi,0x20
   0x00000000000011dc <+115>: call   0x1070 <malloc@plt>
   0x00000000000011e1 <+120>: mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011e5 <+124>: mov    rax,QWORD PTR [rbp-0x40]
   0x00000000000011e9 <+128>: mov    rdi,rax
   0x00000000000011ec <+131>: call   0x1060 <free@plt>
   0x00000000000011f1 <+136>: mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000011f5 <+140>: mov    rdi,rax
   0x00000000000011f8 <+143>: call   0x1060 <free@plt>
   0x00000000000011fd <+148>: mov    rax,QWORD PTR [rbp-0x20]
   0x0000000000001201 <+152>: mov    rdi,rax
   0x0000000000001204 <+155>: call   0x1060 <free@plt>
   0x0000000000001209 <+160>: mov    rax,QWORD PTR [rbp-0x10]
   0x000000000000120d <+164>: mov    rdi,rax
   0x0000000000001210 <+167>: call   0x1060 <free@plt>
   0x0000000000001215 <+172>: mov    edi,0x600
   0x000000000000121a <+177>: call   0x1070 <malloc@plt>
   0x000000000000121f <+182>: nop
   0x0000000000001220 <+183>: leave  
   0x0000000000001221 <+184>: ret    
End of assembler dump.
gef➤  b *main+22
Breakpoint 1 at 0x117f
gef➤  b *main+50
Breakpoint 2 at 0x119b
gef➤  b *main+78
Breakpoint 3 at 0x11b7
gef➤  b *main+106
Breakpoint 4 at 0x11d3
gef➤  b *main+131
Breakpoint 5 at 0x11ec
gef➤  b *main+143
Breakpoint 6 at 0x11f8
gef➤  b *main+155
Breakpoint 7 at 0x1204
gef➤  b *main+167
Breakpoint 8 at 0x1210
gef➤  b *main+177
Breakpoint 9 at 0x121a
gef➤  r
Starting program: /Hackery/shogun/heap_demos/unsorted_bin/unsorted_bin_basic/unsorted_bin_basic 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555517f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00007ffff7fc1000  →  0x00010102464c457f
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x00005555555597a0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x40], rax
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555597a0  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00007ffff7fc1000  →  0x00010102464c457f    ← $rsp
0x00007fffffffdf58│+0x0008: 0x0000010101000000
0x00007fffffffdf60│+0x0010: 0x0000000000000002
0x00007fffffffdf68│+0x0018: 0x00000000078bfbff
0x00007fffffffdf70│+0x0020: 0x00007fffffffe399  →  0x000034365f363878 ("x86_64"?)
0x00007fffffffdf78│+0x0028: 0x0000000000000064 ("d"?)
0x00007fffffffdf80│+0x0030: 0x0000000000001000
0x00007fffffffdf88│+0x0038: 0x0000555555555080  →  <_start+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>         sub    rsp, 0x40
   0x555555555175 <main+12>        mov    edi, 0x500
   0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>        mov    QWORD PTR [rbp-0x40], rax
   0x555555555183 <main+26>        mov    edi, 0x20
   0x555555555188 <main+31>        call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>        mov    QWORD PTR [rbp-0x38], rax
   0x555555555191 <main+40>        mov    edi, 0x500
   0x555555555196 <main+45>        call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x55555555517f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555592a0
gef➤  c
Continuing.

Breakpoint 2, 0x000055555555519b in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555597e0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0000555555559ce0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x000055555555519b  →  <main+50> mov QWORD PTR [rbp-0x30], rax
$r8    : 0x21001           
$r9    : 0x00005555555597e0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559ce0  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x0000000000000002
0x00007fffffffdf68│+0x0018: 0x00000000078bfbff
0x00007fffffffdf70│+0x0020: 0x00007fffffffe399  →  0x000034365f363878 ("x86_64"?)
0x00007fffffffdf78│+0x0028: 0x0000000000000064 ("d"?)
0x00007fffffffdf80│+0x0030: 0x0000000000001000
0x00007fffffffdf88│+0x0038: 0x0000555555555080  →  <_start+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555518d <main+36>        mov    QWORD PTR [rbp-0x38], rax
   0x555555555191 <main+40>        mov    edi, 0x500
   0x555555555196 <main+45>        call   0x555555555070 <malloc@plt>
 → 0x55555555519b <main+50>        mov    QWORD PTR [rbp-0x30], rax
   0x55555555519f <main+54>        mov    edi, 0x20
   0x5555555551a4 <main+59>        call   0x555555555070 <malloc@plt>
   0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x28], rax
   0x5555555551ad <main+68>        mov    edi, 0x600
   0x5555555551b2 <main+73>        call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x55555555519b in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555519b → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x5555555597e0
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555551b7 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559d20  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x611             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x000055555555a320  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551b7  →  <main+78> mov QWORD PTR [rbp-0x20], rax
$r8    : 0x21001           
$r9    : 0x0000555555559d20  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a320  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x00007fffffffe399  →  0x000034365f363878 ("x86_64"?)
0x00007fffffffdf78│+0x0028: 0x0000000000000064 ("d"?)
0x00007fffffffdf80│+0x0030: 0x0000000000001000
0x00007fffffffdf88│+0x0038: 0x0000555555555080  →  <_start+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x28], rax
   0x5555555551ad <main+68>        mov    edi, 0x600
   0x5555555551b2 <main+73>        call   0x555555555070 <malloc@plt>
 → 0x5555555551b7 <main+78>        mov    QWORD PTR [rbp-0x20], rax
   0x5555555551bb <main+82>        mov    edi, 0x20
   0x5555555551c0 <main+87>        call   0x555555555070 <malloc@plt>
   0x5555555551c5 <main+92>        mov    QWORD PTR [rbp-0x18], rax
   0x5555555551c9 <main+96>        mov    edi, 0x500
   0x5555555551ce <main+101>       call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x5555555551b7 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b7 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x555555559d20
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555551d3 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x000055555555a860  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551d3  →  <main+106> mov QWORD PTR [rbp-0x10], rax
$r8    : 0x21001           
$r9    : 0x000055555555a360  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a860  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x0000000000001000
0x00007fffffffdf88│+0x0038: 0x0000555555555080  →  <_start+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c5 <main+92>        mov    QWORD PTR [rbp-0x18], rax
   0x5555555551c9 <main+96>        mov    edi, 0x500
   0x5555555551ce <main+101>       call   0x555555555070 <malloc@plt>
 → 0x5555555551d3 <main+106>       mov    QWORD PTR [rbp-0x10], rax
   0x5555555551d7 <main+110>       mov    edi, 0x20
   0x5555555551dc <main+115>       call   0x555555555070 <malloc@plt>
   0x5555555551e1 <main+120>       mov    QWORD PTR [rbp-0x8], rax
   0x5555555551e5 <main+124>       mov    rax, QWORD PTR [rbp-0x40]
   0x5555555551e9 <main+128>       mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x5555555551d3 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d3 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x55555555a360
```

So we see, `chunk0` is `0x5555555592a0`, `chunk2` is `0x5555555597e0`, `chunk4` is `0x555555559d20`, and `chunk6` is `0x55555555a360`.

Now, let's see the process of these chunks getting inserted into the unsorted bin. Remember, unsorted bin insertion happens at the head:

```
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555551d3 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x000055555555a860  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551d3  →  <main+106> mov QWORD PTR [rbp-0x10], rax
$r8    : 0x21001           
$r9    : 0x000055555555a360  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a860  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x0000000000001000
0x00007fffffffdf88│+0x0038: 0x0000555555555080  →  <_start+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c5 <main+92>        mov    QWORD PTR [rbp-0x18], rax
   0x5555555551c9 <main+96>        mov    edi, 0x500
   0x5555555551ce <main+101>       call   0x555555555070 <malloc@plt>
 → 0x5555555551d3 <main+106>       mov    QWORD PTR [rbp-0x10], rax
   0x5555555551d7 <main+110>       mov    edi, 0x20
   0x5555555551dc <main+115>       call   0x555555555070 <malloc@plt>
   0x5555555551e1 <main+120>       mov    QWORD PTR [rbp-0x8], rax
   0x5555555551e5 <main+124>       mov    rax, QWORD PTR [rbp-0x40]
   0x5555555551e9 <main+128>       mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x5555555551d3 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d3 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x55555555a360
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

Breakpoint 5, 0x00005555555551ec in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x31              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x000055555555a890  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x00005555555551ec  →  <main+131> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e1 <main+120>       mov    QWORD PTR [rbp-0x8], rax
   0x5555555551e5 <main+124>       mov    rax, QWORD PTR [rbp-0x40]
   0x5555555551e9 <main+128>       mov    rdi, rax
 → 0x5555555551ec <main+131>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555592a0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x5555555551ec in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551ec → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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

Breakpoint 6, 0x00005555555551f8 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555597e0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00005555555597e0  →  0x0000000000000000
$rip   : 0x00005555555551f8  →  <main+143> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ec <main+131>       call   0x555555555060 <free@plt>
   0x5555555551f1 <main+136>       mov    rax, QWORD PTR [rbp-0x30]
   0x5555555551f5 <main+140>       mov    rdi, rax
 → 0x5555555551f8 <main+143>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555597e0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x5555555551f8 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551f8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x555555559290, bk=0x555555559290
 →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 7, 0x0000555555555204 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559d20  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x0000555555559d20  →  0x0000000000000000
$rip   : 0x0000555555555204  →  <main+155> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f8 <main+143>       call   0x555555555060 <free@plt>
   0x5555555551fd <main+148>       mov    rax, QWORD PTR [rbp-0x20]
   0x555555555201 <main+152>       mov    rdi, rax
 → 0x555555555204 <main+155>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559d20 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x555555555204 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555204 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x5555555597d0, bk=0x555555559290
 →   Chunk(addr=0x5555555597e0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 8, 0x0000555555555210 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x5f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x000055555555a360  →  0x0000000000000000
$rip   : 0x0000555555555210  →  <main+167> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x00005555555597d0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555204 <main+155>       call   0x555555555060 <free@plt>
   0x555555555209 <main+160>       mov    rax, QWORD PTR [rbp-0x10]
   0x55555555520d <main+164>       mov    rdi, rax
 → 0x555555555210 <main+167>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x000055555555a360 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x555555555210 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555210 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x555555559d10, bk=0x555555559290
 →   Chunk(addr=0x555555559d20, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555597e0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 9, 0x000055555555521a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x600             
$rip   : 0x000055555555521a  →  <main+177> call 0x555555555070 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x00005555555597d0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000555555559d10  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555520d <main+164>       mov    rdi, rax
   0x555555555210 <main+167>       call   0x555555555060 <free@plt>
   0x555555555215 <main+172>       mov    edi, 0x600
 → 0x55555555521a <main+177>       call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <_start+0>       endbr64 
      0x555555555084 <_start+4>       xor    ebp, ebp
      0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000600
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x55555555521a in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555521a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x55555555a350, bk=0x555555559290
 →   Chunk(addr=0x55555555a360, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559d20, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555597e0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 4 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

Now finally, let's see the allocation of `chunk4`, and `chunk0/chunk2` getting moved over into the large bin:

```
Breakpoint 9, 0x000055555555521a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x600             
$rip   : 0x000055555555521a  →  <main+177> call 0x555555555070 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x00005555555597d0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x0000555555559d10  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555520d <main+164>       mov    rdi, rax
   0x555555555210 <main+167>       call   0x555555555060 <free@plt>
   0x555555555215 <main+172>       mov    edi, 0x600
 → 0x55555555521a <main+177>       call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <_start+0>       endbr64 
      0x555555555084 <_start+4>       xor    ebp, ebp
      0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000600
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x55555555521a in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555521a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x55555555a350, bk=0x555555559290
 →   Chunk(addr=0x55555555a360, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559d20, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555597e0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 4 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rsp   : 0x00007fffffffdf48  →  0x000055555555521f  →  <main+182> nop 
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x600             
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x000055555555a870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf48│+0x0000: 0x000055555555521f  →  <main+182> nop     ← $rsp
0x00007fffffffdf50│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
0x00007fffffffdf58│+0x0010: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0018: 0x00005555555597e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf68│+0x0020: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0028: 0x0000555555559d20  →  0x00005555555597d0  →  0x0000000000000000
0x00007fffffffdf78│+0x0030: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0038: 0x000055555555a360  →  0x0000555555559d10  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>       endbr64 
   0x555555555084 <_start+4>       xor    ebp, ebp
   0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x55555555521f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x000055555555521f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559d20  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x31              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf50  →  0x00005555555592a0  →  0x00005555555597d0  →  0x0000000000000000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x2               
$rip   : 0x000055555555521f  →  <main+182> nop 
$r8    : 0x0               
$r9    : 0x0000555555559d20  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r10   : 0x000055555555a320  →  0x0000000000000610
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3aa  →  "/Hackery/shogun/heap_demos/unsorted_bin/u[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x00005555555592a0  →  0x00005555555597d0  →  0x0000000000000000  ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555597b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555597e0  →  0x00007ffff7e1a110  →  0x00007ffff7e1a100  →  0x00007ffff7e1a0f0  →  0x00007ffff7e1a0e0  →  0x00007ffff7e1a0d0  →  0x00007ffff7e1a0c0
0x00007fffffffdf68│+0x0018: 0x0000555555559cf0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559d20  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x000055555555a330  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a360  →  0x00007ffff7e19ce0  →  0x000055555555a890  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a870  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555210 <main+167>       call   0x555555555060 <free@plt>
   0x555555555215 <main+172>       mov    edi, 0x600
   0x55555555521a <main+177>       call   0x555555555070 <malloc@plt>
 → 0x55555555521f <main+182>       nop    
   0x555555555220 <main+183>       leave  
   0x555555555221 <main+184>       ret    
   0x555555555222                  add    BYTE PTR [rax], al
   0x555555555224 <_fini+0>        endbr64 
   0x555555555228 <_fini+4>        sub    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_bin_ba", stopped 0x55555555521f in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555521f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
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
[+] unsorted_bins[0]: fw=0x55555555a350, bk=0x55555555a350
 →   Chunk(addr=0x55555555a360, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] large_bins[67]: fw=0x555555559290, bk=0x5555555597d0
 →   Chunk(addr=0x5555555592a0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555597e0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  p $rax
$5 = 0x555555559d20
gef➤  c
Continuing.
[Inferior 1 (process 51164) exited with code 040]
```

So we see, `chunk0/chunk2` have been inserted into the large bin, `chunk4` has been allocated, and `chunk6` remains in the unsorted bin (just like what we expected). Like that, we have first hand seen unsorted bin insertion, and removals!
