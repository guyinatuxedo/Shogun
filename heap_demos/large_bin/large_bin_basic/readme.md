## large bin basic

So, in this instance, we will be showing the basics of the `small bin`. We will be showing insertions, and removals into the `unsorted bin`.

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x1100
#define CHUNK_SIZE1 0x20

void main() {
   char *chunk0,
   *chunk1,
   *chunk2,
   *chunk3;

   chunk0 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk1 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk2 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk3 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);

   free(chunk0);
   free(chunk1);
   free(chunk2);

   malloc(CHUNK_SIZE0 + 0x10);

   free(chunk3);

   malloc(CHUNK_SIZE0 - 0x10);
}
```

#### large bin basic walkthrough

So, for this walkthrough. We will be showing insertions into, and removals from the large bin. Both insertions into, and removals from the large bin can only occur within calls to `malloc`. A single `malloc` call can have other insertions and removals from a large bin.

So, a quick recap of how the large bin works. For insertions into an individual large bin, it can only get chunks that are removed from the unsorted bin, as part of the unsorted bin iteration in `malloc`. If `malloc` determines that an unsorted bin chunk is not able to meet the immediate allocation requirements, and it's within the size to be fit into a large bin, it will go ahead and insert it into the large bin. Then proceeding with the unsorted bin allocation, it will attempt allocation from the large bin (removal).


So, what will our code do? It will allocate `4` large bin sized chunks, of size `0x1000` bytes, with `0x20` byte chunks allocated in between them to prevent potential consolidation. We go ahead, and free the first `3` chunks, to insert them into the unsorted bin. Proceeding that we will allocate a chunk that is larger than any of the chunks we've allocated before. This will move the `3` unsorted bin chunks, over to the large bin. Proceeding that we will free the fourth and final chunk, to insert it into the unsorted bin. However, we will do one final `malloc`, which is `0x10` bytes smaller than all of the other chunks, but big enough to be allocated from the same large bin which our chunks come from (index `99`). The fourth chunk will be inserted into the same large bin as the rest of the chunks, then allocated from it.

Let's start going through this. First, let's see the addresses of the four chunks:

```
$  gdb ./large_bin_basic
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
Reading symbols from ./large_bin_basic...
(No debugging symbols found in ./large_bin_basic)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:   endbr64
   0x000000000000116d <+4>:   push   rbp
   0x000000000000116e <+5>:   mov   rbp,rsp
   0x0000000000001171 <+8>:   sub   rsp,0x20
   0x0000000000001175 <+12>:  mov   edi,0x1100
   0x000000000000117a <+17>:  call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:  mov   QWORD PTR [rbp-0x20],rax
   0x0000000000001183 <+26>:  mov   edi,0x20
   0x0000000000001188 <+31>:  call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:  mov   edi,0x1100
   0x0000000000001192 <+41>:  call   0x1070 <malloc@plt>
   0x0000000000001197 <+46>:  mov   QWORD PTR [rbp-0x18],rax
   0x000000000000119b <+50>:  mov   edi,0x20
   0x00000000000011a0 <+55>:  call   0x1070 <malloc@plt>
   0x00000000000011a5 <+60>:  mov   edi,0x1100
   0x00000000000011aa <+65>:  call   0x1070 <malloc@plt>
   0x00000000000011af <+70>:  mov   QWORD PTR [rbp-0x10],rax
   0x00000000000011b3 <+74>:  mov   edi,0x20
   0x00000000000011b8 <+79>:  call   0x1070 <malloc@plt>
   0x00000000000011bd <+84>:  mov   edi,0x1100
   0x00000000000011c2 <+89>:  call   0x1070 <malloc@plt>
   0x00000000000011c7 <+94>:  mov   QWORD PTR [rbp-0x8],rax
   0x00000000000011cb <+98>:  mov   edi,0x20
   0x00000000000011d0 <+103>: call   0x1070 <malloc@plt>
   0x00000000000011d5 <+108>: mov   rax,QWORD PTR [rbp-0x20]
   0x00000000000011d9 <+112>: mov   rdi,rax
   0x00000000000011dc <+115>: call   0x1060 <free@plt>
   0x00000000000011e1 <+120>: mov   rax,QWORD PTR [rbp-0x18]
   0x00000000000011e5 <+124>: mov   rdi,rax
   0x00000000000011e8 <+127>: call   0x1060 <free@plt>
   0x00000000000011ed <+132>: mov   rax,QWORD PTR [rbp-0x10]
   0x00000000000011f1 <+136>: mov   rdi,rax
   0x00000000000011f4 <+139>: call   0x1060 <free@plt>
   0x00000000000011f9 <+144>: mov   edi,0x1110
   0x00000000000011fe <+149>: call   0x1070 <malloc@plt>
   0x0000000000001203 <+154>: mov   rax,QWORD PTR [rbp-0x8]
   0x0000000000001207 <+158>: mov   rdi,rax
   0x000000000000120a <+161>: call   0x1060 <free@plt>
   0x000000000000120f <+166>: mov   edi,0x10f0
   0x0000000000001214 <+171>: call   0x1070 <malloc@plt>
   0x0000000000001219 <+176>: nop
   0x000000000000121a <+177>: leave  
   0x000000000000121b <+178>: ret    
End of assembler dump.
gef➤  b *main+22
Breakpoint 1 at 0x117f
gef➤  b *main+46
Breakpoint 2 at 0x1197
gef➤  b *main+70
Breakpoint 3 at 0x11af
gef➤  b *main+94
Breakpoint 4 at 0x11c7
gef➤  b *main+108
Breakpoint 5 at 0x11d5
gef➤  b *main+144
Breakpoint 6 at 0x11f9
gef➤  b *main+158
Breakpoint 7 at 0x1207
gef➤  b *main+166
Breakpoint 8 at 0x120f
gef➤  b *main+176
Breakpoint 9 at 0x1219
gef➤  r
Starting program: /Hackery/shogun/heap_demos/large_bin/large_bin_basic/large_bin_basic
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555517f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1111          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00007fffffffe3b9  →  0x000034365f363878 ("x86_64"?)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555a3a0  →  0x0000000000000000
$rdi   : 0x3             
$rip   : 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x20], rax
$r8   : 0x21001          
$r9   : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a3a0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00007fffffffe3b9  →  0x000034365f363878 ("x86_64"?)   ← $rsp
0x00007fffffffdf98│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfa0│+0x0010: 0x0000000000001000
0x00007fffffffdfa8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>       sub   rsp, 0x20
   0x555555555175 <main+12>      mov   edi, 0x1100
   0x55555555517a <main+17>      call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>      mov   QWORD PTR [rbp-0x20], rax
   0x555555555183 <main+26>      mov   edi, 0x20
   0x555555555188 <main+31>      call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>      mov   edi, 0x1100
   0x555555555192 <main+41>      call   0x555555555070 <malloc@plt>
   0x555555555197 <main+46>      mov   QWORD PTR [rbp-0x18], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x55555555517f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555592a0
gef➤  c
Continuing.

Breakpoint 2, 0x0000555555555197 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a3e0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1111          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555b4e0  →  0x0000000000000000
$rdi   : 0x3             
$rip   : 0x0000555555555197  →  <main+46> mov QWORD PTR [rbp-0x18], rax
$r8   : 0x21001          
$r9   : 0x000055555555a3e0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555b4e0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfa0│+0x0010: 0x0000000000001000
0x00007fffffffdfa8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555188 <main+31>      call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>      mov   edi, 0x1100
   0x555555555192 <main+41>      call   0x555555555070 <malloc@plt>
 → 0x555555555197 <main+46>      mov   QWORD PTR [rbp-0x18], rax
   0x55555555519b <main+50>      mov   edi, 0x20
   0x5555555551a0 <main+55>      call   0x555555555070 <malloc@plt>
   0x5555555551a5 <main+60>      mov   edi, 0x1100
   0x5555555551aa <main+65>      call   0x555555555070 <malloc@plt>
   0x5555555551af <main+70>      mov   QWORD PTR [rbp-0x10], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x555555555197 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555197 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55555555a3e0
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555551af in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555b520  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1111          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555c620  →  0x0000000000000000
$rdi   : 0x3             
$rip   : 0x00005555555551af  →  <main+70> mov QWORD PTR [rbp-0x10], rax
$r8   : 0x21001          
$r9   : 0x000055555555b520  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555c620  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000000000001000
0x00007fffffffdfa8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a0 <main+55>      call   0x555555555070 <malloc@plt>
   0x5555555551a5 <main+60>      mov   edi, 0x1100
   0x5555555551aa <main+65>      call   0x555555555070 <malloc@plt>
 → 0x5555555551af <main+70>      mov   QWORD PTR [rbp-0x10], rax
   0x5555555551b3 <main+74>      mov   edi, 0x20
   0x5555555551b8 <main+79>      call   0x555555555070 <malloc@plt>
   0x5555555551bd <main+84>      mov   edi, 0x1100
   0x5555555551c2 <main+89>      call   0x555555555070 <malloc@plt>
   0x5555555551c7 <main+94>      mov   QWORD PTR [rbp-0x8], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x5555555551af in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551af → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x55555555b520
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555551c7 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555c660  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1111          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555d760  →  0x0000000000000000
$rdi   : 0x3             
$rip   : 0x00005555555551c7  →  <main+94> mov QWORD PTR [rbp-0x8], rax
$r8   : 0x21001          
$r9   : 0x000055555555c660  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555d760  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b8 <main+79>      call   0x555555555070 <malloc@plt>
   0x5555555551bd <main+84>      mov   edi, 0x1100
   0x5555555551c2 <main+89>      call   0x555555555070 <malloc@plt>
 → 0x5555555551c7 <main+94>      mov   QWORD PTR [rbp-0x8], rax
   0x5555555551cb <main+98>      mov   edi, 0x20
   0x5555555551d0 <main+103>     call   0x555555555070 <malloc@plt>
   0x5555555551d5 <main+108>     mov   rax, QWORD PTR [rbp-0x20]
   0x5555555551d9 <main+112>     mov   rdi, rax
   0x5555555551dc <main+115>     call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x5555555551c7 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c7 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x55555555c660
```

So we see `chunk0` is `0x5555555592a0`, `chunk1` is `0x55555555a3e0`, `chunk2` is `0x55555555b520`, and `chunk3` is `0x55555555c660`. Let's see the first three chunks (`0-2`) get inserted into the unsorted bin:

```
gef➤  c
Continuing.

Breakpoint 5, 0x00005555555551d5 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555d770  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x31            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555d790  →  0x0000000000000000
$rdi   : 0x0             
$rip   : 0x00005555555551d5  →  <main+108> mov rax, QWORD PTR [rbp-0x20]
$r8   : 0x21001          
$r9   : 0x000055555555d770  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555d790  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x000055555555c660  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c7 <main+94>      mov   QWORD PTR [rbp-0x8], rax
   0x5555555551cb <main+98>      mov   edi, 0x20
   0x5555555551d0 <main+103>     call   0x555555555070 <malloc@plt>
 → 0x5555555551d5 <main+108>     mov   rax, QWORD PTR [rbp-0x20]
   0x5555555551d9 <main+112>     mov   rdi, rax
   0x5555555551dc <main+115>     call   0x555555555060 <free@plt>
   0x5555555551e1 <main+120>     mov   rax, QWORD PTR [rbp-0x18]
   0x5555555551e5 <main+124>     mov   rdi, rax
   0x5555555551e8 <main+127>     call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x5555555551d5 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d5 → main()
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

Breakpoint 6, 0x00005555555551f9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x10f           
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555d790  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555d790  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551f9  →  <main+144> mov edi, 0x1110
$r8   : 0x21001          
$r9   : 0x000055555555d770  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555d790  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555d790  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x000055555555a3d0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x000055555555c660  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ed <main+132>     mov   rax, QWORD PTR [rbp-0x10]
   0x5555555551f1 <main+136>     mov   rdi, rax
   0x5555555551f4 <main+139>     call   0x555555555060 <free@plt>
 → 0x5555555551f9 <main+144>     mov   edi, 0x1110
   0x5555555551fe <main+149>     call   0x555555555070 <malloc@plt>
   0x555555555203 <main+154>     mov   rax, QWORD PTR [rbp-0x8]
   0x555555555207 <main+158>     mov   rdi, rax
   0x55555555520a <main+161>     call   0x555555555060 <free@plt>
   0x55555555520f <main+166>     mov   edi, 0x10f0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x5555555551f9 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551f9 → main()
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
[+] unsorted_bins[0]: fw=0x55555555b510, bk=0x555555559290
 →   Chunk(addr=0x55555555b520, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a3e0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So, we see the unsorted bin containing `chunk2`, then `chunk1`, and then `chunk0`. Let's execute a `malloc` call, which will move the chunks over into a largebin:

```
gef➤  c
Continuing.

Breakpoint 7, 0x0000555555555207 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555c660  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1121          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555e8b0  →  0x0000000000000000
$rdi   : 0x3             
$rip   : 0x0000555555555207  →  <main+158> mov rdi, rax
$r8   : 0x0              
$r9   : 0x000055555555d7a0  →  0x0000000000000000
$r10   : 0x000055555555a3d0  →  0x0000000000000000
$r11   : 0x00007ffff7e19ce0  →  0x000055555555e8b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000  ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x00007ffff7e1a300  →  0x00007ffff7e1a2f0  →  0x00007ffff7e1a2e0  →  0x00007ffff7e1a2d0  →  0x00007ffff7e1a2c0  →  0x00007ffff7e1a2b0
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x000055555555a3d0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x000055555555c660  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f9 <main+144>     mov   edi, 0x1110
   0x5555555551fe <main+149>     call   0x555555555070 <malloc@plt>
   0x555555555203 <main+154>     mov   rax, QWORD PTR [rbp-0x8]
 → 0x555555555207 <main+158>     mov   rdi, rax
   0x55555555520a <main+161>     call   0x555555555060 <free@plt>
   0x55555555520f <main+166>     mov   edi, 0x10f0
   0x555555555214 <main+171>     call   0x555555555070 <malloc@plt>
   0x555555555219 <main+176>     nop    
   0x55555555521a <main+177>     leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x555555555207 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555207 → main()
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
[+] large_bins[98]: fw=0x555555559290, bk=0x55555555a3d0
 →   Chunk(addr=0x5555555592a0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555b520, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a3e0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
```

So, we see that the three chunks have been moved into a largebin. Let's go ahead, and insert `chunk3` into the unsorted bin:

```
gef➤  c
Continuing.

Breakpoint 8, 0x000055555555520f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x10f           
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555e8b0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x000055555555520f  →  <main+166> mov edi, 0x10f0
$r8   : 0x0              
$r9   : 0x000055555555d7a0  →  0x0000000000000000
$r10   : 0x000055555555a3d0  →  0x0000000000000000
$r11   : 0x00007ffff7e19ce0  →  0x000055555555e8b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000  ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x00007ffff7e1a300  →  0x00007ffff7e1a2f0  →  0x00007ffff7e1a2e0  →  0x00007ffff7e1a2d0  →  0x00007ffff7e1a2c0  →  0x00007ffff7e1a2b0
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x000055555555a3d0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x000055555555c660  →  0x00007ffff7e19ce0  →  0x000055555555e8b0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555203 <main+154>     mov   rax, QWORD PTR [rbp-0x8]
   0x555555555207 <main+158>     mov   rdi, rax
   0x55555555520a <main+161>     call   0x555555555060 <free@plt>
 → 0x55555555520f <main+166>     mov   edi, 0x10f0
   0x555555555214 <main+171>     call   0x555555555070 <malloc@plt>
   0x555555555219 <main+176>     nop    
   0x55555555521a <main+177>     leave  
   0x55555555521b <main+178>     ret    
   0x55555555521c <_fini+0>      endbr64
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x55555555520f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555520f → main()
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
[+] unsorted_bins[0]: fw=0x55555555c650, bk=0x55555555c650
 →   Chunk(addr=0x55555555c660, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] large_bins[98]: fw=0x555555559290, bk=0x55555555a3d0
 →   Chunk(addr=0x5555555592a0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555b520, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a3e0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
```

So, we see `chunk3` has been inserted into the unsorted bin. Let's execute one last `malloc` call, which will insert it into the large bin, then allocate it back:

```
gef➤  c
Continuing.

Breakpoint 9, 0x0000555555555219 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555c660  →  0x000055555555b510  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x1111          
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555b510  →  0x0000000000000000
$rdi   : 0x000055555555c650  →  0x0000000000000000
$rip   : 0x0000555555555219  →  <main+176> nop
$r8   : 0x0              
$r9   : 0x000055555555c660  →  0x000055555555b510  →  0x0000000000000000
$r10   : 0x000055555555b510  →  0x0000000000000000
$r11   : 0x00007ffff7e19ce0  →  0x000055555555e8b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/large_bin/larg[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x000055555555b510  →  0x0000000000000000  ← $rsp
0x00007fffffffdf98│+0x0008: 0x000055555555a3e0  →  0x00007ffff7e1a300  →  0x00007ffff7e1a2f0  →  0x00007ffff7e1a2e0  →  0x00007ffff7e1a2d0  →  0x00007ffff7e1a2c0  →  0x00007ffff7e1a2b0
0x00007fffffffdfa0│+0x0010: 0x000055555555b520  →  0x000055555555a3d0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x000055555555c660  →  0x000055555555b510  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfb8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0030: 0x0000000000000000
0x00007fffffffdfc8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555520a <main+161>     call   0x555555555060 <free@plt>
   0x55555555520f <main+166>     mov   edi, 0x10f0
   0x555555555214 <main+171>     call   0x555555555070 <malloc@plt>
 → 0x555555555219 <main+176>     nop    
   0x55555555521a <main+177>     leave  
   0x55555555521b <main+178>     ret    
   0x55555555521c <_fini+0>      endbr64
   0x555555555220 <_fini+4>      sub   rsp, 0x8
   0x555555555224 <_fini+8>      add   rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_bin_basic", stopped 0x555555555219 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555219 → main()
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
[+] large_bins[98]: fw=0x555555559290, bk=0x55555555a3d0
 →   Chunk(addr=0x5555555592a0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555b520, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a3e0, size=0x1110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
gef➤  c
Continuing.
[Inferior 1 (process 57437) exited with code 0140]
```

Just like that, we've seen an example of large bin insertion / removal!


