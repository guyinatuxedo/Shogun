## tcache basic

So, in this instance, we will be showing the basics of the `tcache`. We will be showing insertions, removals, and the `tcache` struct itself.

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x10
#define CHUNK_SIZE1 0x100
#define CHUNK_SIZE2 0x400

void main() {
   char *chunk0,
   *chunk1,
   *chunk2,
   *chunk3,
   *chunk4,
   *chunk5;

   chunk0 = malloc(CHUNK_SIZE0);
   chunk1 = malloc(CHUNK_SIZE0);
   chunk2 = malloc(CHUNK_SIZE1);
   chunk3 = malloc(CHUNK_SIZE1);
   chunk4 = malloc(CHUNK_SIZE2);
   chunk5 = malloc(CHUNK_SIZE2);

   free(chunk0);
   free(chunk2);
   free(chunk4);

   free(chunk1);
   free(chunk3);
   free(chunk5);

   malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   malloc(CHUNK_SIZE2);

   malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   malloc(CHUNK_SIZE2);
}
```

#### tcache basic walkthrough

So we will first look at the tcache, after it has been initialized and is empty. Then, we will see it after we insert three chunks into three unique tcache bins, and see the tcache in that state. Then, we will insert three more chunks into those tcache bins, and see the state of the tcache then. Then, we will allocate chunks from each of the tcache bins and see the state of the tcache then. Finally, we will empty the tcache bins, and see the state of the heap then.

So starting off, let's set our breakpoints, and see the tcache when it's empty:

```
$  gdb ./tcache_basic 
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
Reading symbols from ./tcache_basic...
(No debugging symbols found in ./tcache_basic)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:   endbr64 
   0x000000000000116d <+4>:   push   rbp
   0x000000000000116e <+5>:   mov    rbp,rsp
   0x0000000000001171 <+8>:   sub    rsp,0x30
   0x0000000000001175 <+12>:  mov    edi,0x10
   0x000000000000117a <+17>:  call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:  mov    QWORD PTR [rbp-0x30],rax
   0x0000000000001183 <+26>:  mov    edi,0x10
   0x0000000000001188 <+31>:  call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:  mov    QWORD PTR [rbp-0x28],rax
   0x0000000000001191 <+40>:  mov    edi,0x100
   0x0000000000001196 <+45>:  call   0x1070 <malloc@plt>
   0x000000000000119b <+50>:  mov    QWORD PTR [rbp-0x20],rax
   0x000000000000119f <+54>:  mov    edi,0x100
   0x00000000000011a4 <+59>:  call   0x1070 <malloc@plt>
   0x00000000000011a9 <+64>:  mov    QWORD PTR [rbp-0x18],rax
   0x00000000000011ad <+68>:  mov    edi,0x400
   0x00000000000011b2 <+73>:  call   0x1070 <malloc@plt>
   0x00000000000011b7 <+78>:  mov    QWORD PTR [rbp-0x10],rax
   0x00000000000011bb <+82>:  mov    edi,0x400
   0x00000000000011c0 <+87>:  call   0x1070 <malloc@plt>
   0x00000000000011c5 <+92>:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011c9 <+96>:  mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000011cd <+100>: mov    rdi,rax
   0x00000000000011d0 <+103>: call   0x1060 <free@plt>
   0x00000000000011d5 <+108>: mov    rax,QWORD PTR [rbp-0x20]
   0x00000000000011d9 <+112>: mov    rdi,rax
   0x00000000000011dc <+115>: call   0x1060 <free@plt>
   0x00000000000011e1 <+120>: mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011e5 <+124>: mov    rdi,rax
   0x00000000000011e8 <+127>: call   0x1060 <free@plt>
   0x00000000000011ed <+132>: mov    rax,QWORD PTR [rbp-0x28]
   0x00000000000011f1 <+136>: mov    rdi,rax
   0x00000000000011f4 <+139>: call   0x1060 <free@plt>
   0x00000000000011f9 <+144>: mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011fd <+148>: mov    rdi,rax
   0x0000000000001200 <+151>: call   0x1060 <free@plt>
   0x0000000000001205 <+156>: mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001209 <+160>: mov    rdi,rax
   0x000000000000120c <+163>: call   0x1060 <free@plt>
   0x0000000000001211 <+168>: mov    edi,0x10
   0x0000000000001216 <+173>: call   0x1070 <malloc@plt>
   0x000000000000121b <+178>: mov    edi,0x100
   0x0000000000001220 <+183>: call   0x1070 <malloc@plt>
   0x0000000000001225 <+188>: mov    edi,0x400
   0x000000000000122a <+193>: call   0x1070 <malloc@plt>
   0x000000000000122f <+198>: mov    edi,0x10
   0x0000000000001234 <+203>: call   0x1070 <malloc@plt>
   0x0000000000001239 <+208>: mov    edi,0x100
   0x000000000000123e <+213>: call   0x1070 <malloc@plt>
   0x0000000000001243 <+218>: mov    edi,0x400
   0x0000000000001248 <+223>: call   0x1070 <malloc@plt>
   0x000000000000124d <+228>: nop
   0x000000000000124e <+229>: leave  
   0x000000000000124f <+230>: ret    
End of assembler dump.
gef➤  b *main+92
Breakpoint 1 at 0x11c5
gef➤  b *main+132
Breakpoint 2 at 0x11ed
gef➤  b *main+168
Breakpoint 3 at 0x1211
gef➤  b *main+198
Breakpoint 4 at 0x122f
gef➤  b *main+228
Breakpoint 1 at 0x124d
gef➤  r
Starting program: /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00005555555551c5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559910  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x411             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d10  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551c5  →  <main+92> mov QWORD PTR [rbp-0x8], rax
$r8    : 0x21001           
$r9    : 0x0000555555559910  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d10  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e1  →  "/Hackery/shogun/heap_demos/tcache/tcache_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555592c0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0010: 0x00005555555592e0  →  0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x00005555555593f0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0020: 0x0000555555559500  →  0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b7 <main+78>        mov    QWORD PTR [rbp-0x10], rax
   0x5555555551bb <main+82>        mov    edi, 0x400
   0x5555555551c0 <main+87>        call   0x555555555070 <malloc@plt>
 → 0x5555555551c5 <main+92>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551c9 <main+96>        mov    rax, QWORD PTR [rbp-0x30]
   0x5555555551cd <main+100>       mov    rdi, rax
   0x5555555551d0 <main+103>       call   0x555555555060 <free@plt>
   0x5555555551d5 <main+108>       mov    rax, QWORD PTR [rbp-0x20]
   0x5555555551d9 <main+112>       mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_basic", stopped 0x5555555551c5 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p tcache
$1 = (tcache_perthread_struct *) 0x555555559010
gef➤  x/80g 0x555555559010
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x0
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
```

So, we see the tcache right now is completely empty. Let's insert some chunks into it:

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555551ed in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x3f              
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfa0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000001
$rdi   : 0x7               
$rip   : 0x00005555555551ed  →  <main+132> mov rax, QWORD PTR [rbp-0x28]
$r8    : 0x0000555555559500  →  0x0000000555555559
$r9    : 0x0000555555559910  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x6a561f9f00b1833e
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e1  →  "/Hackery/shogun/heap_demos/tcache/tcache_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555592c0  →  0x0000000000000000
0x00007fffffffdfb0│+0x0010: 0x00005555555592e0  →  0x0000000555555559
0x00007fffffffdfb8│+0x0018: 0x00005555555593f0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0020: 0x0000555555559500  →  0x0000000555555559
0x00007fffffffdfc8│+0x0028: 0x0000555555559910  →  0x0000000000000000
0x00007fffffffdfd0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
 → 0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x28]
   0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
   0x5555555551f9 <main+144>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551fd <main+148>       mov    rdi, rax
   0x555555555200 <main+151>       call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_basic", stopped 0x5555555551ed in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551ed → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/80g 0x555555559010
0x555555559010:   0x1   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x1000000000000
0x555555559090:   0x5555555592a0 0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555592e0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x555555559500
gef➤  x/10g 0x555555559290
0x555555559290:   0x0   0x21
0x5555555592a0:   0x555555559 0x6a561f9f00b1833e
0x5555555592b0:   0x0   0x21
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x111
gef➤  x/10g 0x5555555592d0
0x5555555592d0:   0x0   0x111
0x5555555592e0:   0x555555559 0x6a561f9f00b1833e
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
gef➤  x/10g 0x5555555594f0
0x5555555594f0:   0x0   0x411
0x555555559500:   0x555555559 0x6a561f9f00b1833e
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
```

So we see that there are three tcache bins, each with a single chunk in there. We see in the tcache size array in the beginning, three separate sizes have a size of `0x01` (which corresponds to the three tcache bins with a size of `0x01`). The rest of the tcache bins have a size of `0x00`. We also see that the three tcache bins each have a head ptr. However, the next ptr for each of those tcache's is `0x00` (it shows it as `0x555555559` because of the ptr mangling). Now, we will go ahead, and insert three more chunks into each of those tcache bins. We also see the tcache key for all of them is `0x6a561f9f00b1833e`.

```
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555211 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x3f              
$rdx   : 0x55500000c059    
$rsp   : 0x00007fffffffdfa0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000002
$rdi   : 0x7               
$rip   : 0x0000555555555211  →  <main+168> mov edi, 0x10
$r8    : 0x0000555555559910  →  0x000055500000c059
$r9    : 0x0000555555559910  →  0x000055500000c059
$r10   : 0x77              
$r11   : 0x6a561f9f00b1833e
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e1  →  "/Hackery/shogun/heap_demos/tcache/tcache_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555592c0  →  0x000055500000c7f9
0x00007fffffffdfb0│+0x0010: 0x00005555555592e0  →  0x0000000555555559
0x00007fffffffdfb8│+0x0018: 0x00005555555593f0  →  0x000055500000c7b9
0x00007fffffffdfc0│+0x0020: 0x0000555555559500  →  0x0000000555555559
0x00007fffffffdfc8│+0x0028: 0x0000555555559910  →  0x000055500000c059
0x00007fffffffdfd0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555205 <main+156>       mov    rax, QWORD PTR [rbp-0x8]
   0x555555555209 <main+160>       mov    rdi, rax
   0x55555555520c <main+163>       call   0x555555555060 <free@plt>
 → 0x555555555211 <main+168>       mov    edi, 0x10
   0x555555555216 <main+173>       call   0x555555555070 <malloc@plt>
   0x55555555521b <main+178>       mov    edi, 0x100
   0x555555555220 <main+183>       call   0x555555555070 <malloc@plt>
   0x555555555225 <main+188>       mov    edi, 0x400
   0x55555555522a <main+193>       call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_basic", stopped 0x555555555211 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555211 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/80g 0x555555559010
0x555555559010:   0x2   0x0
0x555555559020:   0x0   0x2000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x2000000000000
0x555555559090:   0x5555555592c0 0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555593f0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x555555559910
gef➤  x/10g 0x5555555592b0
0x5555555592b0:   0x0   0x21
0x5555555592c0:   0x55500000c7f9 0x6a561f9f00b1833e
0x5555555592d0:   0x0   0x111
0x5555555592e0:   0x555555559 0x6a561f9f00b1833e
0x5555555592f0:   0x0   0x0
gef➤  x/10g 0x5555555593e0
0x5555555593e0:   0x0   0x111
0x5555555593f0:   0x55500000c7b9 0x6a561f9f00b1833e
0x555555559400:   0x0   0x0
0x555555559410:   0x0   0x0
0x555555559420:   0x0   0x0
gef➤  x/10g 0x555555559900
0x555555559900:   0x0   0x411
0x555555559910:   0x55500000c059 0x6a561f9f00b1833e
0x555555559920:   0x0   0x0
0x555555559930:   0x0   0x0
0x555555559940:   0x0   0x0
gef➤  x/10g 0x555555559290
0x555555559290:   0x0   0x21
0x5555555592a0:   0x555555559 0x6a561f9f00b1833e
0x5555555592b0:   0x0   0x21
0x5555555592c0:   0x55500000c7f9 0x6a561f9f00b1833e
0x5555555592d0:   0x0   0x111
gef➤  x/10g 0x5555555592d0
0x5555555592d0:   0x0   0x111
0x5555555592e0:   0x555555559 0x6a561f9f00b1833e
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
gef➤  x/10g 0x5555555594f0
0x5555555594f0:   0x0   0x411
0x555555559500:   0x555555559 0x6a561f9f00b1833e
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
```

So we see that the tcache sizes have all been incremented to `0x02`. In addition to that, the tcache head's have been updated to the new chunks, and the next ptrs have been set to the following chunks. We can demangle the next ptrs like this (keep in mind, the ptr is to the start of the user data section of the chunk, not the chunk header):

```
>>> hex((0x5555555592c0 >> 12) ^ (0x55500000c7f9))
'0x5555555592a0'
>>> hex((0x5555555593f0 >> 12) ^ (0x55500000c7b9))
'0x5555555592e0'
>>> hex((0x555555559910 >> 12) ^ (0x55500000c059))
'0x555555559500'
```

Next up, let's remove three of those chunks:

```
gef➤  c
Continuing.

Breakpoint 4, 0x000055555555522f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559910  →  0x000055500000c059
$rbx   : 0x0               
$rcx   : 0x1               
$rdx   : 0x0000555555559010  →  0x0000000000000001
$rsp   : 0x00007fffffffdfa0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559500  →  0x0000000555555559
$rdi   : 0x4f              
$rip   : 0x000055555555522f  →  <main+198> mov edi, 0x10
$r8    : 0x0000555555559910  →  0x000055500000c059
$r9    : 0x0000555555559910  →  0x000055500000c059
$r10   : 0x77              
$r11   : 0x6a561f9f00b1833e
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e1  →  "/Hackery/shogun/heap_demos/tcache/tcache_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555592c0  →  0x000055500000c7f9
0x00007fffffffdfb0│+0x0010: 0x00005555555592e0  →  0x0000000555555559
0x00007fffffffdfb8│+0x0018: 0x00005555555593f0  →  0x000055500000c7b9
0x00007fffffffdfc0│+0x0020: 0x0000555555559500  →  0x0000000555555559
0x00007fffffffdfc8│+0x0028: 0x0000555555559910  →  0x000055500000c059
0x00007fffffffdfd0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555220 <main+183>       call   0x555555555070 <malloc@plt>
   0x555555555225 <main+188>       mov    edi, 0x400
   0x55555555522a <main+193>       call   0x555555555070 <malloc@plt>
 → 0x55555555522f <main+198>       mov    edi, 0x10
   0x555555555234 <main+203>       call   0x555555555070 <malloc@plt>
   0x555555555239 <main+208>       mov    edi, 0x100
   0x55555555523e <main+213>       call   0x555555555070 <malloc@plt>
   0x555555555243 <main+218>       mov    edi, 0x400
   0x555555555248 <main+223>       call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_basic", stopped 0x55555555522f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555522f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/80g 0x555555559010
0x555555559010:   0x1   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x1000000000000
0x555555559090:   0x5555555592a0 0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555592e0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x555555559500
gef➤  x/10g 0x555555559290
0x555555559290:   0x0   0x21
0x5555555592a0:   0x555555559 0x6a561f9f00b1833e
0x5555555592b0:   0x0   0x21
0x5555555592c0:   0x55500000c7f9 0x0
0x5555555592d0:   0x0   0x111
gef➤  x/10g 0x5555555592d0
0x5555555592d0:   0x0   0x111
0x5555555592e0:   0x555555559 0x6a561f9f00b1833e
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
gef➤  x/10g 0x5555555594f0
0x5555555594f0:   0x0   0x411
0x555555559500:   0x555555559 0x6a561f9f00b1833e
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
```

So, we can see that the tcache sizes have all been decremented to `0x01`, and the tcache heads are back to the original heads. This is because the tcache is a First In, First Out data structure. Now let's allocate the last three chunks (this part was from re-running the same program, in case some specific addresses are different):

```
gef➤  c
Continuing.

Breakpoint 5, 0x000055555555524d in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559500  →  0x0000000555555559
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdfa0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x4f              
$rip   : 0x000055555555524d  →  <main+228> nop 
$r8    : 0x0000555555559910  →  0x000055500000c059
$r9    : 0x0000555555559910  →  0x000055500000c059
$r10   : 0x77              
$r11   : 0x72ddab937dca3916
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/tcache/tcache_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555592c0  →  0x000055500000c7f9
0x00007fffffffdfb0│+0x0010: 0x00005555555592e0  →  0x0000000555555559
0x00007fffffffdfb8│+0x0018: 0x00005555555593f0  →  0x000055500000c7b9
0x00007fffffffdfc0│+0x0020: 0x0000555555559500  →  0x0000000555555559
0x00007fffffffdfc8│+0x0028: 0x0000555555559910  →  0x000055500000c059
0x00007fffffffdfd0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555523e <main+213>       call   0x555555555070 <malloc@plt>
   0x555555555243 <main+218>       mov    edi, 0x400
   0x555555555248 <main+223>       call   0x555555555070 <malloc@plt>
 → 0x55555555524d <main+228>       nop    
   0x55555555524e <main+229>       leave  
   0x55555555524f <main+230>       ret    
   0x555555555250 <_fini+0>        endbr64 
   0x555555555254 <_fini+4>        sub    rsp, 0x8
   0x555555555258 <_fini+8>        add    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_basic", stopped 0x55555555524d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555524d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p tcache
$3 = (tcache_perthread_struct *) 0x555555559010
gef➤  x/80g 0x555555559010
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x0
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  c
Continuing.
[Inferior 1 (process 5621) exited normally]
```

Just like that, we've seen the tcache have chunks inserted into it, and removed from it.
