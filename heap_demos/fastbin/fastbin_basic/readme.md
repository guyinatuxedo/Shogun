## fastbin basic

So, in this instance, we will be showing the basics of the `fastbin`. We will be showing insertions and removals.

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x40
#define CHUNK_SIZE1 0x50
#define CHUNK_SIZE2 0x60

#define MAX_TCACHE_BIN_SIZE 7

void main() {
   char *tcache_chunks0[MAX_TCACHE_BIN_SIZE];
   char *tcache_chunks1[MAX_TCACHE_BIN_SIZE];
   char *tcache_chunks2[MAX_TCACHE_BIN_SIZE];

   char *chunk0,
   *chunk1,
   *chunk2,
   *chunk3,
   *chunk4,
   *chunk5;
   int i;

   for (i = 0; i < MAX_TCACHE_BIN_SIZE; i++) {
   tcache_chunks0[i] = malloc(CHUNK_SIZE0);
   tcache_chunks1[i] = malloc(CHUNK_SIZE1);
   tcache_chunks2[i] = malloc(CHUNK_SIZE2);
   }

   chunk0 = malloc(CHUNK_SIZE0);
   chunk1 = malloc(CHUNK_SIZE0);
   chunk2 = malloc(CHUNK_SIZE1);
   chunk3 = malloc(CHUNK_SIZE1);
   chunk4 = malloc(CHUNK_SIZE2);

   for (i = 0; i < MAX_TCACHE_BIN_SIZE; i++) {
   free(tcache_chunks0[i]);
   free(tcache_chunks1[i]);
   free(tcache_chunks2[i]);
   }

   free(chunk0);
   free(chunk1);
   free(chunk2);
   free(chunk3);  
   free(chunk4);

   for (i = 0; i < MAX_TCACHE_BIN_SIZE; i++) {
   tcache_chunks0[i] = malloc(CHUNK_SIZE0);
   tcache_chunks1[i] = malloc(CHUNK_SIZE1);
   tcache_chunks2[i] = malloc(CHUNK_SIZE2);
   }

   malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   malloc(CHUNK_SIZE2);
}
```

#### fastbin basic walkthrough

So a few things about the fastbin. All of the available sizes for fastbins, have a corresponding tcache bin with that same size. Since there is the preference to use the tcache over the fastbin, it will first look to the tcache to either insert newly freed chunks, or reallocate chunks from. So in order to insert chunks into a fastbin, we have to fill up the tcache bins with the same size (max size is `7`). Then, when we want to allocate chunks from the fastbin, we have to first empty the tcache bins with the same size as our fastbins.

So, for this demo. We will see the fastbins having chunks inserted into it (with the lines around `free(chunk0);`). This will be after we've filled up the tcache. Then, we will see allocation from the fastbins (`malloc(CHUNK_SIZE0);`), after we've emptied the tcache bins. One mechanism we will see (and we will also see this with the small bin later on). Whenever a chunk is allocated from the fastbin, assuming there is space in the corresponding tcache bin with the same size, it will move as many chunks over from the fastbin to the tcache bin.

So starting off, let's see the fastbin filling up:

```
$  gdb ./fastbin_basic 
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
Reading symbols from ./fastbin_basic...
(No debugging symbols found in ./fastbin_basic)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>:   endbr64 
   0x000000000000118d <+4>:   push   rbp
   0x000000000000118e <+5>:   mov    rbp,rsp
   0x0000000000001191 <+8>:   sub    rsp,0xf0
   0x0000000000001198 <+15>:  mov    rax,QWORD PTR fs:0x28
   0x00000000000011a1 <+24>:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011a5 <+28>:  xor    eax,eax
   0x00000000000011a7 <+30>:  mov    DWORD PTR [rbp-0xec],0x0
   0x00000000000011b1 <+40>:  jmp    0x120b <main+130>
   0x00000000000011b3 <+42>:  mov    edi,0x40
   0x00000000000011b8 <+47>:  call   0x1090 <malloc@plt>
   0x00000000000011bd <+52>:  mov    rdx,rax
   0x00000000000011c0 <+55>:  mov    eax,DWORD PTR [rbp-0xec]
   0x00000000000011c6 <+61>:  cdqe   
   0x00000000000011c8 <+63>:  mov    QWORD PTR [rbp+rax*8-0xc0],rdx
   0x00000000000011d0 <+71>:  mov    edi,0x50
   0x00000000000011d5 <+76>:  call   0x1090 <malloc@plt>
   0x00000000000011da <+81>:  mov    rdx,rax
   0x00000000000011dd <+84>:  mov    eax,DWORD PTR [rbp-0xec]
   0x00000000000011e3 <+90>:  cdqe   
   0x00000000000011e5 <+92>:  mov    QWORD PTR [rbp+rax*8-0x80],rdx
   0x00000000000011ea <+97>:  mov    edi,0x60
   0x00000000000011ef <+102>: call   0x1090 <malloc@plt>
   0x00000000000011f4 <+107>: mov    rdx,rax
   0x00000000000011f7 <+110>: mov    eax,DWORD PTR [rbp-0xec]
   0x00000000000011fd <+116>: cdqe   
   0x00000000000011ff <+118>: mov    QWORD PTR [rbp+rax*8-0x40],rdx
   0x0000000000001204 <+123>: add    DWORD PTR [rbp-0xec],0x1
   0x000000000000120b <+130>: cmp    DWORD PTR [rbp-0xec],0x6
   0x0000000000001212 <+137>: jle    0x11b3 <main+42>
   0x0000000000001214 <+139>: mov    edi,0x40
   0x0000000000001219 <+144>: call   0x1090 <malloc@plt>
   0x000000000000121e <+149>: mov    QWORD PTR [rbp-0xe8],rax
   0x0000000000001225 <+156>: mov    edi,0x40
   0x000000000000122a <+161>: call   0x1090 <malloc@plt>
   0x000000000000122f <+166>: mov    QWORD PTR [rbp-0xe0],rax
   0x0000000000001236 <+173>: mov    edi,0x50
   0x000000000000123b <+178>: call   0x1090 <malloc@plt>
   0x0000000000001240 <+183>: mov    QWORD PTR [rbp-0xd8],rax
   0x0000000000001247 <+190>: mov    edi,0x50
   0x000000000000124c <+195>: call   0x1090 <malloc@plt>
   0x0000000000001251 <+200>: mov    QWORD PTR [rbp-0xd0],rax
   0x0000000000001258 <+207>: mov    edi,0x60
   0x000000000000125d <+212>: call   0x1090 <malloc@plt>
   0x0000000000001262 <+217>: mov    QWORD PTR [rbp-0xc8],rax
   0x0000000000001269 <+224>: mov    DWORD PTR [rbp-0xec],0x0
   0x0000000000001273 <+234>: jmp    0x12be <main+309>
   0x0000000000001275 <+236>: mov    eax,DWORD PTR [rbp-0xec]
   0x000000000000127b <+242>: cdqe   
   0x000000000000127d <+244>: mov    rax,QWORD PTR [rbp+rax*8-0xc0]
   0x0000000000001285 <+252>: mov    rdi,rax
   0x0000000000001288 <+255>: call   0x1070 <free@plt>
   0x000000000000128d <+260>: mov    eax,DWORD PTR [rbp-0xec]
   0x0000000000001293 <+266>: cdqe   
   0x0000000000001295 <+268>: mov    rax,QWORD PTR [rbp+rax*8-0x80]
   0x000000000000129a <+273>: mov    rdi,rax
   0x000000000000129d <+276>: call   0x1070 <free@plt>
   0x00000000000012a2 <+281>: mov    eax,DWORD PTR [rbp-0xec]
   0x00000000000012a8 <+287>: cdqe   
   0x00000000000012aa <+289>: mov    rax,QWORD PTR [rbp+rax*8-0x40]
   0x00000000000012af <+294>: mov    rdi,rax
   0x00000000000012b2 <+297>: call   0x1070 <free@plt>
   0x00000000000012b7 <+302>: add    DWORD PTR [rbp-0xec],0x1
   0x00000000000012be <+309>: cmp    DWORD PTR [rbp-0xec],0x6
   0x00000000000012c5 <+316>: jle    0x1275 <main+236>
   0x00000000000012c7 <+318>: mov    rax,QWORD PTR [rbp-0xe8]
   0x00000000000012ce <+325>: mov    rdi,rax
   0x00000000000012d1 <+328>: call   0x1070 <free@plt>
   0x00000000000012d6 <+333>: mov    rax,QWORD PTR [rbp-0xe0]
   0x00000000000012dd <+340>: mov    rdi,rax
   0x00000000000012e0 <+343>: call   0x1070 <free@plt>
   0x00000000000012e5 <+348>: mov    rax,QWORD PTR [rbp-0xd8]
   0x00000000000012ec <+355>: mov    rdi,rax
   0x00000000000012ef <+358>: call   0x1070 <free@plt>
   0x00000000000012f4 <+363>: mov    rax,QWORD PTR [rbp-0xd0]
   0x00000000000012fb <+370>: mov    rdi,rax
   0x00000000000012fe <+373>: call   0x1070 <free@plt>
   0x0000000000001303 <+378>: mov    rax,QWORD PTR [rbp-0xc8]
   0x000000000000130a <+385>: mov    rdi,rax
   0x000000000000130d <+388>: call   0x1070 <free@plt>
   0x0000000000001312 <+393>: mov    DWORD PTR [rbp-0xec],0x0
   0x000000000000131c <+403>: jmp    0x1376 <main+493>
   0x000000000000131e <+405>: mov    edi,0x40
   0x0000000000001323 <+410>: call   0x1090 <malloc@plt>
   0x0000000000001328 <+415>: mov    rdx,rax
   0x000000000000132b <+418>: mov    eax,DWORD PTR [rbp-0xec]
   0x0000000000001331 <+424>: cdqe   
   0x0000000000001333 <+426>: mov    QWORD PTR [rbp+rax*8-0xc0],rdx
   0x000000000000133b <+434>: mov    edi,0x50
   0x0000000000001340 <+439>: call   0x1090 <malloc@plt>
   0x0000000000001345 <+444>: mov    rdx,rax
   0x0000000000001348 <+447>: mov    eax,DWORD PTR [rbp-0xec]
   0x000000000000134e <+453>: cdqe   
   0x0000000000001350 <+455>: mov    QWORD PTR [rbp+rax*8-0x80],rdx
   0x0000000000001355 <+460>: mov    edi,0x60
   0x000000000000135a <+465>: call   0x1090 <malloc@plt>
   0x000000000000135f <+470>: mov    rdx,rax
   0x0000000000001362 <+473>: mov    eax,DWORD PTR [rbp-0xec]
   0x0000000000001368 <+479>: cdqe   
   0x000000000000136a <+481>: mov    QWORD PTR [rbp+rax*8-0x40],rdx
   0x000000000000136f <+486>: add    DWORD PTR [rbp-0xec],0x1
   0x0000000000001376 <+493>: cmp    DWORD PTR [rbp-0xec],0x6
   0x000000000000137d <+500>: jle    0x131e <main+405>
   0x000000000000137f <+502>: mov    edi,0x40
   0x0000000000001384 <+507>: call   0x1090 <malloc@plt>
   0x0000000000001389 <+512>: mov    edi,0x50
   0x000000000000138e <+517>: call   0x1090 <malloc@plt>
   0x0000000000001393 <+522>: mov    edi,0x60
   0x0000000000001398 <+527>: call   0x1090 <malloc@plt>
   0x000000000000139d <+532>: nop
   0x000000000000139e <+533>: mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000013a2 <+537>: sub    rax,QWORD PTR fs:0x28
   0x00000000000013ab <+546>: je     0x13b2 <main+553>
   0x00000000000013ad <+548>: call   0x1080 <__stack_chk_fail@plt>
   0x00000000000013b2 <+553>: leave  
   0x00000000000013b3 <+554>: ret    
End of assembler dump.
gef➤  b *main+328
Breakpoint 1 at 0x12d1
gef➤  b *main+507
Breakpoint 2 at 0x1384
gef➤  r
Starting program: /Hackery/shogun/heap_demos/fastbin/fastbin_basic/fastbin_basic 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00005555555552d1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a80  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x5               
$rdx   : 0x55500000cda9    
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559a80  →  0x0000000000000000
$rip   : 0x00005555555552d1  →  <main+328> call 0x555555555070 <free@plt>
$r8    : 0x0000555555559a10  →  0x000055500000cda9
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000000000000
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552c5 <main+316>       jle    0x555555555275 <main+236>
   0x5555555552c7 <main+318>       mov    rax, QWORD PTR [rbp-0xe8]
   0x5555555552ce <main+325>       mov    rdi, rax
 → 0x5555555552d1 <main+328>       call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>     endbr64 
      0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
      0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <__stack_chk_fail@plt+0> endbr64 
      0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
      0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559a80 → 0x0000000000000000,
   $rsi = 0x0000555555559010 → 0x0007000000000000,
   $rdx = 0x000055500000cda9
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552d1 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
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
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559c40,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  si
0x0000555555555070 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a80  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x5               
$rdx   : 0x55500000cda9    
$rsp   : 0x00007fffffffdec8  →  0x00005555555552d6  →  <main+333> mov rax, QWORD PTR [rbp-0xe0]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559a80  →  0x0000000000000000
$rip   : 0x0000555555555070  →  <free@plt+0> endbr64 
$r8    : 0x0000555555559a10  →  0x000055500000cda9
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x00005555555552d6  →  <main+333> mov rax, QWORD PTR [rbp-0xe0]   ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000000000000
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0038: 0x00005555555592a0  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <__cxa_finalize@plt+0> endbr64 
   0x555555555064 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f8d]        # 0x555555557ff8
   0x55555555506b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <free@plt+0>     endbr64 
   0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555070 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → free@plt()
[#1] 0x5555555552d6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in free@plt ()
0x00005555555552d6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552d6  →  <main+333> mov rax, QWORD PTR [rbp-0xe0]
$r8    : 0x0000555555559a80  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552c7 <main+318>       mov    rax, QWORD PTR [rbp-0xe8]
   0x5555555552ce <main+325>       mov    rdi, rax
   0x5555555552d1 <main+328>       call   0x555555555070 <free@plt>
 → 0x5555555552d6 <main+333>       mov    rax, QWORD PTR [rbp-0xe0]
   0x5555555552dd <main+340>       mov    rdi, rax
   0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
   0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
   0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552d6 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x00005555555552dd in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552dd  →  <main+340> mov rdi, rax
$r8    : 0x0000555555559a80  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ce <main+325>       mov    rdi, rax
   0x5555555552d1 <main+328>       call   0x555555555070 <free@plt>
   0x5555555552d6 <main+333>       mov    rax, QWORD PTR [rbp-0xe0]
 → 0x5555555552dd <main+340>       mov    rdi, rax
   0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
   0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
   0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552dd in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552dd → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552e0 in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559ad0  →  0x0000000000000000
$rip   : 0x00005555555552e0  →  <main+343> call 0x555555555070 <free@plt>
$r8    : 0x0000555555559a80  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d1 <main+328>       call   0x555555555070 <free@plt>
   0x5555555552d6 <main+333>       mov    rax, QWORD PTR [rbp-0xe0]
   0x5555555552dd <main+340>       mov    rdi, rax
 → 0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>     endbr64 
      0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
      0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <__stack_chk_fail@plt+0> endbr64 
      0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
      0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559ad0 → 0x0000000000000000,
   $rsi = 0x0000555555559010 → 0x0007000000000000,
   $rdx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552e0 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec8  →  0x00005555555552e5  →  <main+348> mov rax, QWORD PTR [rbp-0xd8]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559ad0  →  0x0000000000000000
$rip   : 0x0000555555555070  →  <free@plt+0> endbr64 
$r8    : 0x0000555555559a80  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x00005555555552e5  →  <main+348> mov rax, QWORD PTR [rbp-0xd8]   ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0038: 0x00005555555592a0  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <__cxa_finalize@plt+0> endbr64 
   0x555555555064 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f8d]        # 0x555555557ff8
   0x55555555506b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <free@plt+0>     endbr64 
   0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555070 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → free@plt()
[#1] 0x5555555552e5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in free@plt ()
0x00005555555552e5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x55500000cf29    
$rdx   : 0x0000555555559a70  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552e5  →  <main+348> mov rax, QWORD PTR [rbp-0xd8]
$r8    : 0x0000555555559ad0  →  0x000055500000cf29
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d6 <main+333>       mov    rax, QWORD PTR [rbp-0xe0]
   0x5555555552dd <main+340>       mov    rdi, rax
   0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
 → 0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
   0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
   0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552e5 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559ad0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x00005555555552ec in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b20  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000cf29    
$rdx   : 0x0000555555559a70  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552ec  →  <main+355> mov rdi, rax
$r8    : 0x0000555555559ad0  →  0x000055500000cf29
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552dd <main+340>       mov    rdi, rax
   0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
   0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
 → 0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
   0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552ec in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ec → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552ef in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b20  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000cf29    
$rdx   : 0x0000555555559a70  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559b20  →  0x0000000000000000
$rip   : 0x00005555555552ef  →  <main+358> call 0x555555555070 <free@plt>
$r8    : 0x0000555555559ad0  →  0x000055500000cf29
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e0 <main+343>       call   0x555555555070 <free@plt>
   0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
   0x5555555552ec <main+355>       mov    rdi, rax
 → 0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>     endbr64 
      0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
      0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <__stack_chk_fail@plt+0> endbr64 
      0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
      0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559b20 → 0x0000000000000000,
   $rsi = 0x0000555555559010 → 0x0007000000000000,
   $rdx = 0x0000555555559a70 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552ef in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ef → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b20  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000cf29    
$rdx   : 0x0000555555559a70  →  0x0000000000000000
$rsp   : 0x00007fffffffdec8  →  0x00005555555552f4  →  <main+363> mov rax, QWORD PTR [rbp-0xd0]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559b20  →  0x0000000000000000
$rip   : 0x0000555555555070  →  <free@plt+0> endbr64 
$r8    : 0x0000555555559ad0  →  0x000055500000cf29
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x00005555555552f4  →  <main+363> mov rax, QWORD PTR [rbp-0xd0]   ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000000000000
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0038: 0x00005555555592a0  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <__cxa_finalize@plt+0> endbr64 
   0x555555555064 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f8d]        # 0x555555557ff8
   0x55555555506b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <free@plt+0>     endbr64 
   0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555070 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → free@plt()
[#1] 0x5555555552f4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in free@plt ()
0x00005555555552f4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552f4  →  <main+363> mov rax, QWORD PTR [rbp-0xd0]
$r8    : 0x0000555555559b20  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e5 <main+348>       mov    rax, QWORD PTR [rbp-0xd8]
   0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
 → 0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
   0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
   0x55555555530a <main+385>       mov    rdi, rax
   0x55555555530d <main+388>       call   0x555555555070 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552f4 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552f4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559ad0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x00005555555552fb in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x00005555555552fb  →  <main+370> mov rdi, rax
$r8    : 0x0000555555559b20  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ec <main+355>       mov    rdi, rax
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
 → 0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
   0x55555555530a <main+385>       mov    rdi, rax
   0x55555555530d <main+388>       call   0x555555555070 <free@plt>
   0x555555555312 <main+393>       mov    DWORD PTR [rbp-0xec], 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552fb in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552fb → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552fe in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559b80  →  0x0000000000000000
$rip   : 0x00005555555552fe  →  <main+373> call 0x555555555070 <free@plt>
$r8    : 0x0000555555559b20  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ef <main+358>       call   0x555555555070 <free@plt>
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
   0x5555555552fb <main+370>       mov    rdi, rax
 → 0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>     endbr64 
      0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
      0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <__stack_chk_fail@plt+0> endbr64 
      0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
      0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559b80 → 0x0000000000000000,
   $rsi = 0x0000555555559010 → 0x0007000000000000,
   $rdx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x5555555552fe in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552fe → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec8  →  0x0000555555555303  →  <main+378> mov rax, QWORD PTR [rbp-0xc8]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559b80  →  0x0000000000000000
$rip   : 0x0000555555555070  →  <free@plt+0> endbr64 
$r8    : 0x0000555555559b20  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x0000555555555303  →  <main+378> mov rax, QWORD PTR [rbp-0xc8]   ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x0000000000000000
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0038: 0x00005555555592a0  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <__cxa_finalize@plt+0> endbr64 
   0x555555555064 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f8d]        # 0x555555557ff8
   0x55555555506b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <free@plt+0>     endbr64 
   0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555070 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → free@plt()
[#1] 0x555555555303 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in free@plt ()
0x0000555555555303 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x55500000ce49    
$rdx   : 0x0000555555559b10  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x0000555555555303  →  <main+378> mov rax, QWORD PTR [rbp-0xc8]
$r8    : 0x0000555555559b80  →  0x000055500000ce49
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552f4 <main+363>       mov    rax, QWORD PTR [rbp-0xd0]
   0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
 → 0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
   0x55555555530a <main+385>       mov    rdi, rax
   0x55555555530d <main+388>       call   0x555555555070 <free@plt>
   0x555555555312 <main+393>       mov    DWORD PTR [rbp-0xec], 0x0
   0x55555555531c <main+403>       jmp    0x555555555376 <main+493>
   0x55555555531e <main+405>       mov    edi, 0x40
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555303 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555303 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559ad0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559b80, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x000055555555530a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559be0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000ce49    
$rdx   : 0x0000555555559b10  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x000055555555530a  →  <main+385> mov rdi, rax
$r8    : 0x0000555555559b80  →  0x000055500000ce49
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552fb <main+370>       mov    rdi, rax
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
 → 0x55555555530a <main+385>       mov    rdi, rax
   0x55555555530d <main+388>       call   0x555555555070 <free@plt>
   0x555555555312 <main+393>       mov    DWORD PTR [rbp-0xec], 0x0
   0x55555555531c <main+403>       jmp    0x555555555376 <main+493>
   0x55555555531e <main+405>       mov    edi, 0x40
   0x555555555323 <main+410>       call   0x555555555090 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x55555555530a in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555530a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055555555530d in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559be0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000ce49    
$rdx   : 0x0000555555559b10  →  0x0000000000000000
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559be0  →  0x0000000000000000
$rip   : 0x000055555555530d  →  <main+388> call 0x555555555070 <free@plt>
$r8    : 0x0000555555559b80  →  0x000055500000ce49
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552fe <main+373>       call   0x555555555070 <free@plt>
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
   0x55555555530a <main+385>       mov    rdi, rax
 → 0x55555555530d <main+388>       call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>     endbr64 
      0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
      0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <__stack_chk_fail@plt+0> endbr64 
      0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
      0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559be0 → 0x0000000000000000,
   $rsi = 0x0000555555559010 → 0x0007000000000000,
   $rdx = 0x0000555555559b10 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x55555555530d in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555530d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559be0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x55500000ce49    
$rdx   : 0x0000555555559b10  →  0x0000000000000000
$rsp   : 0x00007fffffffdec8  →  0x0000555555555312  →  <main+393> mov DWORD PTR [rbp-0xec], 0x0
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x0000555555559be0  →  0x0000000000000000
$rip   : 0x0000555555555070  →  <free@plt+0> endbr64 
$r8    : 0x0000555555559b80  →  0x000055500000ce49
$r9    : 0x0000555555559be0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x0000555555555312  →  <main+393> mov DWORD PTR [rbp-0xec], 0x0   ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000000000000
0x00007fffffffdf00│+0x0038: 0x00005555555592a0  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <__cxa_finalize@plt+0> endbr64 
   0x555555555064 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f8d]        # 0x555555557ff8
   0x55555555506b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <free@plt+0>     endbr64 
   0x555555555074 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f45]        # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555070 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → free@plt()
[#1] 0x555555555312 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in free@plt ()
0x0000555555555312 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x555555559       
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0007000000000000
$rdi   : 0x7               
$rip   : 0x0000555555555312  →  <main+393> mov DWORD PTR [rbp-0xec], 0x0
$r8    : 0x0000555555559be0  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000555555559
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdf08│+0x0038: 0x00005555555593c0  →  0x000055500000c7f9
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555303 <main+378>       mov    rax, QWORD PTR [rbp-0xc8]
   0x55555555530a <main+385>       mov    rdi, rax
   0x55555555530d <main+388>       call   0x555555555070 <free@plt>
 → 0x555555555312 <main+393>       mov    DWORD PTR [rbp-0xec], 0x0
   0x55555555531c <main+403>       jmp    0x555555555376 <main+493>
   0x55555555531e <main+405>       mov    edi, 0x40
   0x555555555323 <main+410>       call   0x555555555090 <malloc@plt>
   0x555555555328 <main+415>       mov    rdx, rax
   0x55555555532b <main+418>       mov    eax, DWORD PTR [rbp-0xec]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555312 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555312 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559ad0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559b80, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559be0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  p main_arena
$2 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x1,
  fastbinsY = {0x0, 0x0, 0x0, 0x555555559ac0, 0x555555559b70, 0x555555559bd0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559c40,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  x/10g 0x555555559ac0
0x555555559ac0:   0x0   0x51
0x555555559ad0:   0x55500000cf29 0x0
0x555555559ae0:   0x0   0x0
0x555555559af0:   0x0   0x0
0x555555559b00:   0x0   0x0
gef➤  x/10g 0x555555559b70
0x555555559b70:   0x0   0x61
0x555555559b80:   0x55500000ce49 0x0
0x555555559b90:   0x0   0x0
0x555555559ba0:   0x0   0x0
0x555555559bb0:   0x0   0x0
gef➤  x/10g 0x555555559bd0
0x555555559bd0:   0x0   0x71
0x555555559be0:   0x555555559 0x0
0x555555559bf0:   0x0   0x0
0x555555559c00:   0x0   0x0
0x555555559c10:   0x0   0x0
```

So starting off, we see the tcache was full.  Then we see, one by one, the chunks being inserted into the fastbins. There are a total of five separate chunks inserted into three separate fastbins (one has 2, another has 2, the last has 1). We also see the fastbin heads being set in the main arena.

Also, this was the ptr demangling for that:
```
>>> hex((0x555555559ad0 >> 12) ^ 0x55500000cf29)
'0x555555559a70'
>>> hex((0x555555559b80 >> 12) ^ 0x55500000ce49)
'0x555555559b10'
>>> hex((0x555555559be0 >> 12) ^ 0x555555559)
'0x0'
```

next up, let's see allocation from the fastbins:

```
gef➤  c
Continuing.

Breakpoint 2, 0x0000555555555384 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0000555555559350  →  0x0000000555555559
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x40              
$rip   : 0x0000555555555384  →  <main+507> call 0x555555555090 <malloc@plt>
$r8    : 0x0000555555559be0  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000555555559
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555376 <main+493>       cmp    DWORD PTR [rbp-0xec], 0x6
   0x55555555537d <main+500>       jle    0x55555555531e <main+405>
   0x55555555537f <main+502>       mov    edi, 0x40
 → 0x555555555384 <main+507>       call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64 
      0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550a0 <_start+0>       endbr64 
      0x5555555550a4 <_start+4>       xor    ebp, ebp
      0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000040
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555384 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555384 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50]  ←  Chunk(addr=0x555555559ad0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559b80, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559be0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x0000555555555090 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0000555555559350  →  0x0000000555555559
$rsp   : 0x00007fffffffdec8  →  0x0000555555555389  →  <main+512> mov edi, 0x50
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x40              
$rip   : 0x0000555555555090  →  <malloc@plt+0> endbr64 
$r8    : 0x0000555555559be0  →  0x0000000555555559
$r9    : 0x0000555555559be0  →  0x0000000555555559
$r10   : 0xfffffffffffff000
$r11   : 0x7701cec17a72053f
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x0000555555555389  →  <main+512> mov edi, 0x50    ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0038: 0x0000555555559960  →  0x000055500000cd19
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <malloc@plt+0>   endbr64 
   0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>       endbr64 
   0x5555555550a4 <_start+4>       xor    ebp, ebp
   0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555090 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → malloc@plt()
[#1] 0x555555555389 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in malloc@plt ()
0x0000555555555389 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x000055500000cf29
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19ca8  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c98  →  0x0000000000000000
$rip   : 0x0000555555555389  →  <main+512> mov edi, 0x50
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559ad0  →  0x000055500000cf29
$r10   : 0x0000555555559a80  →  0x0000000555555559
$r11   : 0x3               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555537d <main+500>       jle    0x55555555531e <main+405>
   0x55555555537f <main+502>       mov    edi, 0x40
   0x555555555384 <main+507>       call   0x555555555090 <malloc@plt>
 → 0x555555555389 <main+512>       mov    edi, 0x50
   0x55555555538e <main+517>       call   0x555555555090 <malloc@plt>
   0x555555555393 <main+522>       mov    edi, 0x60
   0x555555555398 <main+527>       call   0x555555555090 <malloc@plt>
   0x55555555539d <main+532>       nop    
   0x55555555539e <main+533>       mov    rax, QWORD PTR [rbp-0x8]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555389 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555389 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=1] ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559b80, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559be0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x000055555555538e in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x000055500000cf29
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19ca8  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x50              
$rip   : 0x000055555555538e  →  <main+517> call 0x555555555090 <malloc@plt>
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559ad0  →  0x000055500000cf29
$r10   : 0x0000555555559a80  →  0x0000000555555559
$r11   : 0x3               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555537f <main+502>       mov    edi, 0x40
   0x555555555384 <main+507>       call   0x555555555090 <malloc@plt>
   0x555555555389 <main+512>       mov    edi, 0x50
 → 0x55555555538e <main+517>       call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64 
      0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550a0 <_start+0>       endbr64 
      0x5555555550a4 <_start+4>       xor    ebp, ebp
      0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000050
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x55555555538e in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555538e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555090 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ad0  →  0x000055500000cf29
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19ca8  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec8  →  0x0000555555555393  →  <main+522> mov edi, 0x60
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x50              
$rip   : 0x0000555555555090  →  <malloc@plt+0> endbr64 
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559ad0  →  0x000055500000cf29
$r10   : 0x0000555555559a80  →  0x0000000555555559
$r11   : 0x3               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x0000555555555393  →  <main+522> mov edi, 0x60    ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0038: 0x0000555555559960  →  0x000055500000cd19
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <malloc@plt+0>   endbr64 
   0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>       endbr64 
   0x5555555550a4 <_start+4>       xor    ebp, ebp
   0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555090 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → malloc@plt()
[#1] 0x555555555393 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in malloc@plt ()
0x0000555555555393 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x000055500000ce49
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19cb0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19ca0  →  0x0000000000000000
$rip   : 0x0000555555555393  →  <main+522> mov edi, 0x60
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559b80  →  0x000055500000ce49
$r10   : 0x0000555555559b20  →  0x0000000555555559
$r11   : 0x4               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555384 <main+507>       call   0x555555555090 <malloc@plt>
   0x555555555389 <main+512>       mov    edi, 0x50
   0x55555555538e <main+517>       call   0x555555555090 <malloc@plt>
 → 0x555555555393 <main+522>       mov    edi, 0x60
   0x555555555398 <main+527>       call   0x555555555090 <malloc@plt>
   0x55555555539d <main+532>       nop    
   0x55555555539e <main+533>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555553a2 <main+537>       sub    rax, QWORD PTR fs:0x28
   0x5555555553ab <main+546>       je     0x5555555553b2 <main+553>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555393 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555393 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=1] ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=1] ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559be0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x0000555555555398 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x000055500000ce49
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19cb0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x60              
$rip   : 0x0000555555555398  →  <main+527> call 0x555555555090 <malloc@plt>
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559b80  →  0x000055500000ce49
$r10   : 0x0000555555559b20  →  0x0000000555555559
$r11   : 0x4               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555389 <main+512>       mov    edi, 0x50
   0x55555555538e <main+517>       call   0x555555555090 <malloc@plt>
   0x555555555393 <main+522>       mov    edi, 0x60
 → 0x555555555398 <main+527>       call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64 
      0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550a0 <_start+0>       endbr64 
      0x5555555550a4 <_start+4>       xor    ebp, ebp
      0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000060
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555398 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555398 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555090 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559b80  →  0x000055500000ce49
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19cb0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdec8  →  0x000055555555539d  →  <main+532> nop 
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x60              
$rip   : 0x0000555555555090  →  <malloc@plt+0> endbr64 
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559b80  →  0x000055500000ce49
$r10   : 0x0000555555559b20  →  0x0000000555555559
$r11   : 0x4               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdec8│+0x0000: 0x000055555555539d  →  <main+532> nop     ← $rsp
0x00007fffffffded0│+0x0008: 0x00000007ffffffff
0x00007fffffffded8│+0x0010: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0018: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0020: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0028: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0030: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0038: 0x0000555555559960  →  0x000055500000cd19
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__stack_chk_fail@plt+0> endbr64 
   0x555555555084 <__stack_chk_fail@plt+4> bnd    jmp QWORD PTR [rip+0x2f3d]        # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <malloc@plt+0>   endbr64 
   0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>       endbr64 
   0x5555555550a4 <_start+4>       xor    ebp, ebp
   0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x555555555090 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → malloc@plt()
[#1] 0x55555555539d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in malloc@plt ()
0x000055555555539d in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559be0  →  0x0000000555555559
$rbx   : 0x0               
$rcx   : 0x00007ffff7e19cb8  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffded0  →  0x00000007ffffffff
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19ca8  →  0x0000000000000000
$rip   : 0x000055555555539d  →  <main+532> nop 
$r8    : 0x0000555555559010  →  0x0001000000000000
$r9    : 0x0000555555559be0  →  0x0000000555555559
$r10   : 0x0000555555559b20  →  0x0000000555555559
$r11   : 0x5               
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/heap_demos/fastbin/fastbi[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffded0│+0x0000: 0x00000007ffffffff   ← $rsp
0x00007fffffffded8│+0x0008: 0x0000555555559a80  →  0x0000000555555559
0x00007fffffffdee0│+0x0010: 0x0000555555559ad0  →  0x000055500000cf29
0x00007fffffffdee8│+0x0018: 0x0000555555559b20  →  0x0000000555555559
0x00007fffffffdef0│+0x0020: 0x0000555555559b80  →  0x000055500000ce49
0x00007fffffffdef8│+0x0028: 0x0000555555559be0  →  0x0000000555555559
0x00007fffffffdf00│+0x0030: 0x0000555555559960  →  0x000055500000cd19
0x00007fffffffdf08│+0x0038: 0x0000555555559840  →  0x000055500000c279
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555538e <main+517>       call   0x555555555090 <malloc@plt>
   0x555555555393 <main+522>       mov    edi, 0x60
   0x555555555398 <main+527>       call   0x555555555090 <malloc@plt>
 → 0x55555555539d <main+532>       nop    
   0x55555555539e <main+533>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555553a2 <main+537>       sub    rax, QWORD PTR fs:0x28
   0x5555555553ab <main+546>       je     0x5555555553b2 <main+553>
   0x5555555553ad <main+548>       call   0x555555555080 <__stack_chk_fail@plt>
   0x5555555553b2 <main+553>       leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_basic", stopped 0x55555555539d in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555539d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=1] ←  Chunk(addr=0x555555559a80, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=4, size=0x60, count=1] ←  Chunk(addr=0x555555559b20, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
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
[Inferior 1 (process 5724) exited normally]
```

So, we see a chunk from each of the fastbins being allocated. With the first two fastbins which had a chunk after the allocation, since the corresponding tcache bins had empty spots, that remaining chunk got moved over to the tcache from the fastbin.

With that, we've seen insertions into, and allocations from some fastbins.
