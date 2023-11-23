## Consolidation

So the purpose of this demo is to show how malloc can consolidate two adjacent chunks that are freed. It can consolidate backwards (consolidate a chunk with the previous adjacent chunk) or consolidate forwards (consolidate a chunk with the next adjacent chunk). This can occur when a new chunk is freed, and either the previous or next chunk has already been freed. This will be done with this source code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420

void main() {
    char *chunk0,
   	 *chunk1,
   	 *chunk2,
   	 *chunk3,
   	 *chunk4,
   	 *chunk5;

    chunk0 = malloc(CHUNK_SIZE);
    chunk1 = malloc(CHUNK_SIZE);
    chunk2 = malloc(CHUNK_SIZE);
    chunk3 = malloc(CHUNK_SIZE);
    chunk4 = malloc(CHUNK_SIZE);
    chunk5 = malloc(CHUNK_SIZE);

    // Free chunks for backwards consolidation
    free(chunk0);
    free(chunk1);

    // Free chunks for forwards consolidation
    free(chunk4);
    free(chunk3);
}
```

So, we will allocate six separate chunks. The final chunk (`chunk5`) will not be freed, to have an in use allocated chunk between the rest of the chunks and the top chunk. This will prevent consolidation with the top chunk.

We will free chunks `0`, and then `1`, to cause backwards consolidation of `chunk1` into `chunk0`. We will leave `chunk2` allocated to prevent consolidation with chunks `0/1` with `3/4`.

Then, we will free `chunk4`, then free `chunk3` to consolidate `chunk3` into `chunk4` to cause forward consolidation.

Also, the reason why I have the request size be `0x420` (which leads to a chunk size of `0x430`) is to prevent the freed chunks from being inserted into the tcache / fast bin / etc.

#### Consolidation Walkthrough

So first off, let's break on the first `free` call, and see `chunk0` getting freed and inserted into the unsorted bin:

```
$  gdb ./consolidation 
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
Reading symbols from ./consolidation...
(No debugging symbols found in ./consolidation)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:   endbr64 
   0x000000000000116d <+4>:   push   rbp
   0x000000000000116e <+5>:   mov    rbp,rsp
   0x0000000000001171 <+8>:   sub    rsp,0x30
   0x0000000000001175 <+12>:  mov    edi,0x420
   0x000000000000117a <+17>:  call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:  mov    QWORD PTR [rbp-0x30],rax
   0x0000000000001183 <+26>:  mov    edi,0x420
   0x0000000000001188 <+31>:  call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:  mov    QWORD PTR [rbp-0x28],rax
   0x0000000000001191 <+40>:  mov    edi,0x420
   0x0000000000001196 <+45>:  call   0x1070 <malloc@plt>
   0x000000000000119b <+50>:  mov    QWORD PTR [rbp-0x20],rax
   0x000000000000119f <+54>:  mov    edi,0x420
   0x00000000000011a4 <+59>:  call   0x1070 <malloc@plt>
   0x00000000000011a9 <+64>:  mov    QWORD PTR [rbp-0x18],rax
   0x00000000000011ad <+68>:  mov    edi,0x420
   0x00000000000011b2 <+73>:  call   0x1070 <malloc@plt>
   0x00000000000011b7 <+78>:  mov    QWORD PTR [rbp-0x10],rax
   0x00000000000011bb <+82>:  mov    edi,0x420
   0x00000000000011c0 <+87>:  call   0x1070 <malloc@plt>
   0x00000000000011c5 <+92>:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011c9 <+96>:  mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000011cd <+100>: mov    rdi,rax
   0x00000000000011d0 <+103>: call   0x1060 <free@plt>
   0x00000000000011d5 <+108>: mov    rax,QWORD PTR [rbp-0x28]
   0x00000000000011d9 <+112>: mov    rdi,rax
   0x00000000000011dc <+115>: call   0x1060 <free@plt>
   0x00000000000011e1 <+120>: mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011e5 <+124>: mov    rdi,rax
   0x00000000000011e8 <+127>: call   0x1060 <free@plt>
   0x00000000000011ed <+132>: mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011f1 <+136>: mov    rdi,rax
   0x00000000000011f4 <+139>: call   0x1060 <free@plt>
   0x00000000000011f9 <+144>: nop
   0x00000000000011fa <+145>: leave  
   0x00000000000011fb <+146>: ret    
End of assembler dump.
gef➤  b *main+103
Breakpoint 1 at 0x11d0
gef➤  r
Starting program: /Hackery/shogun/heap_demos/malloc/consolidation/consolidation 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00005555555551d0 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x00005555555551d0  →  <main+103> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c5 <main+92>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551c9 <main+96>        mov    rax, QWORD PTR [rbp-0x30]
   0x5555555551cd <main+100>       mov    rdi, rax
 → 0x5555555551d0 <main+103>       call   0x555555555060 <free@plt>
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
[#0] Id 1, Name: "consolidation", stopped 0x5555555551d0 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d0 → main()
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
gef➤  p $rax
$1 = 0x5555555592a0
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x431
0x5555555592a0:   0x0   0x0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x0
0x555555559360:   0x0   0x0
0x555555559370:   0x0   0x0
0x555555559380:   0x0   0x0
0x555555559390:   0x0   0x0
0x5555555593a0:   0x0   0x0
0x5555555593b0:   0x0   0x0
0x5555555593c0:   0x0   0x0
0x5555555593d0:   0x0   0x0
0x5555555593e0:   0x0   0x0
0x5555555593f0:   0x0   0x0
0x555555559400:   0x0   0x0
0x555555559410:   0x0   0x0
0x555555559420:   0x0   0x0
0x555555559430:   0x0   0x0
0x555555559440:   0x0   0x0
0x555555559450:   0x0   0x0
0x555555559460:   0x0   0x0
0x555555559470:   0x0   0x0
0x555555559480:   0x0   0x0
0x555555559490:   0x0   0x0
0x5555555594a0:   0x0   0x0
0x5555555594b0:   0x0   0x0
0x5555555594c0:   0x0   0x0
0x5555555594d0:   0x0   0x0
0x5555555594e0:   0x0   0x0
0x5555555594f0:   0x0   0x0
0x555555559500:   0x0   0x0
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
0x555555559540:   0x0   0x0
0x555555559550:   0x0   0x0
0x555555559560:   0x0   0x0
0x555555559570:   0x0   0x0
0x555555559580:   0x0   0x0
0x555555559590:   0x0   0x0
0x5555555595a0:   0x0   0x0
0x5555555595b0:   0x0   0x0
0x5555555595c0:   0x0   0x0
0x5555555595d0:   0x0   0x0
0x5555555595e0:   0x0   0x0
0x5555555595f0:   0x0   0x0
0x555555559600:   0x0   0x0
0x555555559610:   0x0   0x0
0x555555559620:   0x0   0x0
0x555555559630:   0x0   0x0
0x555555559640:   0x0   0x0
0x555555559650:   0x0   0x0
0x555555559660:   0x0   0x0
0x555555559670:   0x0   0x0
0x555555559680:   0x0   0x0
0x555555559690:   0x0   0x0
0x5555555596a0:   0x0   0x0
0x5555555596b0:   0x0   0x0
0x5555555596c0:   0x0   0x431
0x5555555596d0:   0x0   0x0
0x5555555596e0:   0x0   0x0
0x5555555596f0:   0x0   0x0
0x555555559700:   0x0   0x0
0x555555559710:   0x0   0x0
0x555555559720:   0x0   0x0
0x555555559730:   0x0   0x0
0x555555559740:   0x0   0x0
0x555555559750:   0x0   0x0
0x555555559760:   0x0   0x0
0x555555559770:   0x0   0x0
0x555555559780:   0x0   0x0
0x555555559790:   0x0   0x0
0x5555555597a0:   0x0   0x0
0x5555555597b0:   0x0   0x0
0x5555555597c0:   0x0   0x0
0x5555555597d0:   0x0   0x0
0x5555555597e0:   0x0   0x0
0x5555555597f0:   0x0   0x0
0x555555559800:   0x0   0x0
0x555555559810:   0x0   0x0
0x555555559820:   0x0   0x0
0x555555559830:   0x0   0x0
0x555555559840:   0x0   0x0
0x555555559850:   0x0   0x0
0x555555559860:   0x0   0x0
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf88  →  0x00005555555551d5  →  <main+108> mov rax, QWORD PTR [rbp-0x28]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf88│+0x0000: 0x00005555555551d5  →  <main+108> mov rax, QWORD PTR [rbp-0x28]   ← $rsp
0x00007fffffffdf90│+0x0008: 0x00005555555592a0  →  0x0000000000000000
0x00007fffffffdf98│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0018: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0020: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0028: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0030: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0038: 0x0000000000000001   ← $rbp
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551d5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x00005555555551d5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551d5  →  <main+108> mov rax, QWORD PTR [rbp-0x28]
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c9 <main+96>        mov    rax, QWORD PTR [rbp-0x30]
   0x5555555551cd <main+100>       mov    rdi, rax
   0x5555555551d0 <main+103>       call   0x555555555060 <free@plt>
 → 0x5555555551d5 <main+108>       mov    rax, QWORD PTR [rbp-0x28]
   0x5555555551d9 <main+112>       mov    rdi, rax
   0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551d5 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x431
0x5555555592a0:   0x7ffff7e19ce0 0x7ffff7e19ce0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x0
0x555555559360:   0x0   0x0
0x555555559370:   0x0   0x0
0x555555559380:   0x0   0x0
0x555555559390:   0x0   0x0
0x5555555593a0:   0x0   0x0
0x5555555593b0:   0x0   0x0
0x5555555593c0:   0x0   0x0
0x5555555593d0:   0x0   0x0
0x5555555593e0:   0x0   0x0
0x5555555593f0:   0x0   0x0
0x555555559400:   0x0   0x0
0x555555559410:   0x0   0x0
0x555555559420:   0x0   0x0
0x555555559430:   0x0   0x0
0x555555559440:   0x0   0x0
0x555555559450:   0x0   0x0
0x555555559460:   0x0   0x0
0x555555559470:   0x0   0x0
0x555555559480:   0x0   0x0
0x555555559490:   0x0   0x0
0x5555555594a0:   0x0   0x0
0x5555555594b0:   0x0   0x0
0x5555555594c0:   0x0   0x0
0x5555555594d0:   0x0   0x0
0x5555555594e0:   0x0   0x0
0x5555555594f0:   0x0   0x0
0x555555559500:   0x0   0x0
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
0x555555559540:   0x0   0x0
0x555555559550:   0x0   0x0
0x555555559560:   0x0   0x0
0x555555559570:   0x0   0x0
0x555555559580:   0x0   0x0
0x555555559590:   0x0   0x0
0x5555555595a0:   0x0   0x0
0x5555555595b0:   0x0   0x0
0x5555555595c0:   0x0   0x0
0x5555555595d0:   0x0   0x0
0x5555555595e0:   0x0   0x0
0x5555555595f0:   0x0   0x0
0x555555559600:   0x0   0x0
0x555555559610:   0x0   0x0
0x555555559620:   0x0   0x0
0x555555559630:   0x0   0x0
0x555555559640:   0x0   0x0
0x555555559650:   0x0   0x0
0x555555559660:   0x0   0x0
0x555555559670:   0x0   0x0
0x555555559680:   0x0   0x0
0x555555559690:   0x0   0x0
0x5555555596a0:   0x0   0x0
0x5555555596b0:   0x0   0x0
0x5555555596c0:   0x430 0x430
0x5555555596d0:   0x0   0x0
0x5555555596e0:   0x0   0x0
0x5555555596f0:   0x0   0x0
0x555555559700:   0x0   0x0
0x555555559710:   0x0   0x0
0x555555559720:   0x0   0x0
0x555555559730:   0x0   0x0
0x555555559740:   0x0   0x0
0x555555559750:   0x0   0x0
0x555555559760:   0x0   0x0
0x555555559770:   0x0   0x0
0x555555559780:   0x0   0x0
0x555555559790:   0x0   0x0
0x5555555597a0:   0x0   0x0
0x5555555597b0:   0x0   0x0
0x5555555597c0:   0x0   0x0
0x5555555597d0:   0x0   0x0
0x5555555597e0:   0x0   0x0
0x5555555597f0:   0x0   0x0
0x555555559800:   0x0   0x0
0x555555559810:   0x0   0x0
0x555555559820:   0x0   0x0
0x555555559830:   0x0   0x0
0x555555559840:   0x0   0x0
0x555555559850:   0x0   0x0
0x555555559860:   0x0   0x0
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
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
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see the `0x5555555592a0` chunk getting freed, and inserted into the unsorted bin. We see the chunk's size is `0x430`. Now we will free the next adjacent chunk `chunk1`. Since the previous chunk has already been freed (and is in either the unsorted/small/large bin), it will backwards consolidate it into the `0x5555555592a0`. After this, the chunk size should be `0x860`, and the unsorted bin should have one chunk in it, it being the `0x5555555592a0` chunk:

```
gef➤  si
0x00005555555551d9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551d9  →  <main+112> mov rdi, rax
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551cd <main+100>       mov    rdi, rax
   0x5555555551d0 <main+103>       call   0x555555555060 <free@plt>
   0x5555555551d5 <main+108>       mov    rax, QWORD PTR [rbp-0x28]
 → 0x5555555551d9 <main+112>       mov    rdi, rax
   0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551d9 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551dc in main ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00005555555596d0  →  0x0000000000000000
$rip   : 0x00005555555551dc  →  <main+115> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551d0 <main+103>       call   0x555555555060 <free@plt>
   0x5555555551d5 <main+108>       mov    rax, QWORD PTR [rbp-0x28]
   0x5555555551d9 <main+112>       mov    rdi, rax
 → 0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555596d0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551dc in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551dc → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf88  →  0x00005555555551e1  →  <main+120> mov rax, QWORD PTR [rbp-0x10]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00005555555596d0  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf88│+0x0000: 0x00005555555551e1  →  <main+120> mov rax, QWORD PTR [rbp-0x10]   ← $rsp
0x00007fffffffdf90│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
0x00007fffffffdf98│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0018: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0020: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0028: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0030: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0038: 0x0000000000000001   ← $rbp
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551e1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x431
0x5555555592a0:   0x7ffff7e19ce0 0x7ffff7e19ce0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x0
0x555555559360:   0x0   0x0
0x555555559370:   0x0   0x0
0x555555559380:   0x0   0x0
0x555555559390:   0x0   0x0
0x5555555593a0:   0x0   0x0
0x5555555593b0:   0x0   0x0
0x5555555593c0:   0x0   0x0
0x5555555593d0:   0x0   0x0
0x5555555593e0:   0x0   0x0
0x5555555593f0:   0x0   0x0
0x555555559400:   0x0   0x0
0x555555559410:   0x0   0x0
0x555555559420:   0x0   0x0
0x555555559430:   0x0   0x0
0x555555559440:   0x0   0x0
0x555555559450:   0x0   0x0
0x555555559460:   0x0   0x0
0x555555559470:   0x0   0x0
0x555555559480:   0x0   0x0
0x555555559490:   0x0   0x0
0x5555555594a0:   0x0   0x0
0x5555555594b0:   0x0   0x0
0x5555555594c0:   0x0   0x0
0x5555555594d0:   0x0   0x0
0x5555555594e0:   0x0   0x0
0x5555555594f0:   0x0   0x0
0x555555559500:   0x0   0x0
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
0x555555559540:   0x0   0x0
0x555555559550:   0x0   0x0
0x555555559560:   0x0   0x0
0x555555559570:   0x0   0x0
0x555555559580:   0x0   0x0
0x555555559590:   0x0   0x0
0x5555555595a0:   0x0   0x0
0x5555555595b0:   0x0   0x0
0x5555555595c0:   0x0   0x0
0x5555555595d0:   0x0   0x0
0x5555555595e0:   0x0   0x0
0x5555555595f0:   0x0   0x0
0x555555559600:   0x0   0x0
0x555555559610:   0x0   0x0
0x555555559620:   0x0   0x0
0x555555559630:   0x0   0x0
0x555555559640:   0x0   0x0
0x555555559650:   0x0   0x0
0x555555559660:   0x0   0x0
0x555555559670:   0x0   0x0
0x555555559680:   0x0   0x0
0x555555559690:   0x0   0x0
0x5555555596a0:   0x0   0x0
0x5555555596b0:   0x0   0x0
0x5555555596c0:   0x430 0x430
0x5555555596d0:   0x0   0x0
0x5555555596e0:   0x0   0x0
0x5555555596f0:   0x0   0x0
0x555555559700:   0x0   0x0
0x555555559710:   0x0   0x0
0x555555559720:   0x0   0x0
0x555555559730:   0x0   0x0
0x555555559740:   0x0   0x0
0x555555559750:   0x0   0x0
0x555555559760:   0x0   0x0
0x555555559770:   0x0   0x0
0x555555559780:   0x0   0x0
0x555555559790:   0x0   0x0
0x5555555597a0:   0x0   0x0
0x5555555597b0:   0x0   0x0
0x5555555597c0:   0x0   0x0
0x5555555597d0:   0x0   0x0
0x5555555597e0:   0x0   0x0
0x5555555597f0:   0x0   0x0
0x555555559800:   0x0   0x0
0x555555559810:   0x0   0x0
0x555555559820:   0x0   0x0
0x555555559830:   0x0   0x0
0x555555559840:   0x0   0x0
0x555555559850:   0x0   0x0
0x555555559860:   0x0   0x0
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
gef➤  si
0x0000555555555064 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf88  →  0x00005555555551e1  →  <main+120> mov rax, QWORD PTR [rbp-0x10]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00005555555596d0  →  0x0000000000000000
$rip   : 0x0000555555555064  →  <free@plt+4> bnd jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf88│+0x0000: 0x00005555555551e1  →  <main+120> mov rax, QWORD PTR [rbp-0x10]   ← $rsp
0x00007fffffffdf90│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
0x00007fffffffdf98│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0018: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0020: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0028: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0030: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0038: 0x0000000000000001   ← $rbp
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555060 <free@plt+0>     endbr64 
 → 0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>       endbr64 
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x555555555064 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555064 → free@plt()
[#1] 0x5555555551e1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555064 in free@plt ()
0x00005555555551e1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x0000555555559290  →  0x0000000000000000
$rip   : 0x00005555555551e1  →  <main+120> mov rax, QWORD PTR [rbp-0x10]
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551d5 <main+108>       mov    rax, QWORD PTR [rbp-0x28]
   0x5555555551d9 <main+112>       mov    rdi, rax
   0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
 → 0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551e1 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551e1 → main()
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
 →   Chunk(addr=0x5555555592a0, size=0x860, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x861
0x5555555592a0:   0x7ffff7e19ce0 0x7ffff7e19ce0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x0
0x555555559360:   0x0   0x0
0x555555559370:   0x0   0x0
0x555555559380:   0x0   0x0
0x555555559390:   0x0   0x0
0x5555555593a0:   0x0   0x0
0x5555555593b0:   0x0   0x0
0x5555555593c0:   0x0   0x0
0x5555555593d0:   0x0   0x0
0x5555555593e0:   0x0   0x0
0x5555555593f0:   0x0   0x0
0x555555559400:   0x0   0x0
0x555555559410:   0x0   0x0
0x555555559420:   0x0   0x0
0x555555559430:   0x0   0x0
0x555555559440:   0x0   0x0
0x555555559450:   0x0   0x0
0x555555559460:   0x0   0x0
0x555555559470:   0x0   0x0
0x555555559480:   0x0   0x0
0x555555559490:   0x0   0x0
0x5555555594a0:   0x0   0x0
0x5555555594b0:   0x0   0x0
0x5555555594c0:   0x0   0x0
0x5555555594d0:   0x0   0x0
0x5555555594e0:   0x0   0x0
0x5555555594f0:   0x0   0x0
0x555555559500:   0x0   0x0
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
0x555555559540:   0x0   0x0
0x555555559550:   0x0   0x0
0x555555559560:   0x0   0x0
0x555555559570:   0x0   0x0
0x555555559580:   0x0   0x0
0x555555559590:   0x0   0x0
0x5555555595a0:   0x0   0x0
0x5555555595b0:   0x0   0x0
0x5555555595c0:   0x0   0x0
0x5555555595d0:   0x0   0x0
0x5555555595e0:   0x0   0x0
0x5555555595f0:   0x0   0x0
0x555555559600:   0x0   0x0
0x555555559610:   0x0   0x0
0x555555559620:   0x0   0x0
0x555555559630:   0x0   0x0
0x555555559640:   0x0   0x0
0x555555559650:   0x0   0x0
0x555555559660:   0x0   0x0
0x555555559670:   0x0   0x0
0x555555559680:   0x0   0x0
0x555555559690:   0x0   0x0
0x5555555596a0:   0x0   0x0
0x5555555596b0:   0x0   0x0
0x5555555596c0:   0x430 0x430
0x5555555596d0:   0x0   0x0
0x5555555596e0:   0x0   0x0
0x5555555596f0:   0x0   0x0
0x555555559700:   0x0   0x0
0x555555559710:   0x0   0x0
0x555555559720:   0x0   0x0
0x555555559730:   0x0   0x0
0x555555559740:   0x0   0x0
0x555555559750:   0x0   0x0
0x555555559760:   0x0   0x0
0x555555559770:   0x0   0x0
0x555555559780:   0x0   0x0
0x555555559790:   0x0   0x0
0x5555555597a0:   0x0   0x0
0x5555555597b0:   0x0   0x0
0x5555555597c0:   0x0   0x0
0x5555555597d0:   0x0   0x0
0x5555555597e0:   0x0   0x0
0x5555555597f0:   0x0   0x0
0x555555559800:   0x0   0x0
0x555555559810:   0x0   0x0
0x555555559820:   0x0   0x0
0x555555559830:   0x0   0x0
0x555555559840:   0x0   0x0
0x555555559850:   0x0   0x0
0x555555559860:   0x0   0x0
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
```

So, we see that `chunk1` (`0x5555555596d0`) got consolidated into `chunk0` (`0x5555555592a0`), to form one massive chunk of size `0x860`. Also that this is the only chunk in the unsorted bin. Now we will go ahead and free `chunk4` (`0x55555555a360`):

```
gef➤  si
0x00005555555551e5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x0000555555559290  →  0x0000000000000000
$rip   : 0x00005555555551e5  →  <main+124> mov rdi, rax
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551d9 <main+112>       mov    rdi, rax
   0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
 → 0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
   0x5555555551f9 <main+144>       nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551e5 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551e5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551e8 in main ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x000055555555a360  →  0x0000000000000000
$rip   : 0x00005555555551e8  →  <main+127> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551dc <main+115>       call   0x555555555060 <free@plt>
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
 → 0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
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
[#0] Id 1, Name: "consolidation", stopped 0x5555555551e8 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551e8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x000055555555a350
0x55555555a350:   0x0   0x431
0x55555555a360:   0x0   0x0
0x55555555a370:   0x0   0x0
0x55555555a380:   0x0   0x0
0x55555555a390:   0x0   0x0
0x55555555a3a0:   0x0   0x0
0x55555555a3b0:   0x0   0x0
0x55555555a3c0:   0x0   0x0
0x55555555a3d0:   0x0   0x0
0x55555555a3e0:   0x0   0x0
0x55555555a3f0:   0x0   0x0
0x55555555a400:   0x0   0x0
0x55555555a410:   0x0   0x0
0x55555555a420:   0x0   0x0
0x55555555a430:   0x0   0x0
0x55555555a440:   0x0   0x0
0x55555555a450:   0x0   0x0
0x55555555a460:   0x0   0x0
0x55555555a470:   0x0   0x0
0x55555555a480:   0x0   0x0
0x55555555a490:   0x0   0x0
0x55555555a4a0:   0x0   0x0
0x55555555a4b0:   0x0   0x0
0x55555555a4c0:   0x0   0x0
0x55555555a4d0:   0x0   0x0
0x55555555a4e0:   0x0   0x0
0x55555555a4f0:   0x0   0x0
0x55555555a500:   0x0   0x0
0x55555555a510:   0x0   0x0
0x55555555a520:   0x0   0x0
0x55555555a530:   0x0   0x0
0x55555555a540:   0x0   0x0
0x55555555a550:   0x0   0x0
0x55555555a560:   0x0   0x0
0x55555555a570:   0x0   0x0
0x55555555a580:   0x0   0x0
0x55555555a590:   0x0   0x0
0x55555555a5a0:   0x0   0x0
0x55555555a5b0:   0x0   0x0
0x55555555a5c0:   0x0   0x0
0x55555555a5d0:   0x0   0x0
0x55555555a5e0:   0x0   0x0
0x55555555a5f0:   0x0   0x0
0x55555555a600:   0x0   0x0
0x55555555a610:   0x0   0x0
0x55555555a620:   0x0   0x0
0x55555555a630:   0x0   0x0
0x55555555a640:   0x0   0x0
0x55555555a650:   0x0   0x0
0x55555555a660:   0x0   0x0
0x55555555a670:   0x0   0x0
0x55555555a680:   0x0   0x0
0x55555555a690:   0x0   0x0
0x55555555a6a0:   0x0   0x0
0x55555555a6b0:   0x0   0x0
0x55555555a6c0:   0x0   0x0
0x55555555a6d0:   0x0   0x0
0x55555555a6e0:   0x0   0x0
0x55555555a6f0:   0x0   0x0
0x55555555a700:   0x0   0x0
0x55555555a710:   0x0   0x0
0x55555555a720:   0x0   0x0
0x55555555a730:   0x0   0x0
0x55555555a740:   0x0   0x0
0x55555555a750:   0x0   0x0
0x55555555a760:   0x0   0x0
0x55555555a770:   0x0   0x0
0x55555555a780:   0x0   0x431
0x55555555a790:   0x0   0x0
0x55555555a7a0:   0x0   0x0
0x55555555a7b0:   0x0   0x0
0x55555555a7c0:   0x0   0x0
0x55555555a7d0:   0x0   0x0
0x55555555a7e0:   0x0   0x0
0x55555555a7f0:   0x0   0x0
0x55555555a800:   0x0   0x0
0x55555555a810:   0x0   0x0
0x55555555a820:   0x0   0x0
0x55555555a830:   0x0   0x0
0x55555555a840:   0x0   0x0
0x55555555a850:   0x0   0x0
0x55555555a860:   0x0   0x0
0x55555555a870:   0x0   0x0
0x55555555a880:   0x0   0x0
0x55555555a890:   0x0   0x0
0x55555555a8a0:   0x0   0x0
0x55555555a8b0:   0x0   0x0
0x55555555a8c0:   0x0   0x0
0x55555555a8d0:   0x0   0x0
0x55555555a8e0:   0x0   0x0
0x55555555a8f0:   0x0   0x0
0x55555555a900:   0x0   0x0
0x55555555a910:   0x0   0x0
0x55555555a920:   0x0   0x0
0x55555555a930:   0x0   0x0
0x55555555a940:   0x0   0x0
0x55555555a950:   0x0   0x0
0x55555555a960:   0x0   0x0
0x55555555a970:   0x0   0x0
0x55555555a980:   0x0   0x0
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf88  →  0x00005555555551ed  →  <main+132> mov rax, QWORD PTR [rbp-0x18]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rdi   : 0x000055555555a360  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf88│+0x0000: 0x00005555555551ed  →  <main+132> mov rax, QWORD PTR [rbp-0x18]   ← $rsp
0x00007fffffffdf90│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
0x00007fffffffdf98│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0018: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0020: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0028: 0x000055555555a360  →  0x0000000000000000
0x00007fffffffdfb8│+0x0030: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0038: 0x0000000000000001   ← $rbp
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551ed → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x00005555555551ed in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551ed  →  <main+132> mov rax, QWORD PTR [rbp-0x18]
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e1 <main+120>       mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
 → 0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
   0x5555555551f9 <main+144>       nop    
   0x5555555551fa <main+145>       leave  
   0x5555555551fb <main+146>       ret    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551ed in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551ed → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x000055555555a350
0x55555555a350:   0x0   0x431
0x55555555a360:   0x555555559290 0x7ffff7e19ce0
0x55555555a370:   0x0   0x0
0x55555555a380:   0x0   0x0
0x55555555a390:   0x0   0x0
0x55555555a3a0:   0x0   0x0
0x55555555a3b0:   0x0   0x0
0x55555555a3c0:   0x0   0x0
0x55555555a3d0:   0x0   0x0
0x55555555a3e0:   0x0   0x0
0x55555555a3f0:   0x0   0x0
0x55555555a400:   0x0   0x0
0x55555555a410:   0x0   0x0
0x55555555a420:   0x0   0x0
0x55555555a430:   0x0   0x0
0x55555555a440:   0x0   0x0
0x55555555a450:   0x0   0x0
0x55555555a460:   0x0   0x0
0x55555555a470:   0x0   0x0
0x55555555a480:   0x0   0x0
0x55555555a490:   0x0   0x0
0x55555555a4a0:   0x0   0x0
0x55555555a4b0:   0x0   0x0
0x55555555a4c0:   0x0   0x0
0x55555555a4d0:   0x0   0x0
0x55555555a4e0:   0x0   0x0
0x55555555a4f0:   0x0   0x0
0x55555555a500:   0x0   0x0
0x55555555a510:   0x0   0x0
0x55555555a520:   0x0   0x0
0x55555555a530:   0x0   0x0
0x55555555a540:   0x0   0x0
0x55555555a550:   0x0   0x0
0x55555555a560:   0x0   0x0
0x55555555a570:   0x0   0x0
0x55555555a580:   0x0   0x0
0x55555555a590:   0x0   0x0
0x55555555a5a0:   0x0   0x0
0x55555555a5b0:   0x0   0x0
0x55555555a5c0:   0x0   0x0
0x55555555a5d0:   0x0   0x0
0x55555555a5e0:   0x0   0x0
0x55555555a5f0:   0x0   0x0
0x55555555a600:   0x0   0x0
0x55555555a610:   0x0   0x0
0x55555555a620:   0x0   0x0
0x55555555a630:   0x0   0x0
0x55555555a640:   0x0   0x0
0x55555555a650:   0x0   0x0
0x55555555a660:   0x0   0x0
0x55555555a670:   0x0   0x0
0x55555555a680:   0x0   0x0
0x55555555a690:   0x0   0x0
0x55555555a6a0:   0x0   0x0
0x55555555a6b0:   0x0   0x0
0x55555555a6c0:   0x0   0x0
0x55555555a6d0:   0x0   0x0
0x55555555a6e0:   0x0   0x0
0x55555555a6f0:   0x0   0x0
0x55555555a700:   0x0   0x0
0x55555555a710:   0x0   0x0
0x55555555a720:   0x0   0x0
0x55555555a730:   0x0   0x0
0x55555555a740:   0x0   0x0
0x55555555a750:   0x0   0x0
0x55555555a760:   0x0   0x0
0x55555555a770:   0x0   0x0
0x55555555a780:   0x430 0x430
0x55555555a790:   0x0   0x0
0x55555555a7a0:   0x0   0x0
0x55555555a7b0:   0x0   0x0
0x55555555a7c0:   0x0   0x0
0x55555555a7d0:   0x0   0x0
0x55555555a7e0:   0x0   0x0
0x55555555a7f0:   0x0   0x0
0x55555555a800:   0x0   0x0
0x55555555a810:   0x0   0x0
0x55555555a820:   0x0   0x0
0x55555555a830:   0x0   0x0
0x55555555a840:   0x0   0x0
0x55555555a850:   0x0   0x0
0x55555555a860:   0x0   0x0
0x55555555a870:   0x0   0x0
0x55555555a880:   0x0   0x0
0x55555555a890:   0x0   0x0
0x55555555a8a0:   0x0   0x0
0x55555555a8b0:   0x0   0x0
0x55555555a8c0:   0x0   0x0
0x55555555a8d0:   0x0   0x0
0x55555555a8e0:   0x0   0x0
0x55555555a8f0:   0x0   0x0
0x55555555a900:   0x0   0x0
0x55555555a910:   0x0   0x0
0x55555555a920:   0x0   0x0
0x55555555a930:   0x0   0x0
0x55555555a940:   0x0   0x0
0x55555555a950:   0x0   0x0
0x55555555a960:   0x0   0x0
0x55555555a970:   0x0   0x0
0x55555555a980:   0x0   0x0
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
 →   Chunk(addr=0x55555555a360, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x860, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So, we see that `chunk4` has been freed, and inserted into the unsorted bin. Now we will go ahead and free `chunk3` (`0x0000555555559f30`) directly before it. This will cause `chunk3` to consolidate forwards, and consume `chunk4`. Unlike with backwards consolidation, with forwards consolidation to the new chunk being inserted is the one that consumes the other. As such, after this is done, we should see `chunk3` (`0x0000555555559f30`) present in the unsorted bin, with a size of `0x860`:

```
gef➤  si
0x00005555555551f1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559f30  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551f1  →  <main+136> mov rdi, rax
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e5 <main+124>       mov    rdi, rax
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
 → 0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
   0x5555555551f9 <main+144>       nop    
   0x5555555551fa <main+145>       leave  
   0x5555555551fb <main+146>       ret    
   0x5555555551fc <_fini+0>        endbr64 
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551f1 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551f1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551f4 in main ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559f30  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x0000555555559f30  →  0x0000000000000000
$rip   : 0x00005555555551f4  →  <main+139> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e8 <main+127>       call   0x555555555060 <free@plt>
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551f1 <main+136>       mov    rdi, rax
 → 0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559f30 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551f4 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551f4 → main()
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
 →   Chunk(addr=0x55555555a360, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x860, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/200g 0x000055555555a350
0x55555555a350:   0x0   0x431
0x55555555a360:   0x555555559290 0x7ffff7e19ce0
0x55555555a370:   0x0   0x0
0x55555555a380:   0x0   0x0
0x55555555a390:   0x0   0x0
0x55555555a3a0:   0x0   0x0
0x55555555a3b0:   0x0   0x0
0x55555555a3c0:   0x0   0x0
0x55555555a3d0:   0x0   0x0
0x55555555a3e0:   0x0   0x0
0x55555555a3f0:   0x0   0x0
0x55555555a400:   0x0   0x0
0x55555555a410:   0x0   0x0
0x55555555a420:   0x0   0x0
0x55555555a430:   0x0   0x0
0x55555555a440:   0x0   0x0
0x55555555a450:   0x0   0x0
0x55555555a460:   0x0   0x0
0x55555555a470:   0x0   0x0
0x55555555a480:   0x0   0x0
0x55555555a490:   0x0   0x0
0x55555555a4a0:   0x0   0x0
0x55555555a4b0:   0x0   0x0
0x55555555a4c0:   0x0   0x0
0x55555555a4d0:   0x0   0x0
0x55555555a4e0:   0x0   0x0
0x55555555a4f0:   0x0   0x0
0x55555555a500:   0x0   0x0
0x55555555a510:   0x0   0x0
0x55555555a520:   0x0   0x0
0x55555555a530:   0x0   0x0
0x55555555a540:   0x0   0x0
0x55555555a550:   0x0   0x0
0x55555555a560:   0x0   0x0
0x55555555a570:   0x0   0x0
0x55555555a580:   0x0   0x0
0x55555555a590:   0x0   0x0
0x55555555a5a0:   0x0   0x0
0x55555555a5b0:   0x0   0x0
0x55555555a5c0:   0x0   0x0
0x55555555a5d0:   0x0   0x0
0x55555555a5e0:   0x0   0x0
0x55555555a5f0:   0x0   0x0
0x55555555a600:   0x0   0x0
0x55555555a610:   0x0   0x0
0x55555555a620:   0x0   0x0
0x55555555a630:   0x0   0x0
0x55555555a640:   0x0   0x0
0x55555555a650:   0x0   0x0
0x55555555a660:   0x0   0x0
0x55555555a670:   0x0   0x0
0x55555555a680:   0x0   0x0
0x55555555a690:   0x0   0x0
0x55555555a6a0:   0x0   0x0
0x55555555a6b0:   0x0   0x0
0x55555555a6c0:   0x0   0x0
0x55555555a6d0:   0x0   0x0
0x55555555a6e0:   0x0   0x0
0x55555555a6f0:   0x0   0x0
0x55555555a700:   0x0   0x0
0x55555555a710:   0x0   0x0
0x55555555a720:   0x0   0x0
0x55555555a730:   0x0   0x0
0x55555555a740:   0x0   0x0
0x55555555a750:   0x0   0x0
0x55555555a760:   0x0   0x0
0x55555555a770:   0x0   0x0
0x55555555a780:   0x430 0x430
0x55555555a790:   0x0   0x0
0x55555555a7a0:   0x0   0x0
0x55555555a7b0:   0x0   0x0
0x55555555a7c0:   0x0   0x0
0x55555555a7d0:   0x0   0x0
0x55555555a7e0:   0x0   0x0
0x55555555a7f0:   0x0   0x0
0x55555555a800:   0x0   0x0
0x55555555a810:   0x0   0x0
0x55555555a820:   0x0   0x0
0x55555555a830:   0x0   0x0
0x55555555a840:   0x0   0x0
0x55555555a850:   0x0   0x0
0x55555555a860:   0x0   0x0
0x55555555a870:   0x0   0x0
0x55555555a880:   0x0   0x0
0x55555555a890:   0x0   0x0
0x55555555a8a0:   0x0   0x0
0x55555555a8b0:   0x0   0x0
0x55555555a8c0:   0x0   0x0
0x55555555a8d0:   0x0   0x0
0x55555555a8e0:   0x0   0x0
0x55555555a8f0:   0x0   0x0
0x55555555a900:   0x0   0x0
0x55555555a910:   0x0   0x0
0x55555555a920:   0x0   0x0
0x55555555a930:   0x0   0x0
0x55555555a940:   0x0   0x0
0x55555555a950:   0x0   0x0
0x55555555a960:   0x0   0x0
0x55555555a970:   0x0   0x0
0x55555555a980:   0x0   0x0
gef➤  x/200g 0x0000555555559f20
0x555555559f20:   0x0   0x431
0x555555559f30:   0x0   0x0
0x555555559f40:   0x0   0x0
0x555555559f50:   0x0   0x0
0x555555559f60:   0x0   0x0
0x555555559f70:   0x0   0x0
0x555555559f80:   0x0   0x0
0x555555559f90:   0x0   0x0
0x555555559fa0:   0x0   0x0
0x555555559fb0:   0x0   0x0
0x555555559fc0:   0x0   0x0
0x555555559fd0:   0x0   0x0
0x555555559fe0:   0x0   0x0
0x555555559ff0:   0x0   0x0
0x55555555a000:   0x0   0x0
0x55555555a010:   0x0   0x0
0x55555555a020:   0x0   0x0
0x55555555a030:   0x0   0x0
0x55555555a040:   0x0   0x0
0x55555555a050:   0x0   0x0
0x55555555a060:   0x0   0x0
0x55555555a070:   0x0   0x0
0x55555555a080:   0x0   0x0
0x55555555a090:   0x0   0x0
0x55555555a0a0:   0x0   0x0
0x55555555a0b0:   0x0   0x0
0x55555555a0c0:   0x0   0x0
0x55555555a0d0:   0x0   0x0
0x55555555a0e0:   0x0   0x0
0x55555555a0f0:   0x0   0x0
0x55555555a100:   0x0   0x0
0x55555555a110:   0x0   0x0
0x55555555a120:   0x0   0x0
0x55555555a130:   0x0   0x0
0x55555555a140:   0x0   0x0
0x55555555a150:   0x0   0x0
0x55555555a160:   0x0   0x0
0x55555555a170:   0x0   0x0
0x55555555a180:   0x0   0x0
0x55555555a190:   0x0   0x0
0x55555555a1a0:   0x0   0x0
0x55555555a1b0:   0x0   0x0
0x55555555a1c0:   0x0   0x0
0x55555555a1d0:   0x0   0x0
0x55555555a1e0:   0x0   0x0
0x55555555a1f0:   0x0   0x0
0x55555555a200:   0x0   0x0
0x55555555a210:   0x0   0x0
0x55555555a220:   0x0   0x0
0x55555555a230:   0x0   0x0
0x55555555a240:   0x0   0x0
0x55555555a250:   0x0   0x0
0x55555555a260:   0x0   0x0
0x55555555a270:   0x0   0x0
0x55555555a280:   0x0   0x0
0x55555555a290:   0x0   0x0
0x55555555a2a0:   0x0   0x0
0x55555555a2b0:   0x0   0x0
0x55555555a2c0:   0x0   0x0
0x55555555a2d0:   0x0   0x0
0x55555555a2e0:   0x0   0x0
0x55555555a2f0:   0x0   0x0
0x55555555a300:   0x0   0x0
0x55555555a310:   0x0   0x0
0x55555555a320:   0x0   0x0
0x55555555a330:   0x0   0x0
0x55555555a340:   0x0   0x0
0x55555555a350:   0x0   0x431
0x55555555a360:   0x555555559290 0x7ffff7e19ce0
0x55555555a370:   0x0   0x0
0x55555555a380:   0x0   0x0
0x55555555a390:   0x0   0x0
0x55555555a3a0:   0x0   0x0
0x55555555a3b0:   0x0   0x0
0x55555555a3c0:   0x0   0x0
0x55555555a3d0:   0x0   0x0
0x55555555a3e0:   0x0   0x0
0x55555555a3f0:   0x0   0x0
0x55555555a400:   0x0   0x0
0x55555555a410:   0x0   0x0
0x55555555a420:   0x0   0x0
0x55555555a430:   0x0   0x0
0x55555555a440:   0x0   0x0
0x55555555a450:   0x0   0x0
0x55555555a460:   0x0   0x0
0x55555555a470:   0x0   0x0
0x55555555a480:   0x0   0x0
0x55555555a490:   0x0   0x0
0x55555555a4a0:   0x0   0x0
0x55555555a4b0:   0x0   0x0
0x55555555a4c0:   0x0   0x0
0x55555555a4d0:   0x0   0x0
0x55555555a4e0:   0x0   0x0
0x55555555a4f0:   0x0   0x0
0x55555555a500:   0x0   0x0
0x55555555a510:   0x0   0x0
0x55555555a520:   0x0   0x0
0x55555555a530:   0x0   0x0
0x55555555a540:   0x0   0x0
0x55555555a550:   0x0   0x0
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559f30  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf88  →  0x00005555555551f9  →  <main+144> nop 
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x0000555555559f30  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf88│+0x0000: 0x00005555555551f9  →  <main+144> nop     ← $rsp
0x00007fffffffdf90│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
0x00007fffffffdf98│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0018: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0020: 0x0000555555559f30  →  0x0000000000000000
0x00007fffffffdfb0│+0x0028: 0x000055555555a360  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb8│+0x0030: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0038: 0x0000000000000001   ← $rbp
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551f9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x00005555555551f9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf90  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559290  →  0x0000000000000000
$rdi   : 0x000055555555a350  →  0x0000000000000000
$rip   : 0x00005555555551f9  →  <main+144> nop 
$r8    : 0x21001           
$r9    : 0x000055555555a790  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3db  →  "/Hackery/shogun/heap_demos/malloc/consoli[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf90│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555abb0  →  0x0000000000000000   ← $rsp
0x00007fffffffdf98│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfa0│+0x0010: 0x0000555555559b00  →  0x0000000000000000
0x00007fffffffdfa8│+0x0018: 0x0000555555559f30  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb0│+0x0020: 0x000055555555a360  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfb8│+0x0028: 0x000055555555a790  →  0x0000000000000000
0x00007fffffffdfc0│+0x0030: 0x0000000000000001   ← $rbp
0x00007fffffffdfc8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ed <main+132>       mov    rax, QWORD PTR [rbp-0x18]
   0x5555555551f1 <main+136>       mov    rdi, rax
   0x5555555551f4 <main+139>       call   0x555555555060 <free@plt>
 → 0x5555555551f9 <main+144>       nop    
   0x5555555551fa <main+145>       leave  
   0x5555555551fb <main+146>       ret    
   0x5555555551fc <_fini+0>        endbr64 
   0x555555555200 <_fini+4>        sub    rsp, 0x8
   0x555555555204 <_fini+8>        add    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "consolidation", stopped 0x5555555551f9 in main (), reason: TEMPORARY BREAKPOINT
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
[+] unsorted_bins[0]: fw=0x555555559f20, bk=0x555555559290
 →   Chunk(addr=0x555555559f30, size=0x860, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x860, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/200g 0x0000555555559f20
0x555555559f20:   0x0   0x861
0x555555559f30:   0x555555559290 0x7ffff7e19ce0
0x555555559f40:   0x0   0x0
0x555555559f50:   0x0   0x0
0x555555559f60:   0x0   0x0
0x555555559f70:   0x0   0x0
0x555555559f80:   0x0   0x0
0x555555559f90:   0x0   0x0
0x555555559fa0:   0x0   0x0
0x555555559fb0:   0x0   0x0
0x555555559fc0:   0x0   0x0
0x555555559fd0:   0x0   0x0
0x555555559fe0:   0x0   0x0
0x555555559ff0:   0x0   0x0
0x55555555a000:   0x0   0x0
0x55555555a010:   0x0   0x0
0x55555555a020:   0x0   0x0
0x55555555a030:   0x0   0x0
0x55555555a040:   0x0   0x0
0x55555555a050:   0x0   0x0
0x55555555a060:   0x0   0x0
0x55555555a070:   0x0   0x0
0x55555555a080:   0x0   0x0
0x55555555a090:   0x0   0x0
0x55555555a0a0:   0x0   0x0
0x55555555a0b0:   0x0   0x0
0x55555555a0c0:   0x0   0x0
0x55555555a0d0:   0x0   0x0
0x55555555a0e0:   0x0   0x0
0x55555555a0f0:   0x0   0x0
0x55555555a100:   0x0   0x0
0x55555555a110:   0x0   0x0
0x55555555a120:   0x0   0x0
0x55555555a130:   0x0   0x0
0x55555555a140:   0x0   0x0
0x55555555a150:   0x0   0x0
0x55555555a160:   0x0   0x0
0x55555555a170:   0x0   0x0
0x55555555a180:   0x0   0x0
0x55555555a190:   0x0   0x0
0x55555555a1a0:   0x0   0x0
0x55555555a1b0:   0x0   0x0
0x55555555a1c0:   0x0   0x0
0x55555555a1d0:   0x0   0x0
0x55555555a1e0:   0x0   0x0
0x55555555a1f0:   0x0   0x0
0x55555555a200:   0x0   0x0
0x55555555a210:   0x0   0x0
0x55555555a220:   0x0   0x0
0x55555555a230:   0x0   0x0
0x55555555a240:   0x0   0x0
0x55555555a250:   0x0   0x0
0x55555555a260:   0x0   0x0
0x55555555a270:   0x0   0x0
0x55555555a280:   0x0   0x0
0x55555555a290:   0x0   0x0
0x55555555a2a0:   0x0   0x0
0x55555555a2b0:   0x0   0x0
0x55555555a2c0:   0x0   0x0
0x55555555a2d0:   0x0   0x0
0x55555555a2e0:   0x0   0x0
0x55555555a2f0:   0x0   0x0
0x55555555a300:   0x0   0x0
0x55555555a310:   0x0   0x0
0x55555555a320:   0x0   0x0
0x55555555a330:   0x0   0x0
0x55555555a340:   0x0   0x0
0x55555555a350:   0x0   0x431
0x55555555a360:   0x555555559290 0x7ffff7e19ce0
0x55555555a370:   0x0   0x0
0x55555555a380:   0x0   0x0
0x55555555a390:   0x0   0x0
0x55555555a3a0:   0x0   0x0
0x55555555a3b0:   0x0   0x0
0x55555555a3c0:   0x0   0x0
0x55555555a3d0:   0x0   0x0
0x55555555a3e0:   0x0   0x0
0x55555555a3f0:   0x0   0x0
0x55555555a400:   0x0   0x0
0x55555555a410:   0x0   0x0
0x55555555a420:   0x0   0x0
0x55555555a430:   0x0   0x0
0x55555555a440:   0x0   0x0
0x55555555a450:   0x0   0x0
0x55555555a460:   0x0   0x0
0x55555555a470:   0x0   0x0
0x55555555a480:   0x0   0x0
0x55555555a490:   0x0   0x0
0x55555555a4a0:   0x0   0x0
0x55555555a4b0:   0x0   0x0
0x55555555a4c0:   0x0   0x0
0x55555555a4d0:   0x0   0x0
0x55555555a4e0:   0x0   0x0
0x55555555a4f0:   0x0   0x0
0x55555555a500:   0x0   0x0
0x55555555a510:   0x0   0x0
0x55555555a520:   0x0   0x0
0x55555555a530:   0x0   0x0
0x55555555a540:   0x0   0x0
0x55555555a550:   0x0   0x0
gef➤  c
Continuing.
[Inferior 1 (process 9561) exited normally]
```

Just like that, we've seen both backwards and forwards heap chunk consolidation.
