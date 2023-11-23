## Chunk Header

So in this demo, we will be covering the Heap Chunk Header. The Heap Chunk Header is a `0x10` byte space, appended to the start of every chunk returned by malloc. The actual ptr returned by malloc, is to right after this header.

Here is the source code we will be stepping through:

```
#include <stdlib.h>

void main() {
    char *chunk0,
   		 *chunk1,
   		 *chunk2,
   		 *chunk3;


    chunk0 = malloc(0x50);
    chunk1 = malloc(0x50);
    chunk2 = malloc(0x500);
    chunk3 = malloc(0x500);


    free(chunk0);
    free(chunk2);
}
```

So, before we go any further, let's explain the structure of the heap chunk header. It is `0x10` bytes, which consists of two `0x08` byte size values. The first is `prev_size`, and the second is `size`. The `size` value is supposed to represent the size of the chunk. The `prev_size` value is supposed to represent the size of the previous chunk, but only if it is not in use.

The thing about the `size` value, is the lower three bits are flags. If they are set, they mean a particular thing. These lower three bits do not actually represent a difference in the size of the chunk.

Now, several things depend on if the previous chunk is in use. What it means for a chunk to be in use, is either that chunk hasn't been freed yet, or if it has been freed, it ended up in either the tcache or the fastbin.

Now, for the three flag bits in the `size` value, here are the flags:

```
0x01    -    PREV_INUSE
0x02    -    IS_MMAPPED
0x04    -    NON_MAIN_ARENA
```

If the `PREV_INUSE` chunk is set, that means the previous chunk is in use. If the `IS_MMAPPED` flags is set, that means the chunk was allocated via mmap from `malloc` (if you just call `mmap` without malloc, it won't have this header). If the `NON_MAIN_ARENA` bit is set, that means that the chunk is from an arena that is not the main arena (for programs with multiple arenas). We will not be really seeing much of the `IS_MMAPPED`/`NON_MAIN_ARENA` flags in this demo.

So, here is a chart showing the chunk header:

```
+=================|==============|================|============|=============+
| 0 1 2 3 4 5 6 7 | 8 9 10 11 12 |  	13    	| 	14 	| 	15  	|
|=================|==============|================|============|=============|
|	prev_size	|   size   	| NON_MAIN_ARENA | IS_MMAPPED | PREV_INUSE  |
+=================|==============|================|============|=============+
```


#### Chunk Header Walkthrough

So effectively, what will we be doing here? We will be allocating some chunks, and seeing their headers at first. Then we will be freeing some of those chunks, and seeing how the chunk headers change with that. We will start off via allocating all `4` of the chunks, and seeing the headers:

```
$    gdb ./chunk_header 
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
Reading symbols from ./chunk_header...
(No debugging symbols found in ./chunk_header)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:   endbr64 
   0x000000000000116d <+4>:   push   rbp
   0x000000000000116e <+5>:   mov    rbp,rsp
   0x0000000000001171 <+8>:   sub    rsp,0x20
   0x0000000000001175 <+12>:  mov    edi,0x50
   0x000000000000117a <+17>:  call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:  mov    QWORD PTR [rbp-0x20],rax
   0x0000000000001183 <+26>:  mov    edi,0x50
   0x0000000000001188 <+31>:  call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:  mov    QWORD PTR [rbp-0x18],rax
   0x0000000000001191 <+40>:  mov    edi,0x500
   0x0000000000001196 <+45>:  call   0x1070 <malloc@plt>
   0x000000000000119b <+50>:  mov    QWORD PTR [rbp-0x10],rax
   0x000000000000119f <+54>:  mov    edi,0x500
   0x00000000000011a4 <+59>:  call   0x1070 <malloc@plt>
   0x00000000000011a9 <+64>:  mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011ad <+68>:  mov    rax,QWORD PTR [rbp-0x20]
   0x00000000000011b1 <+72>:  mov    rdi,rax
   0x00000000000011b4 <+75>:  call   0x1060 <free@plt>
   0x00000000000011b9 <+80>:  mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011bd <+84>:  mov    rdi,rax
   0x00000000000011c0 <+87>:  call   0x1060 <free@plt>
   0x00000000000011c5 <+92>:  nop
   0x00000000000011c6 <+93>:  leave  
   0x00000000000011c7 <+94>:  ret    
End of assembler dump.
gef➤  b *main+17
Breakpoint 1 at 0x117a
gef➤  b *main+64
Breakpoint 2 at 0x11a9
gef➤  r
Starting program: /Hackery/shogun/heap_demos/malloc/chunk_header/chunk_header 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555517a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555169  →  <main+0> endbr64 
$rbx   : 0x0               
$rcx   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe425  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfb0  →  0x00007fffffffe3d9  →  0x2f0034365f363878 ("x86_64"?)
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$rdi   : 0x50              
$rip   : 0x000055555555517a  →  <main+17> call 0x555555555070 <malloc@plt>
$r8    : 0x00007ffff7e1af10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  <_dl_fini+0> endbr64 
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x00007ffff7fde680  →  <_dl_audit_preinit+0> endbr64 
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00007fffffffe3d9  →  0x2f0034365f363878 ("x86_64"?)    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555516e <main+5>         mov    rbp, rsp
   0x555555555171 <main+8>         sub    rsp, 0x20
   0x555555555175 <main+12>        mov    edi, 0x50
 → 0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <_start+0>       endbr64 
      0x555555555084 <_start+4>       xor    ebp, ebp
      0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000050
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x55555555517a in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555169  →  <main+0> endbr64 
$rbx   : 0x0               
$rcx   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe425  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfa8  →  0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x20], rax
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$rdi   : 0x50              
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64 
$r8    : 0x00007ffff7e1af10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  <_dl_fini+0> endbr64 
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x00007ffff7fde680  →  <_dl_audit_preinit+0> endbr64 
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x20], rax    ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00007fffffffe3d9  →  0x2f0034365f363878 ("x86_64"?)
0x00007fffffffdfb8│+0x0010: 0x0000000000000064 ("d"?)
0x00007fffffffdfc0│+0x0018: 0x0000000000001000
0x00007fffffffdfc8│+0x0020: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0028: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0030: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>       endbr64 
   0x555555555084 <_start+4>       xor    ebp, ebp
   0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x000055555555517f in main ()



[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x61              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb0  →  0x00007fffffffe3d9  →  0x2f0034365f363878 ("x86_64"?)
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555592f0  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x20], rax
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x00007ffff7e19ce0  →  0x00005555555592f0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00007fffffffe3d9  →  0x2f0034365f363878 ("x86_64"?)    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>         sub    rsp, 0x20
   0x555555555175 <main+12>        mov    edi, 0x50
   0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>        mov    QWORD PTR [rbp-0x20], rax
   0x555555555183 <main+26>        mov    edi, 0x50
   0x555555555188 <main+31>        call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>        mov    QWORD PTR [rbp-0x18], rax
   0x555555555191 <main+40>        mov    edi, 0x500
   0x555555555196 <main+45>        call   0x555555555070 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x55555555517f in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/10g $rax-0x10
0x555555559290:   0x0   0x61
0x5555555592a0:   0x0   0x0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x61
0x5555555592a0:   0x0   0x0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x20d11
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
0x5555555596c0:   0x0   0x0
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
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555551a9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559870  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d70  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551a9  →  <main+64> mov QWORD PTR [rbp-0x8], rax
$r8    : 0x21001           
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555519d <main+52>        rex.RB 
   0x55555555519e <main+53>        lock   mov edi, 0x500
   0x5555555551a4 <main+59>        call   0x555555555070 <malloc@plt>
 → 0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551ad <main+68>        mov    rax, QWORD PTR [rbp-0x20]
   0x5555555551b1 <main+72>        mov    rdi, rax
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551a9 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551a9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x61
0x5555555592a0:   0x0   0x0
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x61
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x511
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
0x5555555596c0:   0x0   0x0
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
0x555555559860:   0x0   0x511
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
```

So we can see for all four of the chunk headers, the `prev_size` for all of them is `0x0`. The size values for them are `0x61`, `0x61`, `0x511`, and `0x511`. Of course, this corresponds to actual size values `0x60`, `0x60`, `0x510`, and `0x510`, all with the `PREV_INUSE` bit set. Now let's free `chunk0`, and see what happens:

```
gef➤  si
0x00005555555551ad in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559870  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d70  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551ad  →  <main+68> mov rax, QWORD PTR [rbp-0x20]
$r8    : 0x21001           
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555519f <main+54>        mov    edi, 0x500
   0x5555555551a4 <main+59>        call   0x555555555070 <malloc@plt>
   0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x8], rax
 → 0x5555555551ad <main+68>        mov    rax, QWORD PTR [rbp-0x20]
   0x5555555551b1 <main+72>        mov    rdi, rax
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
   0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551ad in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551ad → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551b1 in main ()








[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d70  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00005555555551b1  →  <main+72> mov rdi, rax
$r8    : 0x21001           
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a4 <main+59>        call   0x555555555070 <malloc@plt>
   0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551ad <main+68>        mov    rax, QWORD PTR [rbp-0x20]
 → 0x5555555551b1 <main+72>        mov    rdi, rax
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
   0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
   0x5555555551c5 <main+92>        nop    
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551b1 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551b4 in main ()








[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d70  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x00005555555551b4  →  <main+75> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a9 <main+64>        mov    QWORD PTR [rbp-0x8], rax
   0x5555555551ad <main+68>        mov    rax, QWORD PTR [rbp-0x20]
   0x5555555551b1 <main+72>        mov    rdi, rax
 → 0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555592a0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551b4 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x511             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa8  →  0x00005555555551b9  →  <main+80> mov rax, QWORD PTR [rbp-0x10]
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559d70  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x00005555555551b9  →  <main+80> mov rax, QWORD PTR [rbp-0x10]    ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00005555555592a0  →  0x0000000000000000
0x00007fffffffdfb8│+0x0010: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0018: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0020: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0028: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0030: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551b9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x00005555555551b9 in main ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x4               
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7               
$rip   : 0x00005555555551b9  →  <main+80> mov rax, QWORD PTR [rbp-0x10]
$r8    : 0x00005555555592a0  →  0x0000000555555559
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x930efd64c606d6e6
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ad <main+68>        mov    rax, QWORD PTR [rbp-0x20]
   0x5555555551b1 <main+72>        mov    rdi, rax
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
 → 0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
   0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
   0x5555555551c5 <main+92>        nop    
   0x5555555551c6 <main+93>        leave  
   0x5555555551c7 <main+94>        ret    
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551b9 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x61
0x5555555592a0:   0x555555559 0x930efd64c606d6e6
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x61
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x511
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
0x5555555596c0:   0x0   0x0
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
0x555555559860:   0x0   0x511
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=1] ←  Chunk(addr=0x5555555592a0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
───────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ─────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ───────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So, even though we freed `chunk0`, we can see that `chunk1`'s `PREV_INUSE` bit is still set, and its `prev_size` value is still `0x00`. This is because that `chunk0` is inserted into the tcache (would also be the same if it was inserted into the fastbin). Now let's free `chunk2`:

```
gef➤  si
0x00005555555551bd in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x4               
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7               
$rip   : 0x00005555555551bd  →  <main+84> mov rdi, rax
$r8    : 0x00005555555592a0  →  0x0000000555555559
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x930efd64c606d6e6
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b1 <main+72>        mov    rdi, rax
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
 → 0x5555555551bd <main+84>        mov    rdi, rax
   0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
   0x5555555551c5 <main+92>        nop    
   0x5555555551c6 <main+93>        leave  
   0x5555555551c7 <main+94>        ret    
   0x5555555551c8 <_fini+0>        endbr64 
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551bd in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551bd → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555551c0 in main ()








[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x4               
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x0000555555559360  →  0x0000000000000000
$rip   : 0x00005555555551c0  →  <main+87> call 0x555555555060 <free@plt>
$r8    : 0x00005555555592a0  →  0x0000000555555559
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x930efd64c606d6e6
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b4 <main+75>        call   0x555555555060 <free@plt>
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
 → 0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>     endbr64 
      0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
      0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559360 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551c0 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559360  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x4               
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfa8  →  0x00005555555551c5  →  <main+92> nop 
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x0000555555559360  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x00005555555592a0  →  0x0000000555555559
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x930efd64c606d6e6
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x00005555555551c5  →  <main+92> nop   ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00005555555592a0  →  0x0000000555555559
0x00007fffffffdfb8│+0x0010: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0018: 0x0000555555559360  →  0x0000000000000000
0x00007fffffffdfc8│+0x0020: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0028: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0030: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555050 <__cxa_finalize@plt+0> endbr64 
   0x555555555054 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f9d]        # 0x555555557ff8
   0x55555555505b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555060 <free@plt+0>     endbr64 
   0x555555555064 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f5d]        # 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555070 <malloc@plt+0>   endbr64 
   0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x5555555551c5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x00005555555551c5 in main ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x4f              
$rdx   : 0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00005555555551c5  →  <main+92> nop 
$r8    : 0x00005555555592a0  →  0x0000000555555559
$r9    : 0x0000555555559870  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x930efd64c606d6e6
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e0  →  "/Hackery/shogun/heap_demos/malloc/chunk_h[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000555555559    ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559300  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000555555559360  →  0x00007ffff7e19ce0  →  0x0000555555559d70  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555559870  →  0x0000000000000000
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64 
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b9 <main+80>        mov    rax, QWORD PTR [rbp-0x10]
   0x5555555551bd <main+84>        mov    rdi, rax
   0x5555555551c0 <main+87>        call   0x555555555060 <free@plt>
 → 0x5555555551c5 <main+92>        nop    
   0x5555555551c6 <main+93>        leave  
   0x5555555551c7 <main+94>        ret    
   0x5555555551c8 <_fini+0>        endbr64 
   0x5555555551cc <_fini+4>        sub    rsp, 0x8
   0x5555555551d0 <_fini+8>        add    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chunk_header", stopped 0x5555555551c5 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290:   0x0   0x61
0x5555555592a0:   0x555555559 0x930efd64c606d6e6
0x5555555592b0:   0x0   0x0
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x0
0x5555555592e0:   0x0   0x0
0x5555555592f0:   0x0   0x61
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
0x555555559320:   0x0   0x0
0x555555559330:   0x0   0x0
0x555555559340:   0x0   0x0
0x555555559350:   0x0   0x511
0x555555559360:   0x7ffff7e19ce0 0x7ffff7e19ce0
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
0x5555555596c0:   0x0   0x0
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
0x555555559860:   0x510 0x510
0x555555559870:   0x0   0x0
0x555555559880:   0x0   0x0
0x555555559890:   0x0   0x0
0x5555555598a0:   0x0   0x0
0x5555555598b0:   0x0   0x0
0x5555555598c0:   0x0   0x0
gef➤  c
Continuing.
[Inferior 1 (process 9177) exited normally]
```

So, now that we freed `chunk2`, and it was inserted into the unsorted bin (not the tcache/fastbin), we see the header for `chunk3` has been adjusted. The `prev_size` value was set to `0x510`, and the `PREV_INUSE` bit has been cleared.
