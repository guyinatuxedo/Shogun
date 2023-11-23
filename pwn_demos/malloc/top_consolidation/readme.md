# Top

So, for this writeup. We will again, be focusing on trying to get malloc to reallocate an existing chunk via consolidation. Unlike the other two instances, this will be done via consolidating with the top chunk.

Also one thing to note, functions like `printf` can call `malloc`, which can affect where the top chunk is. Since we're trying to use that, I'm avoiding functions like printf for this.

Here is the code:

```
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x80


void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *chunk3;

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE1);

    chunk0[-1] = (CHUNK_SIZE0 + CHUNK_SIZE1) + 0x20 + 0x1;

    free(chunk0);

    chunk2 = malloc(CHUNK_SIZE0);
    chunk3 = malloc(CHUNK_SIZE0);
}
```

## Walkthrough

So our goal here, is to get malloc to allocate a chunk that completely overlaps `chunk1` via top chunk consolidation. We will alter the heap chunk header size of `chunk0`, to expand the size of the chunk, and have the top chunk immediatly after it. Then we will free it, and since it's next chunk is the top chunk (and it's not tcache/fastbin size), it will consolidate the top chunk, and the top chunk will move up to where `chunk0` is.

Now remember, when malloc won't allocate memory from one of the bins, it will more than likely allocate it from the top chunk (malloc creates new heap chunks via breaking off small pieces of the top chunk). Thus, by subsequently allocating a chunk of memory the size of old `chunk0` (since the bins are empty), it will move the top chunk to overlap directly with `chunk3`. Then we will just allocate a new chunk from the top chunk to get an overlapping chunk with `chunk3`.

Let's see this in action:

```
$   gdb ./top
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
Reading symbols from ./top...
(No debugging symbols found in ./top)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>: endbr64
   0x000000000000116d <+4>: push   rbp
   0x000000000000116e <+5>: mov rbp,rsp
   0x0000000000001171 <+8>: sub rsp,0x20
   0x0000000000001175 <+12>:    mov edi,0x420
   0x000000000000117a <+17>:    call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:    mov QWORD PTR [rbp-0x20],rax
   0x0000000000001183 <+26>:    mov edi,0x80
   0x0000000000001188 <+31>:    call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:    mov QWORD PTR [rbp-0x18],rax
   0x0000000000001191 <+40>:    mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001195 <+44>:    sub rax,0x8
   0x0000000000001199 <+48>:    mov QWORD PTR [rax],0x4c1
   0x00000000000011a0 <+55>:    mov rax,QWORD PTR [rbp-0x20]
   0x00000000000011a4 <+59>:    mov rdi,rax
   0x00000000000011a7 <+62>:    call   0x1060 <free@plt>
   0x00000000000011ac <+67>:    mov edi,0x420
   0x00000000000011b1 <+72>:    call   0x1070 <malloc@plt>
   0x00000000000011b6 <+77>:    mov QWORD PTR [rbp-0x10],rax
   0x00000000000011ba <+81>:    mov edi,0x420
   0x00000000000011bf <+86>:    call   0x1070 <malloc@plt>
   0x00000000000011c4 <+91>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011c8 <+95>:    nop
   0x00000000000011c9 <+96>:    leave  
   0x00000000000011ca <+97>:    ret    
End of assembler dump.
gef➤  b *main+22
Breakpoint 1 at 0x117f
gef➤  b *main+36
Breakpoint 2 at 0x118d
gef➤  b *main+62
Breakpoint 3 at 0x11a7
gef➤  b *main+72
Breakpoint 4 at 0x11b1
gef➤  b *main+77
Breakpoint 5 at 0x11b6
gef➤  b *main+91
Breakpoint 6 at 0x11c4
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/malloc/top_consolidation/top
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555517f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x431           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfb0  →  0x00007fffffffe3d9  →  0x000034365f363878 ("x86_64"?)
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555596c0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x20], rax
$r8 : 0x21001        
$r9 : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00007fffffffe3d9  →  0x000034365f363878 ("x86_64"?)   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>      sub rsp, 0x20
   0x555555555175 <main+12>     mov edi, 0x420
   0x55555555517a <main+17>     call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>     mov QWORD PTR [rbp-0x20], rax
   0x555555555183 <main+26>     mov edi, 0x80
   0x555555555188 <main+31>     call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>     mov QWORD PTR [rbp-0x18], rax
   0x555555555191 <main+40>     mov rax, QWORD PTR [rbp-0x20]
   0x555555555195 <main+44>     sub rax, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x55555555517f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555592a0
gef➤  c
Continuing.

Breakpoint 2, 0x000055555555518d in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x91            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559750  →  0x0000000000000000
$rdi   : 0x0             
$rip   : 0x000055555555518d  →  <main+36> mov QWORD PTR [rbp-0x18], rax
$r8 : 0x21001        
$r9 : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559750  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000000000000064 ("d"?)
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555517f <main+22>     mov QWORD PTR [rbp-0x20], rax
   0x555555555183 <main+26>     mov edi, 0x80
   0x555555555188 <main+31>     call   0x555555555070 <malloc@plt>
 → 0x55555555518d <main+36>     mov QWORD PTR [rbp-0x18], rax
   0x555555555191 <main+40>     mov rax, QWORD PTR [rbp-0x20]
   0x555555555195 <main+44>     sub rax, 0x8
   0x555555555199 <main+48>     mov QWORD PTR [rax], 0x4c1
   0x5555555551a0 <main+55>     mov rax, QWORD PTR [rbp-0x20]
   0x5555555551a4 <main+59>     mov rdi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x55555555518d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555518d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x0
0x555555559360: 0x0 0x0
0x555555559370: 0x0 0x0
0x555555559380: 0x0 0x0
0x555555559390: 0x0 0x0
0x5555555593a0: 0x0 0x0
0x5555555593b0: 0x0 0x0
0x5555555593c0: 0x0 0x0
0x5555555593d0: 0x0 0x0
0x5555555593e0: 0x0 0x0
0x5555555593f0: 0x0 0x0
0x555555559400: 0x0 0x0
0x555555559410: 0x0 0x0
0x555555559420: 0x0 0x0
0x555555559430: 0x0 0x0
0x555555559440: 0x0 0x0
0x555555559450: 0x0 0x0
0x555555559460: 0x0 0x0
0x555555559470: 0x0 0x0
0x555555559480: 0x0 0x0
0x555555559490: 0x0 0x0
0x5555555594a0: 0x0 0x0
0x5555555594b0: 0x0 0x0
0x5555555594c0: 0x0 0x0
0x5555555594d0: 0x0 0x0
0x5555555594e0: 0x0 0x0
0x5555555594f0: 0x0 0x0
0x555555559500: 0x0 0x0
0x555555559510: 0x0 0x0
0x555555559520: 0x0 0x0
0x555555559530: 0x0 0x0
0x555555559540: 0x0 0x0
0x555555559550: 0x0 0x0
0x555555559560: 0x0 0x0
0x555555559570: 0x0 0x0
0x555555559580: 0x0 0x0
0x555555559590: 0x0 0x0
0x5555555595a0: 0x0 0x0
0x5555555595b0: 0x0 0x0
0x5555555595c0: 0x0 0x0
0x5555555595d0: 0x0 0x0
0x5555555595e0: 0x0 0x0
0x5555555595f0: 0x0 0x0
0x555555559600: 0x0 0x0
0x555555559610: 0x0 0x0
0x555555559620: 0x0 0x0
0x555555559630: 0x0 0x0
0x555555559640: 0x0 0x0
0x555555559650: 0x0 0x0
0x555555559660: 0x0 0x0
0x555555559670: 0x0 0x0
0x555555559680: 0x0 0x0
0x555555559690: 0x0 0x0
0x5555555596a0: 0x0 0x0
0x5555555596b0: 0x0 0x0
0x5555555596c0: 0x0 0x91
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x208b1
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
```

So, we see `chunk0` at `0x5555555592a0`, and `chunk1` at `0x5555555596d0`. We also see the top chunk at `0x555555559750`. Now let's see the two chunks after we've prepped for top chunk consolidation with `chunk0`:

```
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555551a7 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x91            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559750  →  0x0000000000000000
$rdi   : 0x00005555555592a0  →  0x0000000000000000
$rip   : 0x00005555555551a7  →  <main+62> call 0x555555555060 <free@plt>
$r8 : 0x21001        
$r9 : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559750  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555199 <main+48>     mov QWORD PTR [rax], 0x4c1
   0x5555555551a0 <main+55>     mov rax, QWORD PTR [rbp-0x20]
   0x5555555551a4 <main+59>     mov rdi, rax
 → 0x5555555551a7 <main+62>     call   0x555555555060 <free@plt>
   ↳  0x555555555060 <free@plt+0>   endbr64
    0x555555555064 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f5d]      # 0x555555557fc8 <free@got.plt>
    0x55555555506b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x555555555070 <malloc@plt+0>   endbr64
    0x555555555074 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f55]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555507b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555592a0 → 0x0000000000000000,
   $rsi = 0x0000555555559750 → 0x0000000000000000,
   $rdx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x5555555551a7 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551a7 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/200g 0x555555559290
0x555555559290: 0x0 0x4c1
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x0
0x555555559360: 0x0 0x0
0x555555559370: 0x0 0x0
0x555555559380: 0x0 0x0
0x555555559390: 0x0 0x0
0x5555555593a0: 0x0 0x0
0x5555555593b0: 0x0 0x0
0x5555555593c0: 0x0 0x0
0x5555555593d0: 0x0 0x0
0x5555555593e0: 0x0 0x0
0x5555555593f0: 0x0 0x0
0x555555559400: 0x0 0x0
0x555555559410: 0x0 0x0
0x555555559420: 0x0 0x0
0x555555559430: 0x0 0x0
0x555555559440: 0x0 0x0
0x555555559450: 0x0 0x0
0x555555559460: 0x0 0x0
0x555555559470: 0x0 0x0
0x555555559480: 0x0 0x0
0x555555559490: 0x0 0x0
0x5555555594a0: 0x0 0x0
0x5555555594b0: 0x0 0x0
0x5555555594c0: 0x0 0x0
0x5555555594d0: 0x0 0x0
0x5555555594e0: 0x0 0x0
0x5555555594f0: 0x0 0x0
0x555555559500: 0x0 0x0
0x555555559510: 0x0 0x0
0x555555559520: 0x0 0x0
0x555555559530: 0x0 0x0
0x555555559540: 0x0 0x0
0x555555559550: 0x0 0x0
0x555555559560: 0x0 0x0
0x555555559570: 0x0 0x0
0x555555559580: 0x0 0x0
0x555555559590: 0x0 0x0
0x5555555595a0: 0x0 0x0
0x5555555595b0: 0x0 0x0
0x5555555595c0: 0x0 0x0
0x5555555595d0: 0x0 0x0
0x5555555595e0: 0x0 0x0
0x5555555595f0: 0x0 0x0
0x555555559600: 0x0 0x0
0x555555559610: 0x0 0x0
0x555555559620: 0x0 0x0
0x555555559630: 0x0 0x0
0x555555559640: 0x0 0x0
0x555555559650: 0x0 0x0
0x555555559660: 0x0 0x0
0x555555559670: 0x0 0x0
0x555555559680: 0x0 0x0
0x555555559690: 0x0 0x0
0x5555555596a0: 0x0 0x0
0x5555555596b0: 0x0 0x0
0x5555555596c0: 0x0 0x91
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x208b1
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
gef➤  p main_arena
$2 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559750,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
```

So, we see that the header size value at `0x555555559298` has been increased to `0x4c1`. This will cause the next adjacent chunk to be at `0x555555559290 + 0x4c0 = 0x555555559750`, which is where the top chunk is (bypassing `chunk1`). Now, we will free `chunk0` to cause the top chunk to consolidate with it:

```
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555551b1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x4a            
$rdx   : 0xfffffffffffff000
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x420           
$rip   : 0x00005555555551b1  →  <main+72> call 0x555555555070 <malloc@plt>
$r8 : 0x21001        
$r9 : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559290  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a4 <main+59>     mov rdi, rax
   0x5555555551a7 <main+62>     call   0x555555555060 <free@plt>
   0x5555555551ac <main+67>     mov edi, 0x420
 → 0x5555555551b1 <main+72>     call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64
    0x555555555074 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f55]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555507b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x555555555080 <_start+0>       endbr64
    0x555555555084 <_start+4>       xor ebp, ebp
    0x555555555086 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000420,
   $rsi = 0x0000000000000000,
   $rdx = 0xfffffffffffff000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x5555555551b1 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b1 → main()
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
gef➤  p main_arena
$3 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559290,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  x/200g 0x555555559290
0x555555559290: 0x0 0x20d71
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x0
0x555555559360: 0x0 0x0
0x555555559370: 0x0 0x0
0x555555559380: 0x0 0x0
0x555555559390: 0x0 0x0
0x5555555593a0: 0x0 0x0
0x5555555593b0: 0x0 0x0
0x5555555593c0: 0x0 0x0
0x5555555593d0: 0x0 0x0
0x5555555593e0: 0x0 0x0
0x5555555593f0: 0x0 0x0
0x555555559400: 0x0 0x0
0x555555559410: 0x0 0x0
0x555555559420: 0x0 0x0
0x555555559430: 0x0 0x0
0x555555559440: 0x0 0x0
0x555555559450: 0x0 0x0
0x555555559460: 0x0 0x0
0x555555559470: 0x0 0x0
0x555555559480: 0x0 0x0
0x555555559490: 0x0 0x0
0x5555555594a0: 0x0 0x0
0x5555555594b0: 0x0 0x0
0x5555555594c0: 0x0 0x0
0x5555555594d0: 0x0 0x0
0x5555555594e0: 0x0 0x0
0x5555555594f0: 0x0 0x0
0x555555559500: 0x0 0x0
0x555555559510: 0x0 0x0
0x555555559520: 0x0 0x0
0x555555559530: 0x0 0x0
0x555555559540: 0x0 0x0
0x555555559550: 0x0 0x0
0x555555559560: 0x0 0x0
0x555555559570: 0x0 0x0
0x555555559580: 0x0 0x0
0x555555559590: 0x0 0x0
0x5555555595a0: 0x0 0x0
0x5555555595b0: 0x0 0x0
0x5555555595c0: 0x0 0x0
0x5555555595d0: 0x0 0x0
0x5555555595e0: 0x0 0x0
0x5555555595f0: 0x0 0x0
0x555555559600: 0x0 0x0
0x555555559610: 0x0 0x0
0x555555559620: 0x0 0x0
0x555555559630: 0x0 0x0
0x555555559640: 0x0 0x0
0x555555559650: 0x0 0x0
0x555555559660: 0x0 0x0
0x555555559670: 0x0 0x0
0x555555559680: 0x0 0x0
0x555555559690: 0x0 0x0
0x5555555596a0: 0x0 0x0
0x5555555596b0: 0x0 0x0
0x5555555596c0: 0x0 0x91
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x208b1
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
```

So now, we see the top chunk has been moved up to `0x555555559290`, directly overlapping it with `chunk0`. Now, we will allocate a chunk from the top chunk the same size as `chunk0`. This way, the top chunk will move down to overlap directly with `chunk1` (which hasn't been freed):

```
gef➤  c
Continuing.

Breakpoint 5, 0x00005555555551b6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x431           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555596c0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x00005555555551b6  →  <main+77> mov QWORD PTR [rbp-0x10], rax
$r8 : 0x21001        
$r9 : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000000000001000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551a7 <main+62>     call   0x555555555060 <free@plt>
   0x5555555551ac <main+67>     mov edi, 0x420
   0x5555555551b1 <main+72>     call   0x555555555070 <malloc@plt>
 → 0x5555555551b6 <main+77>     mov QWORD PTR [rbp-0x10], rax
   0x5555555551ba <main+81>     mov edi, 0x420
   0x5555555551bf <main+86>     call   0x555555555070 <malloc@plt>
   0x5555555551c4 <main+91>     mov QWORD PTR [rbp-0x8], rax
   0x5555555551c8 <main+95>     nop    
   0x5555555551c9 <main+96>     leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x5555555551b6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551b6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x5555555592a0
gef➤  x/200g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x0
0x555555559360: 0x0 0x0
0x555555559370: 0x0 0x0
0x555555559380: 0x0 0x0
0x555555559390: 0x0 0x0
0x5555555593a0: 0x0 0x0
0x5555555593b0: 0x0 0x0
0x5555555593c0: 0x0 0x0
0x5555555593d0: 0x0 0x0
0x5555555593e0: 0x0 0x0
0x5555555593f0: 0x0 0x0
0x555555559400: 0x0 0x0
0x555555559410: 0x0 0x0
0x555555559420: 0x0 0x0
0x555555559430: 0x0 0x0
0x555555559440: 0x0 0x0
0x555555559450: 0x0 0x0
0x555555559460: 0x0 0x0
0x555555559470: 0x0 0x0
0x555555559480: 0x0 0x0
0x555555559490: 0x0 0x0
0x5555555594a0: 0x0 0x0
0x5555555594b0: 0x0 0x0
0x5555555594c0: 0x0 0x0
0x5555555594d0: 0x0 0x0
0x5555555594e0: 0x0 0x0
0x5555555594f0: 0x0 0x0
0x555555559500: 0x0 0x0
0x555555559510: 0x0 0x0
0x555555559520: 0x0 0x0
0x555555559530: 0x0 0x0
0x555555559540: 0x0 0x0
0x555555559550: 0x0 0x0
0x555555559560: 0x0 0x0
0x555555559570: 0x0 0x0
0x555555559580: 0x0 0x0
0x555555559590: 0x0 0x0
0x5555555595a0: 0x0 0x0
0x5555555595b0: 0x0 0x0
0x5555555595c0: 0x0 0x0
0x5555555595d0: 0x0 0x0
0x5555555595e0: 0x0 0x0
0x5555555595f0: 0x0 0x0
0x555555559600: 0x0 0x0
0x555555559610: 0x0 0x0
0x555555559620: 0x0 0x0
0x555555559630: 0x0 0x0
0x555555559640: 0x0 0x0
0x555555559650: 0x0 0x0
0x555555559660: 0x0 0x0
0x555555559670: 0x0 0x0
0x555555559680: 0x0 0x0
0x555555559690: 0x0 0x0
0x5555555596a0: 0x0 0x0
0x5555555596b0: 0x0 0x0
0x5555555596c0: 0x0 0x20941
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x208b1
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
gef➤  p main_arena
$5 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555596c0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
```

Now that the top chunk directly overlaps with `chunk1`. So we can just go ahead an allocate another chunk from the top chunk, to get an overlapping chunk with `chunk1`:

```
gef➤  c
Continuing.

Breakpoint 6, 0x00005555555551c4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x431           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x00005555555551c4  →  <main+91> mov QWORD PTR [rbp-0x8], rax
$r8 : 0x21001        
$r9 : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e7  →  "/Hackery/shogun/pwn_demos/malloc/top_cons[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000   ← $rsp
0x00007fffffffdfb8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x00005555555592a0  →  0x0000000000000000
0x00007fffffffdfc8│+0x0018: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfd0│+0x0020: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0028: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0030: 0x0000000000000000
0x00007fffffffdfe8│+0x0038: 0x0000555555555169  →  <main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b6 <main+77>     mov QWORD PTR [rbp-0x10], rax
   0x5555555551ba <main+81>     mov edi, 0x420
   0x5555555551bf <main+86>     call   0x555555555070 <malloc@plt>
 → 0x5555555551c4 <main+91>     mov QWORD PTR [rbp-0x8], rax
   0x5555555551c8 <main+95>     nop    
   0x5555555551c9 <main+96>     leave  
   0x5555555551ca <main+97>     ret    
   0x5555555551cb               add bl, dh
   0x5555555551cd <_fini+1>     nop edx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top", stopped 0x5555555551c4 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$6 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559af0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  p $rax
$7 = 0x5555555596d0
gef➤  x/200g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x0 0x0
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
0x555555559350: 0x0 0x0
0x555555559360: 0x0 0x0
0x555555559370: 0x0 0x0
0x555555559380: 0x0 0x0
0x555555559390: 0x0 0x0
0x5555555593a0: 0x0 0x0
0x5555555593b0: 0x0 0x0
0x5555555593c0: 0x0 0x0
0x5555555593d0: 0x0 0x0
0x5555555593e0: 0x0 0x0
0x5555555593f0: 0x0 0x0
0x555555559400: 0x0 0x0
0x555555559410: 0x0 0x0
0x555555559420: 0x0 0x0
0x555555559430: 0x0 0x0
0x555555559440: 0x0 0x0
0x555555559450: 0x0 0x0
0x555555559460: 0x0 0x0
0x555555559470: 0x0 0x0
0x555555559480: 0x0 0x0
0x555555559490: 0x0 0x0
0x5555555594a0: 0x0 0x0
0x5555555594b0: 0x0 0x0
0x5555555594c0: 0x0 0x0
0x5555555594d0: 0x0 0x0
0x5555555594e0: 0x0 0x0
0x5555555594f0: 0x0 0x0
0x555555559500: 0x0 0x0
0x555555559510: 0x0 0x0
0x555555559520: 0x0 0x0
0x555555559530: 0x0 0x0
0x555555559540: 0x0 0x0
0x555555559550: 0x0 0x0
0x555555559560: 0x0 0x0
0x555555559570: 0x0 0x0
0x555555559580: 0x0 0x0
0x555555559590: 0x0 0x0
0x5555555595a0: 0x0 0x0
0x5555555595b0: 0x0 0x0
0x5555555595c0: 0x0 0x0
0x5555555595d0: 0x0 0x0
0x5555555595e0: 0x0 0x0
0x5555555595f0: 0x0 0x0
0x555555559600: 0x0 0x0
0x555555559610: 0x0 0x0
0x555555559620: 0x0 0x0
0x555555559630: 0x0 0x0
0x555555559640: 0x0 0x0
0x555555559650: 0x0 0x0
0x555555559660: 0x0 0x0
0x555555559670: 0x0 0x0
0x555555559680: 0x0 0x0
0x555555559690: 0x0 0x0
0x5555555596a0: 0x0 0x0
0x5555555596b0: 0x0 0x0
0x5555555596c0: 0x0 0x431
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x208b1
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
gef➤  c
Continuing.
[Inferior 1 (process 32854) exited with code 0320]
```

Just like that, using top chunk consolidation, and without freeing `chunk1`, we were able to relocate it.
