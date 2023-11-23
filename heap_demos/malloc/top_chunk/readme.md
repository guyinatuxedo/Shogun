## Top Chunk

So the purpose of this demo is to show two separate things. The first is allocation from the top chunk (the top chunk shrinking to make new chunks). The second is consolidating freed adjacent chunks into the top chunk (the top chunk increasing to consume freed adjacent chunks)

Here is the source code we will be stepping through:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x420

void main() {
    char *chunk;

    malloc(CHUNK_SIZE);
    
    chunk = malloc(CHUNK_SIZE);

    free(chunk);
}
```

So, this code will have two mallocs, and one free. The purpose of the first malloc, is to initialize the heap. The purpose of the second malloc is so we can allocate from the top chunk. The purpose of the free, is to see consolidation into the top chunk.

A few things. First off, the size of the chunk we are consolidating into the top chunk is `0x430` (the request size is `0x420`, but we'll see the chunk size is `0x430`). This is because the max tcache size is `0x420` (and the max fast bin size is below that). As such, the freed chunk will not be inserted into either (which would prevent it from being consolidated into the top chunk).

Secondly, the chunk we are consolidating into the top chunk via free, is directly adjacent to the top chunk. There are no chunks in between it and the top chunk.

#### Top Chunk Walkthrough

So starting off, we see that the heap has not been initialized right before the first malloc call:

```
$   gdb ./top_chunk 
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
Reading symbols from ./top_chunk...
(No debugging symbols found in ./top_chunk)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>: endbr64 
   0x000000000000116d <+4>: push   rbp
   0x000000000000116e <+5>: mov    rbp,rsp
   0x0000000000001171 <+8>: sub    rsp,0x10
   0x0000000000001175 <+12>:    mov    edi,0x420
   0x000000000000117a <+17>:    call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:    mov    edi,0x420
   0x0000000000001184 <+27>:    call   0x1070 <malloc@plt>
   0x0000000000001189 <+32>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000118d <+36>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001191 <+40>:    mov    rdi,rax
   0x0000000000001194 <+43>:    call   0x1060 <free@plt>
   0x0000000000001199 <+48>:    nop
   0x000000000000119a <+49>:    leave  
   0x000000000000119b <+50>:    ret    
End of assembler dump.
gef➤  b *main+17
Breakpoint 1 at 0x117a
gef➤  r
Starting program: /Hackery/shogun/heap_demos/malloc/top_chunk/top_chunk 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555517a in main ()








[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555169  →  <main+0> endbr64 
$rbx   : 0x0               
$rcx   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe421  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$rdi   : 0x420             
$rip   : 0x000055555555517a  →  <main+17> call 0x555555555070 <malloc@plt>
$r8    : 0x00007ffff7e1af10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  <_dl_fini+0> endbr64 
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x00007ffff7fde680  →  <_dl_audit_preinit+0> endbr64 
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555516e <main+5>         mov    rbp, rsp
   0x555555555171 <main+8>         sub    rsp, 0x10
   0x555555555175 <main+12>        mov    edi, 0x420
 → 0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <_start+0>       endbr64 
      0x555555555084 <_start+4>       xor    ebp, ebp
      0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000420
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x55555555517a in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x0,
  last_remainder = 0x0,
  bins = {0x0 <repeats 254 times>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x0,
  max_system_mem = 0x0
}
```

So, we step through and finish the malloc call, and see that `main_arena` was intialized:

```
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555169  →  <main+0> endbr64 
$rbx   : 0x0               
$rcx   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$rdx   : 0x00007fffffffe0f8  →  0x00007fffffffe421  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdfb8  →  0x000055555555517f  →  <main+22> mov edi, 0x420
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$rdi   : 0x420             
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64 
$r8    : 0x00007ffff7e1af10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  <_dl_fini+0> endbr64 
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x00007ffff7fde680  →  <_dl_audit_preinit+0> endbr64 
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb8│+0x0000: 0x000055555555517f  →  <main+22> mov edi, 0x420  ← $rsp
0x00007fffffffdfc0│+0x0008: 0x0000000000001000
0x00007fffffffdfc8│+0x0010: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0018: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0028: 0x0000000000000000
0x00007fffffffdfe8│+0x0030: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0038: 0x00000001ffffe0d0
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
[#0] Id 1, Name: "top_chunk", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
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
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555596c0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x000055555555517f  →  <main+22> mov edi, 0x420
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>         sub    rsp, 0x10
   0x555555555175 <main+12>        mov    edi, 0x420
   0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>        mov    edi, 0x420
   0x555555555184 <main+27>        call   0x555555555070 <malloc@plt>
   0x555555555189 <main+32>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555191 <main+40>        mov    rdi, rax
   0x555555555194 <main+43>        call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x55555555517f in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$2 = {
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
gef➤  x/10g  0x5555555596c0
0x5555555596c0: 0x0 0x20941
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
gef➤  
```

So we see that the top chunk is `0x5555555596c0`. Let's step through to the next malloc call, and see it allocate a chunk from the top chunk:

```
gef➤  si
0x0000555555555184 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555596c0  →  0x0000000000000000
$rdi   : 0x420             
$rip   : 0x0000555555555184  →  <main+27> call 0x555555555070 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555175 <main+12>        mov    edi, 0x420
   0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
   0x55555555517f <main+22>        mov    edi, 0x420
 → 0x555555555184 <main+27>        call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64 
      0x555555555074 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f55]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555507b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555080 <_start+0>       endbr64 
      0x555555555084 <_start+4>       xor    ebp, ebp
      0x555555555086 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000420
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x555555555184 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555184 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb8  →  0x0000555555555189  →  <main+32> mov QWORD PTR [rbp-0x8], rax
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x00005555555596c0  →  0x0000000000000000
$rdi   : 0x420             
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb8│+0x0000: 0x0000555555555189  →  <main+32> mov QWORD PTR [rbp-0x8], rax    ← $rsp
0x00007fffffffdfc0│+0x0008: 0x0000000000001000
0x00007fffffffdfc8│+0x0010: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0018: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0028: 0x0000000000000000
0x00007fffffffdfe8│+0x0030: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0038: 0x00000001ffffe0d0
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
[#0] Id 1, Name: "top_chunk", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x555555555189 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x0000555555555189 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x0000555555555189  →  <main+32> mov QWORD PTR [rbp-0x8], rax
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64 
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555517a <main+17>        call   0x555555555070 <malloc@plt>
   0x55555555517f <main+22>        mov    edi, 0x420
   0x555555555184 <main+27>        call   0x555555555070 <malloc@plt>
 → 0x555555555189 <main+32>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555191 <main+40>        mov    rdi, rax
   0x555555555194 <main+43>        call   0x555555555060 <free@plt>
   0x555555555199 <main+48>        nop    
   0x55555555519a <main+49>        leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x555555555189 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555189 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x5555555596d0
gef➤  p main_arena
$4 = {
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
gef➤  
```

So, we see that after our chunk allocation, the top chunk got moved down to `0x555555559af0`. We see the chunk size of our new malloc chunk is `0x430`. The top chunk used to be `0x5555555596c0`, which is `0x5555555596c0 - 0x555555559af0 = 0x430` bytes away from where the top chunk should be. Which is the same size as the malloc chunk we just allocated. This is because it carved out a block of memory for the chunk, allocated that, and moved the top chunk down. We also see, since we allocated a chunk from the top chunk, it is directly adjacent (as of right now), and there are no heap chunks between it, and the top chunk. We also see that the top chunk size got decremented to `0x20940 - 0x430 = 0x20510`, which is the size of the chunk.

Now, let's see free the `0x5555555596d0` chunk, so it will be reconsolidated back into the top chunk:

```
gef➤  si
0x000055555555518d in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x000055555555518d  →  <main+36> mov rax, QWORD PTR [rbp-0x8]
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555517f <main+22>        mov    edi, 0x420
   0x555555555184 <main+27>        call   0x555555555070 <malloc@plt>
   0x555555555189 <main+32>        mov    QWORD PTR [rbp-0x8], rax
 → 0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555191 <main+40>        mov    rdi, rax
   0x555555555194 <main+43>        call   0x555555555060 <free@plt>
   0x555555555199 <main+48>        nop    
   0x55555555519a <main+49>        leave  
   0x55555555519b <main+50>        ret    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x55555555518d in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555518d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555191 in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x0000555555555191  →  <main+40> mov rdi, rax
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555184 <main+27>        call   0x555555555070 <malloc@plt>
   0x555555555189 <main+32>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
 → 0x555555555191 <main+40>        mov    rdi, rax
   0x555555555194 <main+43>        call   0x555555555060 <free@plt>
   0x555555555199 <main+48>        nop    
   0x55555555519a <main+49>        leave  
   0x55555555519b <main+50>        ret    
   0x55555555519c <_fini+0>        endbr64 
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x555555555191 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555191 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555194 in main ()





[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x00005555555596d0  →  0x0000000000000000
$rip   : 0x0000555555555194  →  <main+43> call 0x555555555060 <free@plt>
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555189 <main+32>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555191 <main+40>        mov    rdi, rax
 → 0x555555555194 <main+43>        call   0x555555555060 <free@plt>
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
[#0] Id 1, Name: "top_chunk", stopped 0x555555555194 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555194 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555060 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfb8  →  0x0000555555555199  →  <main+48> nop 
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0000555555559af0  →  0x0000000000000000
$rdi   : 0x00005555555596d0  →  0x0000000000000000
$rip   : 0x0000555555555060  →  <free@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559af0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb8│+0x0000: 0x0000555555555199  →  <main+48> nop     ← $rsp
0x00007fffffffdfc0│+0x0008: 0x0000000000001000
0x00007fffffffdfc8│+0x0010: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfd0│+0x0018: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0028: 0x0000000000000000
0x00007fffffffdfe8│+0x0030: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0038: 0x00000001ffffe0d0
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
[#0] Id 1, Name: "top_chunk", stopped 0x555555555060 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555060 → free@plt()
[#1] 0x555555555199 → main()
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
gef➤  finish
Run till exit from #0  0x0000555555555060 in free@plt ()
0x0000555555555199 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x41              
$rdx   : 0xfffffffffffff000
$rsp   : 0x00007fffffffdfc0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfd0  →  0x0000000000000001
$rsi   : 0x0               
$rdi   : 0x20000           
$rip   : 0x0000555555555199  →  <main+48> nop 
$r8    : 0x21001           
$r9    : 0x00005555555596d0  →  0x0000000000000000
$r10   : 0x77              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555596c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64 
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfc0│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdfc8│+0x0008: 0x00005555555596d0  →  0x0000000000000000
0x00007fffffffdfd0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdfd8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfe0│+0x0020: 0x0000000000000000
0x00007fffffffdfe8│+0x0028: 0x0000555555555169  →  <main+0> endbr64 
0x00007fffffffdff0│+0x0030: 0x00000001ffffe0d0
0x00007fffffffdff8│+0x0038: 0x00007fffffffe0e8  →  0x00007fffffffe3e2  →  "/Hackery/shogun/heap_demos/malloc/top_chu[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555518d <main+36>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555191 <main+40>        mov    rdi, rax
   0x555555555194 <main+43>        call   0x555555555060 <free@plt>
 → 0x555555555199 <main+48>        nop    
   0x55555555519a <main+49>        leave  
   0x55555555519b <main+50>        ret    
   0x55555555519c <_fini+0>        endbr64 
   0x5555555551a0 <_fini+4>        sub    rsp, 0x8
   0x5555555551a4 <_fini+8>        add    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "top_chunk", stopped 0x555555555199 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555199 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$7 = {
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
gef➤  c
Continuing.
[Inferior 1 (process 9334) exited normally]
```

So, we see after freeing the chunk and having it consolidate back into the top chunk, we saw the top chunk move up from `0x555555559af0` back to `0x5555555596c0`, and the size of the top chunk increase back up to `0x20940`. So with that, we've seen a top chunk allocated from, and consolidate back into the top chunk.
