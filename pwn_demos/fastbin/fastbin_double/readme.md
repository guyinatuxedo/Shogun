# Fastbin Double

So the goal this time is to get malloc to allocate the same chunk multiple times without freeing it in between. This will be done via inserting the same chunk multiple times into the fastbin.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x50

void main() {
    int i;
    long *tcache_chunks[7];
    long *fastbin_chunk0,
            *fastbin_chunk1,
            *fastbin_chunk2,
            *reallocated_chunk0,
            *reallocated_chunk1,
            *reallocated_chunk2;

    printf("So this time around, our goal is to get malloc to allocate the same fastbin chunk multiple times.\n");
    printf("This will be done via executing a fastbin double free.\n");
    printf("Which is when we free the same chunk twice, and insert it into the fastbin.\n");
    printf("There is a check to catch chunks being inserted into the fastbin multiple times (double free).\n");
    printf("However, it will only check if the chunk being inserted is the same as the fastbin head chunk.\n");
    printf("So if we just free a chunk in between, we can free the same chunk twice.\n");
    printf("Also, since printf uses memory allocation, I will not use printf until the end, to avoid issues.\n\n");

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    fastbin_chunk0 = malloc(CHUNK_SIZE);
    fastbin_chunk1 = malloc(CHUNK_SIZE);
    fastbin_chunk2 = malloc(CHUNK_SIZE);


    malloc(CHUNK_SIZE);

    for (i = 0; i < 7; i++) {
        free(tcache_chunks[i]);
    }

    free(fastbin_chunk0);
    free(fastbin_chunk1);
    free(fastbin_chunk0);

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    reallocated_chunk0 = malloc(CHUNK_SIZE);
    reallocated_chunk1 = malloc(CHUNK_SIZE);
    reallocated_chunk2 = malloc(CHUNK_SIZE);

    printf("Reallocated Chunk 0:\t%p\n", reallocated_chunk0);
    printf("Reallocated Chunk 1:\t%p\n", reallocated_chunk1);
    printf("Reallocated Chunk 2:\t%p\n\n", reallocated_chunk2);

    printf("Malloc allocated the same chunk multiple times?\t%s\n", (reallocated_chunk0 == reallocated_chunk2) ? "True" : "False");

}
```

## Walkthrough

So our goal is to get malloc to allocate the same chunk multiple times via inserting the same chunk into the fastbin multiple times. The issue with this, is similar to the tcache, there is a check to help prevent this very thing (double free). This check is when a new chunk is being inserted into the fastbin, that it isn't the same as the current fastbin head. However this will only catch double frees where the same chunk is being inserted into the fastbin, without any chunks in between. So if we simply free a chunk in between the double free, it will work just fine.

Let's see this in action:

```
$   gdb ./fastbin_double
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
Reading symbols from ./fastbin_double...
(No debugging symbols found in ./fastbin_double)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011c9 <+0>: endbr64
   0x00000000000011cd <+4>: push   rbp
   0x00000000000011ce <+5>: mov rbp,rsp
   0x00000000000011d1 <+8>: add rsp,0xffffffffffffff80
   0x00000000000011d5 <+12>:    mov rax,QWORD PTR fs:0x28
   0x00000000000011de <+21>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011e2 <+25>:    xor eax,eax
   0x00000000000011e4 <+27>:    lea rax,[rip+0xe1d]     # 0x2008
   0x00000000000011eb <+34>:    mov rdi,rax
   0x00000000000011ee <+37>:    call   0x10a0 <puts@plt>
   0x00000000000011f3 <+42>:    lea rax,[rip+0xe76]     # 0x2070
   0x00000000000011fa <+49>:    mov rdi,rax
   0x00000000000011fd <+52>:    call   0x10a0 <puts@plt>
   0x0000000000001202 <+57>:    lea rax,[rip+0xe9f]     # 0x20a8
   0x0000000000001209 <+64>:    mov rdi,rax
   0x000000000000120c <+67>:    call   0x10a0 <puts@plt>
   0x0000000000001211 <+72>:    lea rax,[rip+0xee0]     # 0x20f8
   0x0000000000001218 <+79>:    mov rdi,rax
   0x000000000000121b <+82>:    call   0x10a0 <puts@plt>
   0x0000000000001220 <+87>:    lea rax,[rip+0xf31]     # 0x2158
   0x0000000000001227 <+94>:    mov rdi,rax
   0x000000000000122a <+97>:    call   0x10a0 <puts@plt>
   0x000000000000122f <+102>:   lea rax,[rip+0xf82]     # 0x21b8
   0x0000000000001236 <+109>:   mov rdi,rax
   0x0000000000001239 <+112>:   call   0x10a0 <puts@plt>
   0x000000000000123e <+117>:   lea rax,[rip+0xfc3]     # 0x2208
   0x0000000000001245 <+124>:   mov rdi,rax
   0x0000000000001248 <+127>:   call   0x10a0 <puts@plt>
   0x000000000000124d <+132>:   mov DWORD PTR [rbp-0x74],0x0
   0x0000000000001254 <+139>:   jmp 0x1271 <main+168>
   0x0000000000001256 <+141>:   mov edi,0x50
   0x000000000000125b <+146>:   call   0x10d0 <malloc@plt>
   0x0000000000001260 <+151>:   mov rdx,rax
   0x0000000000001263 <+154>:   mov eax,DWORD PTR [rbp-0x74]
   0x0000000000001266 <+157>:   cdqe   
   0x0000000000001268 <+159>:   mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x000000000000126d <+164>:   add DWORD PTR [rbp-0x74],0x1
   0x0000000000001271 <+168>:   cmp DWORD PTR [rbp-0x74],0x6
   0x0000000000001275 <+172>:   jle 0x1256 <main+141>
   0x0000000000001277 <+174>:   mov edi,0x50
   0x000000000000127c <+179>:   call   0x10d0 <malloc@plt>
   0x0000000000001281 <+184>:   mov QWORD PTR [rbp-0x70],rax
   0x0000000000001285 <+188>:   mov edi,0x50
   0x000000000000128a <+193>:   call   0x10d0 <malloc@plt>
   0x000000000000128f <+198>:   mov QWORD PTR [rbp-0x68],rax
   0x0000000000001293 <+202>:   mov edi,0x50
   0x0000000000001298 <+207>:   call   0x10d0 <malloc@plt>
   0x000000000000129d <+212>:   mov QWORD PTR [rbp-0x60],rax
   0x00000000000012a1 <+216>:   mov edi,0x50
   0x00000000000012a6 <+221>:   call   0x10d0 <malloc@plt>
   0x00000000000012ab <+226>:   mov DWORD PTR [rbp-0x74],0x0
   0x00000000000012b2 <+233>:   jmp 0x12ca <main+257>
   0x00000000000012b4 <+235>:   mov eax,DWORD PTR [rbp-0x74]
   0x00000000000012b7 <+238>:   cdqe   
   0x00000000000012b9 <+240>:   mov rax,QWORD PTR [rbp+rax*8-0x40]
   0x00000000000012be <+245>:   mov rdi,rax
   0x00000000000012c1 <+248>:   call   0x1090 <free@plt>
   0x00000000000012c6 <+253>:   add DWORD PTR [rbp-0x74],0x1
   0x00000000000012ca <+257>:   cmp DWORD PTR [rbp-0x74],0x6
   0x00000000000012ce <+261>:   jle 0x12b4 <main+235>
   0x00000000000012d0 <+263>:   mov rax,QWORD PTR [rbp-0x70]
   0x00000000000012d4 <+267>:   mov rdi,rax
   0x00000000000012d7 <+270>:   call   0x1090 <free@plt>
   0x00000000000012dc <+275>:   mov rax,QWORD PTR [rbp-0x68]
   0x00000000000012e0 <+279>:   mov rdi,rax
   0x00000000000012e3 <+282>:   call   0x1090 <free@plt>
   0x00000000000012e8 <+287>:   mov rax,QWORD PTR [rbp-0x70]
   0x00000000000012ec <+291>:   mov rdi,rax
   0x00000000000012ef <+294>:   call   0x1090 <free@plt>
   0x00000000000012f4 <+299>:   mov DWORD PTR [rbp-0x74],0x0
   0x00000000000012fb <+306>:   jmp 0x1318 <main+335>
   0x00000000000012fd <+308>:   mov edi,0x50
   0x0000000000001302 <+313>:   call   0x10d0 <malloc@plt>
   0x0000000000001307 <+318>:   mov rdx,rax
   0x000000000000130a <+321>:   mov eax,DWORD PTR [rbp-0x74]
   0x000000000000130d <+324>:   cdqe   
   0x000000000000130f <+326>:   mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x0000000000001314 <+331>:   add DWORD PTR [rbp-0x74],0x1
   0x0000000000001318 <+335>:   cmp DWORD PTR [rbp-0x74],0x6
   0x000000000000131c <+339>:   jle 0x12fd <main+308>
   0x000000000000131e <+341>:   mov edi,0x50
   0x0000000000001323 <+346>:   call   0x10d0 <malloc@plt>
   0x0000000000001328 <+351>:   mov QWORD PTR [rbp-0x58],rax
   0x000000000000132c <+355>:   mov edi,0x50
   0x0000000000001331 <+360>:   call   0x10d0 <malloc@plt>
   0x0000000000001336 <+365>:   mov QWORD PTR [rbp-0x50],rax
   0x000000000000133a <+369>:   mov edi,0x50
   0x000000000000133f <+374>:   call   0x10d0 <malloc@plt>
   0x0000000000001344 <+379>:   mov QWORD PTR [rbp-0x48],rax
   0x0000000000001348 <+383>:   mov rax,QWORD PTR [rbp-0x58]
   0x000000000000134c <+387>:   mov rsi,rax
   0x000000000000134f <+390>:   lea rax,[rip+0xf14]     # 0x226a
   0x0000000000001356 <+397>:   mov rdi,rax
   0x0000000000001359 <+400>:   mov eax,0x0
   0x000000000000135e <+405>:   call   0x10c0 <printf@plt>
   0x0000000000001363 <+410>:   mov rax,QWORD PTR [rbp-0x50]
   0x0000000000001367 <+414>:   mov rsi,rax
   0x000000000000136a <+417>:   lea rax,[rip+0xf12]     # 0x2283
   0x0000000000001371 <+424>:   mov rdi,rax
   0x0000000000001374 <+427>:   mov eax,0x0
   0x0000000000001379 <+432>:   call   0x10c0 <printf@plt>
   0x000000000000137e <+437>:   mov rax,QWORD PTR [rbp-0x48]
   0x0000000000001382 <+441>:   mov rsi,rax
   0x0000000000001385 <+444>:   lea rax,[rip+0xf10]     # 0x229c
   0x000000000000138c <+451>:   mov rdi,rax
   0x000000000000138f <+454>:   mov eax,0x0
   0x0000000000001394 <+459>:   call   0x10c0 <printf@plt>
   0x0000000000001399 <+464>:   mov rax,QWORD PTR [rbp-0x58]
   0x000000000000139d <+468>:   cmp rax,QWORD PTR [rbp-0x48]
   0x00000000000013a1 <+472>:   jne 0x13ac <main+483>
   0x00000000000013a3 <+474>:   lea rax,[rip+0xf0c]     # 0x22b6
   0x00000000000013aa <+481>:   jmp 0x13b3 <main+490>
   0x00000000000013ac <+483>:   lea rax,[rip+0xf08]     # 0x22bb
   0x00000000000013b3 <+490>:   mov rsi,rax
   0x00000000000013b6 <+493>:   lea rax,[rip+0xf0b]     # 0x22c8
   0x00000000000013bd <+500>:   mov rdi,rax
   0x00000000000013c0 <+503>:   mov eax,0x0
   0x00000000000013c5 <+508>:   call   0x10c0 <printf@plt>
   0x00000000000013ca <+513>:   nop
   0x00000000000013cb <+514>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000013cf <+518>:   sub rax,QWORD PTR fs:0x28
   0x00000000000013d8 <+527>:   je  0x13df <main+534>
   0x00000000000013da <+529>:   call   0x10b0 <__stack_chk_fail@plt>
   0x00000000000013df <+534>:   leave  
   0x00000000000013e0 <+535>:   ret    
End of assembler dump.
gef➤  b *main+267
Breakpoint 1 at 0x12d4
gef➤  b *main+299
Breakpoint 2 at 0x12f4
gef➤  b *main+346
Breakpoint 3 at 0x1323
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/fastbin/fastbin_double/fastbin_double
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
So this time around, our goal is to get malloc to allocate the same fastbin chunk multiple times.
This will be done via executing a fastbin double free.
Which is when we free the same chunk twice, and insert it into the fastbin.
There is a check to catch chunks being inserted into the fastbin multiple times (double free).
However, it will only check if the chunk being inserted is the same as the fastbin head chunk.
So if we just free a chunk in between, we can free the same chunk twice.
Also, since printf uses memory allocation, I will not use printf until the end, to avoid issues.


Breakpoint 1, 0x00005555555552d4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x4             
$rdx   : 0x55500000cdc9    
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x6             
$rip   : 0x00005555555552d4  →  <main+267> mov rdi, rax
$r8 : 0x7            
$r9 : 0x00005555555598f0  →  0x000055500000cdc9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000000000000
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ca <main+257>    cmp DWORD PTR [rbp-0x74], 0x6
   0x5555555552ce <main+261>    jle 0x5555555552b4 <main+235>
   0x5555555552d0 <main+263>    mov rax, QWORD PTR [rbp-0x70]
 → 0x5555555552d4 <main+267>    mov rdi, rax
   0x5555555552d7 <main+270>    call   0x555555555090 <free@plt>
   0x5555555552dc <main+275>    mov rax, QWORD PTR [rbp-0x68]
   0x5555555552e0 <main+279>    mov rdi, rax
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552d4 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555598f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559710, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  si
0x00005555555552d7 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x4             
$rdx   : 0x55500000cdc9    
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x0000555555559950  →  0x0000000000000000
$rip   : 0x00005555555552d7  →  <main+270> call 0x555555555090 <free@plt>
$r8 : 0x7            
$r9 : 0x00005555555598f0  →  0x000055500000cdc9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000000000000
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ce <main+261>    jle 0x5555555552b4 <main+235>
   0x5555555552d0 <main+263>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552d4 <main+267>    mov rdi, rax
 → 0x5555555552d7 <main+270>    call   0x555555555090 <free@plt>
   ↳  0x555555555090 <free@plt+0>   endbr64
    0x555555555094 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
    0x55555555509b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <puts@plt+0>     endbr64
    0x5555555550a4 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
    0x5555555550ab <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559950 → 0x0000000000000000,
   $rsi = 0x0000000000000007,
   $rdx = 0x000055500000cdc9
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552d7 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d7 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$1 = 0x555555559950
gef➤  si
0x0000555555555090 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x4             
$rdx   : 0x55500000cdc9    
$rsp   : 0x00007fffffffdf38  →  0x00005555555552dc  →  <main+275> mov rax, QWORD PTR [rbp-0x68]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x0000555555559950  →  0x0000000000000000
$rip   : 0x0000555555555090  →  <free@plt+0> endbr64
$r8 : 0x7            
$r9 : 0x00005555555598f0  →  0x000055500000cdc9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x00005555555552dc  →  <main+275> mov rax, QWORD PTR [rbp-0x68]  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x0000000000000000
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000000000000002
0x00007fffffffdf70│+0x0038: 0xffffffffffffffff
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__cxa_finalize@plt+0> endbr64
   0x555555555084 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f6d]      # 0x555555557ff8
   0x55555555508b <__cxa_finalize@plt+11> nop   DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <free@plt+0>  endbr64
   0x555555555094 <free@plt+4>  bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
   0x55555555509b <free@plt+11> nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <puts@plt+0>  endbr64
   0x5555555550a4 <puts@plt+4>  bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
   0x5555555550ab <puts@plt+11> nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555090 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → free@plt()
[#1] 0x5555555552dc → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in free@plt ()
0x00005555555552dc in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x555555559     
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x7             
$rip   : 0x00005555555552dc  →  <main+275> mov rax, QWORD PTR [rbp-0x68]
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x0000000555555559
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d0 <main+263>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552d4 <main+267>    mov rdi, rax
   0x5555555552d7 <main+270>    call   0x555555555090 <free@plt>
 → 0x5555555552dc <main+275>    mov rax, QWORD PTR [rbp-0x68]
   0x5555555552e0 <main+279>    mov rdi, rax
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552ec <main+291>    mov rdi, rax
   0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552dc in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552dc → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552e0 in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x555555559     
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x7             
$rip   : 0x00005555555552e0  →  <main+279> mov rdi, rax
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x0000000555555559
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d4 <main+267>    mov rdi, rax
   0x5555555552d7 <main+270>    call   0x555555555090 <free@plt>
   0x5555555552dc <main+275>    mov rax, QWORD PTR [rbp-0x68]
 → 0x5555555552e0 <main+279>    mov rdi, rax
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552ec <main+291>    mov rdi, rax
   0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
   0x5555555552f4 <main+299>    mov DWORD PTR [rbp-0x74], 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552e0 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e0 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552e3 in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x555555559     
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x00005555555599b0  →  0x0000000000000000
$rip   : 0x00005555555552e3  →  <main+282> call 0x555555555090 <free@plt>
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x0000000555555559
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d7 <main+270>    call   0x555555555090 <free@plt>
   0x5555555552dc <main+275>    mov rax, QWORD PTR [rbp-0x68]
   0x5555555552e0 <main+279>    mov rdi, rax
 → 0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   ↳  0x555555555090 <free@plt+0>   endbr64
    0x555555555094 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
    0x55555555509b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <puts@plt+0>     endbr64
    0x5555555550a4 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
    0x5555555550ab <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555599b0 → 0x0000000000000000,
   $rsi = 0x0000000000000007,
   $rdx = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552e3 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e3 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$2 = 0x5555555599b0
gef➤  si
0x0000555555555090 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x555555559     
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf38  →  0x00005555555552e8  →  <main+287> mov rax, QWORD PTR [rbp-0x70]
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x00005555555599b0  →  0x0000000000000000
$rip   : 0x0000555555555090  →  <free@plt+0> endbr64
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x0000000555555559
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x00005555555552e8  →  <main+287> mov rax, QWORD PTR [rbp-0x70]  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000000000000002
0x00007fffffffdf70│+0x0038: 0xffffffffffffffff
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__cxa_finalize@plt+0> endbr64
   0x555555555084 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f6d]      # 0x555555557ff8
   0x55555555508b <__cxa_finalize@plt+11> nop   DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <free@plt+0>  endbr64
   0x555555555094 <free@plt+4>  bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
   0x55555555509b <free@plt+11> nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <puts@plt+0>  endbr64
   0x5555555550a4 <puts@plt+4>  bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
   0x5555555550ab <puts@plt+11> nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555090 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → free@plt()
[#1] 0x5555555552e8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in free@plt ()
0x00005555555552e8 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x55500000cc19    
$rdx   : 0x0000555555559940  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x7             
$rip   : 0x00005555555552e8  →  <main+287> mov rax, QWORD PTR [rbp-0x70]
$r8 : 0x7            
$r9 : 0x00005555555599b0  →  0x000055500000cc19
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552dc <main+275>    mov rax, QWORD PTR [rbp-0x68]
   0x5555555552e0 <main+279>    mov rdi, rax
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
 → 0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552ec <main+291>    mov rdi, rax
   0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
   0x5555555552f4 <main+299>    mov DWORD PTR [rbp-0x74], 0x0
   0x5555555552fb <main+306>    jmp 0x555555555318 <main+335>
   0x5555555552fd <main+308>    mov edi, 0x50
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552e8 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e8 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552ec in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x55500000cc19    
$rdx   : 0x0000555555559940  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x7             
$rip   : 0x00005555555552ec  →  <main+291> mov rdi, rax
$r8 : 0x7            
$r9 : 0x00005555555599b0  →  0x000055500000cc19
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e0 <main+279>    mov rdi, rax
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
 → 0x5555555552ec <main+291>    mov rdi, rax
   0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
   0x5555555552f4 <main+299>    mov DWORD PTR [rbp-0x74], 0x0
   0x5555555552fb <main+306>    jmp 0x555555555318 <main+335>
   0x5555555552fd <main+308>    mov edi, 0x50
   0x555555555302 <main+313>    call   0x5555555550d0 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552ec in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ec → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555552ef in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x55500000cc19    
$rdx   : 0x0000555555559940  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x0000555555559950  →  0x0000000555555559
$rip   : 0x00005555555552ef  →  <main+294> call 0x555555555090 <free@plt>
$r8 : 0x7            
$r9 : 0x00005555555599b0  →  0x000055500000cc19
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e3 <main+282>    call   0x555555555090 <free@plt>
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552ec <main+291>    mov rdi, rax
 → 0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
   ↳  0x555555555090 <free@plt+0>   endbr64
    0x555555555094 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
    0x55555555509b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <puts@plt+0>     endbr64
    0x5555555550a4 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
    0x5555555550ab <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559950 → 0x0000000555555559,
   $rsi = 0x0000000000000007,
   $rdx = 0x0000555555559940 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552ef in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ef → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$3 = 0x555555559950
gef➤  si
0x0000555555555090 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x55500000cc19    
$rdx   : 0x0000555555559940  →  0x0000000000000000
$rsp   : 0x00007fffffffdf38  →  0x00005555555552f4  →  <main+299> mov DWORD PTR [rbp-0x74], 0x0
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x0000555555559950  →  0x0000000555555559
$rip   : 0x0000555555555090  →  <free@plt+0> endbr64
$r8 : 0x7            
$r9 : 0x00005555555599b0  →  0x000055500000cc19
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x00005555555552f4  →  <main+299> mov DWORD PTR [rbp-0x74], 0x0  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000000000000002
0x00007fffffffdf70│+0x0038: 0xffffffffffffffff
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555080 <__cxa_finalize@plt+0> endbr64
   0x555555555084 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f6d]      # 0x555555557ff8
   0x55555555508b <__cxa_finalize@plt+11> nop   DWORD PTR [rax+rax*1+0x0]
 → 0x555555555090 <free@plt+0>  endbr64
   0x555555555094 <free@plt+4>  bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
   0x55555555509b <free@plt+11> nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <puts@plt+0>  endbr64
   0x5555555550a4 <puts@plt+4>  bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
   0x5555555550ab <puts@plt+11> nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555090 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → free@plt()
[#1] 0x5555555552f4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in free@plt ()

Breakpoint 2, 0x00005555555552f4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x55500000ccf9    
$rdx   : 0x00005555555599a0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7             
$rdi   : 0x7             
$rip   : 0x00005555555552f4  →  <main+299> mov DWORD PTR [rbp-0x74], 0x0
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x000055500000ccf9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000ccf9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e8 <main+287>    mov rax, QWORD PTR [rbp-0x70]
   0x5555555552ec <main+291>    mov rdi, rax
   0x5555555552ef <main+294>    call   0x555555555090 <free@plt>
 → 0x5555555552f4 <main+299>    mov DWORD PTR [rbp-0x74], 0x0
   0x5555555552fb <main+306>    jmp 0x555555555318 <main+335>
   0x5555555552fd <main+308>    mov edi, 0x50
   0x555555555302 <main+313>    call   0x5555555550d0 <malloc@plt>
   0x555555555307 <main+318>    mov rdx, rax
   0x55555555530a <main+321>    mov eax, DWORD PTR [rbp-0x74]
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555552f4 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552f4 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555598f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559710, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7ffff7e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see here, and the three frees that lead to it, that we were able to free the `0x555555559950` chunk twice, and insert it into the fastbin. Now, as we can see this created a loop. This is because chunk 0 in that fastbin points to chunk 1, and chunk 1 points to chunk 0.

Now, we will empty the tcache so we can allocate chunks from the fastbin. After we allocate the first chunk from the fastbin, those chunks would get moved over to the tcache. We will see, the infinite loop stays intact in the tcache. However, we can still allocate the same chunk multiple times:

```
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555323 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x00005555555596b0  →  0x0000000555555559
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x50            
$rip   : 0x0000555555555323  →  <main+346> call 0x5555555550d0 <malloc@plt>
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x000055500000ccf9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000ccf9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555318 <main+335>    cmp DWORD PTR [rbp-0x74], 0x6
   0x55555555531c <main+339>    jle 0x5555555552fd <main+308>
   0x55555555531e <main+341>    mov edi, 0x50
 → 0x555555555323 <main+346>    call   0x5555555550d0 <malloc@plt>
   ↳  0x5555555550d0 <malloc@plt+0>   endbr64
    0x5555555550d4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
    0x5555555550db <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550e0 <_start+0>       endbr64
    0x5555555550e4 <_start+4>       xor ebp, ebp
    0x5555555550e6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000050,
   $rsi = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555323 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555323 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e2cca0 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x00005555555550d0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x00005555555596b0  →  0x0000000555555559
$rsp   : 0x00007fffffffdf38  →  0x0000555555555328  →  <main+351> mov QWORD PTR [rbp-0x58], rax
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x50            
$rip   : 0x00005555555550d0  →  <malloc@plt+0> endbr64
$r8 : 0x7            
$r9 : 0x0000555555559950  →  0x000055500000ccf9
$r10   : 0x93c7839f1b10db3a
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x0000555555555328  →  <main+351> mov QWORD PTR [rbp-0x58], rax  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x000055500000ccf9
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000000000000002
0x00007fffffffdf70│+0x0038: 0xffffffffffffffff
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550c0 <printf@plt+0>   endbr64
   0x5555555550c4 <printf@plt+4>   bnd  jmp QWORD PTR [rip+0x2efd]      # 0x555555557fc8 <printf@got.plt>
   0x5555555550cb <printf@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550d0 <malloc@plt+0>   endbr64
   0x5555555550d4 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
   0x5555555550db <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
   0x5555555550e0 <_start+0>    endbr64
   0x5555555550e4 <_start+4>    xor ebp, ebp
   0x5555555550e6 <_start+6>    mov r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555550d0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550d0 → malloc@plt()
[#1] 0x555555555328 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550d0 in malloc@plt ()
0x0000555555555328 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x000055500000cce9
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2ccd0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e2ccc0  →  0x0000000000000000
$rip   : 0x0000555555555328  →  <main+351> mov QWORD PTR [rbp-0x58], rax
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000000000000002
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555531c <main+339>    jle 0x5555555552fd <main+308>
   0x55555555531e <main+341>    mov edi, 0x50
   0x555555555323 <main+346>    call   0x5555555550d0 <malloc@plt>
 → 0x555555555328 <main+351>    mov QWORD PTR [rbp-0x58], rax
   0x55555555532c <main+355>    mov edi, 0x50
   0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
   0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
   0x55555555533a <main+369>    mov edi, 0x50
   0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555328 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555328 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x555555559950
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=2] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
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
gef➤  si
0x000055555555532c in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x000055500000cce9
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2ccd0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e2ccc0  →  0x0000000000000000
$rip   : 0x000055555555532c  →  <main+355> mov edi, 0x50
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555531e <main+341>    mov edi, 0x50
   0x555555555323 <main+346>    call   0x5555555550d0 <malloc@plt>
   0x555555555328 <main+351>    mov QWORD PTR [rbp-0x58], rax
 → 0x55555555532c <main+355>    mov edi, 0x50
   0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
   0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
   0x55555555533a <main+369>    mov edi, 0x50
   0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
   0x555555555344 <main+379>    mov QWORD PTR [rbp-0x48], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x55555555532c in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555532c → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555331 in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x000055500000cce9
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2ccd0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x50            
$rip   : 0x0000555555555331  →  <main+360> call 0x5555555550d0 <malloc@plt>
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555323 <main+346>    call   0x5555555550d0 <malloc@plt>
   0x555555555328 <main+351>    mov QWORD PTR [rbp-0x58], rax
   0x55555555532c <main+355>    mov edi, 0x50
 → 0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
   ↳  0x5555555550d0 <malloc@plt+0>   endbr64
    0x5555555550d4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
    0x5555555550db <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550e0 <_start+0>       endbr64
    0x5555555550e4 <_start+4>       xor ebp, ebp
    0x5555555550e6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000050,
   $rsi = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555331 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555331 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555550d0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x000055500000cce9
$rbx   : 0x0             
$rcx   : 0x00007ffff7e2ccd0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf38  →  0x0000555555555336  →  <main+365> mov QWORD PTR [rbp-0x50], rax
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x50            
$rip   : 0x00005555555550d0  →  <malloc@plt+0> endbr64
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x0000555555555336  →  <main+365> mov QWORD PTR [rbp-0x50], rax  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0038: 0xffffffffffffffff
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550c0 <printf@plt+0>   endbr64
   0x5555555550c4 <printf@plt+4>   bnd  jmp QWORD PTR [rip+0x2efd]      # 0x555555557fc8 <printf@got.plt>
   0x5555555550cb <printf@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550d0 <malloc@plt+0>   endbr64
   0x5555555550d4 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
   0x5555555550db <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
   0x5555555550e0 <_start+0>    endbr64
   0x5555555550e4 <_start+4>    xor ebp, ebp
   0x5555555550e6 <_start+6>    mov r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555550d0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550d0 → malloc@plt()
[#1] 0x555555555336 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550d0 in malloc@plt ()
0x0000555555555336 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x000055500000cc09
$rbx   : 0x0             
$rcx   : 0x2             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559950  →  0x000055500000cce9
$rdi   : 0x14            
$rip   : 0x0000555555555336  →  <main+365> mov QWORD PTR [rbp-0x50], rax
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0xffffffffffffffff
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555328 <main+351>    mov QWORD PTR [rbp-0x58], rax
   0x55555555532c <main+355>    mov edi, 0x50
   0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
 → 0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
   0x55555555533a <main+369>    mov edi, 0x50
   0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
   0x555555555344 <main+379>    mov QWORD PTR [rbp-0x48], rax
   0x555555555348 <main+383>    mov rax, QWORD PTR [rbp-0x58]
   0x55555555534c <main+387>    mov rsi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555336 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555336 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$5 = 0x5555555599b0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=2] ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
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
gef➤  si
0x000055555555533a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x000055500000cc09
$rbx   : 0x0             
$rcx   : 0x2             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559950  →  0x000055500000cce9
$rdi   : 0x14            
$rip   : 0x000055555555533a  →  <main+369> mov edi, 0x50
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555532c <main+355>    mov edi, 0x50
   0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
   0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
 → 0x55555555533a <main+369>    mov edi, 0x50
   0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
   0x555555555344 <main+379>    mov QWORD PTR [rbp-0x48], rax
   0x555555555348 <main+383>    mov rax, QWORD PTR [rbp-0x58]
   0x55555555534c <main+387>    mov rsi, rax
   0x55555555534f <main+390>    lea rax, [rip+0xf14]        # 0x55555555626a
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x55555555533a in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555533a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055555555533f in main ()






[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x000055500000cc09
$rbx   : 0x0             
$rcx   : 0x2             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559950  →  0x000055500000cce9
$rdi   : 0x50            
$rip   : 0x000055555555533f  →  <main+374> call 0x5555555550d0 <malloc@plt>
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555331 <main+360>    call   0x5555555550d0 <malloc@plt>
   0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
   0x55555555533a <main+369>    mov edi, 0x50
 → 0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
   ↳  0x5555555550d0 <malloc@plt+0>   endbr64
    0x5555555550d4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
    0x5555555550db <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550e0 <_start+0>       endbr64
    0x5555555550e4 <_start+4>       xor ebp, ebp
    0x5555555550e6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000050,
   $rsi = 0x0000555555559950 → 0x000055500000cce9
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x55555555533f in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555533f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x00005555555550d0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599b0  →  0x000055500000cc09
$rbx   : 0x0             
$rcx   : 0x2             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf38  →  0x0000555555555344  →  <main+379> mov QWORD PTR [rbp-0x48], rax
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559950  →  0x000055500000cce9
$rdi   : 0x50            
$rip   : 0x00005555555550d0  →  <malloc@plt+0> endbr64
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf38│+0x0000: 0x0000555555555344  →  <main+379> mov QWORD PTR [rbp-0x48], rax  ← $rsp
0x00007fffffffdf40│+0x0008: 0x0000000000000000
0x00007fffffffdf48│+0x0010: 0x0000000700000000
0x00007fffffffdf50│+0x0018: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0020: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0028: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0030: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0038: 0x00005555555599b0  →  0x000055500000cc09
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550c0 <printf@plt+0>   endbr64
   0x5555555550c4 <printf@plt+4>   bnd  jmp QWORD PTR [rip+0x2efd]      # 0x555555557fc8 <printf@got.plt>
   0x5555555550cb <printf@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550d0 <malloc@plt+0>   endbr64
   0x5555555550d4 <malloc@plt+4>   bnd  jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
   0x5555555550db <malloc@plt+11>  nop  DWORD PTR [rax+rax*1+0x0]
   0x5555555550e0 <_start+0>    endbr64
   0x5555555550e4 <_start+4>    xor ebp, ebp
   0x5555555550e6 <_start+6>    mov r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x5555555550d0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550d0 → malloc@plt()
[#1] 0x555555555344 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550d0 in malloc@plt ()
0x0000555555555344 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559950  →  0x000055500000cce9
$rbx   : 0x0             
$rcx   : 0x1             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00005555555599b0  →  0x000055500000cc09
$rdi   : 0x14            
$rip   : 0x0000555555555344  →  <main+379> mov QWORD PTR [rbp-0x48], rax
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x00005555555599b0  →  0x000055500000cc09
$r10   : 0x4             
$r11   : 0x14            
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557d90  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000000700000000
0x00007fffffffdf50│+0x0010: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf58│+0x0018: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf60│+0x0020: 0x0000555555559a10  →  0x0000000000000000
0x00007fffffffdf68│+0x0028: 0x0000555555559950  →  0x000055500000cce9
0x00007fffffffdf70│+0x0030: 0x00005555555599b0  →  0x000055500000cc09
0x00007fffffffdf78│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555336 <main+365>    mov QWORD PTR [rbp-0x50], rax
   0x55555555533a <main+369>    mov edi, 0x50
   0x55555555533f <main+374>    call   0x5555555550d0 <malloc@plt>
 → 0x555555555344 <main+379>    mov QWORD PTR [rbp-0x48], rax
   0x555555555348 <main+383>    mov rax, QWORD PTR [rbp-0x58]
   0x55555555534c <main+387>    mov rsi, rax
   0x55555555534f <main+390>    lea rax, [rip+0xf14]        # 0x55555555626a
   0x555555555356 <main+397>    mov rdi, rax
   0x555555555359 <main+400>    mov eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_double", stopped 0x555555555344 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555344 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$6 = 0x555555559950
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=2] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
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
gef➤  c
Continuing.
Reallocated Chunk 0:    0x555555559950
Reallocated Chunk 1:    0x5555555599b0
Reallocated Chunk 2:    0x555555559950

Malloc allocated the same chunk multiple times? True
[Inferior 1 (process 83999) exited normally]
```

Just like that, we see that we have managed to allocate the same chunk twice. Interestingly enough, we see that the loop remains intact. As long as we don't write over the next ptr for those chunks, we should be able to continually allocate the same two chunks (as long as there isn't a check that prevents it).
