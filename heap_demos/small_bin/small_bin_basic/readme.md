## small bin basic

So, in this instance, we will be showing the basics of the `small bin`. We will be showing insertions, and removals into the `unsorted bin`.

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x200
#define CHUNK_SIZE1 0x20
#define CHUNK_SIZE2 0x600

void main() {
   char *chunk0,
   *chunk1,
   *chunk2,
   *chunk3,
   *chunk4,
   *chunk5,
   *chunk6,
   *chunk7,
   *chunk8,
   *chunk9,
   *chunk10;

   puts("\n\nLet's fill up the tcache!\n\n");

   chunk0 = malloc(CHUNK_SIZE0);
   chunk1 = malloc(CHUNK_SIZE0);
   chunk2 = malloc(CHUNK_SIZE0);
   chunk3 = malloc(CHUNK_SIZE0);
   chunk4 = malloc(CHUNK_SIZE0);
   chunk5 = malloc(CHUNK_SIZE0);
   chunk6 = malloc(CHUNK_SIZE0);
   chunk7 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk8 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk9 = malloc(CHUNK_SIZE0);
   malloc(CHUNK_SIZE1);
   chunk10 = malloc(CHUNK_SIZE2);
   malloc(CHUNK_SIZE1);

   free(chunk0);
   free(chunk1);
   free(chunk2);
   free(chunk3);
   free(chunk4);
   free(chunk5);
   free(chunk6);

   puts("\n\nThe tcache has been filled up! Let's insert chunks into the unsorted bin now!\n\n");

   free(chunk7);
   free(chunk8);
   free(chunk9);

   puts("\n\nLet's empty the tcache now, so we can allocated chunks from the small bin\n\n");

   for (int i = 0; i < 7; i++) {
   malloc(CHUNK_SIZE0);
   }

   puts("\n\nLet's allocate our first chunk from the small bin!\n\n");

   malloc(CHUNK_SIZE0 - 0x10);

   puts("\n\nLet's insert another chunk into the unsorted bin (not small bin size)!\n\n");

   free(chunk10);

   puts("\n\nLet's allocate our second chunk from the small bin!\n\n");

   malloc(CHUNK_SIZE0);
}
```

#### small bin basic walkthrough


So a bit about the small bin first. The small bin is a part of the bin array in the main arena. All chunks inserted into it, are removed from the unsorted bin durring the unsorted bin iteration in malloc (assuming the malloc code path hits that part).

Each small bin correlates to a specific size, and all of the sizes have overlap with the tcache (and there is some overlap with the fastbin, but ). Since the tcache has priority for both insertions / removals, we will need to both fill up and empty the tcache to actually get insertions/allocations from the small bin.

So, there are two places where small bin chunks can be allocated via malloc. The first is before the unsorted bin iteration. The second, is after the unsorted bin iteration happens, it will check if there is a smallbin chunk size that can service the request. For the allocation prior to the unsorted bin iteration, it will check for an exact size match. For after the iteration, it will simply check for the next biggest smallbin chunk size.

Our code will work in this manner. First, we will allocate all of the chunks we need. Then, we will free chunks, to fill up the corresponding tcache bin, for the size of the small bin we wish to use. Then we will insert three chunks of the same size into the unsorted bin via free. Then we will empty the tcache, so we can hit the allocation from the small bin.

After we empty the tcache, the unsorted bin should have `3` chunks in it. During that allocation (since the allocation size is less than the `3` chunks in the unsorted bin), all three chunks will be moved over to the small bin, then one of those chunks will be allocated for that allocation. This is part of the "next best fit" principle with the small / large bins. So after that allocation, there should only be `2` chunk in the small bin (`chunk7` would be allocated here).

After that, we will insert another chunk into the unsorted bin (of large bin size). Then, we will allocate a final chunk (`chunk8`) from the small bin. We can see that this chunk was allocated prior to the unsorted bin iteration, as `chunk10` is still present in the unsorted bin.

Also, one more interesting thing we will see happen. At the final small bin allocation, when we allocate chunks like that, it will attempt to empty the small bin chunks into the corresponding tcache (similar to the fastbin). We will see that happen here with `chunk9`:

Now let's see this in action! First, let's see what the addresses of chunks `7/8/9/10` are:

```
$  gdb ./small_bin_basic
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
Reading symbols from ./small_bin_basic...
(No debugging symbols found in ./small_bin_basic)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>:   endbr64
   0x000000000000118d <+4>:   push   rbp
   0x000000000000118e <+5>:   mov   rbp,rsp
   0x0000000000001191 <+8>:   sub   rsp,0x60
   0x0000000000001195 <+12>:  lea   rax,[rip+0xe6c]      # 0x2008
   0x000000000000119c <+19>:  mov   rdi,rax
   0x000000000000119f <+22>:  call   0x1080 <puts@plt>
   0x00000000000011a4 <+27>:  mov   edi,0x200
   0x00000000000011a9 <+32>:  call   0x1090 <malloc@plt>
   0x00000000000011ae <+37>:  mov   QWORD PTR [rbp-0x58],rax
   0x00000000000011b2 <+41>:  mov   edi,0x200
   0x00000000000011b7 <+46>:  call   0x1090 <malloc@plt>
   0x00000000000011bc <+51>:  mov   QWORD PTR [rbp-0x50],rax
   0x00000000000011c0 <+55>:  mov   edi,0x200
   0x00000000000011c5 <+60>:  call   0x1090 <malloc@plt>
   0x00000000000011ca <+65>:  mov   QWORD PTR [rbp-0x48],rax
   0x00000000000011ce <+69>:  mov   edi,0x200
   0x00000000000011d3 <+74>:  call   0x1090 <malloc@plt>
   0x00000000000011d8 <+79>:  mov   QWORD PTR [rbp-0x40],rax
   0x00000000000011dc <+83>:  mov   edi,0x200
   0x00000000000011e1 <+88>:  call   0x1090 <malloc@plt>
   0x00000000000011e6 <+93>:  mov   QWORD PTR [rbp-0x38],rax
   0x00000000000011ea <+97>:  mov   edi,0x200
   0x00000000000011ef <+102>: call   0x1090 <malloc@plt>
   0x00000000000011f4 <+107>: mov   QWORD PTR [rbp-0x30],rax
   0x00000000000011f8 <+111>: mov   edi,0x200
   0x00000000000011fd <+116>: call   0x1090 <malloc@plt>
   0x0000000000001202 <+121>: mov   QWORD PTR [rbp-0x28],rax
   0x0000000000001206 <+125>: mov   edi,0x200
   0x000000000000120b <+130>: call   0x1090 <malloc@plt>
   0x0000000000001210 <+135>: mov   QWORD PTR [rbp-0x20],rax
   0x0000000000001214 <+139>: mov   edi,0x20
   0x0000000000001219 <+144>: call   0x1090 <malloc@plt>
   0x000000000000121e <+149>: mov   edi,0x200
   0x0000000000001223 <+154>: call   0x1090 <malloc@plt>
   0x0000000000001228 <+159>: mov   QWORD PTR [rbp-0x18],rax
   0x000000000000122c <+163>: mov   edi,0x20
   0x0000000000001231 <+168>: call   0x1090 <malloc@plt>
   0x0000000000001236 <+173>: mov   edi,0x200
   0x000000000000123b <+178>: call   0x1090 <malloc@plt>
   0x0000000000001240 <+183>: mov   QWORD PTR [rbp-0x10],rax
   0x0000000000001244 <+187>: mov   edi,0x20
   0x0000000000001249 <+192>: call   0x1090 <malloc@plt>
   0x000000000000124e <+197>: mov   edi,0x600
   0x0000000000001253 <+202>: call   0x1090 <malloc@plt>
   0x0000000000001258 <+207>: mov   QWORD PTR [rbp-0x8],rax
   0x000000000000125c <+211>: mov   edi,0x20
   0x0000000000001261 <+216>: call   0x1090 <malloc@plt>
   0x0000000000001266 <+221>: mov   rax,QWORD PTR [rbp-0x58]
   0x000000000000126a <+225>: mov   rdi,rax
   0x000000000000126d <+228>: call   0x1070 <free@plt>
   0x0000000000001272 <+233>: mov   rax,QWORD PTR [rbp-0x50]
   0x0000000000001276 <+237>: mov   rdi,rax
   0x0000000000001279 <+240>: call   0x1070 <free@plt>
   0x000000000000127e <+245>: mov   rax,QWORD PTR [rbp-0x48]
   0x0000000000001282 <+249>: mov   rdi,rax
   0x0000000000001285 <+252>: call   0x1070 <free@plt>
   0x000000000000128a <+257>: mov   rax,QWORD PTR [rbp-0x40]
   0x000000000000128e <+261>: mov   rdi,rax
   0x0000000000001291 <+264>: call   0x1070 <free@plt>
   0x0000000000001296 <+269>: mov   rax,QWORD PTR [rbp-0x38]
   0x000000000000129a <+273>: mov   rdi,rax
   0x000000000000129d <+276>: call   0x1070 <free@plt>
   0x00000000000012a2 <+281>: mov   rax,QWORD PTR [rbp-0x30]
   0x00000000000012a6 <+285>: mov   rdi,rax
   0x00000000000012a9 <+288>: call   0x1070 <free@plt>
   0x00000000000012ae <+293>: mov   rax,QWORD PTR [rbp-0x28]
   0x00000000000012b2 <+297>: mov   rdi,rax
   0x00000000000012b5 <+300>: call   0x1070 <free@plt>
   0x00000000000012ba <+305>: lea   rax,[rip+0xd67]      # 0x2028
   0x00000000000012c1 <+312>: mov   rdi,rax
   0x00000000000012c4 <+315>: call   0x1080 <puts@plt>
   0x00000000000012c9 <+320>: mov   rax,QWORD PTR [rbp-0x20]
   0x00000000000012cd <+324>: mov   rdi,rax
   0x00000000000012d0 <+327>: call   0x1070 <free@plt>
   0x00000000000012d5 <+332>: mov   rax,QWORD PTR [rbp-0x18]
   0x00000000000012d9 <+336>: mov   rdi,rax
   0x00000000000012dc <+339>: call   0x1070 <free@plt>
   0x00000000000012e1 <+344>: mov   rax,QWORD PTR [rbp-0x10]
   0x00000000000012e5 <+348>: mov   rdi,rax
   0x00000000000012e8 <+351>: call   0x1070 <free@plt>
   0x00000000000012ed <+356>: lea   rax,[rip+0xd8c]      # 0x2080
   0x00000000000012f4 <+363>: mov   rdi,rax
   0x00000000000012f7 <+366>: call   0x1080 <puts@plt>
   0x00000000000012fc <+371>: mov   DWORD PTR [rbp-0x5c],0x0
   0x0000000000001303 <+378>: jmp   0x1313 <main+394>
   0x0000000000001305 <+380>: mov   edi,0x200
   0x000000000000130a <+385>: call   0x1090 <malloc@plt>
   0x000000000000130f <+390>: add   DWORD PTR [rbp-0x5c],0x1
   0x0000000000001313 <+394>: cmp   DWORD PTR [rbp-0x5c],0x6
   0x0000000000001317 <+398>: jle   0x1305 <main+380>
   0x0000000000001319 <+400>: lea   rax,[rip+0xdb0]      # 0x20d0
   0x0000000000001320 <+407>: mov   rdi,rax
   0x0000000000001323 <+410>: call   0x1080 <puts@plt>
   0x0000000000001328 <+415>: mov   edi,0x1f0
   0x000000000000132d <+420>: call   0x1090 <malloc@plt>
   0x0000000000001332 <+425>: lea   rax,[rip+0xdcf]      # 0x2108
   0x0000000000001339 <+432>: mov   rdi,rax
   0x000000000000133c <+435>: call   0x1080 <puts@plt>
   0x0000000000001341 <+440>: mov   rax,QWORD PTR [rbp-0x8]
   0x0000000000001345 <+444>: mov   rdi,rax
   0x0000000000001348 <+447>: call   0x1070 <free@plt>
   0x000000000000134d <+452>: lea   rax,[rip+0xe04]      # 0x2158
   0x0000000000001354 <+459>: mov   rdi,rax
   0x0000000000001357 <+462>: call   0x1080 <puts@plt>
   0x000000000000135c <+467>: mov   edi,0x200
   0x0000000000001361 <+472>: call   0x1090 <malloc@plt>
   0x0000000000001366 <+477>: nop
   0x0000000000001367 <+478>: leave  
   0x0000000000001368 <+479>: ret    
End of assembler dump.
gef➤  b *main+135
Breakpoint 1 at 0x1210
gef➤  b *main+159
Breakpoint 2 at 0x1228
gef➤  b *main+183
Breakpoint 3 at 0x1240
gef➤  b *main+207
Breakpoint 4 at 0x1258
gef➤  b *main+228
Breakpoint 5 at 0x126d
gef➤  b *main+356
Breakpoint 6 at 0x12ed
gef➤  b *main+420
Breakpoint 7 at 0x132d
gef➤  b *main+425
Breakpoint 8 at 0x1332
gef➤  b *main+447
Breakpoint 9 at 0x1348
gef➤  b *main+452
Breakpoint 10 at 0x134d
gef➤  b *main+472
Breakpoint 11 at 0x1361
gef➤  b *main+477
Breakpoint 12 at 0x1366
gef➤  r
Starting program: /Hackery/shogun/heap_demos/small_bin/small_bin_basic/small_bin_basic
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".


Let's fill up the tcache!



Breakpoint 1, 0x0000555555555210 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a520  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x211           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555a720  →  0x0000000000000000
$rdi   : 0x1             
$rip   : 0x0000555555555210  →  <main+135> mov QWORD PTR [rbp-0x20], rax
$r8   : 0x0              
$r9   : 0x000055555555a520  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a720  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555202 <main+121>     mov   QWORD PTR [rbp-0x28], rax
   0x555555555206 <main+125>     mov   edi, 0x200
   0x55555555520b <main+130>     call   0x555555555090 <malloc@plt>
 → 0x555555555210 <main+135>     mov   QWORD PTR [rbp-0x20], rax
   0x555555555214 <main+139>     mov   edi, 0x20
   0x555555555219 <main+144>     call   0x555555555090 <malloc@plt>
   0x55555555521e <main+149>     mov   edi, 0x200
   0x555555555223 <main+154>     call   0x555555555090 <malloc@plt>
   0x555555555228 <main+159>     mov   QWORD PTR [rbp-0x18], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555210 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555210 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x55555555a520
gef➤  c
Continuing.

Breakpoint 2, 0x0000555555555228 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a760  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x211           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555a960  →  0x0000000000000000
$rdi   : 0x1             
$rip   : 0x0000555555555228  →  <main+159> mov QWORD PTR [rbp-0x18], rax
$r8   : 0x0              
$r9   : 0x000055555555a760  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a960  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555219 <main+144>     call   0x555555555090 <malloc@plt>
   0x55555555521e <main+149>     mov   edi, 0x200
   0x555555555223 <main+154>     call   0x555555555090 <malloc@plt>
 → 0x555555555228 <main+159>     mov   QWORD PTR [rbp-0x18], rax
   0x55555555522c <main+163>     mov   edi, 0x20
   0x555555555231 <main+168>     call   0x555555555090 <malloc@plt>
   0x555555555236 <main+173>     mov   edi, 0x200
   0x55555555523b <main+178>     call   0x555555555090 <malloc@plt>
   0x555555555240 <main+183>     mov   QWORD PTR [rbp-0x10], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555228 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555228 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x55555555a760
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555240 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a9a0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x211           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555aba0  →  0x0000000000000000
$rdi   : 0x1             
$rip   : 0x0000555555555240  →  <main+183> mov QWORD PTR [rbp-0x10], rax
$r8   : 0x0              
$r9   : 0x000055555555a9a0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555aba0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555231 <main+168>     call   0x555555555090 <malloc@plt>
   0x555555555236 <main+173>     mov   edi, 0x200
   0x55555555523b <main+178>     call   0x555555555090 <malloc@plt>
 → 0x555555555240 <main+183>     mov   QWORD PTR [rbp-0x10], rax
   0x555555555244 <main+187>     mov   edi, 0x20
   0x555555555249 <main+192>     call   0x555555555090 <malloc@plt>
   0x55555555524e <main+197>     mov   edi, 0x600
   0x555555555253 <main+202>     call   0x555555555090 <malloc@plt>
   0x555555555258 <main+207>     mov   QWORD PTR [rbp-0x8], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555240 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555240 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x55555555a9a0
gef➤  c
Continuing.

Breakpoint 4, 0x0000555555555258 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555abe0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x611           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555b1e0  →  0x0000000000000000
$rdi   : 0x2             
$rip   : 0x0000555555555258  →  <main+207> mov QWORD PTR [rbp-0x8], rax
$r8   : 0x0              
$r9   : 0x000055555555abe0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555b1e0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555249 <main+192>     call   0x555555555090 <malloc@plt>
   0x55555555524e <main+197>     mov   edi, 0x600
   0x555555555253 <main+202>     call   0x555555555090 <malloc@plt>
 → 0x555555555258 <main+207>     mov   QWORD PTR [rbp-0x8], rax
   0x55555555525c <main+211>     mov   edi, 0x20
   0x555555555261 <main+216>     call   0x555555555090 <malloc@plt>
   0x555555555266 <main+221>     mov   rax, QWORD PTR [rbp-0x58]
   0x55555555526a <main+225>     mov   rdi, rax
   0x55555555526d <main+228>     call   0x555555555070 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555258 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555258 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x55555555abe0
```

So we see, for the chunk addresses, `chunk7` is `0x55555555a520`, `chunk8` is `0x55555555a760`, `chunk9` is `0x55555555a9a0`, and `chunk10` is `0x55555555abe0`.

Now, let's see the tcache become full, and the unsorted bin have three chunks inserted into it:
```
gef➤  c
Continuing.

Breakpoint 5, 0x000055555555526d in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x31            
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x000055555555b210  →  0x0000000000000000
$rdi   : 0x00005555555596b0  →  0x0000000000000000
$rip   : 0x000055555555526d  →  <main+228> call 0x555555555070 <free@plt>
$r8   : 0x0              
$r9   : 0x000055555555b1f0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x000055555555b210  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000000000000
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x0000000000000000
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x0000000000000000
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555261 <main+216>     call   0x555555555090 <malloc@plt>
   0x555555555266 <main+221>     mov   rax, QWORD PTR [rbp-0x58]
   0x55555555526a <main+225>     mov   rdi, rax
 → 0x55555555526d <main+228>     call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>   endbr64
   0x555555555074 <free@plt+4>   bnd   jmp QWORD PTR [rip+0x2f45]       # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>  nop   DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <puts@plt+0>   endbr64
   0x555555555084 <puts@plt+4>   bnd   jmp QWORD PTR [rip+0x2f3d]       # 0x555555557fc8 <puts@got.plt>
   0x55555555508b <puts@plt+11>  nop   DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555596b0 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x55555555526d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555526d → main()
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


The tcache has been filled up! Let's insert chunks into the unsorted bin now!



Breakpoint 6, 0x00005555555552ed in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x1f            
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555b210  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x0000555555554040  →   (bad)
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x7             
$rip   : 0x00005555555552ed  →  <main+356> lea rax, [rip+0xd8c]      # 0x555555556080
$r8   : 0x000055555555a9a0  →  0x000055555555a750  →  0x0000000000000000
$r9   : 0x000055555555b1f0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x8c46e905368fee36
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000555555554040  →   (bad)   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552e1 <main+344>     mov   rax, QWORD PTR [rbp-0x10]
   0x5555555552e5 <main+348>     mov   rdi, rax
   0x5555555552e8 <main+351>     call   0x555555555070 <free@plt>
 → 0x5555555552ed <main+356>     lea   rax, [rip+0xd8c]     # 0x555555556080
   0x5555555552f4 <main+363>     mov   rdi, rax
   0x5555555552f7 <main+366>     call   0x555555555080 <puts@plt>
   0x5555555552fc <main+371>     mov   DWORD PTR [rbp-0x5c], 0x0
   0x555555555303 <main+378>     jmp   0x555555555313 <main+394>
   0x555555555305 <main+380>     mov   edi, 0x200
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x5555555552ed in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ed → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=31, size=0x210, count=7] ←  Chunk(addr=0x55555555a310, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55555555a100, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559ef0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559ce0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559ad0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598c0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55555555a990, bk=0x55555555a510
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a520, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

We see chunks `9/8/7` are in the unsorted bin. Now, let's see the tcache become emptied, and our first allocation from the small bin happen (and also see the unsorted bin becoming cleared out):

```
gef➤  c
Continuing.


Let's empty the tcache now, so we can allocated chunks from the small bin




Let's allocate our first chunk from the small bin!



Breakpoint 7, 0x000055555555532d in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x37            
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x1f0           
$rip   : 0x000055555555532d  →  <main+420> call 0x555555555090 <malloc@plt>
$r8   : 0x0              
$r9   : 0x000055555555b1f0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555320 <main+407>     mov   rdi, rax
   0x555555555323 <main+410>     call   0x555555555080 <puts@plt>
   0x555555555328 <main+415>     mov   edi, 0x1f0
 → 0x55555555532d <main+420>     call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
   0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]       # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>     endbr64
   0x5555555550a4 <_start+4>     xor   ebp, ebp
   0x5555555550a6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x00000000000001f0
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x55555555532d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555532d → main()
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
[+] unsorted_bins[0]: fw=0x55555555a990, bk=0x55555555a510
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a520, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 8, 0x0000555555555332 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a520  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$rbx   : 0x0             
$rcx   : 0x000055555555a510  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80  →  0x00007ffff7e19e70
$rdi   : 0x000055555555a510  →  0x0000000000000000
$rip   : 0x0000555555555332  →  <main+425> lea rax, [rip+0xdcf]      # 0x555555556108
$r8   : 0x0              
$r9   : 0x000055555555a520  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$r10   : 0x000055555555a750  →  0x0000000000000000
$r11   : 0x00007ffff7e19ce0  →  0x000055555555b210  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555323 <main+410>     call   0x555555555080 <puts@plt>
   0x555555555328 <main+415>     mov   edi, 0x1f0
   0x55555555532d <main+420>     call   0x555555555090 <malloc@plt>
 → 0x555555555332 <main+425>     lea   rax, [rip+0xdcf]     # 0x555555556108
   0x555555555339 <main+432>     mov   rdi, rax
   0x55555555533c <main+435>     call   0x555555555080 <puts@plt>
   0x555555555341 <main+440>     mov   rax, QWORD PTR [rbp-0x8]
   0x555555555345 <main+444>     mov   rdi, rax
   0x555555555348 <main+447>     call   0x555555555070 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555332 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555332 → main()
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
[+] small_bins[32]: fw=0x55555555a990, bk=0x55555555a750
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  p $rax
$5 = 0x55555555a520
```

So, we see chunks `9/8` have been moved over to the small bin, and `chunk7` has been allocated from the small bin.

Now finally, let's see our final unsorted bin chunk get allocated, and our final small bin chunk get allocated. Since this happens prior to the unsorted bin allocation, the unsorted bin chunk will not be used. We will also see the final small bin chunk getting moved over to the tcache:

```
gef➤  c
Continuing.


Let's insert another chunk into the unsorted bin (not small bin size)!



Breakpoint 9, 0x0000555555555348 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555abe0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x000055555555abe0  →  0x0000000000000000
$rip   : 0x0000555555555348  →  <main+447> call 0x555555555070 <free@plt>
$r8   : 0x0              
$r9   : 0x000055555555a520  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$r10   : 0x000055555555a750  →  0x0000000000000000
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555533c <main+435>     call   0x555555555080 <puts@plt>
   0x555555555341 <main+440>     mov   rax, QWORD PTR [rbp-0x8]
   0x555555555345 <main+444>     mov   rdi, rax
 → 0x555555555348 <main+447>     call   0x555555555070 <free@plt>
   ↳  0x555555555070 <free@plt+0>   endbr64
   0x555555555074 <free@plt+4>   bnd   jmp QWORD PTR [rip+0x2f45]       # 0x555555557fc0 <free@got.plt>
   0x55555555507b <free@plt+11>  nop   DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <puts@plt+0>   endbr64
   0x555555555084 <puts@plt+4>   bnd   jmp QWORD PTR [rip+0x2f3d]       # 0x555555557fc8 <puts@got.plt>
   0x55555555508b <puts@plt+11>  nop   DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x000055555555abe0 → 0x0000000000000000,
   $rsi = 0x0000000000000001,
   $rdx = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555348 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555348 → main()
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
[+] small_bins[32]: fw=0x55555555a990, bk=0x55555555a750
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 10, 0x000055555555534d in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x5f            
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555b210  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x000055555555534d  →  <main+452> lea rax, [rip+0xe04]      # 0x555555556158
$r8   : 0x0              
$r9   : 0x000055555555a520  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$r10   : 0x000055555555a750  →  0x0000000000000000
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555341 <main+440>     mov   rax, QWORD PTR [rbp-0x8]
   0x555555555345 <main+444>     mov   rdi, rax
   0x555555555348 <main+447>     call   0x555555555070 <free@plt>
 → 0x55555555534d <main+452>     lea   rax, [rip+0xe04]     # 0x555555556158
   0x555555555354 <main+459>     mov   rdi, rax
   0x555555555357 <main+462>     call   0x555555555080 <puts@plt>
   0x55555555535c <main+467>     mov   edi, 0x200
   0x555555555361 <main+472>     call   0x555555555090 <malloc@plt>
   0x555555555366 <main+477>     nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x55555555534d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555534d → main()
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
[+] unsorted_bins[0]: fw=0x55555555abd0, bk=0x55555555abd0
 →   Chunk(addr=0x55555555abe0, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] small_bins[32]: fw=0x55555555a990, bk=0x55555555a750
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.


Let's allocate our second chunk from the small bin!



Breakpoint 11, 0x0000555555555361 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x38            
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x200           
$rip   : 0x0000555555555361  →  <main+472> call 0x555555555090 <malloc@plt>
$r8   : 0x0              
$r9   : 0x000055555555a520  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$r10   : 0x000055555555a750  →  0x0000000000000000
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555354 <main+459>     mov   rdi, rax
   0x555555555357 <main+462>     call   0x555555555080 <puts@plt>
   0x55555555535c <main+467>     mov   edi, 0x200
 → 0x555555555361 <main+472>     call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64
   0x555555555094 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f35]       # 0x555555557fd0 <malloc@got.plt>
   0x55555555509b <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550a0 <_start+0>     endbr64
   0x5555555550a4 <_start+4>     xor   ebp, ebp
   0x5555555550a6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000200,
   $rsi = 0x0000000000000001,
   $rdx = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555361 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555361 → main()
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
[+] unsorted_bins[0]: fw=0x55555555abd0, bk=0x55555555abd0
 →   Chunk(addr=0x55555555abe0, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] small_bins[32]: fw=0x55555555a990, bk=0x55555555a750
 →   Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55555555a760, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.

Breakpoint 12, 0x0000555555555366 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a760  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$rbx   : 0x0             
$rcx   : 0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80  →  0x00007ffff7e19e70
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000000755554040
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x1f            
$rip   : 0x0000555555555366  →  <main+477> nop
$r8   : 0x0000555555559010  →  0x0000000000000000
$r9   : 0x000055555555a760  →  0x00007ffff7e19ee0  →  0x00007ffff7e19ed0  →  0x00007ffff7e19ec0  →  0x00007ffff7e19eb0  →  0x00007ffff7e19ea0  →  0x00007ffff7e19e90  →  0x00007ffff7e19e80
$r10   : 0x1             
$r11   : 0x7             
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c5  →  "/Hackery/shogun/heap_demos/small_bin/smal[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64
$r14   : 0x0000555555557db0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000755554040   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x00005555555598c0  →  0x000055500000c3e9
0x00007fffffffdf68│+0x0018: 0x0000555555559ad0  →  0x000055500000cd99
0x00007fffffffdf70│+0x0020: 0x0000555555559ce0  →  0x000055500000cf89
0x00007fffffffdf78│+0x0028: 0x0000555555559ef0  →  0x000055500000c9b9
0x00007fffffffdf80│+0x0030: 0x000055555555a100  →  0x000055500000cbaa
0x00007fffffffdf88│+0x0038: 0x000055555555a310  →  0x000055500000f45a
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555357 <main+462>     call   0x555555555080 <puts@plt>
   0x55555555535c <main+467>     mov   edi, 0x200
   0x555555555361 <main+472>     call   0x555555555090 <malloc@plt>
 → 0x555555555366 <main+477>     nop    
   0x555555555367 <main+478>     leave  
   0x555555555368 <main+479>     ret    
   0x555555555369                add   BYTE PTR [rax], al
   0x55555555536b                add   bl, dh
   0x55555555536d <_fini+1>      nop   edx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "small_bin_basic", stopped 0x555555555366 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555366 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=31, size=0x210, count=1] ←  Chunk(addr=0x55555555a9a0, size=0x210, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55555555abd0, bk=0x55555555abd0
 →   Chunk(addr=0x55555555abe0, size=0x610, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  p $rax
$6 = 0x55555555a760
gef➤  c
Continuing.
[Inferior 1 (process 53808) exited with code 0140]
```

So we see `chunk8` has been allocated, and `chunk9` has been moved over to the tcache. Just like that, we've seen the basics of small bin insertion and removals!



