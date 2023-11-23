# tcache fake chunk

So for this writeup, we will cover a new topic. Basically, we will be creating a fake chunk. We will effectively write some data somewhere in memory we know, to make it look like a heap chunk. We will then pass a ptr to that chunk, to a `free` call to free it. Then depending on the status of the heap and our chunk, it will likely be inserted into a heap bin.

This can be helpful, especially if it's somewhere we can easily write to the data in our fake chunk. Then we can edit a chunk in one of the heap bins, to hopefully get something like an arbitrary read/write.

Here is the code we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100

void main() {
    long *chunk;
    long fake_chunk[4];

    printf("So our goal here, is to show how we can create fake chunks.\n");
    printf("We can create a fake chunk, with chunk metadata similar to that of a real chunk.\n");
    printf("We can go ahead and free that fake chunk, to insert it into the heap.\n");
    printf("This way, we can free a chunk of memory not actually in the heap.\n");
    printf("We will be making a fake chunk on the stack.\n\n");

    printf("Fake Chunk Being Made At:\t%p\n\n", &fake_chunk[2]);

    printf("Now we have to write the chunk metadata.\n");
    printf("We will mark the size as 0x111.\n");
    printf("We want to be able to allocate the chunk via requesting a chunk size of 0x100.\n");
    printf("A 0x110 byte chunk will be able to give us the 0x100 bytes, plus 0x10 byte heap header.\n");
    printf("The 0x1 is for the PREV_INUSE bit flag of the size value.\n");
    printf("For the prev_size, we are going write 0x00 to it.\n");
    printf("We will also null out the first 0x10 bytes of the chunk, even though we don't need to.\n");
    printf("Now let's write the heap values!\n\n");

    fake_chunk[0] = 0x00;
    fake_chunk[1] = 0x111;
    fake_chunk[2] = 0x00;
    fake_chunk[3] = 0x00;

    printf("Value @ %p:\t0x%lx\n", &fake_chunk[0], fake_chunk[0]);
    printf("Value @ %p:\t0x%lx\n", &fake_chunk[1], fake_chunk[1]);
    printf("Value @ %p:\t0x%lx\n", &fake_chunk[2], fake_chunk[2]);
    printf("Value @ %p:\t0x%lx\n\n", &fake_chunk[3], fake_chunk[3]);

    printf("Now let's go ahead and free the chunk!\n");

    free(&fake_chunk[2]);

    printf("Now that we freed it!\n");
    printf("Based on the value we set for the size, we will need to request 0x100 bytes.\n\n");

    chunk = malloc(CHUNK_SIZE0);

    printf("Allocated Chunk:\t%p\n\n", chunk);

    printf("As we've seen, we were able to create a fake heap chunk on the stack.\n");
    printf("We were able to free it, insert it into the tcache, and reallocate it.\n");
}
```

## Walkthrough

So, in order to do this. We effectively just need to establish a spot in memory, that we can get the address for, and write to the preceding `0x10` bytes. In this instance, I choose the third entry in the `fake_chunk` long array `fake_chunk[2]`.

We need to be able to write to the preceding `0x10` bytes, for the heap metadata. In this instance, I want the chunk to have a chunksize of `0x110`, and have the `PREV_INUSE` bit set, so for the size I set `0x111`. For the previous chunk size, I have that set to `0x00000000`. We are having this inserted into the tcache, so iirc we don't need it.

Also one other consideration you might have, is that the address of the chunk will probably have to meet certain alignment requirements (meaning the address is a multiple of some number).

So let's see this in practice. First, let's see the prepared heap chunk getting inserted into the tcache:

```
$   gdb ./tcache_fake_chunk
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
diGEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 12.0.90 in 0.00ms using Python engine 3.10
Reading symbols from ./tcache_fake_chunk...
(No debugging symbols found in ./tcache_fake_chunk)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011c9 <+0>: endbr64
   0x00000000000011cd <+4>: push   rbp
   0x00000000000011ce <+5>: mov rbp,rsp
   0x00000000000011d1 <+8>: sub rsp,0x40
   0x00000000000011d5 <+12>:    mov rax,QWORD PTR fs:0x28
   0x00000000000011de <+21>:    mov QWORD PTR [rbp-0x8],rax
   0x00000000000011e2 <+25>:    xor eax,eax
   0x00000000000011e4 <+27>:    lea rax,[rip+0xe1d]     # 0x2008
   0x00000000000011eb <+34>:    mov rdi,rax
   0x00000000000011ee <+37>:    call   0x10a0 <puts@plt>
   0x00000000000011f3 <+42>:    lea rax,[rip+0xe4e]     # 0x2048
   0x00000000000011fa <+49>:    mov rdi,rax
   0x00000000000011fd <+52>:    call   0x10a0 <puts@plt>
   0x0000000000001202 <+57>:    lea rax,[rip+0xe97]     # 0x20a0
   0x0000000000001209 <+64>:    mov rdi,rax
   0x000000000000120c <+67>:    call   0x10a0 <puts@plt>
   0x0000000000001211 <+72>:    lea rax,[rip+0xed0]     # 0x20e8
   0x0000000000001218 <+79>:    mov rdi,rax
   0x000000000000121b <+82>:    call   0x10a0 <puts@plt>
   0x0000000000001220 <+87>:    lea rax,[rip+0xf09]     # 0x2130
   0x0000000000001227 <+94>:    mov rdi,rax
   0x000000000000122a <+97>:    call   0x10a0 <puts@plt>
   0x000000000000122f <+102>:   lea rax,[rbp-0x30]
   0x0000000000001233 <+106>:   add rax,0x10
   0x0000000000001237 <+110>:   mov rsi,rax
   0x000000000000123a <+113>:   lea rax,[rip+0xf1f]     # 0x2160
   0x0000000000001241 <+120>:   mov rdi,rax
   0x0000000000001244 <+123>:   mov eax,0x0
   0x0000000000001249 <+128>:   call   0x10c0 <printf@plt>
   0x000000000000124e <+133>:   lea rax,[rip+0xf2b]     # 0x2180
   0x0000000000001255 <+140>:   mov rdi,rax
   0x0000000000001258 <+143>:   call   0x10a0 <puts@plt>
   0x000000000000125d <+148>:   lea rax,[rip+0xf4c]     # 0x21b0
   0x0000000000001264 <+155>:   mov rdi,rax
   0x0000000000001267 <+158>:   call   0x10a0 <puts@plt>
   0x000000000000126c <+163>:   lea rax,[rip+0xf5d]     # 0x21d0
   0x0000000000001273 <+170>:   mov rdi,rax
   0x0000000000001276 <+173>:   call   0x10a0 <puts@plt>
   0x000000000000127b <+178>:   lea rax,[rip+0xf9e]     # 0x2220
   0x0000000000001282 <+185>:   mov rdi,rax
   0x0000000000001285 <+188>:   call   0x10a0 <puts@plt>
   0x000000000000128a <+193>:   lea rax,[rip+0xfe7]     # 0x2278
   0x0000000000001291 <+200>:   mov rdi,rax
   0x0000000000001294 <+203>:   call   0x10a0 <puts@plt>
   0x0000000000001299 <+208>:   lea rax,[rip+0x1018]        # 0x22b8
   0x00000000000012a0 <+215>:   mov rdi,rax
   0x00000000000012a3 <+218>:   call   0x10a0 <puts@plt>
   0x00000000000012a8 <+223>:   lea rax,[rip+0x1041]        # 0x22f0
   0x00000000000012af <+230>:   mov rdi,rax
   0x00000000000012b2 <+233>:   call   0x10a0 <puts@plt>
   0x00000000000012b7 <+238>:   lea rax,[rip+0x108a]        # 0x2348
   0x00000000000012be <+245>:   mov rdi,rax
   0x00000000000012c1 <+248>:   call   0x10a0 <puts@plt>
   0x00000000000012c6 <+253>:   mov QWORD PTR [rbp-0x30],0x0
   0x00000000000012ce <+261>:   mov QWORD PTR [rbp-0x28],0x111
   0x00000000000012d6 <+269>:   mov QWORD PTR [rbp-0x20],0x0
   0x00000000000012de <+277>:   mov QWORD PTR [rbp-0x18],0x0
   0x00000000000012e6 <+285>:   mov rdx,QWORD PTR [rbp-0x30]
   0x00000000000012ea <+289>:   lea rax,[rbp-0x30]
   0x00000000000012ee <+293>:   mov rsi,rax
   0x00000000000012f1 <+296>:   lea rax,[rip+0x1072]        # 0x236a
   0x00000000000012f8 <+303>:   mov rdi,rax
   0x00000000000012fb <+306>:   mov eax,0x0
   0x0000000000001300 <+311>:   call   0x10c0 <printf@plt>
   0x0000000000001305 <+316>:   mov rax,QWORD PTR [rbp-0x28]
   0x0000000000001309 <+320>:   lea rdx,[rbp-0x30]
   0x000000000000130d <+324>:   lea rcx,[rdx+0x8]
   0x0000000000001311 <+328>:   mov rdx,rax
   0x0000000000001314 <+331>:   mov rsi,rcx
   0x0000000000001317 <+334>:   lea rax,[rip+0x104c]        # 0x236a
   0x000000000000131e <+341>:   mov rdi,rax
   0x0000000000001321 <+344>:   mov eax,0x0
   0x0000000000001326 <+349>:   call   0x10c0 <printf@plt>
   0x000000000000132b <+354>:   mov rax,QWORD PTR [rbp-0x20]
   0x000000000000132f <+358>:   lea rdx,[rbp-0x30]
   0x0000000000001333 <+362>:   lea rcx,[rdx+0x10]
   0x0000000000001337 <+366>:   mov rdx,rax
   0x000000000000133a <+369>:   mov rsi,rcx
   0x000000000000133d <+372>:   lea rax,[rip+0x1026]        # 0x236a
   0x0000000000001344 <+379>:   mov rdi,rax
   0x0000000000001347 <+382>:   mov eax,0x0
   0x000000000000134c <+387>:   call   0x10c0 <printf@plt>
   0x0000000000001351 <+392>:   mov rax,QWORD PTR [rbp-0x18]
   0x0000000000001355 <+396>:   lea rdx,[rbp-0x30]
   0x0000000000001359 <+400>:   lea rcx,[rdx+0x18]
   0x000000000000135d <+404>:   mov rdx,rax
   0x0000000000001360 <+407>:   mov rsi,rcx
   0x0000000000001363 <+410>:   lea rax,[rip+0x1013]        # 0x237d
   0x000000000000136a <+417>:   mov rdi,rax
   0x000000000000136d <+420>:   mov eax,0x0
   0x0000000000001372 <+425>:   call   0x10c0 <printf@plt>
   0x0000000000001377 <+430>:   lea rax,[rip+0x101a]        # 0x2398
   0x000000000000137e <+437>:   mov rdi,rax
   0x0000000000001381 <+440>:   call   0x10a0 <puts@plt>
   0x0000000000001386 <+445>:   lea rax,[rbp-0x30]
   0x000000000000138a <+449>:   add rax,0x10
   0x000000000000138e <+453>:   mov rdi,rax
   0x0000000000001391 <+456>:   call   0x1090 <free@plt>
   0x0000000000001396 <+461>:   lea rax,[rip+0x1022]        # 0x23bf
   0x000000000000139d <+468>:   mov rdi,rax
   0x00000000000013a0 <+471>:   call   0x10a0 <puts@plt>
   0x00000000000013a5 <+476>:   lea rax,[rip+0x102c]        # 0x23d8
   0x00000000000013ac <+483>:   mov rdi,rax
   0x00000000000013af <+486>:   call   0x10a0 <puts@plt>
   0x00000000000013b4 <+491>:   mov edi,0x100
   0x00000000000013b9 <+496>:   call   0x10d0 <malloc@plt>
   0x00000000000013be <+501>:   mov QWORD PTR [rbp-0x38],rax
   0x00000000000013c2 <+505>:   mov rax,QWORD PTR [rbp-0x38]
   0x00000000000013c6 <+509>:   mov rsi,rax
   0x00000000000013c9 <+512>:   lea rax,[rip+0x1056]        # 0x2426
   0x00000000000013d0 <+519>:   mov rdi,rax
   0x00000000000013d3 <+522>:   mov eax,0x0
   0x00000000000013d8 <+527>:   call   0x10c0 <printf@plt>
   0x00000000000013dd <+532>:   lea rax,[rip+0x105c]        # 0x2440
   0x00000000000013e4 <+539>:   mov rdi,rax
   0x00000000000013e7 <+542>:   call   0x10a0 <puts@plt>
   0x00000000000013ec <+547>:   lea rax,[rip+0x1095]        # 0x2488
   0x00000000000013f3 <+554>:   mov rdi,rax
   0x00000000000013f6 <+557>:   call   0x10a0 <puts@plt>
   0x00000000000013fb <+562>:   nop
   0x00000000000013fc <+563>:   mov rax,QWORD PTR [rbp-0x8]
   0x0000000000001400 <+567>:   sub rax,QWORD PTR fs:0x28
   0x0000000000001409 <+576>:   je  0x1410 <main+583>
   0x000000000000140b <+578>:   call   0x10b0 <__stack_chk_fail@plt>
   0x0000000000001410 <+583>:   leave  
   0x0000000000001411 <+584>:   ret    
End of assembler dump.
gef➤  b *main+456
Breakpoint 1 at 0x1391
gef➤  b *main+496
Breakpoint 2 at 0x13b9
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So our goal here, is to show how we can create fake chunks.
We can create a fake chunk, with chunk metadata similar to that of a real chunk.
We can go ahead and free that fake chunk, to insert it into the heap.
This way, we can free a chunk of memory not actually in the heap.
We will be making a fake chunk on the stack.

Fake Chunk Being Made At:   0x7fffffffdf90

Now we have to write the chunk metadata.
We will mark the size as 0x111.
We want to be able to allocate the chunk via requesting a chunk size of 0x100.
A 0x110 byte chunk will be able to give us the 0x100 bytes, plus 0x10 byte heap header.
The 0x1 is for the PREV_INUSE bit flag of the size value.
For the prev_size, we are going write 0x00 to it.
We will also null out the first 0x10 bytes of the chunk, even though we don't need to.
Now let's write the heap values!

Value @ 0x7fffffffdf80: 0x0
Value @ 0x7fffffffdf88: 0x111
Value @ 0x7fffffffdf90: 0x0
Value @ 0x7fffffffdf98: 0x0

Now let's go ahead and free the chunk!

Breakpoint 1, 0x0000555555555391 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf90  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf70  →  0x00007ffff7fc1000  →  0x00010102464c457f
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x00007fffffffdf90  →  0x0000000000000000
$rip   : 0x0000555555555391  →  <main+456> call 0x555555555090 <free@plt>
$r8 : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00007ffff7fc1000  →  0x00010102464c457f   ← $rsp
0x00007fffffffdf78│+0x0008: 0x0000010101000000
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x0000000000000111
0x00007fffffffdf90│+0x0020: 0x0000000000000000   ← $rax, $rdi
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000001000
0x00007fffffffdfa8│+0x0038: 0xf60f78668fa0e900
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555386 <main+445>    lea rax, [rbp-0x30]
   0x55555555538a <main+449>    add rax, 0x10
   0x55555555538e <main+453>    mov rdi, rax
 → 0x555555555391 <main+456>    call   0x555555555090 <free@plt>
   ↳  0x555555555090 <free@plt+0>   endbr64
    0x555555555094 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f15]      # 0x555555557fb0 <free@got.plt>
    0x55555555509b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550a0 <puts@plt+0>     endbr64
    0x5555555550a4 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f0d]      # 0x555555557fb8 <puts@got.plt>
    0x5555555550ab <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00007fffffffdf90 → 0x0000000000000000,
   $rsi = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x555555555391 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555391 → main()
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
gef➤  p $rdi
$1 = 0x7fffffffdf90
gef➤  x/10g 0x7fffffffdf80
0x7fffffffdf80: 0x0 0x111
0x7fffffffdf90: 0x0 0x0
0x7fffffffdfa0: 0x1000  0xf60f78668fa0e900
0x7fffffffdfb0: 0x1 0x7ffff7c29d90
0x7fffffffdfc0: 0x0 0x5555555551c9
gef➤  vmmap 0x7fffffffdf80
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /Hackery/shogun/pwn_demos/tcache/tcache_fake_chunk/tcache_fake_chunk
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
0x00007ffff7c00000 0x00007ffff7c28000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7c28000 0x00007ffff7dbd000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dbd000 0x00007ffff7e15000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e15000 0x00007ffff7e19000 0x0000000000214000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e19000 0x00007ffff7e1b000 0x0000000000218000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7e1b000 0x00007ffff7e28000 0x0000000000000000 rw-
0x00007ffff7fa4000 0x00007ffff7fa7000 0x0000000000000000 rw-
0x00007ffff7fbb000 0x00007ffff7fbd000 0x0000000000000000 rw-
0x00007ffff7fbd000 0x00007ffff7fc1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc1000 0x00007ffff7fc3000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc3000 0x00007ffff7fc5000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7fc5000 0x00007ffff7fef000 0x0000000000002000 r-x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7fef000 0x00007ffff7ffa000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000037000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000039000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  si
0x0000555555555090 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf90  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf68  →  0x0000555555555396  →  <main+461> lea rax, [rip+0x1022]     # 0x5555555563bf
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x00007fffffffdf90  →  0x0000000000000000
$rip   : 0x0000555555555090  →  <free@plt+0> endbr64
$r8 : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf68│+0x0000: 0x0000555555555396  →  <main+461> lea rax, [rip+0x1022]     # 0x5555555563bf  ← $rsp
0x00007fffffffdf70│+0x0008: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf78│+0x0010: 0x0000010101000000
0x00007fffffffdf80│+0x0018: 0x0000000000000000
0x00007fffffffdf88│+0x0020: 0x0000000000000111
0x00007fffffffdf90│+0x0028: 0x0000000000000000   ← $rax, $rdi
0x00007fffffffdf98│+0x0030: 0x0000000000000000
0x00007fffffffdfa0│+0x0038: 0x0000000000001000
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
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x555555555090 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555090 → free@plt()
[#1] 0x555555555396 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555090 in free@plt ()
0x0000555555555396 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x7fffffffd     
$rsp   : 0x00007fffffffdf70  →  0x00007ffff7fc1000  →  0x00010102464c457f
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7             
$rip   : 0x0000555555555396  →  <main+461> lea rax, [rip+0x1022]        # 0x5555555563bf
$r8 : 0x00007fffffffdf90  →  0x00000007fffffffd
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x19412e268fe5cb02
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00007ffff7fc1000  →  0x00010102464c457f   ← $rsp
0x00007fffffffdf78│+0x0008: 0x0000010101000000
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x0000000000000111
0x00007fffffffdf90│+0x0020: 0x00000007fffffffd   ← $r8
0x00007fffffffdf98│+0x0028: 0x19412e268fe5cb02
0x00007fffffffdfa0│+0x0030: 0x0000000000001000
0x00007fffffffdfa8│+0x0038: 0xf60f78668fa0e900
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555538a <main+449>    add rax, 0x10
   0x55555555538e <main+453>    mov rdi, rax
   0x555555555391 <main+456>    call   0x555555555090 <free@plt>
 → 0x555555555396 <main+461>    lea rax, [rip+0x1022]       # 0x5555555563bf
   0x55555555539d <main+468>    mov rdi, rax
   0x5555555553a0 <main+471>    call   0x5555555550a0 <puts@plt>
   0x5555555553a5 <main+476>    lea rax, [rip+0x102c]       # 0x5555555563d8
   0x5555555553ac <main+483>    mov rdi, rax
   0x5555555553af <main+486>    call   0x5555555550a0 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x555555555396 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555396 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x7fffffffdf90, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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

So, we can see our stack chunk at `0x7fffffffdf90` in the tcache. Now let's see it get allocated:

```
gef➤  c
Continuing.
Now that we freed it!
Based on the value we set for the size, we will need to request 0x100 bytes.


Breakpoint 2, 0x00005555555553b9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4e            
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf70  →  0x00007ffff7fc1000  →  0x00010102464c457f
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x100           
$rip   : 0x00005555555553b9  →  <main+496> call 0x5555555550d0 <malloc@plt>
$r8 : 0x0            
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00007ffff7fc1000  →  0x00010102464c457f   ← $rsp
0x00007fffffffdf78│+0x0008: 0x0000010101000000
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x0000000000000111
0x00007fffffffdf90│+0x0020: 0x00000007fffffffd
0x00007fffffffdf98│+0x0028: 0x19412e268fe5cb02
0x00007fffffffdfa0│+0x0030: 0x0000000000001000
0x00007fffffffdfa8│+0x0038: 0xf60f78668fa0e900
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555553ac <main+483>    mov rdi, rax
   0x5555555553af <main+486>    call   0x5555555550a0 <puts@plt>
   0x5555555553b4 <main+491>    mov edi, 0x100
 → 0x5555555553b9 <main+496>    call   0x5555555550d0 <malloc@plt>
   ↳  0x5555555550d0 <malloc@plt+0>   endbr64
    0x5555555550d4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2ef5]      # 0x555555557fd0 <malloc@got.plt>
    0x5555555550db <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
    0x5555555550e0 <_start+0>       endbr64
    0x5555555550e4 <_start+4>       xor ebp, ebp
    0x5555555550e6 <_start+6>       mov r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000100,
   $rsi = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x5555555553b9 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553b9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x7fffffffdf90, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  p $rdi
$2 = 0x100
gef➤  si
0x00005555555550d0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4e            
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf68  →  0x00005555555553be  →  <main+501> mov QWORD PTR [rbp-0x38], rax
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x100           
$rip   : 0x00005555555550d0  →  <malloc@plt+0> endbr64
$r8 : 0x0            
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf68│+0x0000: 0x00005555555553be  →  <main+501> mov QWORD PTR [rbp-0x38], rax  ← $rsp
0x00007fffffffdf70│+0x0008: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf78│+0x0010: 0x0000010101000000
0x00007fffffffdf80│+0x0018: 0x0000000000000000
0x00007fffffffdf88│+0x0020: 0x0000000000000111
0x00007fffffffdf90│+0x0028: 0x00000007fffffffd
0x00007fffffffdf98│+0x0030: 0x19412e268fe5cb02
0x00007fffffffdfa0│+0x0038: 0x0000000000001000
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
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x5555555550d0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550d0 → malloc@plt()
[#1] 0x5555555553be → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550d0 in malloc@plt ()
0x00005555555553be in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf90  →  0x00000007fffffffd
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf70  →  0x00007ffff7fc1000  →  0x00010102464c457f
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x1f            
$rip   : 0x00005555555553be  →  <main+501> mov QWORD PTR [rbp-0x38], rax
$r8 : 0x0            
$r9 : 0x00007fffffffde47  →  0x0f78668fa0e90030 ("0"?)
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3cb  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551c9  →  <main+0> endbr64
$r14   : 0x0000555555557da0  →  0x0000555555555180  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x00007ffff7fc1000  →  0x00010102464c457f   ← $rsp
0x00007fffffffdf78│+0x0008: 0x0000010101000000
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x0000000000000111
0x00007fffffffdf90│+0x0020: 0x00000007fffffffd   ← $rax
0x00007fffffffdf98│+0x0028: 0x0000000000000000
0x00007fffffffdfa0│+0x0030: 0x0000000000001000
0x00007fffffffdfa8│+0x0038: 0xf60f78668fa0e900
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555553af <main+486>    call   0x5555555550a0 <puts@plt>
   0x5555555553b4 <main+491>    mov edi, 0x100
   0x5555555553b9 <main+496>    call   0x5555555550d0 <malloc@plt>
 → 0x5555555553be <main+501>    mov QWORD PTR [rbp-0x38], rax
   0x5555555553c2 <main+505>    mov rax, QWORD PTR [rbp-0x38]
   0x5555555553c6 <main+509>    mov rsi, rax
   0x5555555553c9 <main+512>    lea rax, [rip+0x1056]       # 0x555555556426
   0x5555555553d0 <main+519>    mov rdi, rax
   0x5555555553d3 <main+522>    mov eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fake_chu", stopped 0x5555555553be in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555553be → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$3 = 0x7fffffffdf90
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
Allocated Chunk:    0x7fffffffdf90

As we've seen, we were able to create a fake heap chunk on the stack.
We were able to free it, insert it into the tcache, and reallocate it.
[Inferior 1 (process 5278) exited normally]
```

Just like that, we were able to get a fake chunk of memory on the stack (outside of the heap memory region) inserted into the tcache, and reallocated!
