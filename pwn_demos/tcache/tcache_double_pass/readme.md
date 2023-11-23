# tcache double free pass

So in previous writeups, we've seen an example of a tcache double free. In the previous example, we've seen a tcache double free get caught with a check, which kills the program. Here we will show one method to bypass this check.

Here is the code for the program:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100


void main() {
    long *chunk0;

    printf("So the purpose of this, is we want to actually pull off a tcache double free successfully.\n");
    printf("Double frees can be helpful with heap exploitation.");
    printf("This is because a lot of heap exploitation revolves around editing the data of freed chunks.\n");
    printf("By having a chunk inserted multiple times into the heap bins, you can allocate one copy of it, while it is still in a heap bin.\n");
    printf("In many instances this will lead to you being able to edit a freed heap bin chunk.\n");
    printf("Let's allocate a chunk, which will later be freed twice!.\n\n");

    chunk0 = malloc(CHUNK_SIZE0);

    printf("Chunk allocated at:\t%p\n\n", chunk0);

    printf("Now let's free it, to insert it into the tcache.\n\n");

    free(chunk0);

    printf("Now how does the tcache detect double frees?\n");
    printf("It does this, by writing a value to a specific offset in the chunk.\n");
    printf("This value is known as the tcache key, and it is set at offset `0x08` in the user data section of the chunk.\n");
    printf("Then when malloc attempts to insert a new chunk into the tcache, it sees if it has the tcache key value set.\n");
    printf("If it does, it know the chunk is already present in the tcache, and flags it as a double free.\n\n");



    printf("We see here, the tcache key is 0x%lx\n\n", *(chunk0 + 1));

    printf("So to pass this check, we will simply overwrite the tcache key of the chunk with a different value.\n\n");

    *(chunk0 + 1) = 0x0000000000000000;

    printf("We see here, the tcache key is 0x%lx\n\n", *(chunk0 + 1));

    printf("Now let's free the chunk again!\n");

    free(chunk0);

    printf("Now we have freed the same chunk twice.\n");
    printf("We will be able to allocate it twice now!\n\n");

    printf("Chunk Allocation 0:\t%p\n", malloc(CHUNK_SIZE0));
    printf("Chunk Allocation 1:\t%p\n", malloc(CHUNK_SIZE0));
}
```

## Walkthrough

So first off, how does the tcache double free check work? It works via checking if the tcache key value (which has been discussed previously, and is set at offset `0x08` from the user data section of the freed chunk, right after the mangled next ptr) has been set. So simply, we just overwrite the tcache key value with another value. This way even though the tcache already has the same chunk in it, it will pass and the same chunk will be inserted multiple times into the same tcache bin.

Let's see this in action:

```
$	gdb ./tcache_double_pass 
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
Reading symbols from ./tcache_double_pass...
(No debugging symbols found in ./tcache_double_pass)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>:	endbr64 
   0x00000000000011ad <+4>:	push   rbp
   0x00000000000011ae <+5>:	mov    rbp,rsp
   0x00000000000011b1 <+8>:	sub    rsp,0x10
   0x00000000000011b5 <+12>:	lea    rax,[rip+0xe4c]        # 0x2008
   0x00000000000011bc <+19>:	mov    rdi,rax
   0x00000000000011bf <+22>:	call   0x1090 <puts@plt>
   0x00000000000011c4 <+27>:	lea    rax,[rip+0xe9d]        # 0x2068
   0x00000000000011cb <+34>:	mov    rdi,rax
   0x00000000000011ce <+37>:	mov    eax,0x0
   0x00000000000011d3 <+42>:	call   0x10a0 <printf@plt>
   0x00000000000011d8 <+47>:	lea    rax,[rip+0xec1]        # 0x20a0
   0x00000000000011df <+54>:	mov    rdi,rax
   0x00000000000011e2 <+57>:	call   0x1090 <puts@plt>
   0x00000000000011e7 <+62>:	lea    rax,[rip+0xf12]        # 0x2100
   0x00000000000011ee <+69>:	mov    rdi,rax
   0x00000000000011f1 <+72>:	call   0x1090 <puts@plt>
   0x00000000000011f6 <+77>:	lea    rax,[rip+0xf83]        # 0x2180
   0x00000000000011fd <+84>:	mov    rdi,rax
   0x0000000000001200 <+87>:	call   0x1090 <puts@plt>
   0x0000000000001205 <+92>:	lea    rax,[rip+0xfcc]        # 0x21d8
   0x000000000000120c <+99>:	mov    rdi,rax
   0x000000000000120f <+102>:	call   0x1090 <puts@plt>
   0x0000000000001214 <+107>:	mov    edi,0x100
   0x0000000000001219 <+112>:	call   0x10b0 <malloc@plt>
   0x000000000000121e <+117>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001222 <+121>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001226 <+125>:	mov    rsi,rax
   0x0000000000001229 <+128>:	lea    rax,[rip+0xfe3]        # 0x2213
   0x0000000000001230 <+135>:	mov    rdi,rax
   0x0000000000001233 <+138>:	mov    eax,0x0
   0x0000000000001238 <+143>:	call   0x10a0 <printf@plt>
   0x000000000000123d <+148>:	lea    rax,[rip+0xfec]        # 0x2230
   0x0000000000001244 <+155>:	mov    rdi,rax
   0x0000000000001247 <+158>:	call   0x1090 <puts@plt>
   0x000000000000124c <+163>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001250 <+167>:	mov    rdi,rax
   0x0000000000001253 <+170>:	call   0x1080 <free@plt>
   0x0000000000001258 <+175>:	lea    rax,[rip+0x1009]        # 0x2268
   0x000000000000125f <+182>:	mov    rdi,rax
   0x0000000000001262 <+185>:	call   0x1090 <puts@plt>
   0x0000000000001267 <+190>:	lea    rax,[rip+0x102a]        # 0x2298
   0x000000000000126e <+197>:	mov    rdi,rax
   0x0000000000001271 <+200>:	call   0x1090 <puts@plt>
   0x0000000000001276 <+205>:	lea    rax,[rip+0x1063]        # 0x22e0
   0x000000000000127d <+212>:	mov    rdi,rax
   0x0000000000001280 <+215>:	call   0x1090 <puts@plt>
   0x0000000000001285 <+220>:	lea    rax,[rip+0x10c4]        # 0x2350
   0x000000000000128c <+227>:	mov    rdi,rax
   0x000000000000128f <+230>:	call   0x1090 <puts@plt>
   0x0000000000001294 <+235>:	lea    rax,[rip+0x1125]        # 0x23c0
   0x000000000000129b <+242>:	mov    rdi,rax
   0x000000000000129e <+245>:	call   0x1090 <puts@plt>
   0x00000000000012a3 <+250>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000012a7 <+254>:	add    rax,0x8
   0x00000000000012ab <+258>:	mov    rax,QWORD PTR [rax]
   0x00000000000012ae <+261>:	mov    rsi,rax
   0x00000000000012b1 <+264>:	lea    rax,[rip+0x1168]        # 0x2420
   0x00000000000012b8 <+271>:	mov    rdi,rax
   0x00000000000012bb <+274>:	mov    eax,0x0
   0x00000000000012c0 <+279>:	call   0x10a0 <printf@plt>
   0x00000000000012c5 <+284>:	lea    rax,[rip+0x117c]        # 0x2448
   0x00000000000012cc <+291>:	mov    rdi,rax
   0x00000000000012cf <+294>:	call   0x1090 <puts@plt>
   0x00000000000012d4 <+299>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000012d8 <+303>:	add    rax,0x8
   0x00000000000012dc <+307>:	mov    QWORD PTR [rax],0x0
   0x00000000000012e3 <+314>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000012e7 <+318>:	add    rax,0x8
   0x00000000000012eb <+322>:	mov    rax,QWORD PTR [rax]
   0x00000000000012ee <+325>:	mov    rsi,rax
   0x00000000000012f1 <+328>:	lea    rax,[rip+0x1128]        # 0x2420
   0x00000000000012f8 <+335>:	mov    rdi,rax
   0x00000000000012fb <+338>:	mov    eax,0x0
   0x0000000000001300 <+343>:	call   0x10a0 <printf@plt>
   0x0000000000001305 <+348>:	lea    rax,[rip+0x11a4]        # 0x24b0
   0x000000000000130c <+355>:	mov    rdi,rax
   0x000000000000130f <+358>:	call   0x1090 <puts@plt>
   0x0000000000001314 <+363>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001318 <+367>:	mov    rdi,rax
   0x000000000000131b <+370>:	call   0x1080 <free@plt>
   0x0000000000001320 <+375>:	lea    rax,[rip+0x11a9]        # 0x24d0
   0x0000000000001327 <+382>:	mov    rdi,rax
   0x000000000000132a <+385>:	call   0x1090 <puts@plt>
   0x000000000000132f <+390>:	lea    rax,[rip+0x11c2]        # 0x24f8
   0x0000000000001336 <+397>:	mov    rdi,rax
   0x0000000000001339 <+400>:	call   0x1090 <puts@plt>
   0x000000000000133e <+405>:	mov    edi,0x100
   0x0000000000001343 <+410>:	call   0x10b0 <malloc@plt>
   0x0000000000001348 <+415>:	mov    rsi,rax
   0x000000000000134b <+418>:	lea    rax,[rip+0x11d1]        # 0x2523
   0x0000000000001352 <+425>:	mov    rdi,rax
   0x0000000000001355 <+428>:	mov    eax,0x0
   0x000000000000135a <+433>:	call   0x10a0 <printf@plt>
   0x000000000000135f <+438>:	mov    edi,0x100
   0x0000000000001364 <+443>:	call   0x10b0 <malloc@plt>
   0x0000000000001369 <+448>:	mov    rsi,rax
   0x000000000000136c <+451>:	lea    rax,[rip+0x11c8]        # 0x253b
   0x0000000000001373 <+458>:	mov    rdi,rax
   0x0000000000001376 <+461>:	mov    eax,0x0
   0x000000000000137b <+466>:	call   0x10a0 <printf@plt>
   0x0000000000001380 <+471>:	nop
   0x0000000000001381 <+472>:	leave  
   0x0000000000001382 <+473>:	ret    
End of assembler dump.
gef➤  b *main+117
Breakpoint 1 at 0x121e
gef➤  b *main+175
Breakpoint 2 at 0x1258
gef➤  b *main+307
Breakpoint 3 at 0x12dc
gef➤  b *main+370
Breakpoint 4 at 0x131b
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_double_pass/tcache_double_pass 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So the purpose of this, is we want to actually pull off a tcache double free successfully.
Double frees can be helpful with heap exploitation.This is because a lot of heap exploitation revolves around editing the data of freed chunks.
By having a chunk inserted multiple times into the heap bins, you can allocate one copy of it, while it is still in a heap bin.
In many instances this will lead to you being able to edit a freed heap bin chunk.
Let's allocate a chunk, which will later be freed twice!.


Breakpoint 1, 0x000055555555521e in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x111             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x00005555555597b0  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x000055555555521e  →  <main+117> mov QWORD PTR [rbp-0x8], rax
$r8    : 0x0               
$r9    : 0x00005555555596b0  →  0x0000000000000000
$r10   : 0x0000555555556068  →  "Double frees can be helpful with heap exploitation[...]"
$r11   : 0x00007ffff7e19ce0  →  0x00005555555597b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555550c0  →  <_start+0> endbr64 
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555520f <main+102>       call   0x555555555090 <puts@plt>
   0x555555555214 <main+107>       mov    edi, 0x100
   0x555555555219 <main+112>       call   0x5555555550b0 <malloc@plt>
 → 0x55555555521e <main+117>       mov    QWORD PTR [rbp-0x8], rax
   0x555555555222 <main+121>       mov    rax, QWORD PTR [rbp-0x8]
   0x555555555226 <main+125>       mov    rsi, rax
   0x555555555229 <main+128>       lea    rax, [rip+0xfe3]        # 0x555555556213
   0x555555555230 <main+135>       mov    rdi, rax
   0x555555555233 <main+138>       mov    eax, 0x0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x55555555521e in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555521e → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555596b0
```

So, we see that the address of the chunk is `0x5555555596b0`. Let's see it get freed and inserted into the tcache:

```
gef➤  c
Continuing.
Chunk allocated at:	0x5555555596b0

Now let's free it, to insert it into the tcache.


Breakpoint 2, 0x0000555555555258 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0xf               
$rdx   : 0x555555559       
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7               
$rip   : 0x0000555555555258  →  <main+175> lea rax, [rip+0x1009]        # 0x555555556268
$r8    : 0x00005555555596b0  →  0x0000000555555559
$r9    : 0x00007fffffffde6c  →  "5555555596b0"
$r10   : 0x0               
$r11   : 0xde8a8fcc0332ea5d
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555524c <main+163>       mov    rax, QWORD PTR [rbp-0x8]
   0x555555555250 <main+167>       mov    rdi, rax
   0x555555555253 <main+170>       call   0x555555555080 <free@plt>
 → 0x555555555258 <main+175>       lea    rax, [rip+0x1009]        # 0x555555556268
   0x55555555525f <main+182>       mov    rdi, rax
   0x555555555262 <main+185>       call   0x555555555090 <puts@plt>
   0x555555555267 <main+190>       lea    rax, [rip+0x102a]        # 0x555555556298
   0x55555555526e <main+197>       mov    rdi, rax
   0x555555555271 <main+200>       call   0x555555555090 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x555555555258 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555258 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
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
```

So we see that our chunk is now present in the tcache. Let's see it have the tcache key value get overwritten:

```
gef➤  c
Continuing.
Now how does the tcache detect double frees?
It does this, by writing a value to a specific offset in the chunk.
This value is known as the tcache key, and it is set at offset `0x08` in the user data section of the chunk.
Then when malloc attempts to insert a new chunk into the tcache, it sees if it has the tcache key value set.
If it does, it know the chunk is already present in the tcache, and flags it as a double free.

We see here, the tcache key is 0xde8a8fcc0332ea5d

So to pass this check, we will simply overwrite the tcache key of the chunk with a different value.


Breakpoint 3, 0x00005555555552dc in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b8  →  0xde8a8fcc0332ea5d
$rbx   : 0x0               
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x00007ffff7e1ba70  →  0x0000000000000000
$rip   : 0x00005555555552dc  →  <main+307> mov QWORD PTR [rax], 0x0
$r8    : 0x0               
$r9    : 0x00007fffffffde68  →  "de8a8fcc0332ea5d"
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552cf <main+294>       call   0x555555555090 <puts@plt>
   0x5555555552d4 <main+299>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555552d8 <main+303>       add    rax, 0x8
 → 0x5555555552dc <main+307>       mov    QWORD PTR [rax], 0x0
   0x5555555552e3 <main+314>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555552e7 <main+318>       add    rax, 0x8
   0x5555555552eb <main+322>       mov    rax, QWORD PTR [rax]
   0x5555555552ee <main+325>       mov    rsi, rax
   0x5555555552f1 <main+328>       lea    rax, [rip+0x1128]        # 0x555555556420
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x5555555552dc in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552dc → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/20g 0x5555555596a0
0x5555555596a0:	0x0	0x111
0x5555555596b0:	0x555555559	0xde8a8fcc0332ea5d
0x5555555596c0:	0x0	0x0
0x5555555596d0:	0x0	0x0
0x5555555596e0:	0x0	0x0
0x5555555596f0:	0x0	0x0
0x555555559700:	0x0	0x0
0x555555559710:	0x0	0x0
0x555555559720:	0x0	0x0
0x555555559730:	0x0	0x0
gef➤  si
0x00005555555552e3 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b8  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x00007ffff7e1ba70  →  0x0000000000000000
$rip   : 0x00005555555552e3  →  <main+314> mov rax, QWORD PTR [rbp-0x8]
$r8    : 0x0               
$r9    : 0x00007fffffffde68  →  "de8a8fcc0332ea5d"
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552d4 <main+299>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555552d8 <main+303>       add    rax, 0x8
   0x5555555552dc <main+307>       mov    QWORD PTR [rax], 0x0
 → 0x5555555552e3 <main+314>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555552e7 <main+318>       add    rax, 0x8
   0x5555555552eb <main+322>       mov    rax, QWORD PTR [rax]
   0x5555555552ee <main+325>       mov    rsi, rax
   0x5555555552f1 <main+328>       lea    rax, [rip+0x1128]        # 0x555555556420
   0x5555555552f8 <main+335>       mov    rdi, rax
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x5555555552e3 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552e3 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/20g 0x5555555596a0
0x5555555596a0:	0x0	0x111
0x5555555596b0:	0x555555559	0x0
0x5555555596c0:	0x0	0x0
0x5555555596d0:	0x0	0x0
0x5555555596e0:	0x0	0x0
0x5555555596f0:	0x0	0x0
0x555555559700:	0x0	0x0
0x555555559710:	0x0	0x0
0x555555559720:	0x0	0x0
0x555555559730:	0x0	0x0
```

Now that the tcache key value has been overwritten, let's see the double free actually happen:

```
gef➤  c
Continuing.
We see here, the tcache key is 0x0

Now let's free the chunk again!

Breakpoint 4, 0x000055555555531b in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000555555559
$rbx   : 0x0               
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x00005555555596b0  →  0x0000000555555559
$rip   : 0x000055555555531b  →  <main+370> call 0x555555555080 <free@plt>
$r8    : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9    : 0x00007fffffffde77  →  0xf3e95b30ca490030 ("0"?)
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555530f <main+358>       call   0x555555555090 <puts@plt>
   0x555555555314 <main+363>       mov    rax, QWORD PTR [rbp-0x8]
   0x555555555318 <main+367>       mov    rdi, rax
 → 0x55555555531b <main+370>       call   0x555555555080 <free@plt>
   ↳  0x555555555080 <free@plt+0>     endbr64 
      0x555555555084 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f2d]        # 0x555555557fb8 <free@got.plt>
      0x55555555508b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555090 <puts@plt+0>     endbr64 
      0x555555555094 <puts@plt+4>     bnd    jmp QWORD PTR [rip+0x2f25]        # 0x555555557fc0 <puts@got.plt>
      0x55555555509b <puts@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555596b0 → 0x0000000555555559,
   $rsi = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x55555555531b in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555531b → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
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
gef➤  p $rdi
$2 = 0x5555555596b0
gef➤  si
0x0000555555555080 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000555555559
$rbx   : 0x0               
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdf98  →  0x0000555555555320  →  <main+375> lea rax, [rip+0x11a9]        # 0x5555555564d0
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x1               
$rdi   : 0x00005555555596b0  →  0x0000000555555559
$rip   : 0x0000555555555080  →  <free@plt+0> endbr64 
$r8    : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9    : 0x00007fffffffde77  →  0xf3e95b30ca490030 ("0"?)
$r10   : 0x0               
$r11   : 0x246             
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf98│+0x0000: 0x0000555555555320  →  <main+375> lea rax, [rip+0x11a9]        # 0x5555555564d0	 ← $rsp
0x00007fffffffdfa0│+0x0008: 0x0000000000001000
0x00007fffffffdfa8│+0x0010: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdfb0│+0x0018: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0028: 0x0000000000000000
0x00007fffffffdfc8│+0x0030: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0038: 0x00000001ffffe0b0
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555070 <__cxa_finalize@plt+0> endbr64 
   0x555555555074 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2f7d]        # 0x555555557ff8
   0x55555555507b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555080 <free@plt+0>     endbr64 
   0x555555555084 <free@plt+4>     bnd    jmp QWORD PTR [rip+0x2f2d]        # 0x555555557fb8 <free@got.plt>
   0x55555555508b <free@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555090 <puts@plt+0>     endbr64 
   0x555555555094 <puts@plt+4>     bnd    jmp QWORD PTR [rip+0x2f25]        # 0x555555557fc0 <puts@got.plt>
   0x55555555509b <puts@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x555555555080 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555080 → free@plt()
[#1] 0x555555555320 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555080 in free@plt ()
0x0000555555555320 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0xf               
$rdx   : 0x55500000c3e9    
$rsp   : 0x00007fffffffdfa0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfb0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7               
$rip   : 0x0000555555555320  →  <main+375> lea rax, [rip+0x11a9]        # 0x5555555564d0
$r8    : 0x00005555555596b0  →  0x000055500000c3e9
$r9    : 0x00007fffffffde77  →  0xf3e95b30ca490030 ("0"?)
$r10   : 0x0               
$r11   : 0xde8a8fcc0332ea5d
$r12   : 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64 
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000001000	 ← $rsp
0x00007fffffffdfa8│+0x0008: 0x00005555555596b0  →  0x000055500000c3e9
0x00007fffffffdfb0│+0x0010: 0x0000000000000001	 ← $rbp
0x00007fffffffdfb8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfc0│+0x0020: 0x0000000000000000
0x00007fffffffdfc8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64 
0x00007fffffffdfd0│+0x0030: 0x00000001ffffe0b0
0x00007fffffffdfd8│+0x0038: 0x00007fffffffe0c8  →  0x00007fffffffe3c6  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555314 <main+363>       mov    rax, QWORD PTR [rbp-0x8]
   0x555555555318 <main+367>       mov    rdi, rax
   0x55555555531b <main+370>       call   0x555555555080 <free@plt>
 → 0x555555555320 <main+375>       lea    rax, [rip+0x11a9]        # 0x5555555564d0
   0x555555555327 <main+382>       mov    rdi, rax
   0x55555555532a <main+385>       call   0x555555555090 <puts@plt>
   0x55555555532f <main+390>       lea    rax, [rip+0x11c2]        # 0x5555555564f8
   0x555555555336 <main+397>       mov    rdi, rax
   0x555555555339 <main+400>       call   0x555555555090 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_p", stopped 0x555555555320 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555320 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
──────────────────────────────────────── Tcachebins for thread 1 ────────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
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
gef➤  c
Continuing.
Now we have freed the same chunk twice.
We will be able to allocate it twice now!

Chunk Allocation 0:	0x5555555596b0
Chunk Allocation 1:	0x5555555596b0
[Inferior 1 (process 5211) exited with code 043]
```

Just like that, we have successfully seen a tcache double free!
