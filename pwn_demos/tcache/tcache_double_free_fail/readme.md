# tcache double free fail

So the purpose of this is to introduce the concept of a double free bug. A double free bug is effective when we can free the same chunk multiple times. The purpose of this is genuinely to have the same chunk inserted into binning mechanisms multiple times. That way, we can allocate one instance of that chunk in a binning mechanism. That way we have a chunk that we have both allocated, and in a heap bin. That way, in a lot of instances, it gives us a practical way to edit a chunk in a binning mechanism, to hopefully give us the ability to allocate a chunk to an arbitrary address.

One issue that can happen, especially with the fastbin/tcache, is that there are checks to catch this. This will just be showing an instance, where we fail a tcache double free check. Later on, we will show how to bypass these checks. Here is the code for the program:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100


void main() {
    long *chunk0;

    printf("So the purpose of this, is we want to introduce a double free bug.\n");
    printf("This is when we will free a chunk twice, to hopefully insert it multiple times into the heap bins.\n");
    printf("Now, for some of the bins, like tcache/fastbin, there are checks to hopefully catch it.\n");
    printf("When a check detects a double free, the program ends.\n");
    printf("Here we will see an instance where a check detects a double free.\n");
    printf("Now let's allocate a chunk.\n\n");

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

    printf("Now let's free the chunk again, and fail the double free chunk!\n");

    free(chunk0);

    printf("This printf should never run, because  we fail the tcache double free check.\n");
}
```

## Walkthrough

So for this walkthrough. We will see a chunk get allocated, freed, and inserted into the tcache. We will see it have a tcache key value set. Then when we free it again, we will see the tcache double free check fail, and the program ends. We first see the program run:

```
$   ./tcache_double_free_fail
So the purpose of this, is we want to introduce a double free bug.
This is when we will free a chunk twice, to hopefully insert it multiple times into the heap bins.
Now, for some of the bins, like tcache/fastbin, there are checks to hopefully catch it.
When a check detects a double free, the program ends.
Here we will see an instance where a check detects a double free.
Now let's allocate a chunk.

Chunk allocated at: 0x562956f546b0

Now let's free it, to insert it into the tcache.

Now how does the tcache detect double frees?
It does this, by writing a value to a speicifc offset in the chunk.
This value is known as the tcache key, and it is set at offset `0x08` in the user data section of the chunk.
Then when malloc attempts to insert a new chunk into the tcache, it sees if it has the tcache key value set.
If it does, it know the chunk is already present in the tcache, and flags it as a double free.

We see here, the tcache key is 0x1a36e96dfee55ba1

Now let's free the chunk again, and fail the double free chunk!
free(): double free detected in tcache 2
Aborted (core dumped)
```

Now let's see it in a debugger. We will see what the chunk looks like in the tcache:

```
$   gdb ./tcache_double_free_fail
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
Reading symbols from ./tcache_double_free_fail...
(No debugging symbols found in ./tcache_double_free_fail)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>: endbr64
   0x00000000000011ad <+4>: push   rbp
   0x00000000000011ae <+5>: mov rbp,rsp
   0x00000000000011b1 <+8>: sub rsp,0x10
   0x00000000000011b5 <+12>:    lea rax,[rip+0xe4c]     # 0x2008
   0x00000000000011bc <+19>:    mov rdi,rax
   0x00000000000011bf <+22>:    call   0x1090 <puts@plt>
   0x00000000000011c4 <+27>:    lea rax,[rip+0xe85]     # 0x2050
   0x00000000000011cb <+34>:    mov rdi,rax
   0x00000000000011ce <+37>:    call   0x1090 <puts@plt>
   0x00000000000011d3 <+42>:    lea rax,[rip+0xede]     # 0x20b8
   0x00000000000011da <+49>:    mov rdi,rax
   0x00000000000011dd <+52>:    call   0x1090 <puts@plt>
   0x00000000000011e2 <+57>:    lea rax,[rip+0xf27]     # 0x2110
   0x00000000000011e9 <+64>:    mov rdi,rax
   0x00000000000011ec <+67>:    call   0x1090 <puts@plt>
   0x00000000000011f1 <+72>:    lea rax,[rip+0xf50]     # 0x2148
   0x00000000000011f8 <+79>:    mov rdi,rax
   0x00000000000011fb <+82>:    call   0x1090 <puts@plt>
   0x0000000000001200 <+87>:    lea rax,[rip+0xf83]     # 0x218a
   0x0000000000001207 <+94>:    mov rdi,rax
   0x000000000000120a <+97>:    call   0x1090 <puts@plt>
   0x000000000000120f <+102>:   mov edi,0x100
   0x0000000000001214 <+107>:   call   0x10b0 <malloc@plt>
   0x0000000000001219 <+112>:   mov QWORD PTR [rbp-0x8],rax
   0x000000000000121d <+116>:   mov rax,QWORD PTR [rbp-0x8]
   0x0000000000001221 <+120>:   mov rsi,rax
   0x0000000000001224 <+123>:   lea rax,[rip+0xf7c]     # 0x21a7
   0x000000000000122b <+130>:   mov rdi,rax
   0x000000000000122e <+133>:   mov eax,0x0
   0x0000000000001233 <+138>:   call   0x10a0 <printf@plt>
   0x0000000000001238 <+143>:   lea rax,[rip+0xf81]     # 0x21c0
   0x000000000000123f <+150>:   mov rdi,rax
   0x0000000000001242 <+153>:   call   0x1090 <puts@plt>
   0x0000000000001247 <+158>:   mov rax,QWORD PTR [rbp-0x8]
   0x000000000000124b <+162>:   mov rdi,rax
   0x000000000000124e <+165>:   call   0x1080 <free@plt>
   0x0000000000001253 <+170>:   lea rax,[rip+0xf9e]     # 0x21f8
   0x000000000000125a <+177>:   mov rdi,rax
   0x000000000000125d <+180>:   call   0x1090 <puts@plt>
   0x0000000000001262 <+185>:   lea rax,[rip+0xfbf]     # 0x2228
   0x0000000000001269 <+192>:   mov rdi,rax
   0x000000000000126c <+195>:   call   0x1090 <puts@plt>
   0x0000000000001271 <+200>:   lea rax,[rip+0xff8]     # 0x2270
   0x0000000000001278 <+207>:   mov rdi,rax
   0x000000000000127b <+210>:   call   0x1090 <puts@plt>
   0x0000000000001280 <+215>:   lea rax,[rip+0x1059]        # 0x22e0
   0x0000000000001287 <+222>:   mov rdi,rax
   0x000000000000128a <+225>:   call   0x1090 <puts@plt>
   0x000000000000128f <+230>:   lea rax,[rip+0x10ba]        # 0x2350
   0x0000000000001296 <+237>:   mov rdi,rax
   0x0000000000001299 <+240>:   call   0x1090 <puts@plt>
   0x000000000000129e <+245>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000012a2 <+249>:   add rax,0x8
   0x00000000000012a6 <+253>:   mov rax,QWORD PTR [rax]
   0x00000000000012a9 <+256>:   mov rsi,rax
   0x00000000000012ac <+259>:   lea rax,[rip+0x10fd]        # 0x23b0
   0x00000000000012b3 <+266>:   mov rdi,rax
   0x00000000000012b6 <+269>:   mov eax,0x0
   0x00000000000012bb <+274>:   call   0x10a0 <printf@plt>
   0x00000000000012c0 <+279>:   lea rax,[rip+0x1111]        # 0x23d8
   0x00000000000012c7 <+286>:   mov rdi,rax
   0x00000000000012ca <+289>:   call   0x1090 <puts@plt>
   0x00000000000012cf <+294>:   mov rax,QWORD PTR [rbp-0x8]
   0x00000000000012d3 <+298>:   mov rdi,rax
   0x00000000000012d6 <+301>:   call   0x1080 <free@plt>
   0x00000000000012db <+306>:   lea rax,[rip+0x1136]        # 0x2418
   0x00000000000012e2 <+313>:   mov rdi,rax
   0x00000000000012e5 <+316>:   call   0x1090 <puts@plt>
   0x00000000000012ea <+321>:   nop
   0x00000000000012eb <+322>:   leave  
   0x00000000000012ec <+323>:   ret    
End of assembler dump.
gef➤  b *main+170
Breakpoint 1 at 0x1253
gef➤  b *main+301
Breakpoint 2 at 0x12d6
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_double_free_fail/tcache_double_free_fail
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
So the purpose of this, is we want to introduce a double free bug.
This is when we will free a chunk twice, to hopefully insert it multiple times into the heap bins.
Now, for some of the bins, like tcache/fastbin, there are checks to hopefully catch it.
When a check detects a double free, the program ends.
Here we will see an instance where a check detects a double free.
Now let's allocate a chunk.

Chunk allocated at: 0x5555555596b0

Now let's free it, to insert it into the tcache.


Breakpoint 1, 0x0000555555555253 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf80  →  0x0000000000001000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x7             
$rip   : 0x0000555555555253  →  <main+170> lea rax, [rip+0xf9e]     # 0x5555555561f8
$r8 : 0x00005555555596b0  →  0x0000000555555559
$r9 : 0x00007fffffffde4c  →  "5555555596b0"
$r10   : 0x0             
$r11   : 0x7a07586f5f3b2ca8
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3ad  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf90│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdf98│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfa0│+0x0020: 0x0000000000000000
0x00007fffffffdfa8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x00000001ffffe090
0x00007fffffffdfb8│+0x0038: 0x00007fffffffe0a8  →  0x00007fffffffe3ad  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555247 <main+158>    mov rax, QWORD PTR [rbp-0x8]
   0x55555555524b <main+162>    mov rdi, rax
   0x55555555524e <main+165>    call   0x555555555080 <free@plt>
 → 0x555555555253 <main+170>    lea rax, [rip+0xf9e]        # 0x5555555561f8
   0x55555555525a <main+177>    mov rdi, rax
   0x55555555525d <main+180>    call   0x555555555090 <puts@plt>
   0x555555555262 <main+185>    lea rax, [rip+0xfbf]        # 0x555555556228
   0x555555555269 <main+192>    mov rdi, rax
   0x55555555526c <main+195>    call   0x555555555090 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_f", stopped 0x555555555253 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555253 → main()
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
gef➤  x/20g 0x5555555596a0
0x5555555596a0: 0x0 0x111
0x5555555596b0: 0x555555559 0x7a07586f5f3b2ca8
0x5555555596c0: 0x0 0x0
0x5555555596d0: 0x0 0x0
0x5555555596e0: 0x0 0x0
0x5555555596f0: 0x0 0x0
0x555555559700: 0x0 0x0
0x555555559710: 0x0 0x0
0x555555559720: 0x0 0x0
0x555555559730: 0x0 0x0
```

So we see that our chunk (at `0x5555555596b0`) is in the tcache, with a tcache key value of `0x7a07586f5f3b2ca8`. Now let's see this chunk get freed again, which malloc will attempt to insert it into the tcache again, and fail the double free check:

```
gef➤  c
Continuing.
Now how does the tcache detect double frees?
It does this, by writing a value to a speicifc offset in the chunk.
This value is known as the tcache key, and it is set at offset `0x08` in the user data section of the chunk.
Then when malloc attempts to insert a new chunk into the tcache, it sees if it has the tcache key value set.
If it does, it know the chunk is already present in the tcache, and flags it as a double free.

We see here, the tcache key is 0x7a07586f5f3b2ca8

Now let's free the chunk again, and fail the double free chunk!

Breakpoint 2, 0x00005555555552d6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf80  →  0x0000000000001000
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x00005555555596b0  →  0x0000000555555559
$rip   : 0x00005555555552d6  →  <main+301> call 0x555555555080 <free@plt>
$r8 : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9 : 0x00007fffffffde48  →  "7a07586f5f3b2ca8"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3ad  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf80│+0x0000: 0x0000000000001000   ← $rsp
0x00007fffffffdf88│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf90│+0x0010: 0x0000000000000001   ← $rbp
0x00007fffffffdf98│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfa0│+0x0020: 0x0000000000000000
0x00007fffffffdfa8│+0x0028: 0x00005555555551a9  →  <main+0> endbr64
0x00007fffffffdfb0│+0x0030: 0x00000001ffffe090
0x00007fffffffdfb8│+0x0038: 0x00007fffffffe0a8  →  0x00007fffffffe3ad  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ca <main+289>    call   0x555555555090 <puts@plt>
   0x5555555552cf <main+294>    mov rax, QWORD PTR [rbp-0x8]
   0x5555555552d3 <main+298>    mov rdi, rax
 → 0x5555555552d6 <main+301>    call   0x555555555080 <free@plt>
   ↳  0x555555555080 <free@plt+0>   endbr64
    0x555555555084 <free@plt+4>     bnd jmp QWORD PTR [rip+0x2f2d]      # 0x555555557fb8 <free@got.plt>
    0x55555555508b <free@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
    0x555555555090 <puts@plt+0>     endbr64
    0x555555555094 <puts@plt+4>     bnd jmp QWORD PTR [rip+0x2f25]      # 0x555555557fc0 <puts@got.plt>
    0x55555555509b <puts@plt+11>    nop DWORD PTR [rax+rax*1+0x0]
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00005555555596b0 → 0x0000000555555559,
   $rsi = 0x0000000000000001,
   $rdx = 0x0000000000000001
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_f", stopped 0x5555555552d6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552d6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdi
$1 = 0x5555555596b0
gef➤  si
0x0000555555555080 in free@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x00007ffff7d14a37  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1             
$rsp   : 0x00007fffffffdf78  →  0x00005555555552db  →  <main+306> lea rax, [rip+0x1136]     # 0x555555556418
$rbp   : 0x00007fffffffdf90  →  0x0000000000000001
$rsi   : 0x1             
$rdi   : 0x00005555555596b0  →  0x0000000555555559
$rip   : 0x0000555555555080  →  <free@plt+0> endbr64
$r8 : 0x00007ffff7e1ba70  →  0x0000000000000000
$r9 : 0x00007fffffffde48  →  "7a07586f5f3b2ca8"
$r10   : 0x0             
$r11   : 0x246           
$r12   : 0x00007fffffffe0a8  →  0x00007fffffffe3ad  →  "/Hackery/shogun/pwn_demos/tcache/tcache_d[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf78│+0x0000: 0x00005555555552db  →  <main+306> lea rax, [rip+0x1136]     # 0x555555556418  ← $rsp
0x00007fffffffdf80│+0x0008: 0x0000000000001000
0x00007fffffffdf88│+0x0010: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf90│+0x0018: 0x0000000000000001   ← $rbp
0x00007fffffffdf98│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfa0│+0x0028: 0x0000000000000000
0x00007fffffffdfa8│+0x0030: 0x00005555555551a9  →  <main+0> endbr64
0x00007fffffffdfb0│+0x0038: 0x00000001ffffe090
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
[#0] Id 1, Name: "tcache_double_f", stopped 0x555555555080 in free@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555080 → free@plt()
[#1] 0x5555555552db → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555080 in free@plt ()
free(): double free detected in tcache 2

Program received signal SIGABRT, Aborted.
__pthread_kill_implementation (no_tid=0x0, signo=0x6, threadid=0x7ffff7fa4740) at ./nptl/pthread_kill.c:44
44  ./nptl/pthread_kill.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x00007ffff7fa4740  →  0x00007ffff7fa4740  →  [loop detected]
$rcx   : 0x00007ffff7c96a7c  →  <pthread_kill+300> mov r13d, eax
$rdx   : 0x6             
$rsp   : 0x00007fffffffdbb0  →  0x00007ffff7fc3908  →  0x000d00120000000e
$rbp   : 0x5700          
$rsi   : 0x5700          
$rdi   : 0x5700          
$rip   : 0x00007ffff7c96a7c  →  <pthread_kill+300> mov r13d, eax
$r8 : 0x00007fffffffdc80  →  0x0000000000000020 (" "?)
$r9 : 0x0            
$r10   : 0x8             
$r11   : 0x246           
$r12   : 0x6             
$r13   : 0x16            
$r14   : 0x1             
$r15   : 0x1             
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdbb0│+0x0000: 0x00007ffff7fc3908  →  0x000d00120000000e   ← $rsp
0x00007fffffffdbb8│+0x0008: 0x00007ffff7ffdaf0  →  0x00007ffff7fc3000  →  0x03010102464c457f
0x00007fffffffdbc0│+0x0010: 0x00007ffff7fc3c12  →  0x0007000700070000
0x00007fffffffdbc8│+0x0018: 0x0000000000000000
0x00007fffffffdbd0│+0x0020: 0x00007ffff7fc3590  →  0x0000000000000000
0x00007fffffffdbd8│+0x0028: 0x00007ffff7ffca50  →  0x0000000000000000
0x00007fffffffdbe0│+0x0030: 0x00007ffff7fc38d8  →  0x000d001200000258
0x00007fffffffdbe8│+0x0038: 0x00007ffff7fd01d4  →  <_dl_lookup_direct+292> test eax, eax
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7c96a73 <pthread_kill+291> mov    edi, eax
   0x7ffff7c96a75 <pthread_kill+293> mov    eax, 0xea
   0x7ffff7c96a7a <pthread_kill+298> syscall
 → 0x7ffff7c96a7c <pthread_kill+300> mov    r13d, eax
   0x7ffff7c96a7f <pthread_kill+303> neg    r13d
   0x7ffff7c96a82 <pthread_kill+306> cmp    eax, 0xfffff000
   0x7ffff7c96a87 <pthread_kill+311> mov    eax, 0x0
   0x7ffff7c96a8c <pthread_kill+316> cmovbe r13d, eax
   0x7ffff7c96a90 <pthread_kill+320> jmp    0x7ffff7c96a02 <__GI___pthread_kill+178>
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_double_f", stopped 0x7ffff7c96a7c in __pthread_kill_implementation (), reason: SIGABRT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7c96a7c → __pthread_kill_implementation(no_tid=0x0, signo=0x6, threadid=0x7ffff7fa4740)
[#1] 0x7ffff7c96a7c → __pthread_kill_internal(signo=0x6, threadid=0x7ffff7fa4740)
[#2] 0x7ffff7c96a7c → __GI___pthread_kill(threadid=0x7ffff7fa4740, signo=0x6)
[#3] 0x7ffff7c42476 → __GI_raise(sig=0x6)
[#4] 0x7ffff7c287f3 → __GI_abort()
[#5] 0x7ffff7c896f6 → __libc_message(action=do_abort, fmt=0x7ffff7ddbb8c "%s\n")
[#6] 0x7ffff7ca0d7c → malloc_printerr(str=0x7ffff7dde710 "free(): double free detected in tcache 2")
[#7] 0x7ffff7ca312b → _int_free(av=0x7ffff7e19c80 <main_arena>, p=0x5555555596a0, have_lock=0x0)
[#8] 0x7ffff7ca54d3 → __GI___libc_free(mem=<optimized out>)
[#9] 0x5555555552db → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.

Program terminated with signal SIGABRT, Aborted.
The program no longer exists.
```

So like that, we see an instance of a double free fail check that we have to pass in order to actually successfully pull off a double free.
