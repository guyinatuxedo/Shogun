# tcache struct

So in this writeup, we will be looking at something a bit weird. The tcache bins are modeled by the tcache struct which we have reviewed. It's effectively two seperate arrays, the first consists of counts for the tcache bins, the second consists of the heads for the tcache linked list bins. This writeup will look at editing that struct.

Full disclosure, I actually haven't seen a situation in any ctf where this would be helpful. This is just something I think is helpful, and might be useful in some super weird scenario.

So by editing the tcache struct, there are two things we will do in this writeup. Prevent a chunk in the tcache from being reallocated, and change the tcache bin head chunk.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x100

void main() {
   char *chunk0,
         *chunk1;
   long data[10];

   printf("%p\n", &data);

   chunk0 = malloc(CHUNK_SIZE0);
   free(chunk0);
   malloc(CHUNK_SIZE0);
}
```

## Walkthrough Explannation

So for this, we will be doing two seperate things. The first is preventing an existing tcache chunk from being reallocated. The second is to change the tcache head chunk, to change the chunk which would be allocated.

To prevent the existing tcache chunk from being reallocated, we will just change the corresponding bin chunk count to `0x00`, which it uses to see if the bin has chunks left to reallocate.

To change the tcache head chunk, I will just overwrite the head ptr (which isn't mangled). To ensure proper allocation of that chunk, I will set the chunk metadata accordingly.

Before we go through the two different scenarios, here is what it looks like in the normal circumstance. We will be using the gdb debugging functionality, to edit data as needed:

```
$  gdb ./tcache_struct
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
Reading symbols from ./tcache_struct...
(No debugging symbols found in ./tcache_struct)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>:   endbr64
   0x00000000000011ad <+4>:   push   rbp
   0x00000000000011ae <+5>:   mov   rbp,rsp
   0x00000000000011b1 <+8>:   sub   rsp,0x70
   0x00000000000011b5 <+12>:  mov   rax,QWORD PTR fs:0x28
   0x00000000000011be <+21>:  mov   QWORD PTR [rbp-0x8],rax
   0x00000000000011c2 <+25>:  xor   eax,eax
   0x00000000000011c4 <+27>:  lea   rax,[rbp-0x60]
   0x00000000000011c8 <+31>:  mov   rsi,rax
   0x00000000000011cb <+34>:  lea   rax,[rip+0xe32]      # 0x2004
   0x00000000000011d2 <+41>:  mov   rdi,rax
   0x00000000000011d5 <+44>:  mov   eax,0x0
   0x00000000000011da <+49>:  call   0x10a0 <printf@plt>
   0x00000000000011df <+54>:  mov   edi,0x100
   0x00000000000011e4 <+59>:  call   0x10b0 <malloc@plt>
   0x00000000000011e9 <+64>:  mov   QWORD PTR [rbp-0x68],rax
   0x00000000000011ed <+68>:  mov   rax,QWORD PTR [rbp-0x68]
   0x00000000000011f1 <+72>:  mov   rdi,rax
   0x00000000000011f4 <+75>:  call   0x1080 <free@plt>
   0x00000000000011f9 <+80>:  mov   edi,0x100
   0x00000000000011fe <+85>:  call   0x10b0 <malloc@plt>
   0x0000000000001203 <+90>:  nop
   0x0000000000001204 <+91>:  mov   rax,QWORD PTR [rbp-0x8]
   0x0000000000001208 <+95>:  sub   rax,QWORD PTR fs:0x28
   0x0000000000001211 <+104>: je    0x1218 <main+111>
   0x0000000000001213 <+106>: call   0x1090 <__stack_chk_fail@plt>
   0x0000000000001218 <+111>: leave  
   0x0000000000001219 <+112>: ret    
End of assembler dump.
gef➤  b *main+85
Breakpoint 1 at 0x11fe
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_struct/tcache_struct
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x7fffffffdf60

Breakpoint 1, 0x00005555555551fe in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555551fe  →  <main+85> call 0x5555555550b0 <malloc@plt>
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0xb932d3a3571f3793
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0018: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0020: 0x00000000000006f0
0x00007fffffffdf78│+0x0028: 0x00007fffffffe3b9  →  0x26e8302ae8a2e32a
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f1 <main+72>      mov   rdi, rax
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
 → 0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
   ↳  0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000100
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555551fe in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551fe → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555596b0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  si
0x00005555555550b0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf48  →  0x0000555555555203  →  <main+90> nop
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555550b0  →  <malloc@plt+0> endbr64
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0xb932d3a3571f3793
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf48│+0x0000: 0x0000555555555203  →  <main+90> nop   ← $rsp
0x00007fffffffdf50│+0x0008: 0x0000000000000001
0x00007fffffffdf58│+0x0010: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0018: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0020: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0028: 0x00000000000006f0
0x00007fffffffdf78│+0x0030: 0x00007fffffffe3b9  →  0x26e8302ae8a2e32a
0x00007fffffffdf80│+0x0038: 0x00007ffff7fc1000  →  0x00010102464c457f
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550a0 <printf@plt+0>   endbr64
   0x5555555550a4 <printf@plt+4>   bnd jmp QWORD PTR [rip+0x2f1d]       # 0x555555557fc8 <printf@got.plt>
   0x5555555550ab <printf@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555550b0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550b0 → malloc@plt()
[#1] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550b0 in malloc@plt ()
0x0000555555555203 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555596b0  →  0x0000000555555559
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0             
$rdi   : 0x1f            
$rip   : 0x0000555555555203  →  <main+90> nop
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0xb932d3a3571f3793
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0018: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0020: 0x00000000000006f0
0x00007fffffffdf78│+0x0028: 0x00007fffffffe3b9  →  0x26e8302ae8a2e32a
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
   0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
 → 0x555555555203 <main+90>      nop    
   0x555555555204 <main+91>      mov   rax, QWORD PTR [rbp-0x8]
   0x555555555208 <main+95>      sub   rax, QWORD PTR fs:0x28
   0x555555555211 <main+104>     je    0x555555555218 <main+111>
   0x555555555213 <main+106>     call   0x555555555090 <__stack_chk_fail@plt>
   0x555555555218 <main+111>     leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x555555555203 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555596b0
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
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x0
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  c
Continuing.
[Inferior 1 (process 5731) exited normally]
```

## Walkthrough Prevent Tcache Chunk Reallocation

So now, we will prevent the chunk reallocation via setting the corresponding bin count to `0x00`. We see, even though in the normal circumstance the chunk get reallocated, this is enough to prevent the tcache chunk from getting reallocated:

```
$  gdb ./tcache_struct
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
Reading symbols from ./tcache_struct...
(No debugging symbols found in ./tcache_struct)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>:   endbr64
   0x00000000000011ad <+4>:   push   rbp
   0x00000000000011ae <+5>:   mov   rbp,rsp
   0x00000000000011b1 <+8>:   sub   rsp,0x70
   0x00000000000011b5 <+12>:  mov   rax,QWORD PTR fs:0x28
   0x00000000000011be <+21>:  mov   QWORD PTR [rbp-0x8],rax
   0x00000000000011c2 <+25>:  xor   eax,eax
   0x00000000000011c4 <+27>:  lea   rax,[rbp-0x60]
   0x00000000000011c8 <+31>:  mov   rsi,rax
   0x00000000000011cb <+34>:  lea   rax,[rip+0xe32]      # 0x2004
   0x00000000000011d2 <+41>:  mov   rdi,rax
   0x00000000000011d5 <+44>:  mov   eax,0x0
   0x00000000000011da <+49>:  call   0x10a0 <printf@plt>
   0x00000000000011df <+54>:  mov   edi,0x100
   0x00000000000011e4 <+59>:  call   0x10b0 <malloc@plt>
   0x00000000000011e9 <+64>:  mov   QWORD PTR [rbp-0x68],rax
   0x00000000000011ed <+68>:  mov   rax,QWORD PTR [rbp-0x68]
   0x00000000000011f1 <+72>:  mov   rdi,rax
   0x00000000000011f4 <+75>:  call   0x1080 <free@plt>
   0x00000000000011f9 <+80>:  mov   edi,0x100
   0x00000000000011fe <+85>:  call   0x10b0 <malloc@plt>
   0x0000000000001203 <+90>:  nop
   0x0000000000001204 <+91>:  mov   rax,QWORD PTR [rbp-0x8]
   0x0000000000001208 <+95>:  sub   rax,QWORD PTR fs:0x28
   0x0000000000001211 <+104>: je    0x1218 <main+111>
   0x0000000000001213 <+106>: call   0x1090 <__stack_chk_fail@plt>
   0x0000000000001218 <+111>: leave  
   0x0000000000001219 <+112>: ret    
End of assembler dump.
gef➤  b *main+85
Breakpoint 1 at 0x11fe
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_struct/tcache_struct
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x7fffffffdf60

Breakpoint 1, 0x00005555555551fe in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555551fe  →  <main+85> call 0x5555555550b0 <malloc@plt>
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0x5d20d34d4230bcfe
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0018: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0020: 0x00000000000006f0
0x00007fffffffdf78│+0x0028: 0x00007fffffffe3b9  →  0x3d8ea1598d696576
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f1 <main+72>      mov   rdi, rax
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
 → 0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
   ↳  0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000100
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555551fe in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551fe → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555596b0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  set *((long*) 0x555555559028) = 0x00
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x0
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555596b0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  si
0x00005555555550b0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf48  →  0x0000555555555203  →  <main+90> nop
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555550b0  →  <malloc@plt+0> endbr64
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0x5d20d34d4230bcfe
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf48│+0x0000: 0x0000555555555203  →  <main+90> nop   ← $rsp
0x00007fffffffdf50│+0x0008: 0x0000000000000001
0x00007fffffffdf58│+0x0010: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0018: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0020: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0028: 0x00000000000006f0
0x00007fffffffdf78│+0x0030: 0x00007fffffffe3b9  →  0x3d8ea1598d696576
0x00007fffffffdf80│+0x0038: 0x00007ffff7fc1000  →  0x00010102464c457f
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550a0 <printf@plt+0>   endbr64
   0x5555555550a4 <printf@plt+4>   bnd jmp QWORD PTR [rip+0x2f1d]       # 0x555555557fc8 <printf@got.plt>
   0x5555555550ab <printf@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555550b0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550b0 → malloc@plt()
[#1] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550b0 in malloc@plt ()
0x0000555555555203 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555597c0  →  0x0000000000000000
$rbx   : 0x0             
$rcx   : 0x111           
$rdx   : 0x0             
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00005555555598c0  →  0x0000000000000000
$rdi   : 0x0             
$rip   : 0x0000555555555203  →  <main+90> nop
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555597c0  →  0x0000000000000000
$r10   : 0x77            
$r11   : 0x00007ffff7e19ce0  →  0x00005555555598c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0018: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0020: 0x00000000000006f0
0x00007fffffffdf78│+0x0028: 0x00007fffffffe3b9  →  0x3d8ea1598d696576
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
   0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
 → 0x555555555203 <main+90>      nop    
   0x555555555204 <main+91>      mov   rax, QWORD PTR [rbp-0x8]
   0x555555555208 <main+95>      sub   rax, QWORD PTR fs:0x28
   0x555555555211 <main+104>     je    0x555555555218 <main+111>
   0x555555555213 <main+106>     call   0x555555555090 <__stack_chk_fail@plt>
   0x555555555218 <main+111>     leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x555555555203 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555597c0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
[Inferior 1 (process 5712) exited normally]
```

## Walkthrough Change Tcache Bin Head

So in this example, we change the chunk which a tcache bin will allocate. We do this via creating a fake tcache chunk, with correct chunk metadata and next ptr (not the tcache key). Then we set the corresponding head ptr in the tcache bin, to our new chunk. Then with the next allocation from that bin, we see that we get the chunk that we set the head ptr to.

```
$  gdb ./tcache_struct
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
Reading symbols from ./tcache_struct...
(No debugging symbols found in ./tcache_struct)
gef➤  disas main
Dump of assembler code for function main:
   0x00000000000011a9 <+0>:   endbr64
   0x00000000000011ad <+4>:   push   rbp
   0x00000000000011ae <+5>:   mov   rbp,rsp
   0x00000000000011b1 <+8>:   sub   rsp,0x70
   0x00000000000011b5 <+12>:  mov   rax,QWORD PTR fs:0x28
   0x00000000000011be <+21>:  mov   QWORD PTR [rbp-0x8],rax
   0x00000000000011c2 <+25>:  xor   eax,eax
   0x00000000000011c4 <+27>:  lea   rax,[rbp-0x60]
   0x00000000000011c8 <+31>:  mov   rsi,rax
   0x00000000000011cb <+34>:  lea   rax,[rip+0xe32]      # 0x2004
   0x00000000000011d2 <+41>:  mov   rdi,rax
   0x00000000000011d5 <+44>:  mov   eax,0x0
   0x00000000000011da <+49>:  call   0x10a0 <printf@plt>
   0x00000000000011df <+54>:  mov   edi,0x100
   0x00000000000011e4 <+59>:  call   0x10b0 <malloc@plt>
   0x00000000000011e9 <+64>:  mov   QWORD PTR [rbp-0x68],rax
   0x00000000000011ed <+68>:  mov   rax,QWORD PTR [rbp-0x68]
   0x00000000000011f1 <+72>:  mov   rdi,rax
   0x00000000000011f4 <+75>:  call   0x1080 <free@plt>
   0x00000000000011f9 <+80>:  mov   edi,0x100
   0x00000000000011fe <+85>:  call   0x10b0 <malloc@plt>
   0x0000000000001203 <+90>:  nop
   0x0000000000001204 <+91>:  mov   rax,QWORD PTR [rbp-0x8]
   0x0000000000001208 <+95>:  sub   rax,QWORD PTR fs:0x28
   0x0000000000001211 <+104>: je    0x1218 <main+111>
   0x0000000000001213 <+106>: call   0x1090 <__stack_chk_fail@plt>
   0x0000000000001218 <+111>: leave  
   0x0000000000001219 <+112>: ret    
End of assembler dump.
gef➤  b *main+85
Breakpoint 1 at 0x11fe
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/tcache/tcache_struct/tcache_struct
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x7fffffffdf60

Breakpoint 1, 0x00005555555551fe in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555551fe  →  <main+85> call 0x5555555550b0 <malloc@plt>
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0x25b77f1adb05647d
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000555555554040  →   (bad)
0x00007fffffffdf68│+0x0018: 0x00007ffff7fe285c  →  <_dl_sysdep_start+1020> mov rax, QWORD PTR [rsp+0x58]
0x00007fffffffdf70│+0x0020: 0x00000000000006f0
0x00007fffffffdf78│+0x0028: 0x00007fffffffe3b9  →  0xd648c3a3b64126ee
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f1 <main+72>      mov   rdi, rax
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
 → 0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
   ↳  0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000100
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555551fe in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551fe → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=15, size=0x110, count=1] ←  Chunk(addr=0x5555555596b0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555596b0
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  x/20g 0x7fffffffdf60
0x7fffffffdf60:   0x555555554040 0x7ffff7fe285c
0x7fffffffdf70:   0x6f0 0x7fffffffe3b9
0x7fffffffdf80:   0x7ffff7fc1000 0x10101000000
0x7fffffffdf90:   0x2   0x78bfbff
0x7fffffffdfa0:   0x7fffffffe3c9 0x64
0x7fffffffdfb0:   0x1000   0xd648c3a3b6412600
0x7fffffffdfc0:   0x1   0x7ffff7c29d90
0x7fffffffdfd0:   0x0   0x5555555551a9
0x7fffffffdfe0:   0x1ffffe0c0 0x7fffffffe0d8
0x7fffffffdff0:   0x0   0x5d503a82edbe2143
gef➤  set *((long *) 0x7fffffffdf60) = 0x00
gef➤  set *((long *) 0x7fffffffdf68) = 0x111
gef➤  set *((long *) 0x7fffffffdf70) = 0x7fffffffdf
gef➤  set *((long *) 0x555555559108) = 0x7fffffffdf70
gef➤  x/20g 0x7fffffffdf60
0x7fffffffdf60:   0x0   0x111
0x7fffffffdf70:   0x7fffffffdf   0x7fffffffe3b9
0x7fffffffdf80:   0x7ffff7fc1000 0x10101000000
0x7fffffffdf90:   0x2   0x78bfbff
0x7fffffffdfa0:   0x7fffffffe3c9 0x64
0x7fffffffdfb0:   0x1000   0xd648c3a3b6412600
0x7fffffffdfc0:   0x1   0x7ffff7c29d90
0x7fffffffdfd0:   0x0   0x5555555551a9
0x7fffffffdfe0:   0x1ffffe0c0 0x7fffffffe0d8
0x7fffffffdff0:   0x0   0x5d503a82edbe2143
gef➤  x/80g tcache
0x555555559010:   0x0   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x0
0x555555559090:   0x0   0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x7fffffffdf70
0x555555559110:   0x0   0x0
0x555555559120:   0x0   0x0
0x555555559130:   0x0   0x0
0x555555559140:   0x0   0x0
0x555555559150:   0x0   0x0
0x555555559160:   0x0   0x0
0x555555559170:   0x0   0x0
0x555555559180:   0x0   0x0
0x555555559190:   0x0   0x0
0x5555555591a0:   0x0   0x0
0x5555555591b0:   0x0   0x0
0x5555555591c0:   0x0   0x0
0x5555555591d0:   0x0   0x0
0x5555555591e0:   0x0   0x0
0x5555555591f0:   0x0   0x0
0x555555559200:   0x0   0x0
0x555555559210:   0x0   0x0
0x555555559220:   0x0   0x0
0x555555559230:   0x0   0x0
0x555555559240:   0x0   0x0
0x555555559250:   0x0   0x0
0x555555559260:   0x0   0x0
0x555555559270:   0x0   0x0
0x555555559280:   0x0   0x0
gef➤  si
0x00005555555550b0 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0             
$rbx   : 0x0             
$rcx   : 0xf             
$rdx   : 0x555555559     
$rsp   : 0x00007fffffffdf48  →  0x0000555555555203  →  <main+90> nop
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559010  →  0x0000000000000000
$rdi   : 0x100           
$rip   : 0x00005555555550b0  →  <malloc@plt+0> endbr64
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0x25b77f1adb05647d
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf48│+0x0000: 0x0000555555555203  →  <main+90> nop   ← $rsp
0x00007fffffffdf50│+0x0008: 0x0000000000000001
0x00007fffffffdf58│+0x0010: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0018: 0x0000000000000000
0x00007fffffffdf68│+0x0020: 0x0000000000000111
0x00007fffffffdf70│+0x0028: 0x0000007fffffffdf
0x00007fffffffdf78│+0x0030: 0x00007fffffffe3b9  →  0xd648c3a3b64126ee
0x00007fffffffdf80│+0x0038: 0x00007ffff7fc1000  →  0x00010102464c457f
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555550a0 <printf@plt+0>   endbr64
   0x5555555550a4 <printf@plt+4>   bnd jmp QWORD PTR [rip+0x2f1d]       # 0x555555557fc8 <printf@got.plt>
   0x5555555550ab <printf@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
 → 0x5555555550b0 <malloc@plt+0>   endbr64
   0x5555555550b4 <malloc@plt+4>   bnd jmp QWORD PTR [rip+0x2f15]       # 0x555555557fd0 <malloc@got.plt>
   0x5555555550bb <malloc@plt+11>  nop DWORD PTR [rax+rax*1+0x0]
   0x5555555550c0 <_start+0>     endbr64
   0x5555555550c4 <_start+4>     xor   ebp, ebp
   0x5555555550c6 <_start+6>     mov   r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x5555555550b0 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555550b0 → malloc@plt()
[#1] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00005555555550b0 in malloc@plt ()
0x0000555555555203 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdf70  →  0x0000007fffffffdf
$rbx   : 0x0             
$rcx   : 0x0             
$rdx   : 0x0000555555559010  →  0x0000000000000000
$rsp   : 0x00007fffffffdf50  →  0x0000000000000001
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x7800000022    
$rdi   : 0x1f            
$rip   : 0x0000555555555203  →  <main+90> nop
$r8   : 0x00005555555596b0  →  0x0000000555555559
$r9   : 0x00005555555596b0  →  0x0000000555555559
$r10   : 0x77            
$r11   : 0x25b77f1adb05647d
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/pwn_demos/tcache/tcache_s[...]"
$r13   : 0x00005555555551a9  →  <main+0> endbr64
$r14   : 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf50│+0x0000: 0x0000000000000001   ← $rsp
0x00007fffffffdf58│+0x0008: 0x00005555555596b0  →  0x0000000555555559
0x00007fffffffdf60│+0x0010: 0x0000000000000000
0x00007fffffffdf68│+0x0018: 0x0000000000000111
0x00007fffffffdf70│+0x0020: 0x0000007fffffffdf   ← $rax
0x00007fffffffdf78│+0x0028: 0x0000000000000000
0x00007fffffffdf80│+0x0030: 0x00007ffff7fc1000  →  0x00010102464c457f
0x00007fffffffdf88│+0x0038: 0x0000010101000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551f4 <main+75>      call   0x555555555080 <free@plt>
   0x5555555551f9 <main+80>      mov   edi, 0x100
   0x5555555551fe <main+85>      call   0x5555555550b0 <malloc@plt>
 → 0x555555555203 <main+90>      nop    
   0x555555555204 <main+91>      mov   rax, QWORD PTR [rbp-0x8]
   0x555555555208 <main+95>      sub   rax, QWORD PTR fs:0x28
   0x555555555211 <main+104>     je    0x555555555218 <main+111>
   0x555555555213 <main+106>     call   0x555555555090 <__stack_chk_fail@plt>
   0x555555555218 <main+111>     leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tcache_struct", stopped 0x555555555203 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555203 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x7fffffffdf70
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
[!] Command 'heap bins tcache' failed to execute properly, reason: Cannot access memory at address 0x7800000012
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
[Inferior 1 (process 5787) exited normally]
```
