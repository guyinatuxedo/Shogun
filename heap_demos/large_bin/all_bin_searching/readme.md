# All Bin Searching / Last Remainder Allocation

So in this instance, we will look at the last remainder functionality within the unsorted bin. We will be showing chunks becoming the last remainder, and allocations made from the last remainder:

Here is the source code for the binary we will be looking at:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x800
#define CHUNK_SIZE1 0x20
#define CHUNK_SIZE2 0x900
#define CHUNK_SIZE3 0x200

void main() {
    char *chunk0,
   	  *chunk1;

    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    free(chunk0);
    free(chunk1);

    malloc(CHUNK_SIZE2);

    malloc(CHUNK_SIZE3);
    malloc(CHUNK_SIZE3);
}
```

## All Bin Searching / Last Remainder Allocation Walkthrough

So a few things. First off, what is all bin searching? When malloc is trying to allocate a chunk, after it iterates through the unsorted bin, and couldn't find a small / large bin with an appropriately sized chunk, it will attempt to search through the small / large bins, searching for the next largest chunk. This searching process is what I referred to as the All Bin Searching.

After it finds a chunk, of course this chunk will be larger than what it needs. So it will take that chunk, split off a chunk from the larger chunk that is large enough for the allocation and return that. The remainder of that larger chunk we split a smaller chunk off from is what becomes the last remainder. The last remainder becomes a new freed chunk, and inserted into the unsorted bin. In addition to that, the main arena struct will store a ptr to this chunk, in the `last_remainder` field.

Now, for allocation from the `last_remainder` (as in splitting off a chunk from it to allocate a new chunk) there are two spots where this can happen. The first is when All Bin Searching finds a "next largest chunk", which was discussed above. The second, is when unsorted bin iteration begins.

If unsorted bin iteration begins, there is only a single chunk in the unsorted bin which is the `last_remainder`, the request allocation is in the smallbin range, and the `last_remainder` chunk is large enough, it will attempt allocation from that. In both contexts, the `last_remainder` will be updated to the remainder. If the last_remainder gets moved into another bin, or directly allocated from the unsorted bin, it doesn't appear that the `last_remainder` filed in the main arena doesn't get updated at that time. I don't think it matters, since for the first allocation (after the All Bin Searching) it doesn't rely on the set `av->last_remainder` for the allocation, so it doesn't matter there. For the other one, it will only allocate if the `last_remainder` is the only chunk in the unsorted bin (so no malloc/free calls that happen after the `last_remainder` gets set, that deals with the unsorted bin).

So let's begin looking through the code here. We start off allocating two `0x800` byte chunks there (with two `0x20` byte chunks between them to prevent consolidation). Then we free those two `0x800` byte chunks (insert them into the unsorted bin), allocate a `0x900` byte chunk (to move the two `0x800` byte chunks from the unsorted bin to a large bin). Then we will allocate a `0x200` byte chunk. Due to the state of the bins, this will trigger the All Bin Searching, and subsequent Last Remainder Allocation. This will actually set the main arena's `av->last_remainder`. Then we will allocate one more `0x200` byte chunk which will cause a `last_remainder` allocation from an existing `last_remainder` (so without the All Bin Searching).

So, let's see this in action:

```
$    gdb ./all_bin_searching
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
Reading symbols from ./all_bin_searching...
(No debugging symbols found in ./all_bin_searching)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001169 <+0>:    endbr64
   0x000000000000116d <+4>:    push   rbp
   0x000000000000116e <+5>:    mov	rbp,rsp
   0x0000000000001171 <+8>:    sub	rsp,0x10
   0x0000000000001175 <+12>:    mov	edi,0x800
   0x000000000000117a <+17>:    call   0x1070 <malloc@plt>
   0x000000000000117f <+22>:    mov	QWORD PTR [rbp-0x10],rax
   0x0000000000001183 <+26>:    mov	edi,0x20
   0x0000000000001188 <+31>:    call   0x1070 <malloc@plt>
   0x000000000000118d <+36>:    mov	edi,0x800
   0x0000000000001192 <+41>:    call   0x1070 <malloc@plt>
   0x0000000000001197 <+46>:    mov	QWORD PTR [rbp-0x8],rax
   0x000000000000119b <+50>:    mov	edi,0x20
   0x00000000000011a0 <+55>:    call   0x1070 <malloc@plt>
   0x00000000000011a5 <+60>:    mov	rax,QWORD PTR [rbp-0x10]
   0x00000000000011a9 <+64>:    mov	rdi,rax
   0x00000000000011ac <+67>:    call   0x1060 <free@plt>
   0x00000000000011b1 <+72>:    mov	rax,QWORD PTR [rbp-0x8]
   0x00000000000011b5 <+76>:    mov	rdi,rax
   0x00000000000011b8 <+79>:    call   0x1060 <free@plt>
   0x00000000000011bd <+84>:    mov	edi,0x900
   0x00000000000011c2 <+89>:    call   0x1070 <malloc@plt>
   0x00000000000011c7 <+94>:    mov	edi,0x200
   0x00000000000011cc <+99>:    call   0x1070 <malloc@plt>
   0x00000000000011d1 <+104>:    mov	edi,0x200
   0x00000000000011d6 <+109>:    call   0x1070 <malloc@plt>
   0x00000000000011db <+114>:    nop
   0x00000000000011dc <+115>:    leave  
   0x00000000000011dd <+116>:    ret    
End of assembler dump.
gef➤  b *main+89
Breakpoint 1 at 0x11c2
gef➤  b *main+99
Breakpoint 2 at 0x11cc
gef➤  b *main+109
Breakpoint 3 at 0x11d6
gef➤  b *main+22
Breakpoint 4 at 0x117f
gef➤  b *main+46
Breakpoint 5 at 0x1197
gef➤  r
Starting program: /Hackery/shogun/heap_demos/large_bin/all_bin_searching/all_bin_searching
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 4, 0x000055555555517f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x811        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x0000000000001000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559aa0  →  0x0000000000000000
$rdi   : 0x2          	 
$rip   : 0x000055555555517f  →  <main+22> mov QWORD PTR [rbp-0x10], rax
$r8	: 0x21001      	 
$r9	: 0x00005555555592a0  →  0x0000000000000000
$r10   : 0x77         	 
$r11   : 0x00007ffff7e19ce0  →  0x0000555555559aa0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x0000000000001000     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555171 <main+8>     	sub	rsp, 0x10
   0x555555555175 <main+12>    	mov	edi, 0x800
   0x55555555517a <main+17>    	call   0x555555555070 <malloc@plt>
 → 0x55555555517f <main+22>    	mov	QWORD PTR [rbp-0x10], rax
   0x555555555183 <main+26>    	mov	edi, 0x20
   0x555555555188 <main+31>    	call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>    	mov	edi, 0x800
   0x555555555192 <main+41>    	call   0x555555555070 <malloc@plt>
   0x555555555197 <main+46>    	mov	QWORD PTR [rbp-0x8], rax
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x55555555517f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555517f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x5555555592a0
gef➤  c
Continuing.

Breakpoint 5, 0x0000555555555197 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ae0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x811        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555a2e0  →  0x0000000000000000
$rdi   : 0x2          	 
$rip   : 0x0000555555555197  →  <main+46> mov QWORD PTR [rbp-0x8], rax
$r8	: 0x21001      	 
$r9	: 0x0000555555559ae0  →  0x0000000000000000
$r10   : 0x77         	 
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a2e0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000000000000000     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555555080  →  <_start+0> endbr64
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555188 <main+31>    	call   0x555555555070 <malloc@plt>
   0x55555555518d <main+36>    	mov	edi, 0x800
   0x555555555192 <main+41>    	call   0x555555555070 <malloc@plt>
 → 0x555555555197 <main+46>    	mov	QWORD PTR [rbp-0x8], rax
   0x55555555519b <main+50>    	mov	edi, 0x20
   0x5555555551a0 <main+55>    	call   0x555555555070 <malloc@plt>
   0x5555555551a5 <main+60>    	mov	rax, QWORD PTR [rbp-0x10]
   0x5555555551a9 <main+64>    	mov	rdi, rax
   0x5555555551ac <main+67>    	call   0x555555555060 <free@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x555555555197 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555197 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x555555559ae0
```

So we see that `chunk0` is `0x5555555592a0`, and `chunk1` is `0x555555559ae0`. Let's see the chunks end up in a large bin:

```
gef➤  c
Continuing.

Breakpoint 1, 0x00005555555551c2 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0          	 
$rbx   : 0x0          	 
$rcx   : 0x7f         	 
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0          	 
$rdi   : 0x900        	 
$rip   : 0x00005555555551c2  →  <main+89> call 0x555555555070 <malloc@plt>
$r8	: 0x21001      	 
$r9	: 0x000055555555a2f0  →  0x0000000000000000
$r10   : 0x77         	 
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b5 <main+76>    	mov	rdi, rax
   0x5555555551b8 <main+79>    	call   0x555555555060 <free@plt>
   0x5555555551bd <main+84>    	mov	edi, 0x900
 → 0x5555555551c2 <main+89>    	call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64
  	0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
  	0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
  	0x555555555080 <_start+0>   	endbr64
  	0x555555555084 <_start+4>   	xor	ebp, ebp
  	0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000900
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551c2 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c2 → main()
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
[+] unsorted_bins[0]: fw=0x555555559ad0, bk=0x555555559290
 →   Chunk(addr=0x555555559ae0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0          	 
$rbx   : 0x0          	 
$rcx   : 0x7f         	 
$rdx   : 0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
$rsp   : 0x00007fffffffdfa8  →  0x00005555555551c7  →  <main+94> mov edi, 0x200
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0          	 
$rdi   : 0x900        	 
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64
$r8	: 0x21001      	 
$r9	: 0x000055555555a2f0  →  0x0000000000000000
$r10   : 0x77         	 
$r11   : 0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x00005555555551c7  →  <main+94> mov edi, 0x200     ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00005555555592a0  →  0x00007ffff7e19ce0  →  0x000055555555a310  →  0x0000000000000000
0x00007fffffffdfb8│+0x0010: 0x0000555555559ae0  →  0x0000555555559290  →  0x0000000000000000
0x00007fffffffdfc0│+0x0018: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0028: 0x0000000000000000
0x00007fffffffdfd8│+0x0030: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0038: 0x00000001ffffe0c0
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <free@plt+0> 	endbr64
   0x555555555064 <free@plt+4> 	bnd	jmp QWORD PTR [rip+0x2f5d]    	# 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <malloc@plt+0>   endbr64
   0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>   	endbr64
   0x555555555084 <_start+4>   	xor	ebp, ebp
   0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x5555555551c7 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x00005555555551c7 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a320  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x911        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000555555559ad0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555ac20  →  0x0000000000000000
$rdi   : 0x2          	 
$rip   : 0x00005555555551c7  →  <main+94> mov edi, 0x200
$r8	: 0x0          	 
$r9	: 0x000055555555a320  →  0x0000000000000000
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000555555559ad0  →  0x0000000000000000     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551b8 <main+79>    	call   0x555555555060 <free@plt>
   0x5555555551bd <main+84>    	mov	edi, 0x900
   0x5555555551c2 <main+89>    	call   0x555555555070 <malloc@plt>
 → 0x5555555551c7 <main+94>    	mov	edi, 0x200
   0x5555555551cc <main+99>    	call   0x555555555070 <malloc@plt>
   0x5555555551d1 <main+104>   	mov	edi, 0x200
   0x5555555551d6 <main+109>   	call   0x555555555070 <malloc@plt>
   0x5555555551db <main+114>   	nop    
   0x5555555551dc <main+115>   	leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551c7 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551c7 → main()
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
[+] large_bins[79]: fw=0x555555559290, bk=0x555555559ad0
 →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559ae0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
```

So we saw that the two chunks got inserted into the large bin. Now, let's see the All Bin Searching allocate a piece of the `0x5555555592a0` chunk, and the `last_remainder` in the main arena get set:

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555551cc in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a320  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x911        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x0000555555559ad0  →  0x0000000000000000
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555ac20  →  0x0000000000000000
$rdi   : 0x200        	 
$rip   : 0x00005555555551cc  →  <main+99> call 0x555555555070 <malloc@plt>
$r8	: 0x0          	 
$r9	: 0x000055555555a320  →  0x0000000000000000
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x0000555555559ad0  →  0x0000000000000000     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551bd <main+84>    	mov	edi, 0x900
   0x5555555551c2 <main+89>    	call   0x555555555070 <malloc@plt>
   0x5555555551c7 <main+94>    	mov	edi, 0x200
 → 0x5555555551cc <main+99>    	call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64
  	0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
  	0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
  	0x555555555080 <_start+0>   	endbr64
  	0x555555555084 <_start+4>   	xor	ebp, ebp
  	0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000200
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551cc in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551cc → main()
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
[+] large_bins[79]: fw=0x555555559290, bk=0x555555559ad0
 →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559ae0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  p main_arena
$3 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555ac20,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x555555559290, 0x555555559ad0, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x10000, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a320  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x911        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfa8  →  0x00005555555551d1  →  <main+104> mov edi, 0x200
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x000055555555ac20  →  0x0000000000000000
$rdi   : 0x200        	 
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64
$r8	: 0x0          	 
$r9	: 0x000055555555a320  →  0x0000000000000000
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x00005555555551d1  →  <main+104> mov edi, 0x200     ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00005555555592a0  →  0x0000555555559ad0  →  0x0000000000000000
0x00007fffffffdfb8│+0x0010: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0018: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0028: 0x0000000000000000
0x00007fffffffdfd8│+0x0030: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0038: 0x00000001ffffe0c0
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <free@plt+0> 	endbr64
   0x555555555064 <free@plt+4> 	bnd	jmp QWORD PTR [rip+0x2f5d]    	# 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <malloc@plt+0>   endbr64
   0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>   	endbr64
   0x555555555084 <_start+4>   	xor	ebp, ebp
   0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x5555555551d1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x00005555555551d1 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$rbx   : 0x0          	 
$rcx   : 0x0000555555559ad0  →  0x0000000000000000
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$rdi   : 0x0000555555559ad0  →  0x0000000000000000
$rip   : 0x00005555555551d1  →  <main+104> mov edi, 0x200
$r8	: 0x0          	 
$r9	: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c2 <main+89>    	call   0x555555555070 <malloc@plt>
   0x5555555551c7 <main+94>    	mov	edi, 0x200
   0x5555555551cc <main+99>    	call   0x555555555070 <malloc@plt>
 → 0x5555555551d1 <main+104>   	mov	edi, 0x200
   0x5555555551d6 <main+109>   	call   0x555555555070 <malloc@plt>
   0x5555555551db <main+114>   	nop    
   0x5555555551dc <main+115>   	leave  
   0x5555555551dd <main+116>   	ret    
   0x5555555551de              	add	BYTE PTR [rax], al
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551d1 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d1 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$4 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555ac20,
  last_remainder = 0x555555559ce0,
  bins = {0x555555559ce0, 0x555555559ce0, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x555555559290, 0x555555559290, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x10000, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
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
[+] unsorted_bins[0]: fw=0x555555559ce0, bk=0x555555559ce0
 →   Chunk(addr=0x555555559cf0, size=0x600, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] large_bins[79]: fw=0x555555559290, bk=0x555555559290
 →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  p $rax
$5 = 0x555555559ae0
```

So we see that the `0x555555559ae0` had a chunk split off, which was allocated. The remainder (`0x555555559ce0`) became the new main arena's `last_remainder`. Now, we can see another `0x210` byte allocation from the new `last_remainder` chunk `0x555555559ce0`.

```
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555551d6 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$rbx   : 0x0          	 
$rcx   : 0x0000555555559ad0  →  0x0000000000000000
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$rdi   : 0x200        	 
$rip   : 0x00005555555551d6  →  <main+109> call 0x555555555070 <malloc@plt>
$r8	: 0x0          	 
$r9	: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c7 <main+94>    	mov	edi, 0x200
   0x5555555551cc <main+99>    	call   0x555555555070 <malloc@plt>
   0x5555555551d1 <main+104>   	mov	edi, 0x200
 → 0x5555555551d6 <main+109>   	call   0x555555555070 <malloc@plt>
   ↳  0x555555555070 <malloc@plt+0>   endbr64
  	0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
  	0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
  	0x555555555080 <_start+0>   	endbr64
  	0x555555555084 <_start+4>   	xor	ebp, ebp
  	0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000200
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551d6 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551d6 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$7 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555ac20,
  last_remainder = 0x555555559ce0,
  bins = {0x555555559ce0, 0x555555559ce0, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x555555559290, 0x555555559290, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x10000, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
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
[+] unsorted_bins[0]: fw=0x555555559ce0, bk=0x555555559ce0
 →   Chunk(addr=0x555555559cf0, size=0x600, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] large_bins[79]: fw=0x555555559290, bk=0x555555559290
 →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  si
0x0000555555555070 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$rbx   : 0x0          	 
$rcx   : 0x0000555555559ad0  →  0x0000000000000000
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfa8  →  0x00005555555551db  →  <main+114> nop
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$rdi   : 0x200        	 
$rip   : 0x0000555555555070  →  <malloc@plt+0> endbr64
$r8	: 0x0          	 
$r9	: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170
$r10   : 0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180  →  0x00007ffff7e1a170  →  0x00007ffff7e1a160
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa8│+0x0000: 0x00005555555551db  →  <main+114> nop      ← $rsp
0x00007fffffffdfb0│+0x0008: 0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfb8│+0x0010: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0018: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0020: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0028: 0x0000000000000000
0x00007fffffffdfd8│+0x0030: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0038: 0x00000001ffffe0c0
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555060 <free@plt+0> 	endbr64
   0x555555555064 <free@plt+4> 	bnd	jmp QWORD PTR [rip+0x2f5d]    	# 0x555555557fc8 <free@got.plt>
   0x55555555506b <free@plt+11>	nop	DWORD PTR [rax+rax*1+0x0]
 → 0x555555555070 <malloc@plt+0>   endbr64
   0x555555555074 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2f55]    	# 0x555555557fd0 <malloc@got.plt>
   0x55555555507b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
   0x555555555080 <_start+0>   	endbr64
   0x555555555084 <_start+4>   	xor	ebp, ebp
   0x555555555086 <_start+6>   	mov	r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x555555555070 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555070 → malloc@plt()
[#1] 0x5555555551db → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555070 in malloc@plt ()
0x00005555555551db in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559cf0  →  0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x3f1        	 
$rdx   : 0x0          	 
$rsp   : 0x00007fffffffdfb0  →  0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x0000555555559ef0  →  0x0000000000000000
$rdi   : 0x0          	 
$rip   : 0x00005555555551db  →  <main+114> nop
$r8	: 0x0          	 
$r9	: 0x0000555555559cf0  →  0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r10   : 0x000055555555a2e0  →  0x00000000000003f0
$r11   : 0x00007ffff7e19ce0  →  0x000055555555ac20  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
$r13   : 0x0000555555555169  →  <main+0> endbr64
$r14   : 0x0000555555557db8  →  0x0000555555555120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfb0│+0x0000: 0x00005555555592a0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180     ← $rsp
0x00007fffffffdfb8│+0x0008: 0x0000555555559ae0  →  0x00007ffff7e1a1d0  →  0x00007ffff7e1a1c0  →  0x00007ffff7e1a1b0  →  0x00007ffff7e1a1a0  →  0x00007ffff7e1a190  →  0x00007ffff7e1a180
0x00007fffffffdfc0│+0x0010: 0x0000000000000001     ← $rbp
0x00007fffffffdfc8│+0x0018: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfd0│+0x0020: 0x0000000000000000
0x00007fffffffdfd8│+0x0028: 0x0000555555555169  →  <main+0> endbr64
0x00007fffffffdfe0│+0x0030: 0x00000001ffffe0c0
0x00007fffffffdfe8│+0x0038: 0x00007fffffffe0d8  →  0x00007fffffffe3df  →  "/Hackery/shogun/heap_demos/large_bin/all_[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551cc <main+99>    	call   0x555555555070 <malloc@plt>
   0x5555555551d1 <main+104>   	mov	edi, 0x200
   0x5555555551d6 <main+109>   	call   0x555555555070 <malloc@plt>
 → 0x5555555551db <main+114>   	nop    
   0x5555555551dc <main+115>   	leave  
   0x5555555551dd <main+116>   	ret    
   0x5555555551de              	add	BYTE PTR [rax], al
   0x5555555551e0 <_fini+0>    	endbr64
   0x5555555551e4 <_fini+4>    	sub	rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "all_bin_searchi", stopped 0x5555555551db in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555551db → main()
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
[+] unsorted_bins[0]: fw=0x555555559ef0, bk=0x555555559ef0
 →   Chunk(addr=0x555555559f00, size=0x3f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7ffff7e19c80 ──────────────────────────────
[+] large_bins[79]: fw=0x555555559290, bk=0x555555559290
 →   Chunk(addr=0x5555555592a0, size=0x810, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  p main_arena
$8 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x55555555ac20,
  last_remainder = 0x555555559ef0,
  bins = {0x555555559ef0, 0x555555559ef0, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x555555559290, 0x555555559290, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x10000, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  c
Continuing.
[Inferior 1 (process 7710) exited with code 0360]
```

So we have seen another allocation from the `last_remainder`. Just like that, we've seen the All Bin Searching, and the two different ways to allocate memory from the `last_remainder`.

