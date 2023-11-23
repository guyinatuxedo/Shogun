## Sysmalloc Allocation

So, the purpose of this demo. Under the right conditions, when malloc is trying to allocate a chunk from the top chunk, and the top chunk isn't actually large enough (and there are no fastbins it can consolidate), then it will instead allocate the memory with `sysmalloc` versus the standard libc heap. The purpose of this demo is to show that. Here is the source code:

```
#include <stdlib.h>

#define CHUNK_SIZE 0x10000

void main() {
    malloc(0x10);
    
    malloc(CHUNK_SIZE);
    malloc(CHUNK_SIZE);
    malloc(CHUNK_SIZE);
}
```

So, there are four malloc calls. The purpose of the first malloc call is to set up the heap. The purpose of the next two malloc calls is to decrease the size of the top chunk to below `0x10000`. The purpose of the final malloc call is to actually have the sysmalloc allocation happen, because it tries to allocate from the top chunk, however the top chunk doesn't have enough space.

#### Sysmalloc Allocation Walkthrough

So, let's start off with the second malloc call. We will also set a breakpoint at `sysmalloc` prior to it, to show that `sysmalloc` isn't called in the second, or third malloc calls. We will see the second malloc call decrement the top chunk by `0x10000`-ish:

```
$   gdb ./sysmalloc_allocation 
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
Reading symbols from ./sysmalloc_allocation...
(No debugging symbols found in ./sysmalloc_allocation)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001149 <+0>: endbr64 
   0x000000000000114d <+4>: push   rbp
   0x000000000000114e <+5>: mov    rbp,rsp
   0x0000000000001151 <+8>: mov    edi,0x10
   0x0000000000001156 <+13>:    call   0x1050 <malloc@plt>
   0x000000000000115b <+18>:    mov    edi,0x10000
   0x0000000000001160 <+23>:    call   0x1050 <malloc@plt>
   0x0000000000001165 <+28>:    mov    edi,0x10000
   0x000000000000116a <+33>:    call   0x1050 <malloc@plt>
   0x000000000000116f <+38>:    mov    edi,0x10000
   0x0000000000001174 <+43>:    call   0x1050 <malloc@plt>
   0x0000000000001179 <+48>:    nop
   0x000000000000117a <+49>:    pop    rbp
   0x000000000000117b <+50>:    ret    
End of assembler dump.
gef➤  b *main+18
Breakpoint 1 at 0x115b
gef➤  r
Starting program: /Hackery/shogun/heap_demos/malloc/sysmalloc_allocation/sysmalloc_allocation 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x000055555555515b in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x21              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555592b0  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x000055555555515b  →  <main+18> mov edi, 0x10000
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x00007ffff7e19ce0  →  0x00005555555592b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555514e <main+5>         mov    rbp, rsp
   0x555555555151 <main+8>         mov    edi, 0x10
   0x555555555156 <main+13>        call   0x555555555050 <malloc@plt>
 → 0x55555555515b <main+18>        mov    edi, 0x10000
   0x555555555160 <main+23>        call   0x555555555050 <malloc@plt>
   0x555555555165 <main+28>        mov    edi, 0x10000
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   0x55555555516f <main+38>        mov    edi, 0x10000
   0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x55555555515b in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555515b → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  b *sysmalloc
Breakpoint 2 at 0x7ffff7ca3150: file ./malloc/malloc.c, line 2548.
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555592b0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  x/10g 0x5555555592b0
0x5555555592b0: 0x0 0x20d51
0x5555555592c0: 0x0 0x0
0x5555555592d0: 0x0 0x0
0x5555555592e0: 0x0 0x0
0x5555555592f0: 0x0 0x0
gef➤  si
0x0000555555555160 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x21              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555592b0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555160  →  <main+23> call 0x555555555050 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x00007ffff7e19ce0  →  0x00005555555592b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555151 <main+8>         mov    edi, 0x10
   0x555555555156 <main+13>        call   0x555555555050 <malloc@plt>
   0x55555555515b <main+18>        mov    edi, 0x10000
 → 0x555555555160 <main+23>        call   0x555555555050 <malloc@plt>
   ↳  0x555555555050 <malloc@plt+0>   endbr64 
      0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555060 <_start+0>       endbr64 
      0x555555555064 <_start+4>       xor    ebp, ebp
      0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000010000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555160 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555160 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555050 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592a0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x21              
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf98  →  0x0000555555555165  →  <main+28> mov edi, 0x10000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555592b0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555050  →  <malloc@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x00005555555592a0  →  0x0000000000000000
$r10   : 0xfffffffffffff000
$r11   : 0x00007ffff7e19ce0  →  0x00005555555592b0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf98│+0x0000: 0x0000555555555165  →  <main+28> mov edi, 0x10000    ← $rsp
0x00007fffffffdfa0│+0x0008: 0x0000000000000001   ← $rbp
0x00007fffffffdfa8│+0x0010: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0018: 0x0000000000000000
0x00007fffffffdfb8│+0x0020: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0028: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0030: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555040 <__cxa_finalize@plt+0> endbr64 
   0x555555555044 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2fad]        # 0x555555557ff8
   0x55555555504b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555050 <malloc@plt+0>   endbr64 
   0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555060 <_start+0>       endbr64 
   0x555555555064 <_start+4>       xor    ebp, ebp
   0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555050 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555050 → malloc@plt()
[#1] 0x555555555165 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555050 in malloc@plt ()
0x0000555555555165 in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592c0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555692c0  →  0x0000000000000000
$rdi   : 0x3               
$rip   : 0x0000555555555165  →  <main+28> mov edi, 0x10000
$r8    : 0x21001           
$r9    : 0x00005555555592c0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555692c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555156 <main+13>        call   0x555555555050 <malloc@plt>
   0x55555555515b <main+18>        mov    edi, 0x10000
   0x555555555160 <main+23>        call   0x555555555050 <malloc@plt>
 → 0x555555555165 <main+28>        mov    edi, 0x10000
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   0x55555555516f <main+38>        mov    edi, 0x10000
   0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
   0x555555555179 <main+48>        nop    
   0x55555555517a <main+49>        pop    rbp
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555165 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555165 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$2 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555692c0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  x/10g 0x5555555692c0
0x5555555692c0: 0x0 0x10d41
0x5555555692d0: 0x0 0x0
0x5555555692e0: 0x0 0x0
0x5555555692f0: 0x0 0x0
0x555555569300: 0x0 0x0
```

So we see that the top chunk got decremented from `0x20d51` to `0x10d41`. Let's decrement it again with the next malloc call:

```
gef➤  si
0x000055555555516a in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592c0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555692c0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x000055555555516a  →  <main+33> call 0x555555555050 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x00005555555592c0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555692c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555515b <main+18>        mov    edi, 0x10000
   0x555555555160 <main+23>        call   0x555555555050 <malloc@plt>
   0x555555555165 <main+28>        mov    edi, 0x10000
 → 0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   ↳  0x555555555050 <malloc@plt+0>   endbr64 
      0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555060 <_start+0>       endbr64 
      0x555555555064 <_start+4>       xor    ebp, ebp
      0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000010000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x55555555516a in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555516a → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555050 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555592c0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf98  →  0x000055555555516f  →  <main+38> mov edi, 0x10000
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555692c0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555050  →  <malloc@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x00005555555592c0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555692c0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf98│+0x0000: 0x000055555555516f  →  <main+38> mov edi, 0x10000    ← $rsp
0x00007fffffffdfa0│+0x0008: 0x0000000000000001   ← $rbp
0x00007fffffffdfa8│+0x0010: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0018: 0x0000000000000000
0x00007fffffffdfb8│+0x0020: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0028: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0030: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555040 <__cxa_finalize@plt+0> endbr64 
   0x555555555044 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2fad]        # 0x555555557ff8
   0x55555555504b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555050 <malloc@plt+0>   endbr64 
   0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555060 <_start+0>       endbr64 
   0x555555555064 <_start+4>       xor    ebp, ebp
   0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555050 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555050 → malloc@plt()
[#1] 0x55555555516f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555050 in malloc@plt ()
0x000055555555516f in main ()


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555692d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555792d0  →  0x0000000000000000
$rdi   : 0x3               
$rip   : 0x000055555555516f  →  <main+38> mov edi, 0x10000
$r8    : 0x21001           
$r9    : 0x00005555555692d0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555160 <main+23>        call   0x555555555050 <malloc@plt>
   0x555555555165 <main+28>        mov    edi, 0x10000
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
 → 0x55555555516f <main+38>        mov    edi, 0x10000
   0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
   0x555555555179 <main+48>        nop    
   0x55555555517a <main+49>        pop    rbp
   0x55555555517b <main+50>        ret    
   0x55555555517c <_fini+0>        endbr64 
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x55555555516f in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555516f → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$3 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555792d0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  x/10g 0x5555555792d0
0x5555555792d0: 0x0 0xd31
0x5555555792e0: 0x0 0x0
0x5555555792f0: 0x0 0x0
0x555555579300: 0x0 0x0
0x555555579310: 0x0 0x0
```

With the third malloc call, we see that it got decremented from `0x10d41` to `0xd31`

```
gef➤  si
0x0000555555555174 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555692d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555792d0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555174  →  <main+43> call 0x555555555050 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x00005555555692d0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555165 <main+28>        mov    edi, 0x10000
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   0x55555555516f <main+38>        mov    edi, 0x10000
 → 0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
   ↳  0x555555555050 <malloc@plt+0>   endbr64 
      0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555060 <_start+0>       endbr64 
      0x555555555064 <_start+4>       xor    ebp, ebp
      0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000010000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555174 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555174 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x0000555555555050 in malloc@plt ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555692d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf98  →  0x0000555555555179  →  <main+48> nop 
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555792d0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555050  →  <malloc@plt+0> endbr64 
$r8    : 0x21001           
$r9    : 0x00005555555692d0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf98│+0x0000: 0x0000555555555179  →  <main+48> nop     ← $rsp
0x00007fffffffdfa0│+0x0008: 0x0000000000000001   ← $rbp
0x00007fffffffdfa8│+0x0010: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0018: 0x0000000000000000
0x00007fffffffdfb8│+0x0020: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0028: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0030: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555040 <__cxa_finalize@plt+0> endbr64 
   0x555555555044 <__cxa_finalize@plt+4> bnd    jmp QWORD PTR [rip+0x2fad]        # 0x555555557ff8
   0x55555555504b <__cxa_finalize@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
 → 0x555555555050 <malloc@plt+0>   endbr64 
   0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
   0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555060 <_start+0>       endbr64 
   0x555555555064 <_start+4>       xor    ebp, ebp
   0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555050 in malloc@plt (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555050 → malloc@plt()
[#1] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x0000555555555050 in malloc@plt ()

Breakpoint 2, sysmalloc (nb=nb@entry=0x10010, av=av@entry=0x7ffff7e19c80 <main_arena>) at ./malloc/malloc.c:2548
2548    ./malloc/malloc.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007ffff7e19c80  →  0x0000000000000000
$rcx   : 0x10030           
$rdx   : 0xd30             
$rsp   : 0x00007fffffffde98  →  0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax
$rbp   : 0x10000           
$rsi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rdi   : 0x10010           
$rip   : 0x00007ffff7ca3150  →  <sysmalloc+0> push r15
$r8    : 0x21001           
$r9    : 0x7e              
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0xffffffffffffffb8
$r13   : 0x10010           
$r14   : 0x1001            
$r15   : 0xfff             
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde98│+0x0000: 0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax    ← $rsp
0x00007fffffffdea0│+0x0008: 0x0000000000000000
0x00007fffffffdea8│+0x0010: 0x0000000000000000
0x00007fffffffdeb0│+0x0018: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
0x00007fffffffdeb8│+0x0020: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
0x00007fffffffdec0│+0x0028: 0x0000007900000002
0x00007fffffffdec8│+0x0030: 0x0000000000010000
0x00007fffffffded0│+0x0038: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ca313e <_int_free+2590> lea    rdi, [rip+0x136669]        # 0x7ffff7dd97ae
   0x7ffff7ca3145 <_int_free+2597> call   0x7ffff7ca0ef0 <__malloc_assert>
   0x7ffff7ca314a                  nop    WORD PTR [rax+rax*1+0x0]
 → 0x7ffff7ca3150 <sysmalloc+0>    push   r15
   0x7ffff7ca3152 <sysmalloc+2>    push   r14
   0x7ffff7ca3154 <sysmalloc+4>    push   r13
   0x7ffff7ca3156 <sysmalloc+6>    push   r12
   0x7ffff7ca3158 <sysmalloc+8>    push   rbp
   0x7ffff7ca3159 <sysmalloc+9>    mov    rbp, rdi
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x7ffff7ca3150 in sysmalloc (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ca3150 → sysmalloc(nb=0x10010, av=0x7ffff7e19c80 <main_arena>)
[#1] 0x7ffff7ca495d → _int_malloc(av=0x7ffff7e19c80 <main_arena>, bytes=0x10000)
[#2] 0x7ffff7ca52e2 → __GI___libc_malloc(bytes=0x10000)
[#3] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  sysmalloc (nb=nb@entry=0x10010, av=av@entry=0x7ffff7e19c80 <main_arena>) at ./malloc/malloc.c:2548
0x00007ffff7ca495d in _int_malloc (av=av@entry=0x7ffff7e19c80 <main_arena>, bytes=bytes@entry=0x10000) at ./malloc/malloc.c:4407
4407    in ./malloc/malloc.c
Value returned is $4 = (void *) 0x5555555792e0

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555792e0  →  0x0000000000000000
$rbx   : 0x00007ffff7e19c80  →  0x0000000000000000
$rcx   : 0x00005555555792d0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdea0  →  0x0000000000000000
$rbp   : 0x10000           
$rsi   : 0x00005555555892e0  →  0x0000000000000000
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax
$r8    : 0x0               
$r9    : 0x7e              
$r10   : 0x000055555557a000  →  0x0000000000000000
$r11   : 0x206             
$r12   : 0xffffffffffffffb8
$r13   : 0x10010           
$r14   : 0x1001            
$r15   : 0xfff             
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdea0│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdea8│+0x0008: 0x0000000000000000
0x00007fffffffdeb0│+0x0010: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffdeb8│+0x0018: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffdec0│+0x0020: 0x0000007900000002
0x00007fffffffdec8│+0x0028: 0x0000000000010000
0x00007fffffffded0│+0x0030: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffded8│+0x0038: 0x0000003a00000029 (")"?)
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ca4950 <_int_malloc+3872> mov    rdi, r13
   0x7ffff7ca4953 <_int_malloc+3875> mov    rbp, QWORD PTR [rsp+0x28]
   0x7ffff7ca4958 <_int_malloc+3880> call   0x7ffff7ca3150 <sysmalloc>
 → 0x7ffff7ca495d <_int_malloc+3885> mov    r9, rax
   0x7ffff7ca4960 <_int_malloc+3888> test   rax, rax
   0x7ffff7ca4963 <_int_malloc+3891> je     0x7ffff7ca43b0 <_int_malloc+2432>
   0x7ffff7ca4969 <_int_malloc+3897> mov    eax, DWORD PTR [rip+0x17bb8d]        # 0x7ffff7e204fc <perturb_byte>
   0x7ffff7ca496f <_int_malloc+3903> test   eax, eax
   0x7ffff7ca4971 <_int_malloc+3905> je     0x7ffff7ca40f6 <_int_malloc+1734>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x7ffff7ca495d in _int_malloc (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ca495d → _int_malloc(av=0x7ffff7e19c80 <main_arena>, bytes=0x10000)
[#1] 0x7ffff7ca52e2 → __GI___libc_malloc(bytes=0x10000)
[#2] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  0x00007ffff7ca495d in _int_malloc (av=av@entry=0x7ffff7e19c80 <main_arena>, bytes=bytes@entry=0x10000) at ./malloc/malloc.c:4407
__GI___libc_malloc (bytes=0x10000) at ./malloc/malloc.c:3322
3322    in ./malloc/malloc.c
Value returned is $5 = (void *) 0x5555555792e0

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555792e0  →  0x0000000000000000
$rbx   : 0x00007ffff7e19c80  →  0x0000000000000000
$rcx   : 0x00005555555792d0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf70  →  0x0000000000000002
$rbp   : 0x10000           
$rsi   : 0x00005555555892e0  →  0x0000000000000000
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00007ffff7ca52e2  →  <malloc+450> test rax, rax
$r8    : 0x0               
$r9    : 0x00005555555792e0  →  0x0000000000000000
$r10   : 0x000055555557a000  →  0x0000000000000000
$r11   : 0x206             
$r12   : 0xfff             
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf70│+0x0000: 0x0000000000000002   ← $rsp
0x00007fffffffdf78│+0x0008: 0x00000000078bfbff
0x00007fffffffdf80│+0x0010: 0x0000000000000000
0x00007fffffffdf88│+0x0018: 0x00007fffffffdfa0  →  0x0000000000000001
0x00007fffffffdf90│+0x0020: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdf98│+0x0028: 0x0000555555555179  →  <main+48> nop 
0x00007fffffffdfa0│+0x0030: 0x0000000000000001
0x00007fffffffdfa8│+0x0038: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ca52d7 <malloc+439>     mov    rsi, rbp
   0x7ffff7ca52da <malloc+442>     mov    rdi, rbx
   0x7ffff7ca52dd <malloc+445>     call   0x7ffff7ca3a30 <_int_malloc>
 → 0x7ffff7ca52e2 <malloc+450>     test   rax, rax
   0x7ffff7ca52e5 <malloc+453>     je     0x7ffff7ca5380 <__GI___libc_malloc+608>
   0x7ffff7ca52eb <malloc+459>     mov    rdx, QWORD PTR [rax-0x8]
   0x7ffff7ca52ef <malloc+463>     test   dl, 0x2
   0x7ffff7ca52f2 <malloc+466>     jne    0x7ffff7ca5222 <__GI___libc_malloc+258>
   0x7ffff7ca52f8 <malloc+472>     and    edx, 0x4
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x7ffff7ca52e2 in __GI___libc_malloc (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ca52e2 → __GI___libc_malloc(bytes=0x10000)
[#1] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  finish
Run till exit from #0  __GI___libc_malloc (bytes=0x10000) at ./malloc/malloc.c:3322
0x0000555555555179 in main ()
Value returned is $6 = (void *) 0x5555555792e0


[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555792e0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x00005555555792d0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555892e0  →  0x0000000000000000
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x0000555555555179  →  <main+48> nop 
$r8    : 0x0               
$r9    : 0x00005555555792e0  →  0x0000000000000000
$r10   : 0x000055555557a000  →  0x0000000000000000
$r11   : 0x206             
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0xaf396d3b5f30c4de
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   0x55555555516f <main+38>        mov    edi, 0x10000
   0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
 → 0x555555555179 <main+48>        nop    
   0x55555555517a <main+49>        pop    rbp
   0x55555555517b <main+50>        ret    
   0x55555555517c <_fini+0>        endbr64 
   0x555555555180 <_fini+4>        sub    rsp, 0x8
   0x555555555184 <_fini+8>        add    rsp, 0x8
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555179 in main (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$7 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555892e0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x51000,
  max_system_mem = 0x51000
}
gef➤  x/10g 0x5555555892e0
0x5555555892e0: 0x0 0x20d21
0x5555555892f0: 0x0 0x0
0x555555589300: 0x0 0x0
0x555555589310: 0x0 0x0
0x555555589320: 0x0 0x0
```

Now, the `sysmalloc` call will actually expand the amount of memory which the heap, and the top chunk has, which we see there. Which we can see, specifically here, when we rerun the program:

```
$   gdb ./sysmalloc_allocation 
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
Reading symbols from ./sysmalloc_allocation...
(No debugging symbols found in ./sysmalloc_allocation)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001149 <+0>: endbr64 
   0x000000000000114d <+4>: push   rbp
   0x000000000000114e <+5>: mov    rbp,rsp
   0x0000000000001151 <+8>: mov    edi,0x10
   0x0000000000001156 <+13>:    call   0x1050 <malloc@plt>
   0x000000000000115b <+18>:    mov    edi,0x10000
   0x0000000000001160 <+23>:    call   0x1050 <malloc@plt>
   0x0000000000001165 <+28>:    mov    edi,0x10000
   0x000000000000116a <+33>:    call   0x1050 <malloc@plt>
   0x000000000000116f <+38>:    mov    edi,0x10000
   0x0000000000001174 <+43>:    call   0x1050 <malloc@plt>
   0x0000000000001179 <+48>:    nop
   0x000000000000117a <+49>:    pop    rbp
   0x000000000000117b <+50>:    ret    
End of assembler dump.
gef➤  b *main+43
Breakpoint 1 at 0x1174
gef➤  r
Starting program: /Hackery/shogun/heap_demos/malloc/sysmalloc_allocation/sysmalloc_allocation 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555555174 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555692d0  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x10011           
$rdx   : 0x0               
$rsp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rbp   : 0x00007fffffffdfa0  →  0x0000000000000001
$rsi   : 0x00005555555792d0  →  0x0000000000000000
$rdi   : 0x10000           
$rip   : 0x0000555555555174  →  <main+43> call 0x555555555050 <malloc@plt>
$r8    : 0x21001           
$r9    : 0x00005555555692d0  →  0x0000000000000000
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
$r13   : 0x0000555555555149  →  <main+0> endbr64 
$r14   : 0x0000555555557dc0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64 
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfa0│+0x0000: 0x0000000000000001   ← $rsp, $rbp
0x00007fffffffdfa8│+0x0008: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax
0x00007fffffffdfb0│+0x0010: 0x0000000000000000
0x00007fffffffdfb8│+0x0018: 0x0000555555555149  →  <main+0> endbr64 
0x00007fffffffdfc0│+0x0020: 0x00000001ffffe0a0
0x00007fffffffdfc8│+0x0028: 0x00007fffffffe0b8  →  0x00007fffffffe3b8  →  "/Hackery/shogun/heap_demos/malloc/sysmall[...]"
0x00007fffffffdfd0│+0x0030: 0x0000000000000000
0x00007fffffffdfd8│+0x0038: 0x3b5dd910694195a7
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555165 <main+28>        mov    edi, 0x10000
   0x55555555516a <main+33>        call   0x555555555050 <malloc@plt>
   0x55555555516f <main+38>        mov    edi, 0x10000
 → 0x555555555174 <main+43>        call   0x555555555050 <malloc@plt>
   ↳  0x555555555050 <malloc@plt+0>   endbr64 
      0x555555555054 <malloc@plt+4>   bnd    jmp QWORD PTR [rip+0x2f75]        # 0x555555557fd0 <malloc@got.plt>
      0x55555555505b <malloc@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x555555555060 <_start+0>       endbr64 
      0x555555555064 <_start+4>       xor    ebp, ebp
      0x555555555066 <_start+6>       mov    r9, rdx
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   $rdi = 0x0000000000010000
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x555555555174 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555174 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  b *sysmalloc
Breakpoint 2 at 0x7ffff7ca3150: file ./malloc/malloc.c, line 2548.
gef➤  c
Continuing.

Breakpoint 2, sysmalloc (nb=nb@entry=0x10010, av=av@entry=0x7ffff7e19c80 <main_arena>) at ./malloc/malloc.c:2548
2548    ./malloc/malloc.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007ffff7e19c80  →  0x0000000000000000
$rcx   : 0x10030           
$rdx   : 0xd30             
$rsp   : 0x00007fffffffde98  →  0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax
$rbp   : 0x10000           
$rsi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rdi   : 0x10010           
$rip   : 0x00007ffff7ca3150  →  <sysmalloc+0> push r15
$r8    : 0x21001           
$r9    : 0x7e              
$r10   : 0x79              
$r11   : 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
$r12   : 0xffffffffffffffb8
$r13   : 0x10010           
$r14   : 0x1001            
$r15   : 0xfff             
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde98│+0x0000: 0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax    ← $rsp
0x00007fffffffdea0│+0x0008: 0x0000000000000000
0x00007fffffffdea8│+0x0010: 0x0000000000000000
0x00007fffffffdeb0│+0x0018: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
0x00007fffffffdeb8│+0x0020: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
0x00007fffffffdec0│+0x0028: 0x0000007900000002
0x00007fffffffdec8│+0x0030: 0x0000000000010000
0x00007fffffffded0│+0x0038: 0x00007ffff7e19ce0  →  0x00005555555792d0  →  0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ca313e <_int_free+2590> lea    rdi, [rip+0x136669]        # 0x7ffff7dd97ae
   0x7ffff7ca3145 <_int_free+2597> call   0x7ffff7ca0ef0 <__malloc_assert>
   0x7ffff7ca314a                  nop    WORD PTR [rax+rax*1+0x0]
 → 0x7ffff7ca3150 <sysmalloc+0>    push   r15
   0x7ffff7ca3152 <sysmalloc+2>    push   r14
   0x7ffff7ca3154 <sysmalloc+4>    push   r13
   0x7ffff7ca3156 <sysmalloc+6>    push   r12
   0x7ffff7ca3158 <sysmalloc+8>    push   rbp
   0x7ffff7ca3159 <sysmalloc+9>    mov    rbp, rdi
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x7ffff7ca3150 in sysmalloc (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ca3150 → sysmalloc(nb=0x10010, av=0x7ffff7e19c80 <main_arena>)
[#1] 0x7ffff7ca495d → _int_malloc(av=0x7ffff7e19c80 <main_arena>, bytes=0x10000)
[#2] 0x7ffff7ca52e2 → __GI___libc_malloc(bytes=0x10000)
[#3] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555792d0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
gef➤  finish
Run till exit from #0  sysmalloc (nb=nb@entry=0x10010, av=av@entry=0x7ffff7e19c80 <main_arena>) at ./malloc/malloc.c:2548
0x00007ffff7ca495d in _int_malloc (av=av@entry=0x7ffff7e19c80 <main_arena>, bytes=bytes@entry=0x10000) at ./malloc/malloc.c:4407
4407    in ./malloc/malloc.c
Value returned is $2 = (void *) 0x5555555792e0

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00005555555792e0  →  0x0000000000000000
$rbx   : 0x00007ffff7e19c80  →  0x0000000000000000
$rcx   : 0x00005555555792d0  →  0x0000000000000000
$rdx   : 0x0               
$rsp   : 0x00007fffffffdea0  →  0x0000000000000000
$rbp   : 0x10000           
$rsi   : 0x00005555555892e0  →  0x0000000000000000
$rdi   : 0x00007ffff7e19c80  →  0x0000000000000000
$rip   : 0x00007ffff7ca495d  →  <_int_malloc+3885> mov r9, rax
$r8    : 0x0               
$r9    : 0x7e              
$r10   : 0x000055555557a000  →  0x0000000000000000
$r11   : 0x206             
$r12   : 0xffffffffffffffb8
$r13   : 0x10010           
$r14   : 0x1001            
$r15   : 0xfff             
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdea0│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffdea8│+0x0008: 0x0000000000000000
0x00007fffffffdeb0│+0x0010: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffdeb8│+0x0018: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffdec0│+0x0020: 0x0000007900000002
0x00007fffffffdec8│+0x0028: 0x0000000000010000
0x00007fffffffded0│+0x0030: 0x00007ffff7e19ce0  →  0x00005555555892e0  →  0x0000000000000000
0x00007fffffffded8│+0x0038: 0x0000003a00000029 (")"?)
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ca4950 <_int_malloc+3872> mov    rdi, r13
   0x7ffff7ca4953 <_int_malloc+3875> mov    rbp, QWORD PTR [rsp+0x28]
   0x7ffff7ca4958 <_int_malloc+3880> call   0x7ffff7ca3150 <sysmalloc>
 → 0x7ffff7ca495d <_int_malloc+3885> mov    r9, rax
   0x7ffff7ca4960 <_int_malloc+3888> test   rax, rax
   0x7ffff7ca4963 <_int_malloc+3891> je     0x7ffff7ca43b0 <_int_malloc+2432>
   0x7ffff7ca4969 <_int_malloc+3897> mov    eax, DWORD PTR [rip+0x17bb8d]        # 0x7ffff7e204fc <perturb_byte>
   0x7ffff7ca496f <_int_malloc+3903> test   eax, eax
   0x7ffff7ca4971 <_int_malloc+3905> je     0x7ffff7ca40f6 <_int_malloc+1734>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sysmalloc_alloc", stopped 0x7ffff7ca495d in _int_malloc (), reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ca495d → _int_malloc(av=0x7ffff7e19c80 <main_arena>, bytes=0x10000)
[#1] 0x7ffff7ca52e2 → __GI___libc_malloc(bytes=0x10000)
[#2] 0x555555555179 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p main_arena
$3 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x5555555892e0,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x51000,
  max_system_mem = 0x51000
}
gef➤  c
Continuing.
[Inferior 1 (process 9704) exited with code 0340]
```

Just like that, we see sysmalloc memory allocation.
