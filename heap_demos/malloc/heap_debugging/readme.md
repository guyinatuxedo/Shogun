# Heap Debugging

So the purpose of this. The purpose of this is to show the basics of heap debugging. It's basically the same as typical elf debugging with gdb, just there are a few things we'll need to know how to look at. We will see this stuff used in most of the future writeups where we do debugging with the heap (I just wanted to briefly introduce that stuff here). We will have plenty of cases to use this later.

Now, for all of the future walkthroughs, I use a gdb wrapper called gef (from `https://github.com/hugsy/gef`). It effectively is just scripting for gdb, that adds additional functionality. One of the commands it adds is `heap bins`, which will display the current state of all of the bins (tcache/fast/small/large/unsorted bins). This is not available in normal gdb:

```
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=3, size=0x50, count=7] ←  Chunk(addr=0x555555559960, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559840, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559720, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559600, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555594e0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555593c0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x50, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Tcachebins[idx=4, size=0x60, count=7] ←  Chunk(addr=0x5555555599b0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559890, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559770, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559650, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559530, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559410, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592f0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Tcachebins[idx=5, size=0x70, count=7] ←  Chunk(addr=0x555555559a10, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555598f0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555597d0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555596b0, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559590, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559470, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559350, size=0x70, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
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

The next two things I'd like to cover. This is possible for both vanilla gdb, and with gdb gef. It's effectively the manual way of doing the `heap bins` command. We can view all of the same information manually, via looking at the ptrs stored in the `tcache/main_arena` libc global variables.

We see the status of the tcache via looking at the `tcache` libc global variable:


```
gef➤  p tcache
$1 = (tcache_perthread_struct *) 0x555555559010
gef➤  x/80g 0x555555559010
0x555555559010:   0x1   0x0
0x555555559020:   0x0   0x1000000000000
0x555555559030:   0x0   0x0
0x555555559040:   0x0   0x0
0x555555559050:   0x0   0x0
0x555555559060:   0x0   0x0
0x555555559070:   0x0   0x0
0x555555559080:   0x0   0x1000000000000
0x555555559090:   0x5555555592a0 0x0
0x5555555590a0:   0x0   0x0
0x5555555590b0:   0x0   0x0
0x5555555590c0:   0x0   0x0
0x5555555590d0:   0x0   0x0
0x5555555590e0:   0x0   0x0
0x5555555590f0:   0x0   0x0
0x555555559100:   0x0   0x5555555592e0
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
0x555555559280:   0x0   0x555555559500
gef➤  x/10g 0x555555559290
0x555555559290:   0x0   0x21
0x5555555592a0:   0x555555559 0x6a561f9f00b1833e
0x5555555592b0:   0x0   0x21
0x5555555592c0:   0x0   0x0
0x5555555592d0:   0x0   0x111
gef➤  x/10g 0x5555555592d0
0x5555555592d0:   0x0   0x111
0x5555555592e0:   0x555555559 0x6a561f9f00b1833e
0x5555555592f0:   0x0   0x0
0x555555559300:   0x0   0x0
0x555555559310:   0x0   0x0
gef➤  x/10g 0x5555555594f0
0x5555555594f0:   0x0   0x411
0x555555559500:   0x555555559 0x6a561f9f00b1833e
0x555555559510:   0x0   0x0
0x555555559520:   0x0   0x0
0x555555559530:   0x0   0x0
```

Also if you can't view the `tcache` that way (like if the `tcache` symbol doesn't resolve), you can usually just look at offset `0x10` from the base of the heap memory region. Below we see it begins at `0x555555559010`, with the heap starting at `0x0000555555559000`:

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /Hackery/shogun/heap_demos/tcache/tcache_basic/tcache_basic
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
0x00007ffff7c00000 0x00007ffff7c22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7c22000 0x00007ffff7d72000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7d72000 0x00007ffff7dc8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7dc8000 0x00007ffff7dc9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7dc9000 0x00007ffff7e2c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e2c000 0x00007ffff7e2e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e2e000 0x00007ffff7e3b000 0x0000000000000000 rw- 
0x00007ffff7fbf000 0x00007ffff7fc3000 0x0000000000000000 rw- 
0x00007ffff7fc3000 0x00007ffff7fc7000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc7000 0x00007ffff7fc9000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc9000 0x00007ffff7fca000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7fca000 0x00007ffff7ff0000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ff0000 0x00007ffff7ffa000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=2] ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=15, size=0x110, count=2] ←  Chunk(addr=0x5555555593f0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x5555555592e0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
Tcachebins[idx=63, size=0x410, count=2] ←  Chunk(addr=0x555555559910, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x555555559500, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
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
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/80g 0x555555559010
0x555555559010: 0x2 0x0
0x555555559020: 0x0 0x2000000000000
0x555555559030: 0x0 0x0
0x555555559040: 0x0 0x0
0x555555559050: 0x0 0x0
0x555555559060: 0x0 0x0
0x555555559070: 0x0 0x0
0x555555559080: 0x0 0x2000000000000
0x555555559090: 0x5555555592c0  0x0
0x5555555590a0: 0x0 0x0
0x5555555590b0: 0x0 0x0
0x5555555590c0: 0x0 0x0
0x5555555590d0: 0x0 0x0
0x5555555590e0: 0x0 0x0
0x5555555590f0: 0x0 0x0
0x555555559100: 0x0 0x5555555593f0
0x555555559110: 0x0 0x0
0x555555559120: 0x0 0x0
0x555555559130: 0x0 0x0
0x555555559140: 0x0 0x0
0x555555559150: 0x0 0x0
0x555555559160: 0x0 0x0
0x555555559170: 0x0 0x0
0x555555559180: 0x0 0x0
0x555555559190: 0x0 0x0
0x5555555591a0: 0x0 0x0
0x5555555591b0: 0x0 0x0
0x5555555591c0: 0x0 0x0
0x5555555591d0: 0x0 0x0
0x5555555591e0: 0x0 0x0
0x5555555591f0: 0x0 0x0
0x555555559200: 0x0 0x0
0x555555559210: 0x0 0x0
0x555555559220: 0x0 0x0
0x555555559230: 0x0 0x0
0x555555559240: 0x0 0x0
0x555555559250: 0x0 0x0
0x555555559260: 0x0 0x0
0x555555559270: 0x0 0x0
0x555555559280: 0x0 0x555555559910
```

We can do the same thing with `main_arena`. I'm not showing here an in depth look at all of the small / large bins, but the info is there if we wanted to look at it:

```
gef➤  p main_arena
$1 = {
  mutex = 0x0,
  flags = 0x0,
  have_fastchunks = 0x1,
  fastbinsY = {0x0, 0x0, 0x0, 0x555555559ac0, 0x555555559b70, 0x555555559bd0, 0x0, 0x0, 0x0, 0x0},
  top = 0x555555559c40,
  last_remainder = 0x0,
  bins = {0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19ce0 <main_arena+96>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19cf0 <main_arena+112>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d00 <main_arena+128>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d10 <main_arena+144>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d20 <main_arena+160>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d30 <main_arena+176>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d40 <main_arena+192>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d50 <main_arena+208>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d60 <main_arena+224>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d70 <main_arena+240>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d80 <main_arena+256>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19d90 <main_arena+272>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19da0 <main_arena+288>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19db0 <main_arena+304>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dc0 <main_arena+320>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19dd0 <main_arena+336>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19de0 <main_arena+352>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19df0 <main_arena+368>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e00 <main_arena+384>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e10 <main_arena+400>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e20 <main_arena+416>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e30 <main_arena+432>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e40 <main_arena+448>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e50 <main_arena+464>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e60 <main_arena+480>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e70 <main_arena+496>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e80 <main_arena+512>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19e90 <main_arena+528>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19ea0 <main_arena+544>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19eb0 <main_arena+560>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ec0 <main_arena+576>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ed0 <main_arena+592>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ee0 <main_arena+608>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19ef0 <main_arena+624>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f00 <main_arena+640>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f10 <main_arena+656>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f20 <main_arena+672>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f30 <main_arena+688>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f40 <main_arena+704>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f50 <main_arena+720>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f60 <main_arena+736>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f70 <main_arena+752>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f80 <main_arena+768>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19f90 <main_arena+784>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fa0 <main_arena+800>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fb0 <main_arena+816>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fc0 <main_arena+832>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fd0 <main_arena+848>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19fe0 <main_arena+864>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e19ff0 <main_arena+880>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a000 <main_arena+896>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a010 <main_arena+912>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a020 <main_arena+928>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a030 <main_arena+944>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a040 <main_arena+960>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a050 <main_arena+976>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a060 <main_arena+992>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a070 <main_arena+1008>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a080 <main_arena+1024>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a090 <main_arena+1040>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0a0 <main_arena+1056>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0b0 <main_arena+1072>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0c0 <main_arena+1088>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0d0 <main_arena+1104>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0e0 <main_arena+1120>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a0f0 <main_arena+1136>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a100 <main_arena+1152>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a110 <main_arena+1168>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a120 <main_arena+1184>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a130 <main_arena+1200>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a140 <main_arena+1216>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a150 <main_arena+1232>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a160 <main_arena+1248>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a170 <main_arena+1264>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a180 <main_arena+1280>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a190 <main_arena+1296>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1a0 <main_arena+1312>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1b0 <main_arena+1328>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1c0 <main_arena+1344>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1d0 <main_arena+1360>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1e0 <main_arena+1376>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a1f0 <main_arena+1392>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a200 <main_arena+1408>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a210 <main_arena+1424>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a220 <main_arena+1440>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a230 <main_arena+1456>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a240 <main_arena+1472>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a250 <main_arena+1488>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a260 <main_arena+1504>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a270 <main_arena+1520>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a280 <main_arena+1536>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a290 <main_arena+1552>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2a0 <main_arena+1568>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2b0 <main_arena+1584>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2c0 <main_arena+1600>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2d0 <main_arena+1616>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2e0 <main_arena+1632>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a2f0 <main_arena+1648>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a300 <main_arena+1664>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a310 <main_arena+1680>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a320 <main_arena+1696>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a330 <main_arena+1712>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a340 <main_arena+1728>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a350 <main_arena+1744>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a360 <main_arena+1760>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a370 <main_arena+1776>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a380 <main_arena+1792>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a390 <main_arena+1808>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3a0 <main_arena+1824>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3b0 <main_arena+1840>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3c0 <main_arena+1856>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3d0 <main_arena+1872>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3e0 <main_arena+1888>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a3f0 <main_arena+1904>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a400 <main_arena+1920>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a410 <main_arena+1936>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a420 <main_arena+1952>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a430 <main_arena+1968>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a440 <main_arena+1984>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a450 <main_arena+2000>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a460 <main_arena+2016>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a470 <main_arena+2032>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a480 <main_arena+2048>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a490 <main_arena+2064>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4a0 <main_arena+2080>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4b0 <main_arena+2096>, 0x7ffff7e1a4c0 <main_arena+2112>, 0x7ffff7e1a4c0 <main_arena+2112>},
  binmap = {0x0, 0x0, 0x0, 0x0},
  next = 0x7ffff7e19c80 <main_arena>,
  next_free = 0x0,
  attached_threads = 0x1,
  system_mem = 0x21000,
  max_system_mem = 0x21000
}
```


