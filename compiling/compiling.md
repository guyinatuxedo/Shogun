# Compiling

So, the purpose of this readme. It's just to demonstrate how to compile libc from source, and compile binaries to link against that. There are two parts to this, first will be compiling libc from source, and the second will be how to compile binaries to use that new libc version.

The version of libc that is standard on your system, may not be the same one we are using. If it isn't, there will be differences in how the heap works (which can cause certain things that should work to not, or vice versa).

## Compiling Libc

So, first off we need to download the glibc source code. You can find the mirrors at `https://www.gnu.org/software/libc/`. The current version we are working with is `2.38`.

Extract the glibc code, and create the build directory:

```
$   cd ~
$   tar -xf glibc-2.38.tar.bz2
$   cd glibc-2.38/
$   mkdir compiled-2.38
$   mkdir build
$   cd build/
```

Also, these are some things we need installed to compile glibc:

```
$   sudo apt-get install gcc make gawk bison
```

Then, from the `build` directory, we will go ahead and configure glibc for compiling:

```
$   ../configure --prefix=$HOME/glibc-2.38/compiled-2.38/
 . . .
```

Then, we will go ahead and compile glibc, this will take like 10 minutes:

```
$   make -j
 . . .
```

```
$   make install
 . . .
```


## Compile Binaries to Linking Against to new Libc

To compile binaries to link against the newly compiled libc version:

```
$   gcc -Xlinker -rpath=$HOME/glibc-2.38/compiled-2.38/lib/ -Xlinker -I$HOME/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2 tmp.c -o tmp
```

Let's confirm that we are actually using the libc we compiled:

```
$   gdb ./tmp
GNU gdb (Ubuntu 13.1-2ubuntu2) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
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
88 commands loaded and 5 functions added for GDB 13.1 in 0.00ms using Python engine 3.11
Reading symbols from ./tmp...

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./tmp)
gef➤  b *main
Breakpoint 1 at 0x1149
gef➤  r
Starting program: /Hackery/tmp/tmp
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

Breakpoint 1, 0x0000555555555149 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555555149  →  <main+0> endbr64
$rbx   : 0x00007fffffffe028  →  0x00007fffffffe334  →  "/Hackery/tmp/tmp"
$rcx   : 0x0000555555557db0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64
$rdx   : 0x00007fffffffe038  →  0x00007fffffffe345  →  "SHELL=/bin/bash"
$rsp   : 0x00007fffffffdf18  →  0x00007ffff7c23e7d  →  <__libc_start_call_main+109> mov edi, eax
$rbp   : 0x1             
$rsi   : 0x00007fffffffe028  →  0x00007fffffffe334  →  "/Hackery/tmp/tmp"
$rdi   : 0x1             
$rip   : 0x0000555555555149  →  <main+0> endbr64
$r8    : 0x0             
$r9    : 0x00007ffff7fced60  →  <_dl_fini+0> endbr64
$r10   : 0x00007ffff7fca7b0  →  0x000a00120000000e
$r11   : 0x00007ffff7fe19d0  →  <_dl_audit_preinit+0> endbr64
$r12   : 0x0             
$r13   : 0x00007fffffffe038  →  0x00007fffffffe345  →  "SHELL=/bin/bash"
$r14   : 0x0000555555557db0  →  0x0000555555555100  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2c0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf18│+0x0000: 0x00007ffff7c23e7d  →  <__libc_start_call_main+109> mov edi, eax    ← $rsp
0x00007fffffffdf20│+0x0008: 0x00007fffffffe010  →  0x00007fffffffe018  →  0x0000000000000038 ("8"?)
0x00007fffffffdf28│+0x0010: 0x0000555555555149  →  <main+0> endbr64
0x00007fffffffdf30│+0x0018: 0x0000000155554040
0x00007fffffffdf38│+0x0020: 0x00007fffffffe028  →  0x00007fffffffe334  →  "/Hackery/tmp/tmp"
0x00007fffffffdf40│+0x0028: 0x00007fffffffe028  →  0x00007fffffffe334  →  "/Hackery/tmp/tmp"
0x00007fffffffdf48│+0x0030: 0x0407905a142fa6c0
0x00007fffffffdf50│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555139 <__do_global_dtors_aux+57> nop    DWORD PTR [rax+0x0]
   0x555555555140 <frame_dummy+0>  endbr64
   0x555555555144 <frame_dummy+4>  jmp    0x5555555550c0 <register_tm_clones>
 → 0x555555555149 <main+0>       endbr64
   0x55555555514d <main+4>       push   rbp
   0x55555555514e <main+5>       mov    rbp, rsp
   0x555555555151 <main+8>       lea    rax, [rip+0xeac]     # 0x555555556004
   0x555555555158 <main+15>      mov    rdi, rax
   0x55555555515b <main+18>      call   0x555555555050 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tmp", stopped 0x555555555149 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555149 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start            End             Offset          Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /Hackery/tmp/tmp
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /Hackery/tmp/tmp
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /Hackery/tmp/tmp
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /Hackery/tmp/tmp
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /Hackery/tmp/tmp
0x00007ffff7c00000 0x00007ffff7c22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7c22000 0x00007ffff7d74000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7d74000 0x00007ffff7dca000 0x0000000000174000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7dca000 0x00007ffff7e2e000 0x00000000001c9000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e2e000 0x00007ffff7e30000 0x000000000022d000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007ffff7e30000 0x00007ffff7e3d000 0x0000000000000000 rw-
0x00007ffff7fc0000 0x00007ffff7fc4000 0x0000000000000000 rw-
0x00007ffff7fc4000 0x00007ffff7fc8000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc8000 0x00007ffff7fca000 0x0000000000000000 r-x [vdso]
0x00007ffff7fca000 0x00007ffff7fcb000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7fcb000 0x00007ffff7ff1000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ff1000 0x00007ffff7ffb000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

We see, we were able to compile the new binary, to use the newly compiled glibc version.

## Sources

This was based off of:
```
https://iq.opengenus.org/install-specific-version-of-glibc/
https://stackoverflow.com/questions/2728552/how-to-link-to-a-different-libc-file
```

## Gef Wrapper

For a ton of this repo, we use the gef gdb wrapper found here: `https://github.com/hugsy/gef`
