# Basic Heap

- [back](readme.md)

So the purpose of this is to cover some basic information about how the heap works, which will be needed later on.

## What is the heap?

You probably know this. The heap is a system which will allow you to dynamically allocate space within your code. You typically allocate memory with `malloc`, and deallocate it with `free`.

## Chunk Size vs Request Size

Now, when you go ahead and call `malloc`, you pass it an argument. This argument is the minimum size you want for the user data section of the malloc chunk you are requesting to be allocated. The actual size of the chunk will be larger than the size you pass it. This is for several reasons. First off, the malloc chunk will need to store a chunk header, in addition to the data that you wish to store there. This heap header contains data about the chunk, which will need to be used later on. In addition to that, malloc likes to round up chunks to the nearest `0x10` byte divisible size, so that may also increase the size of the chunk.

The size you request from malloc, is typically known as either the request or the user size. The actual total size of the chunk is known as the chunk size. Also the section of the heap chunk which is supposed to hold the data the programmer wants to store, I call it the user data section. The ptr (pointer) returned by malloc is directly to that region.

## Binning

So, take a look at this code:

```
#include <stdio.h>
#include <stdlib.h>

void main(void) {
    char *ptr0, *ptr1, *ptr2;

    ptr0 = malloc(0x450);
    ptr1 = malloc(0x450);
    ptr2 = malloc(0x450);

    puts("I have three malloc chunks!");

}
```

Which at that puts call, the heap will look something like this:

![heap_top](diagrams/heap_top.png)

This is the in memory representation of that. This might not make a lot of sense right now, but it might later:
```
gef➤  x/50g 0x555555559290
0x555555559290:    0x0    0x51
0x5555555592a0:    0x0    0x0
0x5555555592b0:    0x0    0x0
0x5555555592c0:    0x0    0x0
0x5555555592d0:    0x0    0x0
0x5555555592e0:    0x0    0x51
0x5555555592f0:    0x0    0x0
0x555555559300:    0x0    0x0
0x555555559310:    0x0    0x0
0x555555559320:    0x0    0x0
0x555555559330:    0x0    0x51
0x555555559340:    0x0    0x0
0x555555559350:    0x0    0x0
0x555555559360:    0x0    0x0
0x555555559370:    0x0    0x0
0x555555559380:    0x0    0x20c81
0x555555559390:    0x0    0x0
0x5555555593a0:    0x0    0x0
0x5555555593b0:    0x0    0x0
0x5555555593c0:    0x0    0x0
0x5555555593d0:    0x0    0x0
0x5555555593e0:    0x0    0x0
0x5555555593f0:    0x0    0x0
0x555555559400:    0x0    0x0
```

So, we see there are three chunks adjacent to each other in memory, with the last one bordering something known as the `top`. How the heap works, is it starts off with a single contiguous block of memory. When the heap needs to allocate more memory (assuming it can't use recycled memory) and it needs to actually create new chunks, it will split off a small piece of the top chunk to use for this. The `top` ptr is simply a ptr to an address, which is at the border between the unallocated portion (which can have chunks split off from to make new chunks), and the area of memory which has had chunks that have been allocated (although they might have been freed after being allocated). The actual value stored at the memory location the `top` ptr points to, is supposed to say how much space is left in the top chunk (I've also heard it called the heap wilderness).

Now we allocated three chunks, with the specified size being `0x40`. We see here, the actual size of the chunks are `0x50`. The size of the chunk is stored in the heap header. Now it looks like their size is `0x51`. That is because the `1` bit is a flag, to signify the previous heap chunk is in use. The heap (and also the `top` chunk) is initialized the first time that malloc is called. After the first chunk was malloc'd, the top chunk was `0x5555555592e0`. After the second allocation it was `0x555555559330`, and the third was `0x555555559380`. We can see here that the heap is growing towards higher addresses. In addition to that, every time the top chunk ptr shifted by `0x50` bytes, because that was the size of the chunk that we were allocating.

Now, taking a look back at the diagram, we see chunk `0` is at `0x555555559290`, chunk `1` is at `0x5555555592e0`, and chunk `2` is at `0x555555559330`. This is of course, to `0x10` bytes backwards from the ptr that malloc returned to us (remember, the ptr malloc gives us is to the start of the user data section of the chunk, not the start of the chunk). Now, what if we were to started to free some of these chunks?

If we were to free chunk `2` in place of that `puts` call, it would enter into something called the tcache (will be discussed later) since it's such a small chunk, and the tcache has some empty spaces. However if it was a larger chunk (let's say `0x460` bytes instead of `0x50`) malloc would actually merge it into the top chunk. However this would be a different story if we just freed chunk `1`. Since chunk `1` isn't adjacent to the top chunk, we can't merge it back into the top chunk when it's freed. In order for two chunks to be merged, they must be adjacent in memory.

This is leading into something called fragmentation. Just because you have `0x10000` bytes of free space, that doesn't mean you can allocate a `0x10000` byte chunk, since it might not all be one contiguous space. Now to help decrease the downsides to heap fragmentation and improve performance, the libc heap has a lot of different binning mechanisms, which are designed to reuse freed chunks in future malloc allocations. Most of the information in here will be dealing with those various binning mechanisms.

Also one more thing to note. A lot of functions (like `puts`) also call malloc, and thus can affect the state of the heap.
