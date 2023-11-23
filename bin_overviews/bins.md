## Bins

- [back](readme.md)

So, there are three different binning mechanisms that operate similarly. These are the unsorted bin, small bins, and large bins. This will be reviewing some of the basic similarities between the three.

Now, in the main arena (which is a data structure that is used to model the current heap state, it will be covered later), it stores the fast bins, unsorted bin, small and large bins. The unsorted, small, and large bins are stored in a single array. The fast bin is stored in a separate array, with chunks that operate differently than the previous three. This array which stores the unsorted bin, small bins, and large bins will each contain a `malloc_chunk` which will act as a "bin head chunk" to the actual bin.

So, there is an array where the unsorted bin, small bins, and large bins are stored. There are `127` indices to this array. Each index (with the exception of `0`) maps to an individual bin. Index `0` is not used. Index `1` is used for the unsorted bin. Indices `2` to `63` are used for the small bins, and indices `64` to `126` are used for the large bins. There is only one unsorted bin, since there is only one index for it. Since there are multiple indices for both the small and large bins, there are multiple small bins and multiple large bins.

Now each bin is a circular doubly linked list, composed of nodes. This is the code for the data structure for a chunk. In practice, not all of the structs have all of these fields. The `fd_nextsize/bk_nextsize` ptrs are only used by the large bins:

```
/*
  -----------------------  Chunk representations -----------------------
*/


/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T   mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T   mchunk_size;  /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;    /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

Interestingly enough, looking at that comment, it says that this is more of a view. The reason for that is not every `malloc_chunk` has all of the fields. For instance, the "head bin ptrs" only have the `fd/bk` pointers. In addition to that, only the large bin `malloc_chunk`s have the `fd_nextsize/bk_nextsize`.

Now, after the malloc state is initialized (which it's initialized the first time malloc is called) all of the indices (with the exception of index `0`, which doesn't really exist in memory) will actually have a base `malloc_chunk` in that index, to store a sort of "head bin ptr" for the bin. This chunk will be there, regardless if the bin actually has chunks in it, or is empty.

Also another thing to note, I am not aware of any size restrictions on how many chunks can be present within any of these bins (be it the unsorted, a small bin, or a large bin).

Now, the "bin head ptr" isn't a full `malloc_chunk`. It's only the `fd/bk` ptrs. If the bin is empty, both the `fd/bk` pointer will be back to the "head ptr" itself, since the doubly linked list is circular. Now since the "bin head ptr" only has the `fd/bk` ptr, which is at offset `0x10/0x18` in the `malloc_chunk` (`INTERNAL_SIZE_T` is `0x08` bytes), the `fd/bk` ptr will be to `0x10` bytes before the `fd/bk` ptr. We see that when we look at empty "head bin ptrs" in the `main_arena`:

```
gef➤  x/40g 0x7ffff7e19cd0
0x7ffff7e19cd0 <main_arena+80>: 0x0 0x0
0x7ffff7e19ce0 <main_arena+96>: 0x555555559e70  0x0
0x7ffff7e19cf0 <main_arena+112>:  0x7ffff7e19ce0  0x7ffff7e19ce0
0x7ffff7e19d00 <main_arena+128>:  0x7ffff7e19cf0  0x7ffff7e19cf0
0x7ffff7e19d10 <main_arena+144>:  0x7ffff7e19d00  0x7ffff7e19d00
0x7ffff7e19d20 <main_arena+160>:  0x7ffff7e19d10  0x7ffff7e19d10
0x7ffff7e19d30 <main_arena+176>:  0x7ffff7e19d20  0x7ffff7e19d20
0x7ffff7e19d40 <main_arena+192>:  0x7ffff7e19d30  0x7ffff7e19d30
0x7ffff7e19d50 <main_arena+208>:  0x7ffff7e19d40  0x7ffff7e19d40
0x7ffff7e19d60 <main_arena+224>:  0x7ffff7e19d50  0x7ffff7e19d50
0x7ffff7e19d70 <main_arena+240>:  0x7ffff7e19d60  0x7ffff7e19d60
0x7ffff7e19d80 <main_arena+256>:  0x7ffff7e19d70  0x7ffff7e19d70
0x7ffff7e19d90 <main_arena+272>:  0x7ffff7e19d80  0x7ffff7e19d80
0x7ffff7e19da0 <main_arena+288>:  0x7ffff7e19d90  0x7ffff7e19d90
0x7ffff7e19db0 <main_arena+304>:  0x7ffff7e19da0  0x7ffff7e19da0
0x7ffff7e19dc0 <main_arena+320>:  0x7ffff7e19db0  0x7ffff7e19db0
0x7ffff7e19dd0 <main_arena+336>:  0x7ffff7e19dc0  0x7ffff7e19dc0
0x7ffff7e19de0 <main_arena+352>:  0x7ffff7e19dd0  0x7ffff7e19dd0
0x7ffff7e19df0 <main_arena+368>:  0x7ffff7e19de0  0x7ffff7e19de0
0x7ffff7e19e00 <main_arena+384>:  0x7ffff7e19df0  0x7ffff7e19df0
```

Also one thing I might refer to when talking about the unsorted bin, small bins, and the large bins, is the head and tail of the bin. When I refer to the head, I'm talking about the chunk pointed to by the `fd` ptr of the "bin head chunk". When I refer to the tail, I'm talking about the chunk pointed to by the `bk` ptr of the "bin head chunk". Both of these are different from the "bin head chunk", which we've seen described above.



