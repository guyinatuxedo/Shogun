## Free

- [back](readme.md)

So now, let's take a walkthrough `free`. It starts off with the `__libc_free` function.

## __libc_free

```
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                      	/* chunk corresponding to mem */

  if (mem == 0)                          	/* free(0) has no effect */
	return;

  /* Quickly check that the freed pointer matches the tag for the memory.
 	This gives a useful double-free detection.  */
  if (__glibc_unlikely (mtag_enabled))
	*(volatile char *)mem;

  int err = errno;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                   	/* release mmapped memory. */
	{
  	/* See if the dynamic brk/mmap threshold needs adjusting.
     Dumped fake mmapped chunks do not affect the threshold.  */
  	if (!mp_.no_dyn_threshold
      	&& chunksize_nomask (p) > mp_.mmap_threshold
      	&& chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
    	{
      	mp_.mmap_threshold = chunksize (p);
      	mp_.trim_threshold = 2 * mp_.mmap_threshold;
      	LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                  	mp_.mmap_threshold, mp_.trim_threshold);
    	}
  	munmap_chunk (p);
	}
  else
	{
  	MAYBE_INIT_TCACHE ();

  	/* Mark the chunk as belonging to the library again.  */
  	(void)tag_region (chunk2mem (p), memsize (p));

  	ar_ptr = arena_for_chunk (p);
  	_int_free (ar_ptr, p, 0);
	}

  __set_errno (err);
}
libc_hidden_def (__libc_free)
```

Before we look through this, we need to cover a few macros.

First off, there are the `mem2chunk`/`chunk2mem` macros. So like I mentioned before, the pointer returned by malloc is not a ptr to the beginning of the chunk, but the beginning of the "user data section" of the chunk. The purpose of these macros is to get a ptr to the start of the chunk from a ptr to the user data section, or vice versa. A pointer to the "user data section" is referred to as `mem`, and a ptr to the beginning of the chunk is referred to as a `chunk`. It does this via adding/subtracting the size of a heap chunk header `CHUNK_HDR_SZ` (`8` bytes).

```
/* Convert a user mem pointer to a chunk address and extract the right tag.  */
#define mem2chunk(mem) ((mchunkptr)tag_at (((char*)(mem) - CHUNK_HDR_SZ)))

 . . .

/* Convert a chunk address to a user mem pointer without correcting
   the tag.  */
#define chunk2mem(p) ((void*)((char*)(p) + CHUNK_HDR_SZ))

 . . .

/* The chunk header is two SIZE_SZ elements, but this is used widely, so
   we define it here for clarity later.  */
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
```

Next up, there is the `chunk_is_mmapped` macro which will see if a heap chunk was allocated via `mmap`. The `mchunk_size` (size value of a malloc chunk header) actually has some flag bits occupying the lower bits of it's value. The `0x02` bit (`0b10`) is a flag, which means that the chunk was allocated via mmap, instead of malloc.

```
/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)
```

This will get the actual size of the "user data section" of a malloc chunk. It does this via the size value stored in the malloc chunk:

```
/* This is the size of the real usable data in the chunk.  Not valid for
   dumped heap chunks.  */
#define memsize(p)                                                	\
  (__MTAG_GRANULE_SIZE > SIZE_SZ && __glibc_unlikely (mtag_enabled) ? \
	chunksize (p) - CHUNK_HDR_SZ :                                	\
	chunksize (p) - CHUNK_HDR_SZ + (chunk_is_mmapped (p) ? 0 : SIZE_SZ))

 . . .

#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

 . . .

/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))

/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)     	((p)->mchunk_size)
```

The `tag_region` macro deals with memory tagging, which isn't enabled by default. it will not be covered here.

Next up, there is the `arena_for_chunk` macro, which will get the arena associated with the malloc chunk. An arena is more or less, a section of memory designated for malloc to operate from with allocating chunks from. In general, it will check if the chunk is not from the main arena if the `NON_MAIN_ARENA` flag bit in the chunk size is set (similar to `IS_MMAPPED`). If it's from the `main_arena`, it will return the `main_arena` which is in the global variables of the libc. If not, it will use `heap_for_ptr` to get the appropriate arena.

```
/* find the heap and corresponding arena for a given ptr */

static inline heap_info *
heap_for_ptr (void *ptr)
{
  size_t max_size = heap_max_size ();
  return PTR_ALIGN_DOWN (ptr, max_size);
}

static inline struct malloc_state *
arena_for_chunk (mchunkptr ptr)
{
  return chunk_main_arena (ptr) ? &main_arena : heap_for_ptr (ptr)->ar_ptr;
}

 . . .

/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)
```

Next up, we see how it initializes the `tcache`. The `tcache` is a libc global variable. it is a ptr to a `tcache_perthread_struct`. This macro will effectively check if that ptr is null, and if it is, it will call `tcache_init`. That function will effectively allocate a new `tcache_perthread_struct`, memset to zero it out, and set `tcache` equal to that heap chunk:

```
# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
	tcache_init();

 . . .

static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
	return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
	{
  	ar_ptr = arena_get_retry (ar_ptr, bytes);
  	victim = _int_malloc (ar_ptr, bytes);
	}


  if (ar_ptr != NULL)
	__libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
 	- in which case, we just keep trying later.  However, we
 	typically do this very early, so either there is sufficient
 	memory, or there isn't enough memory to do non-trivial
 	allocations anyway.  */
  if (victim)
	{
  	tcache = (tcache_perthread_struct *) victim;
  	memset (tcache, 0, sizeof (tcache_perthread_struct));
	}

}
```

So, now that we went through all of the macros. So what does this function do? It will first off, check if it got a null ptr. If it did, it would just return and do nothing. Assuming it's not a null ptr, it will get the chunk ptr with `mem2chunk` (ptr to the beginning of the malloc chunk, not the "user data section" of the chunk). It will check if it's an mmap chunk with the `chunk_is_mmapped` macro, which effectively just checks for the mmap flag in the heap chunk. The `mmap` function is another function for memory allocation, however it lacks a lot of the additional functionally `malloc` does for optimization. As such, it shouldn't be freed using malloc's `free`, so it will free it with `munmap_chunk` instead.

Now assuming it wasn't allocated via `mmap`, it will initialize the tcache if it needs to be with `MAYBE_INIT_TCACHE` Then it will grab the corresponding arena with `arena_for_chunk`. Then after all of that, it will call the `_int_free` which handles most of the functionality within free that we are interested in. This function is primarily a wrapper for that.

## _int_free

So next up, we have the `_int_free` function, which handles most of the functionality we are looking at. We will break it down into smaller pieces, but this is all of it right here:

```
/*
   ------------------------------ free ------------------------------
 */

static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;    	/* its size */
  mfastbinptr *fb;         	/* associated fastbin */
  mchunkptr nextchunk;     	/* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;	/* its size */
  int nextinuse;           	/* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;	/* size of previous contiguous chunk */
  mchunkptr bck;           	/* misc temp for linking */
  mchunkptr fwd;           	/* misc temp for linking */

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
 	allocator never wrapps around at the end of the address space.
 	Therefore we can exclude some size values which might appear
 	here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
  	|| __builtin_expect (misaligned_chunk (p), 0))
	malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
 	multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
	malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
	size_t tc_idx = csize2tidx (size);
	if (tcache != NULL && tc_idx < mp_.tcache_bins)
  	{
    /* Check to see if it's already in the tcache.  */
    tcache_entry *e = (tcache_entry *) chunk2mem (p);

    /* This test succeeds on double free.  However, we don't 100%
   	trust it (it also matches random payload data at a 1 in
   	2^<size_t> chance), so verify it's not an unlikely
   	coincidence before aborting.  */
    if (__glibc_unlikely (e->key == tcache_key))
      {
    	tcache_entry *tmp;
    	size_t cnt = 0;
    	LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    	for (tmp = tcache->entries[tc_idx];
   	  tmp;
   	  tmp = REVEAL_PTR (tmp->next), ++cnt)
      	{
   	 if (cnt >= mp_.tcache_count)
   	   malloc_printerr ("free(): too many chunks detected in tcache");
   	 if (__glibc_unlikely (!aligned_OK (tmp)))
   	   malloc_printerr ("free(): unaligned chunk detected in tcache 2");
   	 if (tmp == e)
   	   malloc_printerr ("free(): double free detected in tcache 2");
   	 /* If we get here, it was a coincidence.  We've wasted a
   		few cycles, but don't abort.  */
      	}
      }

    if (tcache->counts[tc_idx] < mp_.tcache_count)
      {
    	tcache_put (p, tc_idx);
    	return;
      }
  	}
  }
#endif

  /*
	If eligible, place chunk on a fastbin so it can be found
	and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
  	/*
    If TRIM_FASTBINS set, don't place chunks
    bordering top into fastbins
  	*/
  	&& (chunk_at_offset(p, size) != av->top)
#endif
  	) {

	if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
   		   <= CHUNK_HDR_SZ, 0)
    || __builtin_expect (chunksize (chunk_at_offset (p, size))
   		  	>= av->system_mem, 0))
  	{
    bool fail = true;
    /* We might not have a lock at this point and concurrent modifications
   	of system_mem might result in a false positive.  Redo the test after
   	getting the lock.  */
    if (!have_lock)
      {
    	__libc_lock_lock (av->mutex);
    	fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
   	 	|| chunksize (chunk_at_offset (p, size)) >= av->system_mem);
    	__libc_lock_unlock (av->mutex);
      }

    if (fail)
      malloc_printerr ("free(): invalid next size (fast)");
  	}

	free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

	atomic_store_relaxed (&av->have_fastchunks, true);
	unsigned int idx = fastbin_index(size);
	fb = &fastbin (av, idx);

	/* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
	mchunkptr old = *fb, old2;

	if (SINGLE_THREAD_P)
  	{
    /* Check that the top of the bin is not the record we are going to
   	add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      malloc_printerr ("double free or corruption (fasttop)");
    p->fd = PROTECT_PTR (&p->fd, old);
    *fb = p;
  	}
	else
  	do
    {
      /* Check that the top of the bin is not the record we are going to
     	add (i.e., double free).  */
      if (__builtin_expect (old == p, 0))
    	malloc_printerr ("double free or corruption (fasttop)");
      old2 = old;
      p->fd = PROTECT_PTR (&p->fd, old);
    }
  	while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
     	!= old2);

	/* Check that size of fastbin chunk at the top is the same as
   	size of the chunk that we are adding.  We can dereference OLD
   	only if we have the lock, otherwise it might have already been
   	allocated again.  */
	if (have_lock && old != NULL
    && __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
  	malloc_printerr ("invalid fastbin entry (free)");
  }

  /*
	Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

	/* If we're single-threaded, don't lock the arena.  */
	if (SINGLE_THREAD_P)
  	have_lock = true;

	if (!have_lock)
  	__libc_lock_lock (av->mutex);

	nextchunk = chunk_at_offset(p, size);

	/* Lightweight tests: check whether the block is already the
   	top block.  */
	if (__glibc_unlikely (p == av->top))
  	malloc_printerr ("double free or corruption (top)");
	/* Or whether the next chunk is beyond the boundaries of the arena.  */
	if (__builtin_expect (contiguous (av)
   		   && (char *) nextchunk
   		   >= ((char *) av->top + chunksize(av->top)), 0))
    malloc_printerr ("double free or corruption (out)");
	/* Or whether the block is actually not marked used.  */
	if (__glibc_unlikely (!prev_inuse(nextchunk)))
  	malloc_printerr ("double free or corruption (!prev)");

	nextsize = chunksize(nextchunk);
	if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
    || __builtin_expect (nextsize >= av->system_mem, 0))
  	malloc_printerr ("free(): invalid next size (normal)");

	free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

	/* consolidate backward */
	if (!prev_inuse(p)) {
  	prevsize = prev_size (p);
  	size += prevsize;
  	p = chunk_at_offset(p, -((long) prevsize));
  	if (__glibc_unlikely (chunksize(p) != prevsize))
    	malloc_printerr ("corrupted size vs. prev_size while consolidating");
  	unlink_chunk (av, p);
	}

	if (nextchunk != av->top) {
  	/* get and clear inuse bit */
  	nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

  	/* consolidate forward */
  	if (!nextinuse) {
    unlink_chunk (av, nextchunk);
    size += nextsize;
  	} else
    clear_inuse_bit_at_offset(nextchunk, 0);

  	/*
    Place the chunk in unsorted chunk list. Chunks are
    not placed into regular bins until after they have
    been given one chance to be used in malloc.
  	*/

  	bck = unsorted_chunks(av);
  	fwd = bck->fd;
  	if (__glibc_unlikely (fwd->bk != bck))
    malloc_printerr ("free(): corrupted unsorted chunks");
  	p->fd = fwd;
  	p->bk = bck;
  	if (!in_smallbin_range(size))
    {
      p->fd_nextsize = NULL;
      p->bk_nextsize = NULL;
    }
  	bck->fd = p;
  	fwd->bk = p;

  	set_head(p, size | PREV_INUSE);
  	set_foot(p, size);

  	check_free_chunk(av, p);
	}

	/*
  	If the chunk borders the current high end of memory,
  	consolidate into top
	*/

	else {
  	size += nextsize;
  	set_head(p, size | PREV_INUSE);
  	av->top = p;
  	check_chunk(av, p);
	}

	/*
  	If freeing a large space, consolidate possibly-surrounding
  	chunks. Then, if the total unused topmost memory exceeds trim
  	threshold, ask malloc_trim to reduce top.

  	Unless max_fast is 0, we don't know if there are fastbins
  	bordering top, so we cannot tell for sure whether threshold
  	has been reached unless fastbins are consolidated.  But we
  	don't want to consolidate on each free.  As a compromise,
  	consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
  	is reached.
	*/

	if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
  	if (atomic_load_relaxed (&av->have_fastchunks))
    malloc_consolidate(av);

  	if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
    if ((unsigned long)(chunksize(av->top)) >=
    	(unsigned long)(mp_.trim_threshold))
      systrim(mp_.top_pad, av);
#endif
  	} else {
    /* Always try heap_trim(), even if the top chunk is not
   	large, because the corresponding heap might go away.  */
    heap_info *heap = heap_for_ptr(top(av));

    assert(heap->ar_ptr == av);
    heap_trim(heap, mp_.top_pad);
  	}
	}

	if (!have_lock)
  	__libc_lock_unlock (av->mutex);
  }
  /*
	If the chunk was allocated via mmap, release via munmap().
  */

  else {
	munmap_chunk (p);
  }
}
```

So first off, we have a few initial checks at the beginning. Right after this, we can see the definitions for macros, and constants relevant to this. It will do a comparison, against the negative chunks size field against the actual chunk ptr, both as unsigned values. I believe what this is checking for, is to ensure that there isn't a ludicrously large size value reported in the chunk. In addition to that, there is also a check that the size value isn't too small. On top of that, it checks for proper alignment. Heap chunks (in this architecture) are aligned to next `0x10` byte divisible size, so it checks for that:

```
  size = chunksize (p);

  /* Little security check which won't hurt performance: the
 	allocator never wrapps around at the end of the address space.
 	Therefore we can exclude some size values which might appear
 	here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
  	|| __builtin_expect (misaligned_chunk (p), 0))
	malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
 	multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
	malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);

```

Here we see the definitions:

```

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == CHUNK_HDR_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)

 . . .

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

 . . .

#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

 . . .

#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
   		   ? __alignof__ (long double) : 2 * SIZE_SZ)

 . . .

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

 . . .

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE    	(offsetof(struct malloc_chunk, fd_nextsize))
```

#### tcache freeing

So next up, we have the segment that specifically deals with inserting chunks into the tcache. First off, it will check if the tcache is actually enabled (decided at compile time I think, it really should be enabled):

```
#if USE_TCACHE
  {

 . . .
 
  }
#endif
```

Next up, it will check if the chunk size is appropriate for the tcache. It will first check if the tcache has been initialized (it should have been initialized before this). Then from the chunk size it will get what the corresponding tcache index should be. It will check if this tcache index is actually a valid tcache index via comparing it against `mp_.tcache_bins`. This is because the tcache indices start at `0`, and each subsequent one is larger:

```
	size_t tc_idx = csize2tidx (size);
	if (tcache != NULL && tc_idx < mp_.tcache_bins)
  	{

 . . .

  	}

 . . .

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
```

Proceeding that, we have the tcache key check. It will do this via checking if the tcache key is present within the tcache chunk, present in the "user data section". As we will shortly see, when a chunk is inserted into the tcache, it has the key value put into the chunk. That way, if a chunk is about to be put back into the tcache and it sees the tcache key there, it knows that this is a double free:

```
    /* Check to see if it's already in the tcache.  */
    tcache_entry *e = (tcache_entry *) chunk2mem (p);

    /* This test succeeds on double free.  However, we don't 100%
   	trust it (it also matches random payload data at a 1 in
   	2^<size_t> chance), so verify it's not an unlikely
   	coincidence before aborting.  */
    if (__glibc_unlikely (e->key == tcache_key))
      {
    	tcache_entry *tmp;
    	size_t cnt = 0;
    	LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    	for (tmp = tcache->entries[tc_idx];
   	  tmp;
   	  tmp = REVEAL_PTR (tmp->next), ++cnt)
      	{
   	 if (cnt >= mp_.tcache_count)
   	   malloc_printerr ("free(): too many chunks detected in tcache");
   	 if (__glibc_unlikely (!aligned_OK (tmp)))
   	   malloc_printerr ("free(): unaligned chunk detected in tcache 2");
   	 if (tmp == e)
   	   malloc_printerr ("free(): double free detected in tcache 2");
   	 /* If we get here, it was a coincidence.  We've wasted a
   		few cycles, but don't abort.  */
      	}
      }
```

Next up, if we reach this point, we know that this chunk passed the tcache key check, and that there is a tcache bin for this chunk's size. It will next check if the appropriate tcache bin has spots available via checking if it's size is less than `mp_.tcache_count` which is tha max tcache bin chunk count (`7`)

```
    if (tcache->counts[tc_idx] < mp_.tcache_count)
      {
    	tcache_put (p, tc_idx);
    	return;
      }
```

Assuming that everything passes, the chunk will be inserted into the tcache with the `tcache_put` inlined function:

```
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
 	detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

 . . .

/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

 . . .

/* Process-wide key to try and catch a double-free in the same thread.  */
static uintptr_t tcache_key;
```

So a few things stand out. First off, we can see here that the ptrs inserted into the tcache are to the "user data section", not the beginning of the chunk (`chunk2mem`). We see that it places the tcache key there, and sets the next ptr via ptr mangling (xores it by the address where the ptr is, shifted over by 12 bits) with `PROTECT_PTR`. We also see that it updates the tcache head ptr to the new chunk, and increments the tcache bin count. The `tcache_key` is a value stored in the libc global variables, that is randomized every time the program runs, but should remain constant per thread, as long as the thread is continually running (although don't quote me on that).

#### fastbin Freeing

So, for the fastbin freeing process, it will start off with checking if the size of the chunk is within the fastbin range (between `0` and `128` (`0x80`)). In addition to that, if `TRIM_FASTBINS` is enabled (not by default), it will also check that this chunk is not adjacent to the top chunk. If these checks pass, it will continue down the fastbin freeing code path. if not, it will move onto the next section of free:

```
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
  	/*
  If TRIM_FASTBINS set, don't place chunks
  bordering top into fastbins
  	*/
  	&& (chunk_at_offset(p, size) != av->top)
#endif
  	) {

 . . .

#define set_max_fast(s) \
  global_max_fast = (((size_t) (s) <= MALLOC_ALIGN_MASK - SIZE_SZ)    \
                 	? MIN_CHUNK_SIZE / 2 : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))

static inline INTERNAL_SIZE_T
get_max_fast (void)
{
  /* Tell the GCC optimizers that global_max_fast is never larger
 	than MAX_FAST_SIZE.  This avoids out-of-bounds array accesses in
 	_int_malloc after constant propagation of the size parameter.
 	(The code never executes because malloc preserves the
 	global_max_fast invariant, but the optimizers may not recognize
 	this.)  */
  if (global_max_fast > MAX_FAST_SIZE)
	__builtin_unreachable ();
  return global_max_fast;
}

 . . .

	set_max_fast (DEFAULT_MXFAST);

 . . .

#define DEFAULT_MXFAST 	(64 * SIZE_SZ / 4)

 . . .

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
```

Next up, we see it does some additional checks. These checks aren't done on the chunk being freed, but rather the next adjacent chunk. The size of the current check was already checked before. These checks just ensure that the size of the next chunk is at least that of the heap header chunk size `CHUNK_HDR_SZ`, and not larger than the total system memory in the arena `av->system_mem`. So it's effectively doing a min/max size check on the next adjacent chunk from the chunk being freed:

```
	if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
    	<= CHUNK_HDR_SZ, 0)
  || __builtin_expect (chunksize (chunk_at_offset (p, size))
       	>= av->system_mem, 0))
  	{
  bool fail = true;
  /* We might not have a lock at this point and concurrent modifications
 	of system_mem might result in a false positive.  Redo the test after
 	getting the lock.  */
  if (!have_lock)
	{
  	__libc_lock_lock (av->mutex);
  	fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
    	|| chunksize (chunk_at_offset (p, size)) >= av->system_mem);
  	__libc_lock_unlock (av->mutex);
	}

  if (fail)
	malloc_printerr ("free(): invalid next size (fast)");
  	}
```

Assuming it passes those checks, we have the next section. It is effectively clearing out via `memset` the user data section of the chunk. It is also marking the `have_fastchunks` bool present in the main arena to true, to signify that the main arena does indeed have at least one fastbin chunk:

```
	free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);

	atomic_store_relaxed (&av->have_fastchunks, true);

 . . .

static void
free_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
	memset (p, perturb_byte, n);
}

```

So here, it is actually trying to get a ptr to the head of the corresponding fastbin. The `fb` ptr will be a ptr to the memory location, where the head of the fastbin is stored:

```
	unsigned int idx = fastbin_index(size);
	fb = &fastbin (av, idx);

 . . .

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

So, unlike the tcache, the fastbin mechanism can work with multithreaded systems. How the insertion process works for single threaded is a bit more simple than in multi-threaded instances. Here we have the fastbin insertion for a single threaded instance.

We see that for a single threaded fastbin insertion, it will take the new chunk to be inserted. It will set it's next ptr equal to the old head chunk, and ptr mangled with `PROTECT_PTR`. It will then set the new head of the fastbin to be the newly freed chunk. It's a singly linked list insertion at the head. We also see there is a check which it will check if the newly inserted chunk is the same as the previous head, in an attempt to detect double free bugs:

```
	/* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
	mchunkptr old = *fb, old2;

	if (SINGLE_THREAD_P)
  	{
  /* Check that the top of the bin is not the record we are going to
 	add (i.e., double free).  */
  if (__builtin_expect (old == p, 0))
	malloc_printerr ("double free or corruption (fasttop)");
  p->fd = PROTECT_PTR (&p->fd, old);
  *fb = p;
  	}
```

So I could be wrong here. It looks like to me what's happening is, it's effectively just looping the same write for the insertion process, until it happens, likely for locking purposes. Again, I could be wrong with this. Looks like to me, it's more or less the same insertion process:

```
	else
  	do
  {
	/* Check that the top of the bin is not the record we are going to
   	add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
  	malloc_printerr ("double free or corruption (fasttop)");
	old2 = old;
	p->fd = PROTECT_PTR (&p->fd, old);
  }
  	while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
   	!= old2);
```

Wrapping up, we have one last check here. It is effectively checking that the fastbin index for the old fastbin head chunk actually belongs in that fastbin:

```
	/* Check that size of fastbin chunk at the top is the same as
   	size of the chunk that we are adding.  We can dereference OLD
   	only if we have the lock, otherwise it might have already been
   	allocated again.  */
	if (have_lock && old != NULL
  && __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
  	malloc_printerr ("invalid fastbin entry (free)");
  }
```


#### mmaped Freeing

So next up, we have another check if the chunk being freed was allocated via malloc (checks with that one flag in the size value). If it isn't, it proceeds into the `Generic Freeing` section. If it was, it frees it with the `munmap_chunk` function (goes outside the functionality of the heap from what we're concerned with). That `else` statement is actually the end of the `_int_free` function:

```
  /*
	Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

 . . .

  /*
	If the chunk was allocated via mmap, release via munmap().
  */

  else {
	munmap_chunk (p);
  }
}
```

#### Generic Freeing

So here, we have the generic freeing functionality, where all chunks that don't get inserted into the fastbin / tcache get freed by. First off, if this is a multi-threaded program, it will attempt to get a lock on the arena mutex.

```
	/* If we're single-threaded, don't lock the arena.  */
	if (SINGLE_THREAD_P)
  	have_lock = true;

	if (!have_lock)
  	__libc_lock_lock (av->mutex);
```

Next up, it will grab the next adjacent chunk with `chunk_at_offset`. This is because some of the freeing logic relies on the next adjacent chunk.

Following that, there are some additional checks to hopefully check for some bugs. It will check if the chunk to be freed is the top chunk. It will also check if the next chunk is past the end of the heap bounds, via adding the size of the top chunk to the top chunk. The last check it does, is if the `PREV_INUSE` flag bit of the size value of the next chunk is not set. If set, this flag means that the previous chunk is freed. Since this chunk is to be freed, this flag should not be set:

```
	nextchunk = chunk_at_offset(p, size);

	/* Lightweight tests: check whether the block is already the
   	top block.  */
	if (__glibc_unlikely (p == av->top))
  	malloc_printerr ("double free or corruption (top)");
	/* Or whether the next chunk is beyond the boundaries of the arena.  */
	if (__builtin_expect (contiguous (av)
    	&& (char *) nextchunk
    	>= ((char *) av->top + chunksize(av->top)), 0))
  malloc_printerr ("double free or corruption (out)");
	/* Or whether the block is actually not marked used.  */
	if (__glibc_unlikely (!prev_inuse(nextchunk)))
  	malloc_printerr ("double free or corruption (!prev)");

 . . .

#define NONCONTIGUOUS_BIT 	(2U)

#define contiguous(M)      	(((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M)   	(((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M)   ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M)  	((M)->flags &= ~NONCONTIGUOUS_BIT)

 . . .

/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)   	((p)->mchunk_size & PREV_INUSE)
```

Next up, it will grab the chunk size of the next adjacent chunk. It will do another min/max size check against this check size, against `CHUNK_HDR_SZ`/`av->system_mem`, similar to what we've seen before. In addition to that, it will zero out the user data section of the chunk via `free_perturb`:

```
	nextsize = chunksize(nextchunk);
	if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
  || __builtin_expect (nextsize >= av->system_mem, 0))
  	malloc_printerr ("free(): invalid next size (normal)");

	free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);
```

Before we go any further, we need to discuss chunk unlinking. This function is used to unlink and remove a chunk from one of the small / large (or even unsorted) bins. This function is used later. So, as discussed earlier, the small, unsorted, and large bins all have a doubly linked list. It will first check, that the size of the chunk being freed is the same as the previous chunk size reported in the next chunk. Then, it will check if the `bk` pointer of the next chunk, and the `fd` pointer of the previous chunk are both to the current chunk (as they should be). Assuming those checks are passed, it will unlink this chunk from the doubly linked list via setting the `bk` pointer of the next chunk to the previous chunk from the chunk we are trying to unlink, and vice versa for the previous chunk (set the `fd` ptr of the previous chunk to the next chunk).

Now after that, with the large bin, there is the skip list which might need to be updated. It will check if this needs to be updated via checking if the chunk is not in the small bin range, and that the `fd_nextsize` value is not null (which is used in chunks present in the skip list). If this check passes, it will determine it is a chunk that will need to be removed from the skip list. It will first check in the skip list that the next chunk's previous chunk, and the previous chunk's next chunk, is to the chunk being unlinked (as it should).

Assuming that the next chunk in the doubly linked list (not the skip list) next chunk in the skip list is not null, it will do a traditional removal where the next chunk's prev is set to the previous chunk of the chunk being removed, and vice versa for the prev chunk.

If the next chunk in the doubly linked list next ptr in the skip list is null (`fd->fd_nextsize == null`), it enters into some edge cases. First it will check from the perspective of the chunk being removed, it's next chunk in the skiplist is to itself. If it is, this means the skiplist only has one chunk into it, and it will basically shift the skip list over to the next chunk (`fd->fd_nextsize = fd->bk_nextsize = fd;`). If this check isn't met, then it will for the `fd` (next chunk in the doubly linked list) set it's `fd_nextsize/bk_nextsize` to that of the chunk being removed. In addition to that, it will update those ptrs for the `fd_nextsize/bk_nextsize` of the chunk being removed:

```
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
	malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
	malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
	{
  	if (p->fd_nextsize->bk_nextsize != p
      || p->bk_nextsize->fd_nextsize != p)
    malloc_printerr ("corrupted double-linked list (not small)");

  	if (fd->fd_nextsize == NULL)
    {
      if (p->fd_nextsize == p)
    	fd->fd_nextsize = fd->bk_nextsize = fd;
      else
    	{
      	fd->fd_nextsize = p->fd_nextsize;
      	fd->bk_nextsize = p->bk_nextsize;
      	p->fd_nextsize->bk_nextsize = fd;
      	p->bk_nextsize->fd_nextsize = fd;
    	}
    }
  	else
    {
      p->fd_nextsize->bk_nextsize = p->bk_nextsize;
      p->bk_nextsize->fd_nextsize = p->fd_nextsize;
    }
	}
}

 . . .

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))

/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)

 . . .

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
```

So, getting back to `free`. We see here, is the code for backwards consolidation. It will check via the flags in the current chunk, if the previous chunk is in use. If not, that means it is free, and we will now consolidate the two smaller chunks together. To do this, it will simply shift the chunk ptr to the beginning of the first chunk, and add the two sizes together. It will also unlink that chunk, since it is in either the large / small / unsorted bin/s.

```
	/* consolidate backward */
	if (!prev_inuse(p)) {
  	prevsize = prev_size (p);
  	size += prevsize;
  	p = chunk_at_offset(p, -((long) prevsize));
  	if (__glibc_unlikely (chunksize(p) != prevsize))
    	malloc_printerr ("corrupted size vs. prev_size while consolidating");
  	unlink_chunk (av, p);
	}
```

Here is the code path where the chunk will actually be inserted into the unsorted bin. It will do this, as long as the next adjacent chunk is not the top chunk. First thing it will do is see if the next chunk is in use. It looks like it does this via looking at the previous in use bit, of the chunk after the next chunk. if the next chunk is not in use, it will execute forward consolidation via unlinking that chunk from the small / large / unsorted bin, and increment the size of the current chunk (since we are appending space to the end of the existing chunk, we don't need to actually update the ptr). If the next chunk is in use, it will simply mark the previous in use bit of it, to mark it. Also one thing to note, fastbin / tcache chunks don't have this flag set for it's next chunk. If the next chunk was already freed, and since we combined the two chunks into one, the next chunk's previous in use flag would already be set to mark that the previous chunk is not in use.

Proceeding the forward consolidation, we actually have it where it will add the chunk to the unsorted bin. It will grab the unsorted bin via that bin array from the main arena, and it will execute a typical unsorted bin insertion. If the chunk is not in the small bin range, it will set the corresponding skiplist ptrs to null (likely to prevent a weird heap attack).

We see that it will update the chunk's size, and the previous size of the next chunk with `set_head/set_foot`. The `check_free_chunk` macro appears to be used in debugging, so not too worried about it:

```
	if (nextchunk != av->top) {
  	/* get and clear inuse bit */
  	nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

  	/* consolidate forward */
  	if (!nextinuse) {
  unlink_chunk (av, nextchunk);
  size += nextsize;
  	} else
  clear_inuse_bit_at_offset(nextchunk, 0);

  	/*
  Place the chunk in unsorted chunk list. Chunks are
  not placed into regular bins until after they have
  been given one chance to be used in malloc.
  	*/

  	bck = unsorted_chunks(av);
  	fwd = bck->fd;
  	if (__glibc_unlikely (fwd->bk != bck))
  malloc_printerr ("free(): corrupted unsorted chunks");
  	p->fd = fwd;
  	p->bk = bck;
  	if (!in_smallbin_range(size))
  {
	p->fd_nextsize = NULL;
	p->bk_nextsize = NULL;
  }
  	bck->fd = p;
  	fwd->bk = p;

  	set_head(p, size | PREV_INUSE);
  	set_foot(p, size);

  	check_free_chunk(av, p);
	}

 . . .

/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)   				   	\
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)   				   	\
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)   				   	\
  (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

 . . .

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M)      	(bin_at (M, 1))

 . . .

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))   		   	\
         	- offsetof (struct malloc_chunk, fd))

 . . .

/* Set size/use field */
#define set_head(p, s)   	((p)->mchunk_size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)   	(((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))

 . . .

/*
   Debugging support

   These routines make a number of assertions about the states
   of data structures that should be true at all times. If any
   are not true, it's very likely that a user program has somehow
   trashed memory. (It's also possible that there is a coding error
   in malloc. In which case, please report it!)
 */

#if !MALLOC_DEBUG

# define check_chunk(A, P)
# define check_free_chunk(A, P)
# define check_inuse_chunk(A, P)
# define check_remalloced_chunk(A, P, N)
# define check_malloced_chunk(A, P, N)
# define check_malloc_state(A)
```

Here we have the code for consolidating a chunk with the top chunk. if the chunk we are freeing borders the top chunk, and we reach this point, it will simply move the top chunk up to the start of the chunk we are freeing, and update the size with `set_head`, in order to consolidate it with the top chunk:

```
	/*
  	If the chunk borders the current high end of memory,
  	consolidate into top
	*/

	else {
  	size += nextsize;
  	set_head(p, size | PREV_INUSE);
  	av->top = p;
  	check_chunk(av, p);
	}
```

So here, we have some interesting things. Basically, if the size of the chunk being freed is larger than `FASTBIN_CONSOLIDATION_THRESHOLD` (`0x10000`), we trigger something called fastbin consolidation with the `malloc_consolidate` function. After that, if the size of the chunk get's beyond a certain threshold, it will call the `systrim` function. This will effectively trim off a piece of memory from the top chunk, and give it back to the system. If that isn't the case, it will try to use the `heap_trim` function, which if conditions are right might delete a heap.

```
	/*
  	If freeing a large space, consolidate possibly-surrounding
  	chunks. Then, if the total unused topmost memory exceeds trim
  	threshold, ask malloc_trim to reduce top.

  	Unless max_fast is 0, we don't know if there are fastbins
  	bordering top, so we cannot tell for sure whether threshold
  	has been reached unless fastbins are consolidated.  But we
  	don't want to consolidate on each free.  As a compromise,
  	consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
  	is reached.
	*/

	if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
  	if (atomic_load_relaxed (&av->have_fastchunks))
  malloc_consolidate(av);

  	if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
  if ((unsigned long)(chunksize(av->top)) >=
  	(unsigned long)(mp_.trim_threshold))
	systrim(mp_.top_pad, av);
#endif
  	} else {
  /* Always try heap_trim(), even if the top chunk is not
 	large, because the corresponding heap might go away.  */
  heap_info *heap = heap_for_ptr(top(av));

  assert(heap->ar_ptr == av);
  heap_trim(heap, mp_.top_pad);
  	}
	}

 . . .

/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */

#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)
```

So going through the three parts, we start off with `malloc_consolidate`. Looking at this function, we see it will iterate through all of the fastbins, starting with the smallest, working to the largest. For each fastbin without a null head ptr (meaning it actually has chunks in it), it will iterate through all of the chunks in it. For each chunk, it will attempt a similar backwards/forwards/top chunk consolidation that we saw in free earlier, prior to inserting it into the unsorted bin:

```
/*
  ------------------------- malloc_consolidate -------------------------

  malloc_consolidate is a specialized version of free() that tears
  down chunks held in fastbins.  Free itself cannot be used for this
  purpose since, among other things, it might place chunks back onto
  fastbins.  So, instead, we need to use a minor variant of the same
  code.
*/

static void malloc_consolidate(mstate av)
{
  mfastbinptr*	fb;             	/* current fastbin being consolidated */
  mfastbinptr*	maxfb;          	/* last fastbin (for loop control) */
  mchunkptr   	p;              	/* current chunk being consolidated */
  mchunkptr   	nextp;          	/* next chunk to consolidate */
  mchunkptr   	unsorted_bin;   	/* bin header */
  mchunkptr   	first_unsorted; 	/* chunk to link to */

  /* These have same use as in free() */
  mchunkptr   	nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int         	nextinuse;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
	Remove each chunk from fast bin and consolidate it, placing it
	then in unsorted bin. Among other reasons for doing this,
	placing in unsorted bin avoids needing to calculate actual bins
	until malloc is sure that chunks aren't immediately going to be
	reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
	p = atomic_exchange_acquire (fb, NULL);
	if (p != 0) {
  	do {
    {
      if (__glibc_unlikely (misaligned_chunk (p)))
    	malloc_printerr ("malloc_consolidate(): "
   		  	"unaligned fastbin chunk detected");

      unsigned int idx = fastbin_index (chunksize (p));
      if ((&fastbin (av, idx)) != fb)
    	malloc_printerr ("malloc_consolidate(): invalid chunk size");
    }

    check_inuse_chunk(av, p);
    nextp = REVEAL_PTR (p->fd);

    /* Slightly streamlined version of consolidation code in free() */
    size = chunksize (p);
    nextchunk = chunk_at_offset(p, size);
    nextsize = chunksize(nextchunk);

    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
    	malloc_printerr ("corrupted size vs. prev_size in fastbins");
      unlink_chunk (av, p);
    }

    if (nextchunk != av->top) {
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      if (!nextinuse) {
    	size += nextsize;
    	unlink_chunk (av, nextchunk);
      } else
    	clear_inuse_bit_at_offset(nextchunk, 0);

      first_unsorted = unsorted_bin->fd;
      unsorted_bin->fd = p;
      first_unsorted->bk = p;

      if (!in_smallbin_range (size)) {
    	p->fd_nextsize = NULL;
    	p->bk_nextsize = NULL;
      }

      set_head(p, size | PREV_INUSE);
      p->bk = unsorted_bin;
      p->fd = first_unsorted;
      set_foot(p, size);
    }

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
    }

  	} while ( (p = nextp) != 0);

	}
  } while (fb++ != maxfb);
}
```

Then we end up with `systrim`, which will return a piece of the top chunk to the system. It does this via first, calculating how much extra data it needs to trim off. Then it will call `MORECORE` to actually return that memory, with the argument being the amount of bytes to allocate (which is a negative amount, because we are release memory not allocating):

```
/*
   systrim is an inverse of sorts to sysmalloc.  It gives memory back
   to the system (via negative arguments to sbrk) if there is unused
   memory at the `high' end of the malloc pool. It is called
   automatically by free() when top space exceeds the trim
   threshold. It is also called by the public malloc_trim routine.  It
   returns 1 if it actually released any memory, else 0.
 */

static int
systrim (size_t pad, mstate av)
{
  long top_size;     	/* Amount of top-most memory */
  long extra;        	/* Amount to release */
  long released;     	/* Amount actually released */
  char *current_brk; 	/* address returned by pre-check sbrk call */
  char *new_brk;     	/* address returned by post-check sbrk call */
  long top_area;

  top_size = chunksize (av->top);

  top_area = top_size - MINSIZE - 1;
  if (top_area <= pad)
	return 0;

  /* Release in pagesize units and round down to the nearest page.  */
#if HAVE_TUNABLES && defined (MADV_HUGEPAGE)
  if (__glibc_unlikely (mp_.thp_pagesize != 0))
	extra = ALIGN_DOWN (top_area - pad, mp_.thp_pagesize);
  else
#endif
	extra = ALIGN_DOWN (top_area - pad, GLRO(dl_pagesize));

  if (extra == 0)
	return 0;

  /*
 	Only proceed if end of memory is where we last set it.
 	This avoids problems if there were foreign sbrk calls.
   */
  current_brk = (char *) (MORECORE (0));
  if (current_brk == (char *) (av->top) + top_size)
	{
  	/*
     	Attempt to release memory. We ignore MORECORE return value,
     	and instead call again to find out where new end of memory is.
     	This avoids problems if first call releases less than we asked,
     	of if failure somehow altered brk value. (We could still
     	encounter problems if it altered brk in some very bad way,
     	but the only thing we can do is adjust anyway, which will cause
     	some downstream failure.)
   	*/

  	MORECORE (-extra);
  	new_brk = (char *) (MORECORE (0));

  	LIBC_PROBE (memory_sbrk_less, 2, new_brk, extra);

  	if (new_brk != (char *) MORECORE_FAILURE)
    	{
      	released = (long) (current_brk - new_brk);

      	if (released != 0)
        	{
          	/* Success. Adjust top. */
          	av->system_mem -= released;
          	set_head (av->top, (top_size - released) | PREV_INUSE);
          	check_malloc_state (av);
          	return 1;
        	}
    	}
	}
  return 0;
}

```

Then finally, we see `heap_trim`. I'm not going to go super into details with this one. We see that it executes a lot of checks, in order to determine if it can shrink the heap:

```

/* Delete a heap. */

static int
heap_trim (heap_info *heap, size_t pad)
{
  mstate ar_ptr = heap->ar_ptr;
  mchunkptr top_chunk = top (ar_ptr), p;
  heap_info *prev_heap;
  long new_size, top_size, top_area, extra, prev_size, misalign;
  size_t max_size = heap_max_size ();

  /* Can this heap go away completely? */
  while (top_chunk == chunk_at_offset (heap, sizeof (*heap)))
	{
  	prev_heap = heap->prev;
  	prev_size = prev_heap->size - (MINSIZE - 2 * SIZE_SZ);
  	p = chunk_at_offset (prev_heap, prev_size);
  	/* fencepost must be properly aligned.  */
  	misalign = ((long) p) & MALLOC_ALIGN_MASK;
  	p = chunk_at_offset (prev_heap, prev_size - misalign);
  	assert (chunksize_nomask (p) == (0 | PREV_INUSE)); /* must be fencepost */
  	p = prev_chunk (p);
  	new_size = chunksize (p) + (MINSIZE - 2 * SIZE_SZ) + misalign;
  	assert (new_size > 0 && new_size < (long) (2 * MINSIZE));
  	if (!prev_inuse (p))
    	new_size += prev_size (p);
  	assert (new_size > 0 && new_size < max_size);
  	if (new_size + (max_size - prev_heap->size) < pad + MINSIZE
   					 	+ heap->pagesize)
    	break;
  	ar_ptr->system_mem -= heap->size;
  	LIBC_PROBE (memory_heap_free, 2, heap, heap->size);
  	if ((char *) heap + max_size == aligned_heap_area)
    aligned_heap_area = NULL;
  	__munmap (heap, max_size);
  	heap = prev_heap;
  	if (!prev_inuse (p)) /* consolidate backward */
    	{
      	p = prev_chunk (p);
      	unlink_chunk (ar_ptr, p);
    	}
  	assert (((unsigned long) ((char *) p + new_size) & (heap->pagesize - 1))
      	== 0);
  	assert (((char *) p + new_size) == ((char *) heap + heap->size));
  	top (ar_ptr) = top_chunk = p;
  	set_head (top_chunk, new_size | PREV_INUSE);
  	/*check_chunk(ar_ptr, top_chunk);*/
	}

  /* Uses similar logic for per-thread arenas as the main arena with systrim
 	and _int_free by preserving the top pad and rounding down to the nearest
 	page.  */
  top_size = chunksize (top_chunk);
  if ((unsigned long)(top_size) <
  	(unsigned long)(mp_.trim_threshold))
	return 0;

  top_area = top_size - MINSIZE - 1;
  if (top_area < 0 || (size_t) top_area <= pad)
	return 0;

  /* Release in pagesize units and round down to the nearest page.  */
  extra = ALIGN_DOWN(top_area - pad, heap->pagesize);
  if (extra == 0)
	return 0;

  /* Try to shrink. */
  if (shrink_heap (heap, extra) != 0)
	return 0;

  ar_ptr->system_mem -= extra;

  /* Success. Adjust top accordingly. */
  set_head (top_chunk, (top_size - extra) | PREV_INUSE);
  /*check_chunk(ar_ptr, top_chunk);*/
  return 1;
}

```

To end off `free`, for instances where we have multithreading, we release the lock on the arena.

```
	if (!have_lock)
  	__libc_lock_unlock (av->mutex);
```


