## Malloc

- [back](readme.md)

So now, let's take a walkthrough `malloc`. It starts off with the `__libc_malloc` function:

```
#if IS_IN (libc)
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                "PTRDIFF_MAX is not more than half of SIZE_MAX");

  if (!__malloc_initialized)
  ptmalloc_init ();
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = checked_request2size (bytes);
  if (tbytes == 0)
  {
    __set_errno (ENOMEM);
    return NULL;
  }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
    && tcache
    && tcache->counts[tc_idx] > 0)
  {
    victim = tcache_get (tc_idx);
    return tag_new_usable (victim);
  }
  DIAG_POP_NEEDS_COMMENT;
#endif

  if (SINGLE_THREAD_P)
  {
    victim = tag_new_usable (_int_malloc (&main_arena, bytes));
    assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
      &main_arena == arena_for_chunk (mem2chunk (victim)));
    return victim;
  }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
  before.  */
  if (!victim && ar_ptr != NULL)
  {
    LIBC_PROBE (memory_malloc_retry, 1, bytes);
    ar_ptr = arena_get_retry (ar_ptr, bytes);
    victim = _int_malloc (ar_ptr, bytes);
  }

  if (ar_ptr != NULL)
  __libc_lock_unlock (ar_ptr->mutex);

  victim = tag_new_usable (victim);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
        ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```

So starting off, we see it will initialize the heap if it needs to with `ptmalloc_init`, which we see it calls `tcache_key_initialize / malloc_init_state`. After the heap is initialized, under "normal circumstances", it shouldn't need to be initialized again:

```
/* The value of tcache_key does not really have to be a cryptographically
   secure random number.  It only needs to be arbitrary enough so that it does
   not collide with values present in applications.  If a collision does happen
   consistently enough, it could cause a degradation in performance since the
   entire list is checked to check if the block indeed has been freed the
   second time.  The odds of this happening are exceedingly low though, about 1
   in 2^wordsize.  There is probably a higher chance of the performance
   degradation being due to a double free where the first free happened in a
   different thread; that's a case this check does not cover.  */
static void
tcache_key_initialize (void)
{
  if (__getrandom_nocancel (&tcache_key, sizeof(tcache_key), GRND_NONBLOCK)
    != sizeof (tcache_key))
  {
    tcache_key = random_bits ();
#if __WORDSIZE == 64
    tcache_key = (tcache_key << 32) | random_bits ();
#endif
  }
}

 . . .

/*
   Initialize a malloc_state struct.

   This is called from ptmalloc_init () or from _int_new_arena ()
   when creating a new arena.
 */

static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i)
  {
    bin = bin_at (av, i);
    bin->fd = bin->bk = bin;
  }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);
  if (av == &main_arena)
  set_max_fast (DEFAULT_MXFAST);
  atomic_store_relaxed (&av->have_fastchunks, false);

  av->top = initial_top (av);
}
```

Next up, it will attempt to reallocate a chunk from the tcache. It starts off by taking the request heap chunk size, and converting into the actual total size of the chunk. Since the chunk must store additional data other than what the user puts there, and it's size will need to be divisible by `0x10`, the actual chunk size will need to be larger than the requested size (which is the actual argument to malloc). Proceeding that, it will get the corresponding tcache index for that chunk size. After that, it will initialize the tcache if it needs to be.

Next, it will see if it actually has a chunk it could allocate. It will first check if the tcache index that chunk would come from actually exists (`tc_idx < mp_.tcache_bins`). Proceeding that, it will check if the tcache was actually initialized (`&& tcache`). Lastly, it will check that the actual tcache bin has chunks in it (`tcache->counts[tc_idx] > 0`). If there is a tcache chunk, it will remove the chunk from the tcache with `tcache_get`. We see that the tcache removal process removes a chunk from the head, decrements the tcache bin count, zeroes out that tcache key value, and also sets the new head equal to the next ptr of the old head:

```
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = checked_request2size (bytes);
  if (tbytes == 0)
  {
    __set_errno (ENOMEM);
    return NULL;
  }
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
    && tcache
    && tcache->counts[tc_idx] > 0)
  {
    victim = tcache_get (tc_idx);
    return tag_new_usable (victim);
  }
  DIAG_POP_NEEDS_COMMENT;
#endif

 . . .

/* pad request bytes into a usable size -- internal version */
/* Note: This must be a macro that evaluates to a compile time constant
   if passed a literal constant.  */
#define request2size(req)                                       \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?           \
   MINSIZE :                                                    \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* Check if REQ overflows when padded and aligned and if the resulting
   value is less than PTRDIFF_T.  Returns the requested size or
   MINSIZE in case the value is less than MINSIZE, or 0 if any of the
   previous checks fail.  */
static inline size_t
checked_request2size (size_t req) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))
  return 0;

  /* When using tagged memory, we cannot share the end of the user
  block with the header for the next chunk, so ensure that we
  allocate blocks that are rounded up to the granule size.  Take
  care not to overflow from close to MAX_SIZE_T to a small
  number.  Ideally, this would be part of request2size(), but that
  must be a macro that produces a compile time constant if passed
  a constant literal.  */
  if (__glibc_unlikely (mtag_enabled))
  {
    /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
    asm ("");

    req = (req + (__MTAG_GRANULE_SIZE - 1)) &
      ~(size_t)(__MTAG_GRANULE_SIZE - 1);
  }

  return request2size (req);
}

 . . .

#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS     64
# define MAX_TCACHE_SIZE    tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)    (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Maximum chunks in tcache bins for tunables.  This value must fit the range
   of tcache->counts[] entries, else they may overflow.  */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif

 . . .

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
  malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

Then following up, in `__libc_malloc`, similar to `__libc_free`, this is a wrapper for `_int_malloc` which handles most of the actual malloc functionality. Difference is, in `__libc_malloc`, the basic tcache removal functionality is handled. We see there is some stuff towards the end for potentially dealing with multithreaded programs with multiple arenas, but I'm not going to dive too much into that stuff:

```
  if (SINGLE_THREAD_P)
  {
    victim = tag_new_usable (_int_malloc (&main_arena, bytes));
    assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
      &main_arena == arena_for_chunk (mem2chunk (victim)));
    return victim;
  }

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);

  . . .
```

## _int_malloc

So looking at the whole `_int_malloc` function, we see it's a bit large. However we will break it down into different parts:

```
/*
   ------------------------------ malloc ------------------------------
 */

static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;             /* normalized request size */
  unsigned int idx;               /* associated bin index */
  mbinptr bin;                    /* associated bin */

  mchunkptr victim;               /* inspected/selected chunk */
  INTERNAL_SIZE_T size;           /* its size */
  int victim_index;               /* its bin index */

  mchunkptr remainder;            /* remainder from a split */
  unsigned long remainder_size;   /* its size */

  unsigned int block;             /* bit map traverser */
  unsigned int bit;               /* bit map traverser */
  unsigned int map;               /* current word of binmap */

  mchunkptr fwd;                  /* misc temp for linking */
  mchunkptr bck;                  /* misc temp for linking */

#if USE_TCACHE
  size_t tcache_unsorted_count;   /* count of unsorted chunks processed */
#endif

  /*
  Convert request size to internal form by adding SIZE_SZ bytes
  overhead plus possibly more to obtain necessary alignment and/or
  to obtain a size of at least MINSIZE, the smallest allocatable
  size. Also, checked_request2size returns false for request sizes
  that are so large that they wrap around zero when padded and
  aligned.
   */

  nb = checked_request2size (bytes);
  if (nb == 0)
  {
    __set_errno (ENOMEM);
    return NULL;
  }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
  mmap.  */
  if (__glibc_unlikely (av == NULL))
  {
    void *p = sysmalloc (nb, av);
    if (p != NULL)
  alloc_perturb (p, bytes);
    return p;
  }

  /*
  If the size qualifies as a fastbin, first check corresponding bin.
  This code is safe to execute even if av is not yet initialized, so we
  can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)   \
  do            \
  {           \
    victim = pp;        \
    if (victim == NULL)     \
  break;          \
    pp = REVEAL_PTR (victim->fd);                                   \
    if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))     \
  malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
  }           \
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
   != victim);        \

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
    idx = fastbin_index (nb);
    mfastbinptr *fb = &fastbin (av, idx);
    mchunkptr pp;
    victim = *fb;

    if (victim != NULL)
  {
  if (__glibc_unlikely (misaligned_chunk (victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

  if (SINGLE_THREAD_P)
    *fb = REVEAL_PTR (victim->fd);
  else
    REMOVE_FB (fb, pp, victim);
  if (__glibc_likely (victim != NULL))
    {
      size_t victim_idx = fastbin_index (chunksize (victim));
      if (__builtin_expect (victim_idx != idx, 0))
  malloc_printerr ("malloc(): memory corruption (fast)");
      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
  stash them in the tcache.  */
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx < mp_.tcache_bins)
  {
    mchunkptr tc_victim;

    /* While bin not empty and tcache not full, copy chunks.  */
    while (tcache->counts[tc_idx] < mp_.tcache_count
    && (tc_victim = *fb) != NULL)
      {
        if (__glibc_unlikely (misaligned_chunk (tc_victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
        if (SINGLE_THREAD_P)
    *fb = REVEAL_PTR (tc_victim->fd);
        else
    {
      REMOVE_FB (fb, pp, tc_victim);
      if (__glibc_unlikely (tc_victim == NULL))
        break;
    }
        tcache_put (tc_victim, tc_idx);
      }
  }
#endif
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }
  }
  }

  /*
  If a small request, check regular bin.  Since these "smallbins"
  hold one size each, no searching within bins is necessary.
  (For a large request, we need to wait until unsorted chunks are
  processed to find best fit. But for small ones, fits are exact
  anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
  {
    idx = smallbin_index (nb);
    bin = bin_at (av, idx);

    if ((victim = last (bin)) != bin)
      {
        bck = victim->bk;
  if (__glibc_unlikely (bck->fd != victim))
    malloc_printerr ("malloc(): smallbin double linked list corrupted");
        set_inuse_bit_at_offset (victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        if (av != &main_arena)
    set_non_main_arena (victim);
        check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
  /* While we're here, if we see other chunks of the same size,
    stash them in the tcache.  */
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    {
      mchunkptr tc_victim;

      /* While bin not empty and tcache not full, copy chunks over.  */
      while (tcache->counts[tc_idx] < mp_.tcache_count
      && (tc_victim = last (bin)) != bin)
  {
    if (tc_victim != 0)
      {
        bck = tc_victim->bk;
        set_inuse_bit_at_offset (tc_victim, nb);
        if (av != &main_arena)
    set_non_main_arena (tc_victim);
        bin->bk = bck;
        bck->fd = bin;

        tcache_put (tc_victim, tc_idx);
            }
  }
    }
#endif
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
      }
  }

  /*
  If this is a large request, consolidate fastbins before continuing.
  While it might look excessive to kill all fastbins before
  even seeing if there is space available, this avoids
  fragmentation problems normally associated with fastbins.
  Also, in practice, programs tend to have runs of either small or
  large requests, but less often mixtures, so consolidation is not
  invoked all that often in most programs. And the programs that
  it is called frequently in otherwise tend to fragment.
   */

  else
  {
    idx = largebin_index (nb);
    if (atomic_load_relaxed (&av->have_fastchunks))
      malloc_consolidate (av);
  }

  /*
  Process recently freed or remaindered chunks, taking one only if
  it is exact fit, or, if this a small request, the chunk is remainder from
  the most recent non-exact fit.  Place other traversed chunks in
  bins.  Note that this step is the only place in any routine where
  chunks are placed in bins.

  The outer loop here is needed because we might not realize until
  near the end of malloc that we should have consolidated, so must
  do so and retry. This happens at most once, and only when we would
  otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
  tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
  {
    int iters = 0;
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      {
        bck = victim->bk;
        size = chunksize (victim);
        mchunkptr next = chunk_at_offset (victim, size);

        if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
            || __glibc_unlikely (size > av->system_mem))
          malloc_printerr ("malloc(): invalid size (unsorted)");
        if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
            || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
          malloc_printerr ("malloc(): invalid next size (unsorted)");
        if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
          malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
        if (__glibc_unlikely (bck->fd != victim)
            || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
          malloc_printerr ("malloc(): unsorted double linked list corrupted");
        if (__glibc_unlikely (prev_inuse (next)))
          malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

        /*
          If a small request, try to use last remainder if it is the
          only chunk in unsorted bin.  This helps promote locality for
          runs of consecutive small requests. This is the only
          exception to best-fit, and applies only when there is
          no exact fit for a small chunk.
        */

        if (in_smallbin_range (nb) &&
            bck == unsorted_chunks (av) &&
            victim == av->last_remainder &&
            (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
          {
            /* split and reattach remainder */
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
            av->last_remainder = remainder;
            remainder->bk = remainder->fd = unsorted_chunks (av);
            if (!in_smallbin_range (remainder_size))
              {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
              }

            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);
            set_foot (remainder, remainder_size);

            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }

        /* remove from unsorted list */
        unsorted_chunks (av)->bk = bck;
        bck->fd = unsorted_chunks (av);

        /* Take now instead of binning if exact fit */

        if (size == nb)
          {
            set_inuse_bit_at_offset (victim, size);
            if (av != &main_arena)
  set_non_main_arena (victim);
#if USE_TCACHE
      /* Fill cache first, return to user only if cache fills.
  We may return one of these chunks later.  */
      if (tcache_nb
    && tcache->counts[tc_idx] < mp_.tcache_count)
  {
    tcache_put (victim, tc_idx);
    return_cached = 1;
    continue;
  }
      else
  {
#endif
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
#if USE_TCACHE
  }
#endif
          }

        /* place chunk in bin */

        if (in_smallbin_range (size))
          {
            victim_index = smallbin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;
          }
        else
          {
            victim_index = largebin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;

            /* maintain large bins in sorted order */
            if (fwd != bck)
              {
                /* Or with inuse bit to speed comparisons */
                size |= PREV_INUSE;
                /* if smaller than smallest, bypass loop below */
                assert (chunk_main_arena (bck->bk));
                if ((unsigned long) (size)
        < (unsigned long) chunksize_nomask (bck->bk))
                  {
                    fwd = bck;
                    bck = bck->bk;

                    victim->fd_nextsize = fwd->fd;
                    victim->bk_nextsize = fwd->fd->bk_nextsize;
                    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                  }
                else
                  {
                    assert (chunk_main_arena (fwd));
                    while ((unsigned long) size < chunksize_nomask (fwd))
                      {
                        fwd = fwd->fd_nextsize;
      assert (chunk_main_arena (fwd));
                      }

                    if ((unsigned long) size
      == (unsigned long) chunksize_nomask (fwd))
                      /* Always insert in the second position.  */
                      fwd = fwd->fd;
                    else
                      {
                        victim->fd_nextsize = fwd;
                        victim->bk_nextsize = fwd->bk_nextsize;
                        if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                          malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                        fwd->bk_nextsize = victim;
                        victim->bk_nextsize->fd_nextsize = victim;
                      }
                    bck = fwd->bk;
                    if (bck->fd != fwd)
                      malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                  }
              }
            else
              victim->fd_nextsize = victim->bk_nextsize = victim;
          }

        mark_bin (av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;

#if USE_TCACHE
    /* If we've processed as many chunks as we're allowed while
   filling the cache, return one of the cached ones.  */
    ++tcache_unsorted_count;
    if (return_cached
  && mp_.tcache_unsorted_limit > 0
  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
  {
  return tcache_get (tc_idx);
  }
#endif

#define MAX_ITERS     10000
        if (++iters >= MAX_ITERS)
          break;
      }

#if USE_TCACHE
    /* If all the small chunks we found ended up cached, return one now.  */
    if (return_cached)
  {
  return tcache_get (tc_idx);
  }
#endif

    /*
      If a large request, scan through the chunks of current bin in
      sorted order to find smallest that fits.  Use the skip list for this.
    */

    if (!in_smallbin_range (nb))
      {
        bin = bin_at (av, idx);

        /* skip scan if empty or largest chunk is too small */
        if ((victim = first (bin)) != bin
      && (unsigned long) chunksize_nomask (victim)
        >= (unsigned long) (nb))
          {
            victim = victim->bk_nextsize;
            while (((unsigned long) (size = chunksize (victim)) <
                    (unsigned long) (nb)))
              victim = victim->bk_nextsize;

            /* Avoid removing the first entry for a size so that the skip
              list does not have to be rerouted.  */
            if (victim != last (bin)
    && chunksize_nomask (victim)
      == chunksize_nomask (victim->fd))
              victim = victim->fd;

            remainder_size = size - nb;
            unlink_chunk (av, victim);

            /* Exhaust */
            if (remainder_size < MINSIZE)
              {
                set_inuse_bit_at_offset (victim, size);
                if (av != &main_arena)
      set_non_main_arena (victim);
              }
            /* Split */
            else
              {
                remainder = chunk_at_offset (victim, nb);
                /* We cannot assume the unsorted list is empty and therefore
                  have to perform a complete insert here.  */
                bck = unsorted_chunks (av);
                fwd = bck->fd;
    if (__glibc_unlikely (fwd->bk != bck))
      malloc_printerr ("malloc(): corrupted unsorted chunks");
                remainder->bk = bck;
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;
                if (!in_smallbin_range (remainder_size))
                  {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                  }
                set_head (victim, nb | PREV_INUSE |
                          (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head (remainder, remainder_size | PREV_INUSE);
                set_foot (remainder, remainder_size);
              }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
      }

    /*
      Search for a chunk by scanning bins, starting with next largest
      bin. This search is strictly by best-fit; i.e., the smallest
      (with ties going to approximately the least recently used) chunk
      that fits is selected.

      The bitmap avoids needing to check that most blocks are nonempty.
      The particular case of skipping all bins during warm-up phases
      when no chunks have been returned yet is faster than it might look.
    */

    ++idx;
    bin = bin_at (av, idx);
    block = idx2block (idx);
    map = av->binmap[block];
    bit = idx2bit (idx);

    for (;; )
      {
        /* Skip rest of block if there are no more set bits in this block.  */
        if (bit > map || bit == 0)
          {
            do
              {
                if (++block >= BINMAPSIZE) /* out of bins */
                  goto use_top;
              }
            while ((map = av->binmap[block]) == 0);

            bin = bin_at (av, (block << BINMAPSHIFT));
            bit = 1;
          }

        /* Advance to bin with set bit. There must be one. */
        while ((bit & map) == 0)
          {
            bin = next_bin (bin);
            bit <<= 1;
            assert (bit != 0);
          }

        /* Inspect the bin. It is likely to be non-empty */
        victim = last (bin);

        /*  If a false alarm (empty bin), clear the bit. */
        if (victim == bin)
          {
            av->binmap[block] = map &= ~bit; /* Write through */
            bin = next_bin (bin);
            bit <<= 1;
          }

        else
          {
            size = chunksize (victim);

            /*  We know the first chunk in this bin is big enough to use. */
            assert ((unsigned long) (size) >= (unsigned long) (nb));

            remainder_size = size - nb;

            /* unlink */
            unlink_chunk (av, victim);

            /* Exhaust */
            if (remainder_size < MINSIZE)
              {
                set_inuse_bit_at_offset (victim, size);
                if (av != &main_arena)
      set_non_main_arena (victim);
              }

            /* Split */
            else
              {
                remainder = chunk_at_offset (victim, nb);

                /* We cannot assume the unsorted list is empty and therefore
                  have to perform a complete insert here.  */
                bck = unsorted_chunks (av);
                fwd = bck->fd;
    if (__glibc_unlikely (fwd->bk != bck))
      malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                remainder->bk = bck;
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;

                /* advertise as last remainder */
                if (in_smallbin_range (nb))
                  av->last_remainder = remainder;
                if (!in_smallbin_range (remainder_size))
                  {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                  }
                set_head (victim, nb | PREV_INUSE |
                          (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head (remainder, remainder_size | PREV_INUSE);
                set_foot (remainder, remainder_size);
              }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
      }

  use_top:
    /*
      If large enough, split off the chunk bordering the end of memory
      (held in av->top). Note that this is in accord with the best-fit
      search rule.  In effect, av->top is treated as larger (and thus
      less well fitting) than any other available chunk since it can
      be extended to be as large as necessary (up to system
      limitations).

      We require that av->top always exists (i.e., has size >=
      MINSIZE) after initialization, so if it would otherwise be
      exhausted by current request, it is replenished. (The main
      reason for ensuring it exists is that we may need MINSIZE space
      to put in fenceposts in sysmalloc.)
    */

    victim = av->top;
    size = chunksize (victim);

    if (__glibc_unlikely (size > av->system_mem))
      malloc_printerr ("malloc(): corrupted top size");

    if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
      {
        remainder_size = size - nb;
        remainder = chunk_at_offset (victim, nb);
        av->top = remainder;
        set_head (victim, nb | PREV_INUSE |
                  (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head (remainder, remainder_size | PREV_INUSE);

        check_malloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
      }

    /* When we are using atomic ops to free fast chunks we can get
      here for all block sizes.  */
    else if (atomic_load_relaxed (&av->have_fastchunks))
      {
        malloc_consolidate (av);
        /* restore original bin index */
        if (in_smallbin_range (nb))
          idx = smallbin_index (nb);
        else
          idx = largebin_index (nb);
      }

    /*
      Otherwise, relay to handle system-dependent cases
    */
    else
      {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
          alloc_perturb (p, bytes);
        return p;
      }
  }
}
```

#### Initial checks

So starting off, it will take the request size and convert it to the actual malloc chunk size. It will run some additional checks, but I don't think they are too important (effectively checking request size is not too massive). After that, it will check if the arena struct it got was null, and if it was it will allocate the chunk using `sysmalloc`:

```
  /*
  Convert request size to internal form by adding SIZE_SZ bytes
  overhead plus possibly more to obtain necessary alignment and/or
  to obtain a size of at least MINSIZE, the smallest allocatable
  size. Also, checked_request2size returns false for request sizes
  that are so large that they wrap around zero when padded and
  aligned.
   */

  nb = checked_request2size (bytes);
  if (nb == 0)
  {
    __set_errno (ENOMEM);
    return NULL;
  }

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
  mmap.  */
  if (__glibc_unlikely (av == NULL))
  {
    void *p = sysmalloc (nb, av);
    if (p != NULL)
  alloc_perturb (p, bytes);
    return p;
  }

 . . .

/* pad request bytes into a usable size -- internal version */
/* Note: This must be a macro that evaluates to a compile time constant
   if passed a literal constant.  */
#define request2size(req)                                       \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?           \
   MINSIZE :                                                    \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* Check if REQ overflows when padded and aligned and if the resulting
   value is less than PTRDIFF_T.  Returns the requested size or
   MINSIZE in case the value is less than MINSIZE, or 0 if any of the
   previous checks fail.  */
static inline size_t
checked_request2size (size_t req) __nonnull (1)
{
  if (__glibc_unlikely (req > PTRDIFF_MAX))
  return 0;

  /* When using tagged memory, we cannot share the end of the user
  block with the header for the next chunk, so ensure that we
  allocate blocks that are rounded up to the granule size.  Take
  care not to overflow from close to MAX_SIZE_T to a small
  number.  Ideally, this would be part of request2size(), but that
  must be a macro that produces a compile time constant if passed
  a constant literal.  */
  if (__glibc_unlikely (mtag_enabled))
  {
    /* Ensure this is not evaluated if !mtag_enabled, see gcc PR 99551.  */
    asm ("");

    req = (req + (__MTAG_GRANULE_SIZE - 1)) &
      ~(size_t)(__MTAG_GRANULE_SIZE - 1);
  }

  return request2size (req);
}
```

#### Fastbin Allocation

Next up, we have the fastbin allocation code. It will first check if the size of the chunk we need is less than or equal to the max fastbin size (`get_max_fast ()`). If it is, it continues trying to allocate a chunk from the fastbin. It will get the corresponding fastbin for the size, and get it's head. If the head chunk is null, it will stop trying to allocate from the fastbin.

Assuming the fastbin actually has a chunk, if it's single threaded it will simply set the new fastbin head to the next chunk of the chunk to be allocated. If it's multi-threaded, it will use `REMOVE_FB` to do this. Now after that happens, an interesting thing happens. All of the fastbin sizes have a corresponding tcache bin with the same size. it will attempt to move all of the fastbins it can (from the fastbin that just lost a chunk) over to the corresponding tcache. It will go until either the corresponding tcache bin fills up, or the fast bin we're pulling chunks from runs out of chunks:

```
  /*
  If the size qualifies as a fastbin, first check corresponding bin.
  This code is safe to execute even if av is not yet initialized, so we
  can try it without checking, which saves some time on this fast path.
   */

#define REMOVE_FB(fb, victim, pp)   \
  do            \
  {           \
    victim = pp;        \
    if (victim == NULL)     \
  break;          \
    pp = REVEAL_PTR (victim->fd);                                   \
    if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))     \
  malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
  }           \
  while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
   != victim);        \

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
    idx = fastbin_index (nb);
    mfastbinptr *fb = &fastbin (av, idx);
    mchunkptr pp;
    victim = *fb;

    if (victim != NULL)
  {
  if (__glibc_unlikely (misaligned_chunk (victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

  if (SINGLE_THREAD_P)
    *fb = REVEAL_PTR (victim->fd);
  else
    REMOVE_FB (fb, pp, victim);
  if (__glibc_likely (victim != NULL))
    {
      size_t victim_idx = fastbin_index (chunksize (victim));
      if (__builtin_expect (victim_idx != idx, 0))
  malloc_printerr ("malloc(): memory corruption (fast)");
      check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
  stash them in the tcache.  */
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx < mp_.tcache_bins)
  {
    mchunkptr tc_victim;

    /* While bin not empty and tcache not full, copy chunks.  */
    while (tcache->counts[tc_idx] < mp_.tcache_count
    && (tc_victim = *fb) != NULL)
      {
        if (__glibc_unlikely (misaligned_chunk (tc_victim)))
    malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
        if (SINGLE_THREAD_P)
    *fb = REVEAL_PTR (tc_victim->fd);
        else
    {
      REMOVE_FB (fb, pp, tc_victim);
      if (__glibc_unlikely (tc_victim == NULL))
        break;
    }
        tcache_put (tc_victim, tc_idx);
      }
  }
#endif
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }
  }
  }
```

#### First Smallbin Allocation

Here we have the first (I believe) spot where it will attempt to allocate from the small bin. it will check if the chunk size is within the bounds of the small bin. If it is, it will get the corresponding small bin, and check to see if it has a chunk in it (`((victim = last (bin)) != bin)`). If it does, it will remove that chunk from the bin, and then allocate that chunk. Now, similar to how when we allocate a chunk from a fast bin it will attempt to move as many chunks as it can over to the corresponding tcache bin, the same thing happens here. Also, we see that it will `memset(0)` the chunk to be allocated with `alloc_perturb`:

```
  /*
  If a small request, check regular bin.  Since these "smallbins"
  hold one size each, no searching within bins is necessary.
  (For a large request, we need to wait until unsorted chunks are
  processed to find best fit. But for small ones, fits are exact
  anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
  {
    idx = smallbin_index (nb);
    bin = bin_at (av, idx);

    if ((victim = last (bin)) != bin)
      {
        bck = victim->bk;
  if (__glibc_unlikely (bck->fd != victim))
    malloc_printerr ("malloc(): smallbin double linked list corrupted");
        set_inuse_bit_at_offset (victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        if (av != &main_arena)
    set_non_main_arena (victim);
        check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
  /* While we're here, if we see other chunks of the same size,
    stash them in the tcache.  */
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    {
      mchunkptr tc_victim;

      /* While bin not empty and tcache not full, copy chunks over.  */
      while (tcache->counts[tc_idx] < mp_.tcache_count
      && (tc_victim = last (bin)) != bin)
  {
    if (tc_victim != 0)
      {
        bck = tc_victim->bk;
        set_inuse_bit_at_offset (tc_victim, nb);
        if (av != &main_arena)
    set_non_main_arena (tc_victim);
        bin->bk = bck;
        bck->fd = bin;

        tcache_put (tc_victim, tc_idx);
            }
  }
    }
#endif
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
      }
  }
```

#### Fastbin Consolidation

Now, if the chunk to be allocated is larger than what could go into a small bin, and the main arena does have fastbins, it will once again try to consolidate the fastbins with `malloc_consolidate`:

```
  If this is a large request, consolidate fastbins before continuing.
  While it might look excessive to kill all fastbins before
  even seeing if there is space available, this avoids
  fragmentation problems normally associated with fastbins.
  Also, in practice, programs tend to have runs of either small or
  large requests, but less often mixtures, so consolidation is not
  invoked all that often in most programs. And the programs that
  it is called frequently in otherwise tend to fragment.
   */

  else
  {
    idx = largebin_index (nb);
    if (atomic_load_relaxed (&av->have_fastchunks))
      malloc_consolidate (av);
  }
```

#### "Malloc Allocation" Outer Loop

So, first off here, we see that if the tcache is enabled, it will try to get the corresponding tcache index for the request size, and the tcache index if there is a valid tcache bin for the size. This is because later on, we will see there is functionality to actually insert chunks into the tcache, from other spots.

After that, we see there is a for loop with no exit condition in the `"for statement"`. The exit conditions are present within the loop itself. The contents of this loop makes up the rest of the `_int_malloc` functionality:

```
  /*
  Process recently freed or remaindered chunks, taking one only if
  it is exact fit, or, if this a small request, the chunk is remainder from
  the most recent non-exact fit.  Place other traversed chunks in
  bins.  Note that this step is the only place in any routine where
  chunks are placed in bins.

  The outer loop here is needed because we might not realize until
  near the end of malloc that we should have consolidated, so must
  do so and retry. This happens at most once, and only when we would
  otherwise need to expand memory to service a "small" request.
   */

#if USE_TCACHE
  INTERNAL_SIZE_T tcache_nb = 0;
  size_t tc_idx = csize2tidx (nb);
  if (tcache && tc_idx < mp_.tcache_bins)
  tcache_nb = nb;
  int return_cached = 0;

  tcache_unsorted_count = 0;
#endif

  for (;; )
  {

 . . .

  }
}
```

#### Unsorted Bin Loop

So, this is the first part of the "Malloc Allocation" Outer Loop, which in itself is a while loop. Effectively, this loop will iterate through all of the chunks in the unsorted bin, removing and processing them one by one (assuming in the middle of a loop iteration it doesn't find a chunk it can allocate, in which case the loop will end). Starting off, we see it will take a chunk (starting with the `bk` end of the "unsorted bin main chunk"). It will get its chunksize, and also a ptr to its next adjacent chunk.

Proceeding that, it will run a series of checks:
    *    Is the size of the unsorted bin chunk less than `CHUNK_HDR_SZ`?
    *    Is the size of the next adjacent chunk to the unsorted bin chunk less than `CHUNK_HDR_SZ`
    *    Is the previous size of the next adjacent chunk equal to the size of the current unsorted bin chunk?
    *    Is the fwd ptr (doubly linked list) of the `bk` ptr of the current unsorted bin chunk equal to the current unsorted bin chunk? (`victim->bk->fd == victim`)
    *    Is the previous in use bit of the next adjacent chunk in memory to the current unsorted bin chunk set?

Also, that tcache stuff we see after the loop. Similar to what we've seen before, in this loop we'll see spots where the tcache can have chunks put into it. That is effectively checking did it insert a chunk into the tcache of a size we need, and if so, just allocate it:

```
    int iters = 0;
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      {
        bck = victim->bk;
        size = chunksize (victim);
        mchunkptr next = chunk_at_offset (victim, size);

        if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
            || __glibc_unlikely (size > av->system_mem))
          malloc_printerr ("malloc(): invalid size (unsorted)");
        if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
            || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
          malloc_printerr ("malloc(): invalid next size (unsorted)");
        if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
          malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
        if (__glibc_unlikely (bck->fd != victim)
            || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
          malloc_printerr ("malloc(): unsorted double linked list corrupted");
        if (__glibc_unlikely (prev_inuse (next)))
          malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");

 . . .

      }

#if USE_TCACHE
    /* If all the small chunks we found ended up cached, return one now.  */
    if (return_cached)
  {
  return tcache_get (tc_idx);
  }
#endif
```

Here is the definition of `unsorted_chunks` again:

```
/*
   Unsorted chunks

  All remainders from chunk splits, as well as all returned chunks,
  are first placed in the "unsorted" bin. They are then placed
  in regular bins after malloc gives them ONE chance to be used before
  binning. So, basically, the unsorted_chunks list acts as a queue,
  with chunks being placed on it in free (and malloc_consolidate),
  and taken off (to be either used or placed in bins) in malloc.

  The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
  does not have to be taken into account in size comparisons.
 */

/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M)        (bin_at (M, 1))
```

#### Remainder Allocation (Unsorted Bin Loop)

So part of the functionality we will see later on, is malloc can actually take a chunk from the small / large bin, and split it into two smaller chunks. One of those chunks get's allocated. The other is known as the remainder (`av->last_remainder`) and will be saved to potentially be reallocated later.

In this instance, if the size to be allocated is in the small bin range, there is only one chunk in the unsorted bin, and that one chunk is the remainder, and the remainder has enough space for the new allocation, it will allocate space from the remainder. It will split off a chunk from the remainder, allocate that, and re-insert the new smaller remainder:

```
        /*
          If a small request, try to use last remainder if it is the
          only chunk in unsorted bin.  This helps promote locality for
          runs of consecutive small requests. This is the only
          exception to best-fit, and applies only when there is
          no exact fit for a small chunk.
        */

        if (in_smallbin_range (nb) &&
            bck == unsorted_chunks (av) &&
            victim == av->last_remainder &&
            (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
          {
            /* split and reattach remainder */
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
            av->last_remainder = remainder;
            remainder->bk = remainder->fd = unsorted_chunks (av);
            if (!in_smallbin_range (remainder_size))
              {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
              }

            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);
            set_foot (remainder, remainder_size);

            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
```

#### Unsorted Bin Removal (Unsorted Bin Loop)

In the next part, it will actually remove the current unsorted bin chunk from the unsorted bin. After that, it will check if the size of this chunk is an exact fit for the size we need. Assuming it finds the chunk, and the tcache is enabled, it will enter it into the corresponding tcache bin to be allocated later (remember `return_cached`). If the tcache isn't enabled, it will just allocate the chunk:

```
        /* remove from unsorted list */
        unsorted_chunks (av)->bk = bck;
        bck->fd = unsorted_chunks (av);

        /* Take now instead of binning if exact fit */

        if (size == nb)
          {
            set_inuse_bit_at_offset (victim, size);
            if (av != &main_arena)
  set_non_main_arena (victim);
#if USE_TCACHE
      /* Fill cache first, return to user only if cache fills.
  We may return one of these chunks later.  */
      if (tcache_nb
    && tcache->counts[tc_idx] < mp_.tcache_count)
  {
    tcache_put (victim, tc_idx);
    return_cached = 1;
    continue;
  }
      else
  {
#endif
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
#if USE_TCACHE
  }
#endif
          }
```

#### Small Bin Insertion (Unsorted Bin Loop)

Next up, malloc will attempt to insert the chunk into either the small bin, or large bin. Here it will check if the chunk is small enough to be in the small bin range.

The actual insertion happens later. Here, it will just get the back, and forward chunks for the new chunk to be inserted (remember insertions in the small bin happen at the head):

```
        /* place chunk in bin */

        if (in_smallbin_range (size))
          {
            victim_index = smallbin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;
          }

 . . .

#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
```

#### Large Bin Insertion (Unsorted Bin Loop)

Next up, if the chunk is too large to be in a small bin, then it gets inserted into a large bin. Now, the difference here with the large bin, is there is a skip list on top of the large bin, which may need to be updated too. The skip list chunk insertion works like this.

So, it will first check if the large bin is empty. If it is, it will set the skip list's `bk_nextsize/fd_nextsize` to itself (`victim->fd_nextsize = victim->bk_nextsize = victim;`). Next up it will check if it's the smallest chunk in the large bin (`if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))`). If it is, it will simply stick the chunk in the back, and update the skip list to reflect the new smallest chunk.

Now assuming those conditions are not met, it will need to iterate through the skip list. It will start with the largest chunk, and iterate through until it finds a chunk in the skip list for a chunk with a size that is not larger (`while ((unsigned long) size < chunksize_nomask (fwd))`). Once it finds a chunk with a size that is not larger, one of two things happen.

First off, if it finds a chunk with the same size, this means the skip list will not have any new unique sizes. The skip list only really contains the unique sizes, so it will not need to be updated. So, it will just insert it after the chunk it found with the same size (`fwd = fwd->fd;`). If not, this means the skip list will have a new unique size, and it will need to be updated. So, it will insert it into the skip list.

```
        else
          {
            victim_index = largebin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;

            /* maintain large bins in sorted order */
            if (fwd != bck)
              {
                /* Or with inuse bit to speed comparisons */
                size |= PREV_INUSE;
                /* if smaller than smallest, bypass loop below */
                assert (chunk_main_arena (bck->bk));
                if ((unsigned long) (size)
        < (unsigned long) chunksize_nomask (bck->bk))
                  {
                    fwd = bck;
                    bck = bck->bk;

                    victim->fd_nextsize = fwd->fd;
                    victim->bk_nextsize = fwd->fd->bk_nextsize;
                    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                  }
                else
                  {
                    assert (chunk_main_arena (fwd));
                    while ((unsigned long) size < chunksize_nomask (fwd))
                      {
                        fwd = fwd->fd_nextsize;
      assert (chunk_main_arena (fwd));
                      }

                    if ((unsigned long) size
      == (unsigned long) chunksize_nomask (fwd))
                      /* Always insert in the second position.  */
                      fwd = fwd->fd;
                    else
                      {
                        victim->fd_nextsize = fwd;
                        victim->bk_nextsize = fwd->bk_nextsize;
                        if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                          malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                        fwd->bk_nextsize = victim;
                        victim->bk_nextsize->fd_nextsize = victim;
                      }
                    bck = fwd->bk;
                    if (bck->fd != fwd)
                      malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
                  }
              }
            else
              victim->fd_nextsize = victim->bk_nextsize = victim;
          }

 . . .

// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                             \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)

#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                  \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                  \
   : largebin_index_32 (sz))
```

#### Small Bin / Large Bin Insertion, Tcache Allocation, end of Unsorted Bin Loop (Unsorted Bin Loop)

Now, here is where the actual insertion into the doubly linked list in the small / large bin occurs (since the insertion process into the doubly linked list (not the skip list) is the same for both, it occurs in the same spot). In addition to that, it will mark a bit in one of the maps in the `binmap` array, to signify that that bin has chunks into it. We'll see it's used later.

Lastly here, it will check if it actually inserted a chunk into the tcache that will serve as a reallocation for the requested size, it will allocate it from the tcache.

This is the last part of the "Unsorted Bin Loop":

```
        mark_bin (av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;

#if USE_TCACHE
    /* If we've processed as many chunks as we're allowed while
   filling the cache, return one of the cached ones.  */
    ++tcache_unsorted_count;
    if (return_cached
  && mp_.tcache_unsorted_limit > 0
  && tcache_unsorted_count > mp_.tcache_unsorted_limit)
  {
  return tcache_get (tc_idx);
  }
#endif

#define MAX_ITERS     10000
        if (++iters >= MAX_ITERS)
          break;
      }

 . . .

/*
   Binmap

  To help compensate for the large number of bins, a one-level index
  structure is used for bin-by-bin searching.  `binmap' is a
  bitvector recording whether bins are definitely empty so they can
  be skipped over during during traversals.  The bits are NOT always
  cleared as soon as bins are empty, but instead only
  when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT   5
#define BITSPERMAP    (1U << BINMAPSHIFT)
#define BINMAPSIZE    (NBINS / BITSPERMAP)

#define idx2block(i)  ((i) >> BINMAPSHIFT)
#define idx2bit(i)    ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)  ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))
```

#### Large Bin Allocation

So this is the first piece of code that runs after the "Unsorted Bin Loop". Here it will attempt to allocate a chunk from the large bin. It will first check if the needed chunk size is large enough to be in the large bin. Then it will check if the corresponding large bin for the chunk size is either too empty, or the largest chunk in that large bin is too small (since unlike every other binning mechanism, an individual large bin can store chunks of a variable size).

Assuming those conditions are met, it will go forward with allocating from the large bin. It will iterate through the large bin's skip list, looking for a chunk that is at least the same size as the needed chunk size, if not larger (`while (((unsigned long) (size = chunksize (victim)) < (unsigned long) (nb)))`). Once it finds a unique chunk size, it will move forward with allocating a chunk with that size. If there are multiple chunks with that size, it will grab the next chunk after the chunk it found in the skip list (`if (victim != last (bin) && chunksize_nomask (victim) == chunksize_nomask (victim->fd))`). It does this so it doesn't have to update the skip list with the removal of this chunk. Then it will unlink the chunk, and calculate how much more space the chunk being allocated has in comparison to the needed space. If it is large enough (`/* Split */\nelse`), it will split off a piece of the chunk that is large enough, and use that for the allocation. The remainder will be made into a new freed chunk, and inserted into the unsorted bin. This does not deal with `av->last_remainder`:

```
    /*
      If a large request, scan through the chunks of current bin in
      sorted order to find smallest that fits.  Use the skip list for this.
    */

    if (!in_smallbin_range (nb))
      {
        bin = bin_at (av, idx);

        /* skip scan if empty or largest chunk is too small */
        if ((victim = first (bin)) != bin
      && (unsigned long) chunksize_nomask (victim)
        >= (unsigned long) (nb))
          {
            victim = victim->bk_nextsize;
            while (((unsigned long) (size = chunksize (victim)) <
                    (unsigned long) (nb)))
              victim = victim->bk_nextsize;

            /* Avoid removing the first entry for a size so that the skip
              list does not have to be rerouted.  */
            if (victim != last (bin)
    && chunksize_nomask (victim)
      == chunksize_nomask (victim->fd))
              victim = victim->fd;

            remainder_size = size - nb;
            unlink_chunk (av, victim);

            /* Exhaust */
            if (remainder_size < MINSIZE)
              {
                set_inuse_bit_at_offset (victim, size);
                if (av != &main_arena)
      set_non_main_arena (victim);
              }
            /* Split */
            else
              {
                remainder = chunk_at_offset (victim, nb);
                /* We cannot assume the unsorted list is empty and therefore
                  have to perform a complete insert here.  */
                bck = unsorted_chunks (av);
                fwd = bck->fd;
    if (__glibc_unlikely (fwd->bk != bck))
      malloc_printerr ("malloc(): corrupted unsorted chunks");
                remainder->bk = bck;
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;
                if (!in_smallbin_range (remainder_size))
                  {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                  }
                set_head (victim, nb | PREV_INUSE |
                          (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head (remainder, remainder_size | PREV_INUSE);
                set_foot (remainder, remainder_size);
              }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
      }

 . . .

/* Reminders about list directionality within bins */
#define first(b)  ((b)->fd)
#define last(b)   ((b)->bk)
```

#### All Bin Scanning

So, before I go through this, I will need to explain the binmaps (remember `av->binmap`). Looking in the struct for the main arena, we see that the binmap is an array of unsigned ints:

```
  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];
```

Looking at some of the macros / constant definitions, we see that `BINMAPSIZE` is `4` (`128 / 32 = 4`).

```
/*
   Binmap

  To help compensate for the large number of bins, a one-level index
  structure is used for bin-by-bin searching.  `binmap' is a
  bitvector recording whether bins are definitely empty so they can
  be skipped over during during traversals.  The bits are NOT always
  cleared as soon as bins are empty, but instead only
  when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT   5
#define BITSPERMAP    (1U << BINMAPSHIFT)
#define BINMAPSIZE    (NBINS / BITSPERMAP)

#define idx2block(i)  ((i) >> BINMAPSHIFT)
#define idx2bit(i)    ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)  ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))

```

So the binmap is 4 separate unsigned ints. Now, the purpose of these ints, is to essentially record if a particular bin is empty or not (although it's not always true, which we will see later). Each bin maps to an individual bit, in a particular map. Each bin only is present in one map (a map being one of the `4` unsigned ints in `binmap`). If the corresponding bit is set (equal to `1`), the bin should have chunks in it. If not, it should be empty.

Now, it uses the index to the bin to determine which map, and which bit within the map it belongs to. For the actual int representation of the index, the higher `4` bits are used to determine which individual `map` in `binmap` the bin maps to. This index is known as a block.

The lower `4` bits are used to determine which bit within the `map` the bin maps to. This is known as the `bit`.

So, now that we covered that, what is the purpose of this next code we are about to look through. Effectively, it will search through all of the main arena bins (small, and large) larger than the smallest bin that could hold sizes we need (in ascending order). Once it finds a chunk in one of the bins that is larger than what we need, it will try to split off a chunk from there, and use that for the allocation.

Now, one thing, we are seeing the return of the `idx` variable. This was set way back before the "unsorted bin loop". The `idx` variable should be set, to the smallest small / large bin, that could hold chunks large enough to hold chunks we need. It will move onto the next index after that (`++idx;`) and begin iterating through the bins from there, going up. We see, it starts off with getting the corresponding bin, block, map, and bit for that next bin.

We see it starts off with a check that the `bit` is larger than the `map`. The `bit` value is the actual integer representation of the bit that is supposed to be set within the `map`. So if it's the third bit set, `bit` will be `0b100`, or `4`. If it is greater than `map`, it means that no bins that we need in that block are set, so all of the bins we could be pulling from in that map are empty.

If that is the case, we see in the `while ((map = av->binmap[block]) == 0);` loop, it will search for the next block that is non-empty. Since each greater bin will only hold bins with larger sizes, any chunk in any bin from any larger map should work. Once it finds this, it will initialize itself to the smallest bin in that map (`bin = bin_at (av, (block << BINMAPSHIFT));`).

So that `if` loop is supposed to determine the smallest non-empty `map` that we can use. Up next, there is a `while` loop which will go through and find the smallest non-empty bin in that map. If we had to go through the process of moving to a larger `map`, it will start at the smallest bin in that loop. If it didn't, it will start with what `bit` was initially set to with `bit = idx2bit (idx);` prior to the `for (;; )` loop.

So after that `while ((bit & map) == 0)` loop runs, it should have actually found a bin within the map, that is the smallest bin with chunks large enough for what we need. It will grab the smallest chunk from that bin, and check that the bin is not empty (`if (victim == bin)`). Now the reason it needs to do this double check, is the binmap is only cleared when this malloc traversal happens, it finds a bin that looks like it has chunks in it, and it sees it's empty (so in other words, right here).

So assuming all of those checks pass, it will actually attempt to allocate a piece of that chunk. It will unlink that chunk from whatever bin it came from. Remember, we are searching for a larger chunk than what we need (really the smallest larger chunk from what we need). As such, if the chunk is sufficiently larger than what we need (determined via `if (remainder_size < MINSIZE)`), it will only allocate a piece of that chunk. The remainder will be formed into it's own new chunk, and inserted into the unsorted bin. Then it will take the chunk to be allocated, clear it out with `alloc_perturb`, and return it. If this doesn't work for allocation, it moves onto allocating from the top chunk.

```
    /*
      Search for a chunk by scanning bins, starting with next largest
      bin. This search is strictly by best-fit; i.e., the smallest
      (with ties going to approximately the least recently used) chunk
      that fits is selected.

      The bitmap avoids needing to check that most blocks are nonempty.
      The particular case of skipping all bins during warm-up phases
      when no chunks have been returned yet is faster than it might look.
    */

    ++idx;
    bin = bin_at (av, idx);
    block = idx2block (idx);
    map = av->binmap[block];
    bit = idx2bit (idx);

    for (;; )
      {
        /* Skip rest of block if there are no more set bits in this block.  */
        if (bit > map || bit == 0)
          {
            do
              {
                if (++block >= BINMAPSIZE) /* out of bins */
                  goto use_top;
              }
            while ((map = av->binmap[block]) == 0);

            bin = bin_at (av, (block << BINMAPSHIFT));
            bit = 1;
          }

        /* Advance to bin with set bit. There must be one. */
        while ((bit & map) == 0)
          {
            bin = next_bin (bin);
            bit <<= 1;
            assert (bit != 0);
          }

        /* Inspect the bin. It is likely to be non-empty */
        victim = last (bin);

        /*  If a false alarm (empty bin), clear the bit. */
        if (victim == bin)
          {
            av->binmap[block] = map &= ~bit; /* Write through */
            bin = next_bin (bin);
            bit <<= 1;
          }

        else
          {
            size = chunksize (victim);

            /*  We know the first chunk in this bin is big enough to use. */
            assert ((unsigned long) (size) >= (unsigned long) (nb));

            remainder_size = size - nb;

            /* unlink */
            unlink_chunk (av, victim);

            /* Exhaust */
            if (remainder_size < MINSIZE)
              {
                set_inuse_bit_at_offset (victim, size);
                if (av != &main_arena)
      set_non_main_arena (victim);
              }

            /* Split */
            else
              {
                remainder = chunk_at_offset (victim, nb);

                /* We cannot assume the unsorted list is empty and therefore
                  have to perform a complete insert here.  */
                bck = unsorted_chunks (av);
                fwd = bck->fd;
    if (__glibc_unlikely (fwd->bk != bck))
      malloc_printerr ("malloc(): corrupted unsorted chunks 2");
                remainder->bk = bck;
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;

                /* advertise as last remainder */
                if (in_smallbin_range (nb))
                  av->last_remainder = remainder;
                if (!in_smallbin_range (remainder_size))
                  {
                    remainder->fd_nextsize = NULL;
                    remainder->bk_nextsize = NULL;
                  }
                set_head (victim, nb | PREV_INUSE |
                          (av != &main_arena ? NON_MAIN_ARENA : 0));
                set_head (remainder, remainder_size | PREV_INUSE);
                set_foot (remainder, remainder_size);
              }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
      }

 . . .

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))           \
          - offsetof (struct malloc_chunk, fd))

/* analog of ++bin */
#define next_bin(b)  ((mbinptr) ((char *) (b) + (sizeof (mchunkptr) << 1)))

/* Reminders about list directionality within bins */
#define first(b)  ((b)->fd)
#define last(b)   ((b)->bk)

 . . .

/*
   Binmap

  To help compensate for the large number of bins, a one-level index
  structure is used for bin-by-bin searching.  `binmap' is a
  bitvector recording whether bins are definitely empty so they can
  be skipped over during during traversals.  The bits are NOT always
  cleared as soon as bins are empty, but instead only
  when they are noticed to be empty during traversal in malloc.
 */

/* Conservatively use 32 bits per map word, even if on 64bit system */
#define BINMAPSHIFT   5
#define BITSPERMAP    (1U << BINMAPSHIFT)
#define BINMAPSIZE    (NBINS / BITSPERMAP)

#define idx2block(i)  ((i) >> BINMAPSHIFT)
#define idx2bit(i)    ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))

#define mark_bin(m, i)  ((m)->binmap[idx2block (i)] |= idx2bit (i))
#define unmark_bin(m, i)  ((m)->binmap[idx2block (i)] &= ~(idx2bit (i)))
#define get_binmap(m, i)  ((m)->binmap[idx2block (i)] & idx2bit (i))
```

#### Top Chunk Allocation

So here, is effectively the last resort for `malloc` to allocate memory. If it reaches this point, it means that it couldn't reallocate memory from one of the bins. So, it needs to actually allocate from the top chunk. The top chunk is effectively the massive chunk at the end of the actual malloc heap, which holds unallocated memory (although as we've seen, freed adjacent chunks can be reconsolidated into the top chunk). So if the top chunk actually has enough space (which is the common case), it will effectively break off a chunk of memory from the top chunk, allocate that, and reform the top chunk below it.

If the top chunk doesn't have enough memory, however the main arena does have fastbins, it will attempt to consolidate the heap with `malloc_consolidate`. It will also reset the `idx` variable to the appropriate bin index for the requested size, and then jump back up to the top of the `for (;; )` loop right above the "unsorted bin outer loop".

However, if there are no fastbins, then that likely means that both the top chunk, and attempting memory defragmentation (when you're freed memory is too broken up to allocate as one larger chunk). So, the system needs more memory to allocate, which it will get via `sysmalloc`.

```
  use_top:
    /*
      If large enough, split off the chunk bordering the end of memory
      (held in av->top). Note that this is in accord with the best-fit
      search rule.  In effect, av->top is treated as larger (and thus
      less well fitting) than any other available chunk since it can
      be extended to be as large as necessary (up to system
      limitations).

      We require that av->top always exists (i.e., has size >=
      MINSIZE) after initialization, so if it would otherwise be
      exhausted by current request, it is replenished. (The main
      reason for ensuring it exists is that we may need MINSIZE space
      to put in fenceposts in sysmalloc.)
    */

    victim = av->top;
    size = chunksize (victim);

    if (__glibc_unlikely (size > av->system_mem))
      malloc_printerr ("malloc(): corrupted top size");

    if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
      {
        remainder_size = size - nb;
        remainder = chunk_at_offset (victim, nb);
        av->top = remainder;
        set_head (victim, nb | PREV_INUSE |
                  (av != &main_arena ? NON_MAIN_ARENA : 0));
        set_head (remainder, remainder_size | PREV_INUSE);

        check_malloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
      }

    /* When we are using atomic ops to free fast chunks we can get
      here for all block sizes.  */
    else if (atomic_load_relaxed (&av->have_fastchunks))
      {
        malloc_consolidate (av);
        /* restore original bin index */
        if (in_smallbin_range (nb))
          idx = smallbin_index (nb);
        else
          idx = largebin_index (nb);
      }

    /*
      Otherwise, relay to handle system-dependent cases
    */
    else
      {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
          alloc_perturb (p, bytes);
        return p;
      }
  }
}

```


