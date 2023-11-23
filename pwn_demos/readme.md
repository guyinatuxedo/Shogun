# Pwn Demos

So this shows some of the various primitives we can use as a result of the different heap functionalities. Here is the recommended order.

| Heap Pwn Topic | Category | Brief Description |
| --- | --- | --- |
| [Fwd Consolidation](malloc/fwd_consolidation/readme.md) | Malloc | Shows an example of using forward consolidation to get overlapping memory |
| [Bk Consolidation](malloc/bk_consolidation/readme.md) | Malloc | Shows an example of using back consolidation to reallocate a chunk that wasn't freed |
| [Overlapping Consolidation](malloc/overlapping_consolidation/readme.md) | Malloc | Shows an example of using consolidation to reallocate a chunk that wasn't freed |
| [Top Consolidation](malloc/top_consolidation/readme.md) | Malloc | Shows an example of using top chunk consolidation to reallocate a chunk that wasn't freed |
| [Tcache Linked List Attack](tcache/tcache_linked_list/readme.md) | Tcache | Shows a tcache linked list pwn primitive |
| [Tcache Double Free Key Fail](tcache/tcache_double_free_fail/readme.md) | Tcache | Shows a tcache double free fail due to the tcache key check |
| [Tcache Double Pass](tcache/tcache_double_pass/readme.md) | Tcache | Shows a successful tcache double free |
| [Tcache Fastbin Pass](tcache/tcache_fastbin_double/readme.md) | Tcache | Shows a successful tcache double free between tcache/fastbin |
| [Tcache Fake Chunk](tcache/tcache_fake_chunk/readme.md) | Tcache | Shows inserting a fake chunk with free into the tcache |
| [Tcache Struct](tcache/tcache_struct/readme.md) | Tcache | Shows some things we can do via editing the tcache struct |
| [Fastbin Linked List](fastbin/fastbin_linked/readme.md) | Fastbin | Shows a fastbin linked list primitive |
| [Fastbin Double Free](fastbin/fastbin_double/readme.md) | Fastbin | Shows a fastbin double free |
| [Unsorted Bin Exact Fit](unsorted_bin/exact_fit/readme.md) | Unsorted Bin | Allocate overlapping chunks via Exact Fit Mechanism |
| [Unsorted Bin Linked list](unsorted_bin/unsorted_linked/readme.md) | Unsorted Bin | Allocate chunk into stack leveraging Unsorted Bin Linked List |
| [Last Remainder](unsorted_bin/last_remainder/readme.md) | Unsorted Bin | Reallocate allocated chunks without freeing, via leveraging the last_remainder |
| [Small Bin Linked list](small_bin/linked_list/readme.md) | Small Bin | Allocate chunk into the PIE memory region leveraging Small Bin Linked List |
| [Large Bin Linked list](large_bin/linked_list/readme.md) | Large Bin | Allocate chunk into stack leveraging Large Bin Linked List |
| [Large Bin Skip list](large_bin/skiplist/readme.md) | Large Bin | Allocate chunk into stack leveraging Large Bin Skip List |
