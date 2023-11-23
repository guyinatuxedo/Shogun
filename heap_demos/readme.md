## Heap Demos

So the purpose of this section is to show various heap functionalities I think are relevant. This will be shown via stepping through code in a debugger, and actually seeing the memory layout of the heap when certain functionalities occur.

| Functionality Name | Category | Brief Description |
| --- | --- | --- |
| [Heap Debugging](malloc/heap_debugging/readme.md) | Malloc | Basic intro into heap debugging |
| [Chunk Header](malloc/chunk_header/readme.md) | Malloc | Shows the contents of a malloc chunk header |
| [Top Chunk](malloc/top_chunk/readme.md) | Malloc | Shows Allocation from and Consolidation to the Top Chunk |
| [Consolidation](malloc/consolidation/readme.md) | Malloc | Shows Backwards and Forwards Heap Chunk Consolidation |
| [Sysmalloc Allocation](malloc/sysmalloc_allocation/readme.md) | Malloc | Shows allocation from Sysmalloc |
| [Systrim](malloc/systrim/readme.md) | Malloc | Shows memory returning back to the system with systrim |
| [Tcache Basic](tcache/tcache_basic/readme.md) | Tcache | Shows basic tcache functionality, with insertion/removal of chunks |
| [Fastbin Basic](fastbin/fastbin_basic/readme.md) | Fastbin | Shows basic fastbin functionality, with insertion/removal of chunks |
| [Fastbin Consolidation](fastbin/fastbin_consolidation/readme.md) | Fastbin | Shows basic fastbin consolidation |
| [Unsorted Bin Basic](unsorted_bin/unsorted_bin_basic/readme.md) | Unsorted Bin | Shows basic unsorted bin functionality |
| [Small Bin Basic](small_bin/small_bin_basic/readme.md) | Small Bin | Shows Small Bin Insertion / Removal |
| [Large Bin Basic](large_bin/large_bin_basic/readme.md) | Large Bin | Shows Large Bin Insertion / Removal |
| [All Bin Searching/Last Remainder](large_bin/all_bin_searching/readme.md) | Large Bin | Shows allocation from the last remainder chunk |
