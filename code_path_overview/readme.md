# Code Path Overview

So this part is legit just going through the code path for both malloc and free. In addition to that, I made a brief diagram showing what I think are the major parts of both code paths, for what we care about. By doing this, we gain a much deeper understanding of the glibc heap, and know where we need to look for things like how certain checks work. This is the best order I think, for going through these:

- [free_diagram](free_diagram.md)
- [free](free.md)
- [malloc_diagram](malloc_diagram.md)
- [malloc](malloc.md)
