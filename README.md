# Shogun

So this is a collection of writeups, for ctf glibc heap challenges. At the time of writing this, the latest glibc version is `2.38` which this is based on. A new one comes out roughly every six months.

This is split into `6` separate parts:

| Part | Focus | Part Number |
| ---- | ---- | ---- |
| [compiling](compiling/compiling.md) | Super short, shows how to compile your own libc | 0 |
| [bin_overview](bin_overviews/readme.md) | Brief overview of the heap, and various bins | 1 |
| [heap_demos](heap_demos/readme.md) | Shows some heap functionalities in a running binary | 2 |
| [code_path_overview](code_path_overview/readme.md) | Review the code of malloc | 3 |
| [pwn_demos](pwn_demos/readme.md) | Shows some useful heap pwn primitives | 4 |
| [challs](challs/readme.md) | Shows various heap bugs, and how we can leverage them and heap pwn primitives to get code execution | 5 |

The way this is laid out, is to first impart a practical understanding of how the glibc heap works. First gradual, then a full understanding. Then we introduce how we can leverage it for useful heap primitives. Then, we wrap it all together, and show how we can leverage heap bugs, an understanding of the heap, and those heap primitives together to get code execution.
