from pwn import *

p = process('./prob')
e = ELF("./prob")