from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(log_level='debug')

p = process
