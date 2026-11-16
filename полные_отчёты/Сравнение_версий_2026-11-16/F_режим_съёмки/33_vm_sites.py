"""F: Unicorn — какой ИМЕННО сайт отправляет 0x358 и при каких условиях.

Перехватываем bl на 0x2c116ac и записываем адрес сайта. Прогоняем матрицу:
mode (S+0), sub (S+0xb4), p (свойство 0x979), busy (0x12e82f8(0x29)),
aux (0x2a02384). Результат: site -> условие.
"""
import sys, struct, json
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

S = 0x244eb20
STACK = 0x70000000
SENT = 0xdead0000
b = load('X-H2', 'new', 1)


def run(entry, mode, sub=0, p=0, flag10=1, busy=0, aux=0x55, g1a4=0, geef6=0,
        g265c=0, g25cc=0, g3428=0, g26ac=0, g1c28=1, g3f0=1, g5dc=0, g342c=0,
        maxins=20000):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(b.base & ~0xfff, len(b.data) + 0x2000)
    uc.mem_write(b.base, b.data)
    uc.mem_map(0x244e000, 0x4000)
    uc.mem_map(0x26a3000, 0x20000)
    uc.mem_map(STACK, 0x20000)
    uc.mem_write(S + 0, struct.pack('<I', mode))
    uc.mem_write(S + 8, struct.pack('<Q', 0))
    uc.mem_write(S + 0x10, struct.pack('<I', flag10))
    uc.mem_write(S + 0xb0, struct.pack('<I', 0))
    uc.mem_write(S + 0xb4, struct.pack('<I', sub))
    uc.mem_write(0x244f1a4, struct.pack('<H', g1a4))
    uc.mem_write(0x244eef6, struct.pack('<H', geef6))
    ctx = 0x26bb0a8
    for off, val in ((0x265c, g265c), (0x25cc, g25cc), (0x3428, g3428),
                     (0x26ac, g26ac), (0x1c28, g1c28), (0x3f0, g3f0),
                     (0x5dc, g5dc), (0x342c, g342c)):
        uc.mem_write(ctx + off, struct.pack('<I', val))
    sends = []
    st = {'n': 0}

    def hook(uc, addr, size, user):
        st['n'] += 1
        if addr == SENT or st['n'] > maxins:
            uc.emu_stop()
            return
        w = struct.unpack('<I', uc.mem_read(addr, 4))[0]
        if (w & 0xfc000000) == 0x94000000:
            imm = w & 0x3ffffff
            if imm & (1 << 25):
                imm -= 1 << 26
            tgt = addr + imm * 4
            code = uc.reg_read(UC_ARM64_REG_X0) & 0xffffffff
            if tgt in (0x2c116ac, 0x2c35238):
                sends.append((addr, code))
            if tgt in (0x11335ec, 0x1135930):
                rv = p if 0 <= p <= 3 else 0
            elif tgt == 0x12e82f8:
                rv = busy
            elif tgt == 0x2a02384:
                rv = aux
            else:
                rv = 0
            uc.reg_write(UC_ARM64_REG_X0, rv)
            uc.reg_write(UC_ARM64_REG_PC, addr + 4)
            return

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000)
    uc.reg_write(UC_ARM64_REG_X30, SENT)
    try:
        uc.emu_start(entry, SENT, count=maxins * 2)
    except UcError as e:
        return [('ERR', str(e))]
    return sends


def sites358(sends):
    return sorted({a for a, c in sends if c == 0x358})


if __name__ == '__main__':
    print('== функция B (0x2b47bb8): сайты отправки 0x358')
    for aux in (0x55, 0):
        for busy in (0, 1):
            for mode in (1, 3, 4, 6, 8, 0x15, 0x14, 0xd):
                print(f'  aux={aux:#04x} busy={busy} mode={mode:#04x} sub=2 p=2 -> 358 sites {[hex(s) for s in sites358(run(0x2b47bb8, mode, 2, 2, 1, busy, aux))]}')
    print('\n== функция A (0x2b47840): сайты отправки 0x358')
    for aux in (0x55, 0):
        for busy in (0, 1):
            for mode in (1, 3, 0xd, 0x12, 0x14):
                print(f'  aux={aux:#04x} busy={busy} mode={mode:#04x} -> 358 sites {[hex(s) for s in sites358(run(0x2b47840, mode, 2, 2, 1, busy, aux))]}')
    print('\n== функция A: все отправленные коды (aux=0x55, busy=1, mode=0xd)')
    print([(hex(a), hex(c)) for a, c in run(0x2b47840, 0xd, 2, 2, 1, 1, 0x55)])
    print('\n== функция B: все коды (aux=0x55, busy=1, mode=0x14, sub=2, p=2)')
    print([(hex(a), hex(c)) for a, c in run(0x2b47bb8, 0x14, 2, 2, 1, 1, 0x55)])
