"""F: Unicorn-контроль отправки 0x358 — функции A (0x2b47840) и B (0x2b47bb8).

Параметры: mode=[S+0], sub=[S+0xb4], flag10=[S+0x10], p=свойство 0x979,
busy=результат 0x12e82f8(0x29), aux=результат 0x2a02384().
`bl` перехватывается: заглушки возвращают заданные значения, отправка
0x2c116ac записывается.

Печатаем таблицу: при каких комбинациях отправляется код 0x358.
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
    sent = []
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
            if tgt == 0x2c116ac:
                sent.append(uc.reg_read(UC_ARM64_REG_X0) & 0xffffffff)
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
        return ('ERR', str(e))
    return (0x358 in sent, sent)


if __name__ == '__main__':
    print('== функция B (0x2b47bb8)')
    print(' busy flag10 mode sub  p  aux | 0x358?')
    for busy in (0, 1):
        for flag10 in (0, 1):
            for mode in (0, 1, 3, 4, 6, 7, 8, 0xd, 0x12, 0x14, 0x15):
                row = []
                for sub in (2, 0xb, 0xc, 0xe):
                    for p in (0, 1, 2, 3):
                        r = run(0x2b47bb8, mode, sub, p, flag10, busy)
                        row.append('S' if r[0] is True else '.')
                print(f'  {busy}    {flag10}    {mode:#04x} подрежимы sub=2/b/c/e, p=0..3 | {"".join(row)}')
    print('\n== функция A (0x2b47840), mode ∈ {1,3}')
    for aux in (0, 0x55):
        for mode in (1, 3):
            print(f'  aux={aux:#04x} mode={mode:#x} -> {run(0x2b47840, mode, aux=aux, busy=0)}')
    print('\n== функция A, mode ∉ {1,3} (уходит в case-блок)')
    for mode in (8, 0xd, 0x12, 0x14):
        print(f'  mode={mode:#x} aux=0x55 -> {run(0x2b47840, mode, sub=2, p=2, aux=0x55, busy=0)}')
