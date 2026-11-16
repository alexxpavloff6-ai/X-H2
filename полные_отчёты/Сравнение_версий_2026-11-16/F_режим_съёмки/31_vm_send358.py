"""F: Unicorn-проверка условия отправки события 0x358 в функции 0x2b47bb8 (X-H2 5.33 b1).

Функция B (0x2b47bb8..0x2b47dd8) — один из отправителей 0x358; её внутренний
case-блок (0x2b47c14..) побайтово совпадает с блоком функции A (0x2b47a14..).

Эмулируем ОРИГИНАЛЬНЫЕ инструкции, `bl` перехватываем: возвращаем заглушки.
Переменные: mode = [S+0] (S=0x244eb20), sub = [S+0xb4], p = свойство 0x979,
flag10 = [S+0x10]. Перебираем комбинации и печатаем, отправлен ли 0x358.
"""
import sys, struct, json
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_UNMAPPED, UcError)
from unicorn.arm64_const import *

S = 0x244eb20
CTX = 0x26bb0a8
STACK = 0x70000000
SENT = 0xdead0000

b = load('X-H2', 'new', 1)

# карта памяти
uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN) if False else Uc(UC_ARCH_ARM64, UC_MODE_ARM)

def map_all(uc):
    uc.mem_map(b.base & ~0xfff, len(b.data) + 0x2000)
    uc.mem_write(b.base, b.data)
    uc.mem_map(0x244e000, 0x4000)          # S и соседние глобалы (0x244eef6, 0x244f1a4)
    uc.mem_map(0x26a3000, 0x20000)         # системный контекст
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(0x260d000, 0x1000)

SEND = []
LOG = []

STUBS = {
    0x12e82f8: lambda uc: 0,
    0x11335ec: None,   # get property -> p
    0x1135930: None,   # check property -> p (0..3)
    0x2a02384: lambda uc: 0x55,
    0x130cd44: lambda uc: 0,
    0x2c15200: lambda uc: 0,
    0x2c151d8: lambda uc: 0,
    0x2c11588: lambda uc: 0,
    0x2c129a8: lambda uc: 0,
    0x1309a24: lambda uc: 0,
    0x1309ab0: lambda uc: 0,
    0x12e82f8: lambda uc: 0,
}


def run(mode, sub, p, flag10=1, g1a4=0, geef6=0, maxins=4000):
    SEND.clear()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    map_all(uc)
    # S
    uc.mem_write(S + 0, struct.pack('<I', mode))
    uc.mem_write(S + 0x10, struct.pack('<I', flag10))
    uc.mem_write(S + 0xb0, struct.pack('<I', 0))
    uc.mem_write(S + 0xb4, struct.pack('<I', sub))
    uc.mem_write(S + 8, struct.pack('<Q', 0))
    uc.mem_write(0x244f1a4, struct.pack('<H', g1a4))
    uc.mem_write(0x244eef6, struct.pack('<H', geef6))

    state = {'p': p, 'n': 0}

    def hook(uc, addr, size, user):
        state['n'] += 1
        if addr == SENT:
            uc.emu_stop()
            return
        # перехват bl
        try:
            w = struct.unpack('<I', uc.mem_read(addr, 4))[0]
        except Exception:
            return
        if (w & 0xfc000000) == 0x94000000:
            imm = w & 0x3ffffff
            if imm & (1 << 25):
                imm -= 1 << 26
            tgt = addr + imm * 4
            lr = addr + 4
            if tgt == 0x2c116ac:
                SEND.append(uc.reg_read(UC_ARM64_REG_X0) & 0xffffffff)
            # заглушка
            if tgt in (0x11335ec, 0x1135930):
                rv = state['p']
            elif tgt in STUBS:
                rv = STUBS[tgt](uc)
            else:
                rv = 0
            uc.reg_write(UC_ARM64_REG_X0, rv)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        if state['n'] > maxins:
            uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x10000)
    uc.reg_write(UC_ARM64_REG_X30, SENT)
    uc.reg_write(UC_ARM64_REG_X0, 0)
    try:
        uc.emu_start(0x2b47bb8, SENT, count=20000)
    except UcError as e:
        return ('ERR', str(e))
    return (0x358 in SEND, list(SEND), state['n'])


if __name__ == '__main__':
    print('== контрольные прогоны')
    for mode, sub, p in ((1, 0, 0), (3, 0, 0), (8, 0xb, 0), (0x14, 2, 2), (0x14, 0xb, 2)):
        print(f'  mode={mode:#x} sub={sub:#x} p={p}: {run(mode, sub, p)}')
    print('\n== полный перебор (flag10=1, без прочих флагов)')
    table = {}
    for mode in list(range(0, 0x21)):
        row = []
        for sub in (0, 1, 2, 3, 0xb, 0xc, 0xd, 0xe):
            cell = ''
            for p in (0, 1, 2, 3):
                r = run(mode, sub, p)
                ok = r[0] if isinstance(r, tuple) and r[0] in (True, False) else 'E'
                cell += 'S' if ok is True else ('.' if ok is False else '?')
            row.append(f'{sub:#04x}:{cell}')
        table[mode] = row
    for mode, row in table.items():
        print(f'  mode={mode:#04x}  ' + '  '.join(row))
    json.dump(table, open('vm_send358.json', 'w'), indent=1)
