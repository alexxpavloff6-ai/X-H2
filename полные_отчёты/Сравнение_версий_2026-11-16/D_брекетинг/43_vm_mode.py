# -*- coding: utf-8 -*-
"""D4: VM-контроль ветвления по [ctx+0x3978] и счётчика [ctx+0x429c] (X-H2 5.33).

Эмулируем оригинальные инструкции:
  A) 0x2dd1f94..0x2dd1fa4: ldr w0,[x19+0x3978]; cmp w0,#0x2c; b.eq 0x2dd216c
     -> проверяем, что при 0x2C управление уходит на многокадровую ветку.
  B) 0x2dd216c..0x2dd218c: ldrh w0,[x19+0x429c]; w28 = 4/1/2
     -> при [x19+0x429c] = 2/3/0 получаем w28 = 4/1/2.
Контроль: те же прогоны при других значениях.
"""
import sys, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm64_const import *

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)
CTX = 0x40000000
PAGE = 0x1000

def run(entry, stops, setup, max_insn=200000):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    n = (len(b.data) + PAGE - 1) & ~(PAGE - 1)
    uc.mem_map(b.base, n)
    uc.mem_write(b.base, b.data)
    uc.mem_map(CTX, 0x8000)
    uc.mem_write(CTX, bytes(0x8000))

    def on_unmapped(uc, access, address, size, value, user):
        try:
            uc.mem_map(address & ~(PAGE - 1), 0x10000)
            return True
        except Exception:
            return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    for off, val, width in setup:
        fmt = {1: '<B', 2: '<H', 4: '<I'}[width]
        uc.mem_write(CTX + off, struct.pack(fmt, val))

    trace = []
    st = {'hit': None}
    def on_code(uc, address, size, user):
        if address in stops:
            st['hit'] = address
            uc.emu_stop(); return
        trace.append(address)

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_ARM64_REG_X19, CTX)
    uc.reg_write(UC_ARM64_REG_SP, CTX + 0x7000)
    uc.reg_write(UC_ARM64_REG_LR, 0)
    try:
        uc.emu_start(entry, 0, 0, max_insn)
    except Exception as e:
        return {'error': str(e), 'trace': trace, 'uc': uc, 'hit': st['hit']}
    return {'error': None, 'trace': trace, 'uc': uc, 'hit': st['hit']}

print('=== A) ветвление по [ctx+0x3978] (0x2dd1f94..) ===')
for mode in (0x2c, 0x2d, 0x20, 0x0):
    r = run(0x2dd1f94, {0x2dd1fa4, 0x2dd216c}, [(0x3978, mode, 4)])
    tgt = ('многокадровая ветка 0x2dd216c' if r['hit'] == 0x2dd216c else
           'общая ветка 0x2dd1fa4' if r['hit'] == 0x2dd1fa4 else '?')
    print(f'  mode={mode:#04x}: {tgt}, err={r["error"]}, инструкций={len(r["trace"])}')

print('\n=== B) счётчик [ctx+0x429c] (0x2dd216c..) ===')
for v in (0, 1, 2, 3, 4):
    r = run(0x2dd216c, {0x2dd1fa4}, [(0x429c, v, 2)])
    if r['error']:
        print(f'  [0x429c]={v}: error {r["error"]}')
        continue
    w28 = r['uc'].reg_read(UC_ARM64_REG_W28)
    print(f'  [0x429c]={v}: w28 (число проходов) = {w28}')
