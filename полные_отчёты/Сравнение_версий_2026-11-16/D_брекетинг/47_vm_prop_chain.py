# -*- coding: utf-8 -*-
"""D5: VM-контроль цепочки «settings+0x144 -> ctx+0x3978 -> ветвление 0x2C».

1) Эмулируем копирование на 0x30871a8..0x30871ac: ldr w1,[x19,#0x144]; str w1,[x0,#0x3978].
   Проверяем, что при settings+0x144 = 0x2C в ctx+0x3978 оказывается 0x2C.
2) С этим ctx проверяем ветвление 0x2dd1f94..0x2dd1fa4: уходит ли управление
   в многокадровую ветку 0x2dd216c.
"""
import sys, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm64_const import *

b = load('X-H2', 'new', 1)
PAGE = 0x1000
SETTINGS = 0x41000000
CTX = 0x42000000

def vm(entry, stops, setup):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    n = (len(b.data) + PAGE - 1) & ~(PAGE - 1)
    uc.mem_map(b.base, n); uc.mem_write(b.base, b.data)
    uc.mem_map(SETTINGS, 0x8000); uc.mem_write(SETTINGS, bytes(0x8000))
    uc.mem_map(CTX, 0x8000); uc.mem_write(CTX, bytes(0x8000))
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, lambda uc, a, ad, sz, v, u: (uc.mem_map(ad & ~(PAGE - 1), 0x10000), True)[1])
    hit = {'a': None}
    def on_code(uc, address, size, user):
        if address in stops:
            hit['a'] = address; uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, on_code)
    for base, off, val, width in setup:
        fmt = {1: '<B', 2: '<H', 4: '<I'}[width]
        uc.mem_write(base + off, struct.pack(fmt, val))
    uc.reg_write(UC_ARM64_REG_X19, SETTINGS)
    uc.reg_write(UC_ARM64_REG_X0, CTX)
    uc.reg_write(UC_ARM64_REG_SP, CTX + 0x7000)
    uc.reg_write(UC_ARM64_REG_LR, 0)
    try:
        uc.emu_start(entry, 0, 0, 10000)
    except Exception as e:
        return None, str(e), hit['a']
    return uc, None, hit['a']

for val in (0x2c, 0x21, 0x00):
    uc, err, _ = vm(0x30871a8, {0x30871b0}, [(SETTINGS, 0x144, val, 1)])
    if err:
        print(f'settings+0x144={val:#04x}: ошибка {err}')
        continue
    got = struct.unpack('<I', uc.mem_read(CTX + 0x3978, 4))[0]
    print(f'settings+0x144={val:#04x} -> ctx+0x3978 = {got:#x}')
    # ветвление по полученному ctx (x19 в 0x2dd1f94 = база, кладём туда же)
    uc2, err2, hit = vm(0x2dd1f94, {0x2dd1fa4, 0x2dd216c},
                        [(SETTINGS, 0x3978, got, 4), (SETTINGS, 0x3ff8, 0, 4)])
    if err2:
        print(f'  ветвление: ошибка {err2}')
    else:
        print('  ветвление:', 'многокадровая 0x2dd216c' if hit == 0x2dd216c else
              'общая 0x2dd1fa4' if hit == 0x2dd1fa4 else f'останов {hit}')
