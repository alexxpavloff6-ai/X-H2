# -*- coding: utf-8 -*-
"""D: отладка VM — печатает последние 12 PC перед исключением и сам PC."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import *
from collections import deque

BLOB_BASE, BLOB_SIZE = 0x27008000, 0x200000
STACK, STACK_SIZE, TRAP, PAGE = 0x70000000, 0x40000, 0x70100000, 0x1000

def setup(model, state):
    b0, b1 = load(model, state, 0), load(model, state, 1)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(b0.base, (len(b0.data) + PAGE - 1) & ~(PAGE - 1)); uc.mem_write(b0.base, b0.data)
    uc.mem_map(b1.base, (len(b1.data) + PAGE - 1) & ~(PAGE - 1)); uc.mem_write(b1.base, b1.data)
    uc.mem_map(BLOB_BASE, BLOB_SIZE); uc.mem_write(BLOB_BASE, bytes(BLOB_SIZE))
    uc.mem_map(STACK, STACK_SIZE); uc.mem_map(TRAP, PAGE)
    uc.mem_write(TRAP, struct.pack('<I', 0x14000000))
    return uc, b0, b1

uc, b0, b1 = setup('X-H2', 'new')
uc.mem_write(BLOB_BASE + 0xa8, b'\x80')
uc.mem_map(0x20bf000, PAGE)
uc.mem_write(0x20bf458, struct.pack('<Q', BLOB_BASE))
commit, dst = 0x40002000, 0x40010000
uc.mem_map(commit, 0x1000); uc.mem_map(dst, 0x800000)
hist = deque(maxlen=16)
def on_code(uc, address, size, user):
    if address == TRAP:
        print('TRAP reached'); uc.emu_stop(); return
    hist.append(address)
def on_intr(uc, intno, user):
    print('INTR', intno)
def on_unmapped(uc, access, address, size, value, user):
    try:
        uc.mem_map(address & ~(PAGE-1), 0x10000); return True
    except Exception:
        return False
uc.hook_add(UC_HOOK_CODE, on_code)
uc.hook_add(UC_HOOK_INTR, on_intr)
uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
uc.reg_write(UC_ARM64_REG_X0, commit); uc.reg_write(UC_ARM64_REG_X1, dst); uc.reg_write(UC_ARM64_REG_X2, 0)
uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x200)
uc.reg_write(UC_ARM64_REG_LR, TRAP)
try:
    uc.emu_start(0x2dd0448, TRAP, count=2000)
except Exception as e:
    print('ERR', e, 'pc=', hex(uc.reg_read(UC_ARM64_REG_PC)))
print('последние PC:', [hex(a) for a in hist])
for a in list(hist)[-6:]:
    print(dis(b1, a, 3))
