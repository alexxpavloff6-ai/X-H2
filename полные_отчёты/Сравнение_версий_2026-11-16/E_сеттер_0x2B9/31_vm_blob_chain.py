# -*- coding: utf-8 -*-
"""E31b: VM-контроль (Unicorn) цепочки blob[0x2801C] -> struct+0x144 -> ctx+0x3978.

Блоки 0 и 1 — один образ в общем VA-пространстве, поэтому картируем оба.
A) геттер blob 0x14920fc(id) = blob[id] (blob = [0x20bf458]);
B) фрагмент заполнителя 0x2debb38: id 0x28009+0x13 -> struct+0x144;
C) фрагмент копирования 0x30871a8: struct+0x144 -> ctx+0x3978.
"""
import sys, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm64_const import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b0 = load(MODEL, STATE, 0)
b1 = load(MODEL, STATE, 1)
PAGE = 0x1000
BLOB = 0x30000000
GLOB = 0x20bf000
STACK = 0x50000000
CTX = 0x40000000
SENT = 0x40003000


def new_uc():
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for blk in (b0, b1):
        n = (len(blk.data) + PAGE - 1) & ~(PAGE - 1)
        uc.mem_map(blk.base, n)
        uc.mem_write(blk.base, blk.data)
    uc.mem_map(GLOB, 0x2000)
    uc.mem_write(GLOB + 0x458, struct.pack('<Q', BLOB))
    uc.mem_map(BLOB, 0x40000)
    uc.mem_map(CTX, 0x4000)
    uc.mem_map(STACK, 0x4000)

    def on_unmapped(uc, access, address, size, value, user):
        try:
            uc.mem_map(address & ~(PAGE - 1), 0x10000)
            return True
        except Exception:
            return False
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    return uc


def run(entry, stop_pc, regs=(), mem=(), max_insn=5000):
    uc = new_uc()
    for off, data in mem:
        uc.mem_write(off, data)
    for reg, val in regs:
        uc.reg_write(reg, val)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x3000)
    uc.reg_write(UC_ARM64_REG_LR, SENT)
    st = {'hit': False}

    def on_code(uc, address, size, user):
        if address == stop_pc or address == SENT:
            st['hit'] = (address == stop_pc)
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, on_code)
    err = None
    try:
        uc.emu_start(entry, 0, 0, max_insn)
    except Exception as e:
        err = str(e)
    return uc, st['hit'], err


res = {}
print('=== A) геттер blob 0x14920fc(id): возвращает blob[id] ===')
res['A'] = []
for idv, filler in ((0x2801c, 0x2c), (0x2801c, 0x07), (0x2801d, 0x2c)):
    uc, hit, err = run(0x14920fc, SENT,
                       regs=[(UC_ARM64_REG_X0, idv)],
                       mem=[(BLOB + idv, bytes([filler]))])
    got = uc.reg_read(UC_ARM64_REG_W0)
    res['A'].append({'id': hex(idv), 'blob': hex(filler), 'ret': hex(got), 'err': err})
    print(f'  id={idv:#07x}, blob[id]={filler:#04x} -> w0={got:#04x}  err={err}')

print('\n=== B) заполнитель 0x2debb38 (w19=9): id 0x28009+0x13 -> struct+0x144 ===')
res['B'] = []
for filler in (0x2c, 0x2d, 0x21, 0x00):
    uc, hit, err = run(0x2debb38, 0x2debb48,
                       regs=[(UC_ARM64_REG_X19, 9), (UC_ARM64_REG_X20, CTX)],
                       mem=[(BLOB + 0x2801c, bytes([filler]))])
    got = struct.unpack('<B', uc.mem_read(CTX + 0x144, 1))[0]
    res['B'].append({'blob_2801C': hex(filler), 'struct_144': hex(got), 'stopped': hit, 'err': err})
    print(f'  blob[0x2801C]={filler:#04x} -> struct+0x144={got:#04x}  останов={hit} err={err}')

print('\n=== C) копирование 0x30871a8: struct+0x144 -> ctx+0x3978 ===')
res['C'] = []
for val in (0x2c, 0x2d, 0x20):
    uc, hit, err = run(0x30871a8, 0x30871b0,
                       regs=[(UC_ARM64_REG_X19, CTX), (UC_ARM64_REG_X0, CTX + 0x2000)],
                       mem=[(CTX + 0x144, struct.pack('<I', val))])
    got = struct.unpack('<I', uc.mem_read(CTX + 0x2000 + 0x3978, 4))[0]
    res['C'].append({'struct_144': hex(val), 'ctx_3978': hex(got), 'stopped': hit, 'err': err})
    print(f'  struct+0x144={val:#04x} -> ctx+0x3978={got:#04x}  останов={hit} err={err}')

open('vm_blob_chain.json', 'w', encoding='utf8').write(json.dumps(res, ensure_ascii=False, indent=1))
