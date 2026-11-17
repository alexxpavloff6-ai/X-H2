# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 42: jump-table 0x1AE2F14 (код выдержки -> категория fieldB);
Unicorn: кодировщик 0x14F396C и табличный оценщик 0x2F85F3C (таблица 0x3456B20)."""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR,  # noqa: E402
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)

# 1) jump-table 0x1AE2F14: 18 байт, case = 0x14F3994 + table[code]*4 (sxtb)
jt = b0.off(0x1AE2F14)
table_bytes = list(b0.data[jt:jt + 18])
case_const = {}
for code, tb in enumerate(table_bytes):
    sb = tb - 256 if tb >= 128 else tb
    target = 0x14F3994 + sb * 4
    # константа в case (mov w0,#imm) — дизасм 1 insn
    ins = list(__import__('fwcommon').insns(b0, target, 1))[0]
    case_const[code] = {'target': hex(target), 'insn': f'{ins.mnemonic} {ins.op_str}'}

out = []
out.append('=== jump-table 0x1AE2F14 (код выдержки 0..17 -> case) ===')
for code, info in case_const.items():
    out.append(f"  code {code:2d}: byte={table_bytes[code]:3d} -> {info['target']} : {info['insn']}")
out.append('')


def pagesz(n):
    return (n + 0xFFF) & ~0xFFF


def make_mu():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(b0.base, pagesz(len(b0.data)))
    mu.mem_write(b0.base, b0.data)
    mu.mem_map(b1.base, pagesz(len(b1.data)))
    mu.mem_write(b1.base, b1.data)
    mu.mem_map(0x10000000, 0x10000)  # stack
    mu.reg_write(UC_ARM64_REG_SP, 0x10008000)
    return mu


# 2) Unicorn: кодировщик 0x14F396C(mode=0x1D, arg1=4, arg2=code) -> fieldB
enc_results = {}
for code in range(18):
    mu = make_mu()
    mu.reg_write(UC_ARM64_REG_X0, 0x1D)   # mode
    mu.reg_write(UC_ARM64_REG_X1, 4)      # arg1 (pass-through)
    mu.reg_write(UC_ARM64_REG_X2, code)   # speed code
    mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
    mu.emu_start(0x14F396C, 0x10000000, count=200)
    enc_results[code] = mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
out.append('=== Unicorn 0x14F396C (mode=0x1D,arg1=4): code -> fieldB ===')
for code, v in enc_results.items():
    out.append(f'  code {code:2d} -> fieldB {v}')
out.append('')

# 3) Unicorn: табличный оценщик 0x2F85F3C(fieldB, shutter_type=1) -> table value
# 0x2F85F3C чистый лист (table read). эмулируем для fieldB 0..40, shutter_type 0..5
tab_results = {}
mu = make_mu()
for fb in range(41):
    row = []
    for st in range(6):
        mu.reg_write(UC_ARM64_REG_X0, fb)
        mu.reg_write(UC_ARM64_REG_X1, st)
        mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
        mu.reg_write(UC_ARM64_REG_SP, 0x10008000)
        mu.emu_start(0x2F85F3C, 0x10000000, count=50)
        row.append(mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF)
    tab_results[fb] = row
out.append('=== Unicorn 0x2F85F3C: fieldB x shutter_type -> table value (флаг=1 если ==2) ===')
out.append('fieldB | st0 st1 st2 st3 st4 st5')
for fb, row in tab_results.items():
    mark = '  <<< флаг=1' if row[1] == 2 else ''
    out.append(f'{fb:6d} | ' + ' '.join(f'{v:3d}' for v in row) + mark)

result = {'jump_table_bytes': table_bytes, 'case_const': case_const,
          'encoder_code_to_fieldB': enc_results, 'table_fieldB_x_shuttertype': tab_results}
(HERE / '3круг_vm_кодировка_таблица.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
text = '\n'.join(out)
(HERE / '3круг_vm_кодировка_таблица.txt').write_text(text + '\n', encoding='utf-8')
print(text)
