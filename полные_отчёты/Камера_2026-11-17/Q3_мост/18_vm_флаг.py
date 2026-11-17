# -*- coding: utf-8 -*-
"""Q3 шаг 18: VM-проверка (Unicorn) распространения флага.
Доказываем: memcpy pending->current (0x3105440) и apply-запись (0x31085A4/A8)
переносят payload+0x64 в state+0x43C БЕЗ вычисления из настроек.
Входы: синтетический pending payload+0x64 in {0,1,2,0xFFFFFFFF}.
Камера не используется; только эмуляция кода прошивки."""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_SP,  # noqa: E402
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)

JOB = 0x4C3F088
PENDING = 0x4C3F090
CURRENT = 0x4C3F1F8
STATE = 0x4C33AD8
FLAG_OFF = 0x74          # container+0x74 = payload+0x64
MEMCPY = 0x3105440
MEMCPY_CALLEE = 0x153CE8C
FLAG_LDR = 0x31085A4     # ldr w2,[x1,#0x1e4]
FLAG_STR = 0x31085A8     # str w2,[x0,#0x43c]

RAM_LO = 0x4C30000
RAM_SZ = 0x12000
STACK = 0x4D00000


def pagesz(n):
    return (n + 0xFFF) & ~0xFFF


def run_case(flag_value):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(b0.base, pagesz(len(b0.data)))
    mu.mem_write(b0.base, b0.data)
    mu.mem_map(b1.base, pagesz(len(b1.data)))
    mu.mem_write(b1.base, b1.data)
    mu.mem_map(RAM_LO, RAM_SZ)
    mu.mem_map(STACK, 0x10000)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x8000)

    # job: указатели payload (как в init 0x3105390)
    mu.mem_write(JOB + 0x10, struct.pack('<Q', PENDING + 0x10))
    mu.mem_write(JOB + 0x178, struct.pack('<Q', CURRENT + 0x10))
    # синтетический флаг в pending payload+0x64
    mu.mem_write(PENDING + FLAG_OFF, struct.pack('<I', flag_value & 0xFFFFFFFF))
    # мусор в current, чтобы убедиться что копируется именно pending
    mu.mem_write(CURRENT + FLAG_OFF, struct.pack('<I', 0xDEADBEEF))
    mu.mem_write(STATE + 0x43C, struct.pack('<I', 0xCAFEBABE))

    # hook memcpy-враппера 0x153CE8C: dst=x0,src=x1,len=x2 -> копируем и возвращаемся
    def hook(mu, addr, size, user):
        if addr == MEMCPY_CALLEE:
            dst = mu.reg_read(UC_ARM64_REG_X0)
            src = mu.reg_read(UC_ARM64_REG_X1)
            n = mu.reg_read(UC_ARM64_REG_X2)
            data = mu.mem_read(src, n)
            mu.mem_write(dst, bytes(data))
            lr = mu.reg_read(UC_ARM64_REG_LR)
            mu.reg_write(UC_ARM64_REG_PC, lr)
    mu.hook_add(UC_HOOK_CODE, hook)

    # 1) memcpy pending->current
    mu.reg_write(UC_ARM64_REG_LR, b1.base + 0x10)  # sentinel return
    mu.emu_start(MEMCPY, b1.base + 0x10, count=200)
    cur_flag = struct.unpack('<I', mu.mem_read(CURRENT + FLAG_OFF, 4))[0]

    # 2) apply-запись флага: x1=job, x0=state; эмулируем ldr/str
    mu.reg_write(UC_ARM64_REG_X1, JOB)
    mu.reg_write(UC_ARM64_REG_X0, STATE)
    mu.reg_write(UC_ARM64_REG_LR, b1.base + 0x10)
    mu.emu_start(FLAG_LDR, FLAG_STR + 4, count=4)
    state_flag = struct.unpack('<I', mu.mem_read(STATE + 0x43C, 4))[0]

    return {'input_pending_flag': hex(flag_value & 0xFFFFFFFF),
            'current_flag_after_memcpy': hex(cur_flag),
            'state_flag_after_apply': hex(state_flag),
            'pure_copy': cur_flag == (flag_value & 0xFFFFFFFF) and state_flag == (flag_value & 0xFFFFFFFF)}


cases = [run_case(v) for v in (0, 1, 2, 0xFFFFFFFF)]
result = {
    'firmware': 'X-H2 5.30',
    'claim': 'В анализируемом коде (блоки 0-1) флаг MOVDC переносится копированием payload+0x64 -> current+0x74 -> state+0x43C без вычисления из настроек.',
    'memcpy': hex(MEMCPY), 'flag_ldr_str': [hex(FLAG_LDR), hex(FLAG_STR)],
    'cases': cases,
    'all_pure_copy': all(c['pure_copy'] for c in cases),
}
(HERE / 'vm_флаг.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, ensure_ascii=False, indent=2))
