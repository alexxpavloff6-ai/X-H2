import sys
from pathlib import Path

sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X20, UC_ARM64_REG_X30

block = load('X-H2', 'old', 1)
base = block.base
size = (len(block.data) + 0xFFF) & ~0xFFF
stack_base = 0x50000000
stop_addr = 0x50010000
setter = 0x2C88E98
branch = 0x2C8A2A8
end = 0x2C8ECF8

def run(index):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(base, size)
    uc.mem_write(base, block.data)
    uc.mem_map(stack_base, 0x20000)
    uc.reg_write(UC_ARM64_REG_SP, stack_base + 0x10000)
    uc.reg_write(UC_ARM64_REG_X20, index)
    uc.reg_write(UC_ARM64_REG_X30, stop_addr)
    events = []

    def hook(emu, address, instruction_size, _):
        if address == setter:
            events.append((address, emu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF,
                           emu.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF))
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
        elif address == end:
            emu.emu_stop()
        elif address == stop_addr:
            emu.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(branch, stop_addr, count=500)
    return [{'address': hex(a), 'id': hex(i), 'value': v} for a, i, v in events]

for value in range(5):
    print(value, run(value))
