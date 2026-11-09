"""Исполнить аналогичный фрагмент ARM64 в изолированной виртуальной памяти."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / 'инструменты'))
spec = importlib.util.spec_from_file_location('firmware_base', HERE.parent / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

FILES = {
    'X-H2': (ROOT / 'FIRMWARE/ver 5.30/FWUP0028.DAT', 0x300274, 0x2767d0),
    'X-H2S': (ROOT / 'Firmware на прочиеFuji/FWUP0027.DAT', 0x300274, 0x2743b0),
    'X-T5': (ROOT / 'Firmware на прочиеFuji/FWUP0030.DAT', 0x300274, 0x2737a0),
    'X100VI': (ROOT / 'Firmware на прочиеFuji/FPUPDATE.DAT', 0x9c02bc, 0x29eb28),
}


def main():
    reference = None
    results = {}
    for model, (path, offset, func_off) in FILES.items():
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        block = base.unpack_fflz(raw.translate(base.TRANSLATION), offset)
        address_base = struct.unpack_from('<Q', block, 8)[0]
        function = block[func_off:func_off + 160]
        if reference is None:
            reference = function
        assert function == reference, f'{model}: команды отличаются'
        assert function[-4:] == bytes.fromhex('c0035fd6')
        code_start = address_base & ~4095
        code_end = (address_base + len(block) + 4095) & ~4095
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(code_start, code_end - code_start)
        u.mem_write(address_base, block)
        u.mem_map(0x60000000, 0x10000)
        u.mem_map(0x70000000, 0x10000)
        src, dst, stop = 0x60000000, 0x60001000, 0x70000000
        cases = []
        for values in [(885, -10, 859, -12), (974, -12, 946, -14), (0, -1, 4095, -4096)]:
            for upper in (0, 0xa000, 0xe000):
                u.mem_write(src + 0x1da, struct.pack('<4h', *values))
                u.mem_write(dst + 0x1ec, struct.pack('<4H', *([upper] * 4)))
                u.reg_write(UC_ARM64_REG_X0, src)
                u.reg_write(UC_ARM64_REG_X1, dst)
                u.reg_write(UC_ARM64_REG_X30, stop)
                u.reg_write(UC_ARM64_REG_SP, 0x7000f000)
                u.emu_start(address_base + func_off, stop, count=1000)
                assert u.reg_read(UC_ARM64_REG_PC) == stop
                actual = list(struct.unpack('<4H', u.mem_read(dst + 0x1ec, 8)))
                expected = [upper | (v & 0x1fff) for v in values]
                assert actual == expected, (model, values, upper, actual, expected)
                cases.append({'input': values, 'upper_bits': hex(upper), 'output': actual})
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
        results[model] = {'source_sha256': sha, 'packed_block_offset': hex(offset), 'decoded_block_offset': hex(func_off), 'function_address': hex(address_base + func_off), 'function_sha256': hashlib.sha256(function).hexdigest(), 'cases': cases}
    (HERE / 'Сравнение_машинного_кода_цвета.json').write_text(json.dumps(results, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'models': list(results), 'identical_function_bytes': 160, 'cases_per_model': 9, 'source_unchanged': True}))


if __name__ == '__main__':
    main()
