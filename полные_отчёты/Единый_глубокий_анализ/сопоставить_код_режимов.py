"""Execute each firmware's AArch64 mode translation with artificial inputs.

This is not a full camera simulation. Original firmware files are read only.
"""
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
    'X-H2': ('FIRMWARE/ver 5.30/FWUP0028.DAT', 'be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203', 0x840274, 0x58ac30),
    'X-H2S': ('Firmware на прочиеFuji/FWUP0027.DAT', '87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b', 0x840274, 0x5859a8),
    'X-T5': ('Firmware на прочиеFuji/FWUP0030.DAT', '790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e', 0x820274, 0x588f2c),
    'X100VI': ('Firmware на прочиеFuji/FPUPDATE.DAT', '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a', 0x10e02bc, 0x5bfee4),
}


def main():
    output = {}
    common = None
    for model, (rel, expected_sha, packed_offset, function_offset) in FILES.items():
        path = ROOT / rel
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_sha
        block = base.unpack_fflz(raw.translate(base.TRANSLATION), packed_offset)
        address = struct.unpack_from('<Q', block, 8)[0]
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(address, (len(block) + 4095) & ~4095)
        uc.mem_write(address, block)
        uc.mem_map(0x60000000, 0x10000)
        uc.mem_map(0x70000000, 0x10000)
        out = []
        for value in range(24):
            uc.mem_write(0x60000000, b'\xff' * 16)
            uc.reg_write(UC_ARM64_REG_X0, 0x60000000)
            uc.reg_write(UC_ARM64_REG_X1, value)
            uc.reg_write(UC_ARM64_REG_X30, 0x70000000)
            uc.reg_write(UC_ARM64_REG_SP, 0x7000f000)
            uc.emu_start(address + function_offset, 0x70000000, count=1000)
            assert uc.reg_read(UC_ARM64_REG_PC) == 0x70000000
            out.append(struct.unpack('<I', uc.mem_read(0x60000000, 4))[0])
        if common is None:
            common = out
        assert out == common and out[13] == 8
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha
        output[model] = {'source': rel, 'sha256': expected_sha, 'packed_fflz_offset': hex(packed_offset), 'function_offset_in_unpacked_block': hex(function_offset), 'block_address': hex(address), 'function_address': hex(address + function_offset), 'mapping_inputs_0_to_23': out, 'source_unchanged': True}
    (HERE / 'Коды_режимов_сравнение.json').write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'models': list(output), 'inputs_per_model': 24, 'all_equal': True, '13_to': 8, 'source_unchanged': True}, ensure_ascii=False))

if __name__ == '__main__':
    main()
