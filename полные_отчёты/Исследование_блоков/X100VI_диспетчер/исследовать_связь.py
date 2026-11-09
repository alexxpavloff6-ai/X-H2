"""X100VI recovery: connect two original fragments via an explicit simulated message service.

Read-only source DAT; no device/peripheral access. Run from any directory:
    python -X utf8 Анализ_прошивки/Исследование_блоков/X100VI_диспетчер/исследовать_связь.py
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ANALYSIS = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', ANALYSIS / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP

source = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
expected_hash = '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
sha256 = lambda data: hashlib.sha256(data).hexdigest()
raw = source.read_bytes()
assert sha256(raw) == expected_hash
block = base.unpack_fflz(raw.translate(base.TRANSLATION), 0x1402bc)
R = struct.unpack_from('<Q', block, 8)[0]
assert R == 0x881000
assert sha256(block) == 'fbbacc6736e28c9bb44550fac0f450d8ae23b5a26e94b060c49cfc142cdbeaed'
stack, end = 0x70000000, 0x71000000
global_page = R + 0x254000
state_addr, msg_addr, data_addr, index_addr = (R + x for x in (0x254070, 0x254078, 0x254090, 0x254098))


def run_case(value, state, message_id_override=None, send_result=0):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(R, (len(block) + 4095) & ~4095)
    u.mem_write(R, block)
    u.mem_map(global_page, 0x1000)
    u.mem_map(stack, 0x10000)
    u.mem_map(end, 0x1000)
    u.reg_write(UC_ARM64_REG_SP, stack + 0xf000)
    u.reg_write(UC_ARM64_REG_X30, end)
    u.reg_write(UC_ARM64_REG_X0, value)
    record = {'input': value, 'synthetic_state': state, 'message_id_override': message_id_override,
              'synthetic_send_result': send_result, 'send_calls': [], 'receive_calls': [], 'executed_offsets': []}
    captured = {}
    phase = 'send'
    watched = {0x1514, 0x1574, 0x159c, 0x15c8, 0x1644, 0x1694, 0x1788, 0x17a8, 0x1a60, 0x1a74, 0x16e4}

    def intercept(uc, address, size, unused):
        off = address - R
        if off in watched:
            record['executed_offsets'].append(hex(off))
        if off == 0x3d14:
            uc.reg_write(UC_ARM64_REG_X0, 0x1234)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif off == 0x49e0:
            destination, ptr = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            message = bytes(uc.mem_read(ptr, 24))
            payload_ptr = struct.unpack_from('<Q', message, 16)[0]
            length = struct.unpack_from('<I', message, 8)[0]
            payload = bytes(uc.mem_read(payload_ptr, length))
            captured.update(message=message, payload=payload)
            record['send_calls'].append({'destination': destination, 'id': struct.unpack_from('<H', message)[0],
                                         'length': length, 'payload_hex': payload.hex()})
            uc.reg_write(UC_ARM64_REG_X0, send_result)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif off == 0x4c10:
            destination, ptr = uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)
            assert phase == 'receive' and captured and ptr == msg_addr
            msg = bytearray(captured['message'])
            if message_id_override is not None:
                struct.pack_into('<H', msg, 0, message_id_override)
            struct.pack_into('<Q', msg, 16, data_addr)
            uc.mem_write(data_addr, captured['payload'])
            uc.mem_write(ptr, bytes(msg))
            record['receive_calls'].append({'destination': destination, 'message_id': struct.unpack_from('<H', msg)[0],
                                            'payload_hex': captured['payload'].hex(), 'result': 0})
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif phase == 'receive' and off == 0x15b8 and record['receive_calls']:
            uc.emu_stop()
        elif phase == 'draw' and off in (0x31c6c, 0x31d9c):
            record.setdefault('draw_stubbed_calls', []).append(hex(off))
            uc.reg_write(UC_ARM64_REG_X0, 0x60000000 if off == 0x31c6c else 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        elif phase == 'draw' and off == 0x194c:
            uc.emu_stop()

    u.hook_add(UC_HOOK_CODE, intercept)
    u.emu_start(R + 0x1514, end, count=500)
    assert u.reg_read(UC_ARM64_REG_PC) == end
    record['send_return_w0'] = u.reg_read(UC_ARM64_REG_X0) & 0xffffffff
    if value > 18 or send_result:
        assert record['send_return_w0'] == 0xfffffffa
        record['receive_skipped'] = True
        return record
    assert record['send_return_w0'] == 0
    assert record['send_calls'] == [{'destination': 0xea, 'id': 0x148a, 'length': 4,
                                      'payload_hex': struct.pack('<I', value).hex()}]
    u.mem_write(state_addr, struct.pack('<I', state))
    u.mem_write(index_addr, struct.pack('<I', 0xffffffff))
    u.reg_write(UC_ARM64_REG_SP, stack + 0xf000)
    u.reg_write(UC_ARM64_REG_X30, end)
    phase = 'receive'
    u.emu_start(R + 0x159c, end, count=1500)
    assert u.reg_read(UC_ARM64_REG_PC) == R + 0x15b8
    record['state_after'] = struct.unpack('<I', bytes(u.mem_read(state_addr, 4)))[0]
    record['index_after'] = struct.unpack('<I', bytes(u.mem_read(index_addr, 4)))[0]
    should_update = state == 3 and message_id_override is None
    assert record['index_after'] == (value if should_update else 0xffffffff)
    assert record['state_after'] == state
    assert ('0x1788' in record['executed_offsets']) == should_update
    # Start a second table-selected callback separately, preserving the index.
    # Base and stride are synthetic; stop before the buffer call.
    synthetic_base, synthetic_stride = 0x40080000, 0x1000
    u.mem_write(R + 0x2540a8, struct.pack('<Q', synthetic_base))
    u.mem_write(R + 0x2540b4, struct.pack('<I', synthetic_stride))
    u.reg_write(UC_ARM64_REG_SP, stack + 0xf000)
    u.reg_write(UC_ARM64_REG_X30, end)
    phase = 'draw'
    u.emu_start(R + 0x1770, end, count=1500)
    pc = u.reg_read(UC_ARM64_REG_PC)
    if should_update:
        assert pc == R + 0x194c
        args = [u.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
        assert args == [0x40bc0000, synthetic_base + value * synthetic_stride, synthetic_stride]
        record['separate_draw_callback'] = {'stop_before_call_offset': '0x194c', 'x0': hex(args[0]),
            'x1': hex(args[1]), 'x2': hex(args[2]), 'synthetic_base': hex(synthetic_base),
            'synthetic_stride': hex(synthetic_stride)}
    else:
        assert pc == end
        record['separate_draw_callback'] = {'returned_without_buffer_call': True}
    return record


cases = [run_case(value, 3) for value in (0, 9, 18)]
cases += [run_case(9, state) for state in (0, 1, 2, 4)]
cases += [run_case(9, 3, message_id_override=0x9999), run_case(19, 3), run_case(9, 3, send_result=1)]
assert sha256(source.read_bytes()) == expected_hash
result = {'source': str(source.relative_to(ROOT)), 'source_sha256': expected_hash,
          'recovery_fflz_dat_offset': '0x1402bc', 'block_sha256': sha256(block), 'conditional_base': hex(R),
          'method': 'Original sender and dispatcher execute in one VM; synthetic hooks replace services 0x3d14, 0x49e0, 0x4c10 and manually copy the captured message and payload to the receive buffer. State is synthetic. A separate callback runs with the resulting index, synthetic base/stride and stubbed 0x31c6c/0x31d9c; stops before call 0x194c. No physical device or actual queue.',
          'index_offset_in_conditional_map': '0x254098', 'cases': cases}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'cases': len(cases), 'input_outputs': [(c['input'], c['synthetic_state'], c.get('index_after')) for c in cases],
                  'source_sha256': expected_hash, 'result': str(HERE / 'результаты.json')}, ensure_ascii=False))
