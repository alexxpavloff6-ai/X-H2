"""Проследить передачу коэффициентов Classic Chrome в виртуальную область устройства.

DAT открыт только для чтения. Исходные команды исполняются без исправлений.
Числа настроек и все рабочие буферы искусственные; физической камеры здесь нет.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location(
    'xh2_color_registers', ROOT / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import UC_HOOK_MEM_WRITE


def main():
    x = study.Study()
    x.uc.mem_map(0xFF96C000, 0x4000)
    p, general, registers = 0x60000000, 0x60010000, 0x60020000
    watched = []
    executed = set()

    def capture_write(uc, access, address, size, value, user):
        watched.append({'address': hex(address), 'size': size, 'value': value,
                        'pc': hex(uc.reg_read(study.UC_ARM64_REG_PC))})

    def capture_code(uc, address, size, user):
        executed.add(address)

    x.uc.hook_add(UC_HOOK_MEM_WRITE, capture_write, begin=0xFF96C000, end=0xFF96FFFF)
    x.uc.hook_add(study.UC_HOOK_CODE, capture_code)

    descriptors = [struct.unpack_from('<QQH', x.a, 0x18DF948 - 0x1101000 + j * 24)
                   for j in range(2)]
    assert descriptors == [(0xFF96C634, 0x1EC, 1), (0xFF96C638, 0x1F0, 1)]
    results = []
    for display in range(-4, 5):
        index = display + 4
        gain = x.template[0xAF50 + index]
        expected = [max(-4096, min(4095, (v * gain * 128 * 64) >> 20))
                    for v in (885, -10, 859, -12)]
        x.clear(p)
        x.clear(general)
        for offset, value in [(0x100, 0), (0x12C, 1), (0x130, 8),
                              (0x124, 0x12), (0x128, 0x12), (0x13C, index),
                              (0x10C, 8), (0x17C, 2)]:
            x.word(p + offset, value)

        # Подлинный фрагмент общего сборщика, включая отметку обновления 0x80.
        x.run(0x2F1C7CC, until=0x2F1C7E4,
              registers={19: p, 21: general + 0x96C})
        record_values = list(struct.unpack('<4h', x.uc.mem_read(general + 0xB46, 8)))
        assert record_values == expected
        assert x.u32(p + 0x178) == 0x80
        assert bytes(x.uc.mem_read(general + 0x979, 1)) == b'\x01'

        for upper in (0, 0xA000, 0xE000):
            x.clear(registers)
            # Старшие три бита каждого поля должны сохраниться при упаковке.
            x.uc.mem_write(registers + 0x1EC, struct.pack('<4H', *([upper] * 4)))
            executed.clear()
            x.run(0x2F1CDC8, [general, 0x80, registers])
            packed = list(struct.unpack('<4H', x.uc.mem_read(registers + 0x1EC, 8)))
            assert packed == [upper | (v & 0x1FFF) for v in expected]
            assert {0x2D2F42C, 0x1377870, 0x13777D0, 0x1373E04} <= executed

            # Выполняется весь штатный передатчик, включая две нужные записи.
            watched.clear()
            executed.clear()
            x.run(0x2F1CDF4, [0x80, registers])
            coefficient_writes = [w for w in watched
                                  if int(w['address'], 16) in (0xFF96C634, 0xFF96C638)]
            assert len(coefficient_writes) == 2
            words = list(struct.unpack('<2I', struct.pack('<4H', *packed)))
            assert [(int(w['address'], 16), w['size'], w['value'])
                    for w in coefficient_writes] == [(0xFF96C634, 4, words[0]),
                                                     (0xFF96C638, 4, words[1])]
            assert {0x2D2F5F0, 0x1377884, 0x1373E84, 0x5DE10} <= executed
            results.append({'color': display, 'index': index, 'gain': gain,
                            'record_values': record_values, 'reserved_upper_bits': hex(upper),
                            'packed_fields': packed, 'register_words': [hex(w) for w in words],
                            'coefficient_writes': coefficient_writes,
                            'total_device_writes_in_run': len(watched)})

    # Контроль выбора: без бита 7 именно эта пара адресов не записывается.
    watched.clear()
    x.run(0x2F1CDF4, [0, registers])
    assert not any(int(w['address'], 16) in (0xFF96C634, 0xFF96C638) for w in watched)

    current_hash = hashlib.sha256(study.base.SOURCE.read_bytes()).hexdigest()
    assert current_hash == study.base.EXPECTED_SHA256 == study.sha(x.raw)
    result = {
        'source': str(study.base.SOURCE), 'source_sha256': current_hash,
        'source_unchanged': True, 'date': '2026-11-01',
        'conditions': 'Artificial neutral context; unmodified ARM64 commands; virtual memory only.',
        'not_verified': ['Real camera execution and register readback',
                         'Hardware pixel computation', 'Exact role of these registers in all shooting modes'],
        'descriptor_address': '0x018DF948',
        'descriptors': [{'device_address': hex(a), 'buffer_offset': hex(o), 'word_count': n}
                        for a, o, n in descriptors],
        'general_record_subblock_offset': '0x96C',
        'general_record_coefficient_offsets': ['0xB46', '0xB48', '0xB4A', '0xB4C'],
        'update_mask': '0x80', 'coefficient_storage_bits': 13,
        'virtual_runs': len(x.runs), 'cases': results,
        'negative_control_no_bit7_no_coefficient_writes': True,
    }
    (HERE / 'Проверка_записи_в_виртуальные_регистры.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    windows = [(0x2F1C7CC, 0x2F1C7E4), (0x2F1CDC8, 0x2F1CE08),
               (0x2D2F424, 0x2D2F434), (0x13777D0, 0x1377884),
               (0x2D2F5EC, 0x2D2F5F8), (0x1377884, 0x13778A4),
               (0x1373E84, 0x1373F30), (0x5DE10, 0x5DE1C)]
    lines = []
    for start, end in windows:
        base, block = next((a, b) for a, b in [(0x1101000, x.a), (0x29AE000, x.b),
                                              (0x40000, x.low)] if a <= start < a + len(b))
        lines.append(f'; {start:#010x} .. {end:#010x}')
        lines.extend(f'{z.address:08X}  {z.bytes.hex(" ").upper():11}  {z.mnemonic:7} {z.op_str}'
                     for z in cs.disasm(block[start-base:end-base], start))
    (HERE / 'Команды_передачи_коэффициентов.asm').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({'cases': len(results), 'runs': len(x.runs),
                      'source_unchanged': True,
                      'color_0_and_plus2': [c for c in results if c['color'] in (0, 2)
                                            and c['reserved_upper_bits'] == '0x0']},
                     ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
