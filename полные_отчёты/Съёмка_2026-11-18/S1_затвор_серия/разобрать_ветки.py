import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Сравнение_версий_2026-11-16'))
import fwcommon

b = fwcommon.load('X-H2', 'old', 1)
ids = [0x827, 0x858, 0x859, 0x863, 0x864, 0x866, 0x89F, 0x8A0, 0x883, 0x5BA, 0x5BC, 0x5BD, 0xB, 0xAAB, 0xAB8, 0xACE, 0xACF, 0xA70, 0x874]

def show(title, entry_base, id_base, table):
    print('\n' + title)
    for setting_id in ids:
        if setting_id < id_base:
            continue
        entry = table + 2 * (setting_id - id_base)
        offset = struct.unpack('<h', b.data[b.off(entry):b.off(entry) + 2])[0]
        target = entry_base + offset * 4
        print(f'\nUI_SETP {setting_id:#05x}: ветка {target:#x}')
        print(fwcommon.dis(b, target, 28))

show('СЕТТЕР', 0x2C88F50, 0xB, 0x33A77E8)
show('ГЕТТЕР', 0x2C9403C, 0xF, 0x33A929C)
