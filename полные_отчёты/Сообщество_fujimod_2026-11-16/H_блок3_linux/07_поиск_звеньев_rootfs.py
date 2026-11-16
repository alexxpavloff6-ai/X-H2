"""Поиск трёх звеньев (MOVDC, guard-флаг, задание) в распакованном rootfs.

Только чтение rootfs/; отчёт в свою папку.
"""
from pathlib import Path
import hashlib
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE / 'rootfs'
OUT = HERE / 'rootfs_поиск.txt'

# ищем константы в разных представлениях
PATTERNS = {
    'MOVDC (ascii)': [b'MOVDC', b'movdc', b'MovDc'],
    '0xFF970000 (reg base)': [struct.pack('<I', 0xFF970000), struct.pack('>I', 0xFF970000)],
    '0xFF971000/2000/3000': [struct.pack('<I', 0xFF971000), struct.pack('<I', 0xFF972000),
                             struct.pack('<I', 0xFF973000)],
    '0xFF90C300 (clock gate)': [struct.pack('<I', 0xFF90C300), struct.pack('>I', 0xFF90C300)],
    '0xFF90E100 (mailbox)': [struct.pack('<I', 0xFF90E100), struct.pack('>I', 0xFF90E100),
                             struct.pack('<I', 0xFF90E000), struct.pack('<I', 0xFF90E1)],
    '0x10030001 (MOVDC val)': [struct.pack('<I', 0x10030001), struct.pack('>I', 0x10030001)],
    '0x4c2ff14 (guard)': [struct.pack('<I', 0x4c2ff14), struct.pack('<Q', 0x4c2ff14)],
    '0x4daa6e8 (job)': [struct.pack('<I', 0x4daa6e8), struct.pack('<Q', 0x4daa6e8)],
    'amp_shared': [b'amp_shared', b'amp_isgc'],
    'ISGC': [b'ISGC', b'isgc'],
    'uio dev': [b'/dev/uio', b'uio%d', b'generic-uio'],
    'cia': [b'CIA_', b'ciaCtrl', b'/dev/cia'],
    'MOVDC reg names': [b'MOVDC_DETCTRL', b'C1AFea', b'C1BWind'],
    'D0 stride const': [struct.pack('<I', 0xD0) + b'\0'],
}


def find_all(data, needle, cap=12):
    out = []
    s = 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1
        if len(out) >= cap:
            return out


def printable_near(data, off, span=48):
    seg = data[max(0, off - span):off + span]
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)


def main():
    files = sorted(p for p in ROOT.rglob('*') if p.is_file())
    print(f'файлов: {len(files)}')
    lines = [f'файлов в rootfs: {len(files)}', '']
    report = {k: [] for k in PATTERNS}
    for p in files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        rel = str(p.relative_to(ROOT)).replace('\\', '/')
        for label, needles in PATTERNS.items():
            for nd in needles:
                hits = find_all(data, nd, cap=6)
                if hits:
                    for h in hits[:3]:
                        report[label].append((rel, len(data), h, nd.hex(), printable_near(data, h)))
    for label in PATTERNS:
        rows = report[label]
        lines.append(f'=== {label}: {len(rows)} вхождений ===')
        for rel, size, off, nd, ctx in rows[:60]:
            lines.append(f'  {rel} (size={size}) @0x{off:x} [{nd}]  |{ctx}|')
        if len(rows) > 60:
            lines.append(f'  ... ещё {len(rows)-60}')
        lines.append('')
    OUT.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    for label in PATTERNS:
        print(f'{label}: {len(report[label])}')
    print('written', OUT)


if __name__ == '__main__':
    main()
