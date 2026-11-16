"""62: API-функции, к которым обращаются с id=0x4C (0x11DA148, 0x12E8814), и функция
вокруг 0x12E79BC, где id выбирается между 0x4B и 0x4C по флагу 0x267C3E8.

Только чтение.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

b = fwcommon.load('X-H2', 'new', 0)
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def dump(lo, hi, tag):
    emit(f'--- {tag} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(b, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


dump(0x11DA148, 0x11DA1C0, 'API 0x11DA148 (вызов с id=0x4C)')
dump(0x12E8814, 0x12E8880, 'API 0x12E8814 (вызов с id=0x4C)')

fs = fwcommon.func_start(b, 0x12E79BC)
emit(f'\nfunc_start(0x12E79BC) = {hex(fs) if fs else None}')
if fs:
    dump(fs, min(fs + 0x160, 0x12E7A00), 'функция с выбором 0x4B/0x4C')

(HERE / 'api_4c.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved api_4c.txt')
