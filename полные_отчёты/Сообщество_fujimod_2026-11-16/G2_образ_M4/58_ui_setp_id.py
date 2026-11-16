"""58: имя свойства/настройки id=0x4C по словарю UI_SETP в блоке 0 (номер = индекс строки − 1).

Словарь: блок 0 (X-H2 5.33) 0x1654ED0..0x16C07D8, строки UI_SETP_* подряд.
Печатаем строки с индексами вокруг 0x4C и соседние, а также размер блока данных свойства,
если удаётся найти запись описателя.

Только чтение.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

b = fwcommon.load('X-H2', 'new', 0)
lo, hi = 0x1654ED0, 0x16C07D8
data = b.data[b.off(lo):b.off(hi)]
strings = [s.decode('latin1') for s in data.split(b'\x00') if s.startswith(b'UI_SETP')]
print(f'строк UI_SETP*: {len(strings)}')
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


emit('индекс = id+1; печатаем id 0x40..0x60')
for i, s in enumerate(strings[:120]):
    if 0x38 <= i <= 0x70:
        emit(f'  id={i - 1:#04x} ({i - 1:3d})  {s}')
emit('')
for q in (0x4C, 0x50, 0x2B, 0x2C, 0x2D, 0x74, 0x75):
    if 0 < q < len(strings):
        emit(f'  id={q:#04x} → {strings[q]}   (индекс {q + 1})')

(HERE / 'ui_setp_id4c.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved ui_setp_id4c.txt')
