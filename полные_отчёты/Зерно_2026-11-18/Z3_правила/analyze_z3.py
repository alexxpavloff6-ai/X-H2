"""Повторяемая выборка кода X-H2 5.30 для задания Z3. Только чтение исходных блоков."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import csv
ROOT = Path(r'<корень проекта>')
sys.path.insert(0, str(ROOT / 'Анализ_прошивки' / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis, bl_callers
b = load('X-H2', 'old', 1)
assert b.version == '5.30'
sections = [
    ('проверка монохромной тонировки, still', 0x2ca05a8, 0x2ca0770),
    ('проверка монохромной тонировки, movie', 0x2ca0644, 0x2ca074c),
    ('дополнительные условия BLACK_TONE_RG', 0x2ca0840, 0x2ca0964),
    ('чтение DR и связанного поля RAW-параметров', 0x2c9849c, 0x2c98550),
    ('WB-поля и условные значения RAW-параметров', 0x2c98784, 0x2c989e8),
]
out = []
for title, start, end in sections:
    out.append(f'## {title} [{start:#x}..{end:#x}]')
    out.append(dis(b, start, (end-start)//4))
    out.append('')
for target in (0x2c93fd4, 0x2c9b038, 0x1135930):
    calls = bl_callers(b, target)
    out.append(f'## Прямые вызовы {target:#x}: {len(calls)}; первые 32')
    out.extend(f'{site:#x} {kind}' for site, kind in calls[:32])
    out.append('')
map_path = ROOT / 'Анализ_прошивки' / 'Камера_2026-11-17' / 'K2_прошивка' / 'карта_банка.tsv'
wanted = {'0x68e','0x691','0x6a2','0x6a3','0x6a4','0x6a5','0x6a6','0x6af','0x5f5','0x5f7'}
seen = set()
with map_path.open(encoding='utf8', newline='') as f:
    for row in csv.reader(f, delimiter='\t'):
        if len(row) > 7 and row[0] == 'current' and row[3].lower() in wanted and row[3].lower() not in seen:
            out.append(f'Карта: {row[3]} = {row[5]}, getter {row[7]}, storage {row[8]}')
            seen.add(row[3].lower())
print('\n'.join(out))
