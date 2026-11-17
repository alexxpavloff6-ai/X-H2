# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 36: таблица условия 0x3456B20 [speed_index*6 + shutter_type].
Ищем ячейки == 2 (флаг включён). speed_index 0..40, shutter_type 0..5."""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load  # noqa: E402

b1 = load('X-H2', 'old', 1)
TABLE = 0x3456B20
rows = []
twos = []
for speed in range(41):
    row = []
    for st in range(6):
        off = b1.off(TABLE + (speed * 6 + st) * 4)
        v = struct.unpack_from('<I', b1.data, off)[0]
        row.append(v)
        if v == 2:
            twos.append({'speed_index': speed, 'shutter_type': st, 'value': v})
    rows.append(row)

out = []
out.append('=== таблица 0x3456B20: строки speed_index 0..40, колонки shutter_type 0..5 ===')
out.append('speed | ' + ' '.join(f'st{st}' for st in range(6)))
for speed, row in enumerate(rows):
    mark = '  <<<' if any(v == 2 for v in row) else ''
    out.append(f'{speed:5d} | ' + ' '.join(f'{v:3d}' for v in row) + mark)
out.append('')
out.append(f'=== ячейки == 2 (флаг=1): {len(twos)} ===')
for t in twos:
    out.append(f"  speed_index={t['speed_index']} shutter_type={t['shutter_type']}")
result = {'table_va': hex(TABLE), 'rows': rows, 'cells_equal_2': twos}
(HERE / '2круг_таблица_условия.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
text = '\n'.join(out)
(HERE / '2круг_таблица_условия.txt').write_text(text + '\n', encoding='utf-8')
print(text)
