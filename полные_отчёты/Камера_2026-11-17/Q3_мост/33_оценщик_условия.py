# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 33: оценщик условия 0x30308A0 (6 аргументов) и геттеры настроек."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b1 = load('X-H2', 'old', 1)
b0 = load('X-H2', 'old', 0)
out = []
out.append('===== ОЦЕНЩИК УСЛОВИЯ 0x30308A0 =====')
out.append(dis(b1, 0x30308A0, 220))
out.append('')
for name, va in (('getter0 0x154CEC8', 0x154CEC8), ('getter2 0x154CF6C', 0x154CF6C),
                 ('getter1 0x3030A18', 0x3030A18), ('getter3 0x155B8EC', 0x155B8EC),
                 ('getter4 0x30246D8', 0x30246D8), ('getter5 0x1552658', 0x1552658)):
    b = b0 if va < 0x29AE000 else b1
    out.append(f'===== {name} =====')
    out.append(dis(b, va, 22))
    out.append('')
text = '\n'.join(out)
(HERE / '2круг_ОЦЕНЩИК_УСЛОВИЯ.txt').write_text(text + '\n', encoding='utf-8')
print(text[:13000])
