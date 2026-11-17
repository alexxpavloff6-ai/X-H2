# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 47: писатель source[0x5A8] 0x14F1E6C (func 0x14F1A6C) —
как выдержка преобразуется в code 0..17."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
out = []
out.append('===== контекст писателя source[0x5A8] @ 0x14F1E6C =====')
out.append(dis(b0, 0x14F1E6C - 0x60, 28))
out.append('')
out.append('===== функция 0x14F1A6C (начало) =====')
out.append(dis(b0, 0x14F1A6C, 50))
text = '\n'.join(out)
(HERE / '4круг_писатель_code.txt').write_text(text + '\n', encoding='utf-8')
print(text)
