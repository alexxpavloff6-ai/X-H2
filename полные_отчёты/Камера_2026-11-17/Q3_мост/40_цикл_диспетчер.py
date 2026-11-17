# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 40: цикл диспетчеризации 0x14F67C0 (источник w0 для case fieldB)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
out = []
out.append('===== цикл диспетчеризации 0x14F67C0 =====')
out.append(dis(b0, 0x14F67C0, 90))
text = '\n'.join(out)
(HERE / '3круг_цикл_диспетчер.txt').write_text(text + '\n', encoding='utf-8')
print(text)
