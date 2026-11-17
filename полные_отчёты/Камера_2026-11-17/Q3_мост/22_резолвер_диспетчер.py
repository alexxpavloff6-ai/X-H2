# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 22: резолвер 0x5460C и диспетчер 0x4A458 по реальным VA
(loader base 0x40000). Ищем таблицу записей и обработчик set-записи."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import loader, dis  # noqa: E402

L = loader()
print(repr(L))
out = []
for name, va, n in (('резолвер 0x5460C', 0x5460C, 90),
                    ('диспетчер 0x4A458', 0x4A458, 130),
                    ('скаляр 0x50D94', 0x50D94, 60)):
    out.append(f'===== {name} (реальные VA) =====')
    out.append(dis(L, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / '2круг_резолвер_диспетчер.txt').write_text(text + '\n', encoding='utf-8')
print(text[:12000])
