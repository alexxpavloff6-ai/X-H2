"""F: извлечение всех C-строк (ASCII, >=4 символов) из блоков 0/1/2 всех моделей.

Результат: strings/<model>_<version>_b<idx>.txt  со строками "адрес<TAB>строка".
Нужен для поиска имён полей (DriveMode/Bracket/...) и таблиц значений.
"""
import sys, re, json, struct, os
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'strings')
os.makedirs(OUT, exist_ok=True)
PAT = re.compile(rb'[\x20-\x7e]{4,200}')

for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(model, state, idx)
            rows = []
            for m in PAT.finditer(b.data):
                s = m.group(0)
                # отбрасываем мусор без букв
                if not re.search(rb'[A-Za-z]{3}', s):
                    continue
                rows.append(f'{b.base + m.start():x}\t{s.decode("latin1")}')
            fn = f'{model.replace("-","")}_{b.version}_b{idx}.txt'
            with open(os.path.join(OUT, fn), 'w', encoding='utf8') as f:
                f.write('\n'.join(rows))
            print(fn, len(rows))
