"""38: наша MOVDC-функция: дизасм, вызовы, поиск записей в регистры и работы с дескриптором.

* new 5.33: VA 0x3103ff8; old 5.30: VA 0x3107e84 (из A_LCD_MOVDC/ИТОГ.md);
* печатаем 0x240 байт, собираем bl-цели, ищем str/ldr с offset 0x18/0xD0/0xD8/0xF0
  и обращения к глобалу 0x4C2FF14 (guard-флаг) в этой функции и её калерах.

Только чтение.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


def func_window(b, va, n=0x240):
    rows = []
    for x in fwcommon.insns(b, va, n // 4):
        rows.append(x)
    return rows


for state, va in (('new', 0x3103FF8), ('old', 0x3107E84)):
    b = fwcommon.load('X-H2', state, 1)
    emit(f'== X-H2 {b.version} block1 MOVDC-функция VA {va:#x}')
    rows = func_window(b, va, 0x240)
    for x in rows:
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')
    calls = [int(re.search(r'#(0x[0-9a-f]+)', x.op_str).group(1), 0)
             for x in rows if x.mnemonic == 'bl' and re.search(r'#(0x[0-9a-f]+)', x.op_str)]
    emit(f'  bl-цели: {[hex(c) for c in calls]}')
    out[state] = {'va': hex(va), 'bl': [hex(c) for c in calls]}

(HERE / 'movdc_функция.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'movdc_функция.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved movdc_функция.txt/.json')
