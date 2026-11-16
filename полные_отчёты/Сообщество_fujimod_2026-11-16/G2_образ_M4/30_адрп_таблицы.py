"""30: найти в блоке 1 (X-H2 old 5.30 / new 5.33) все ADRP на страницу таблицы карты регистров
0x385E000 и печатать код вокруг каждого сайта (окно 0x60 до / 0x140 после).

Только чтение. Вывод — в `адрп_385E000.txt` и на экран.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

PAGE = 0x385E000
out = {}
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


for state in ('old', 'new'):
    b = fwcommon.load('X-H2', state, 1)
    sites = fwcommon.adrp_sites(b, PAGE)
    emit(f'=== X-H2 {b.version} block1 base={b.base:#x}: ADRP на {PAGE:#x} — {len(sites)} сайтов')
    emit('   ' + ', '.join(f'{s:#x}(x{r})' for s, r in sites))
    for s, r in sites:
        emit(f'--- сайт {s:#x} (x{r})')
        # печатаем 0x40 назад и 0x100 вперёд
        start = s - 0x40
        for x in fwcommon.insns(b, start, 0x140 // 4):
            mark = ' <==' if x.address == s else ''
            emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')
    out[state] = {'version': b.version, 'sites': [hex(s) for s, _ in sites]}

(HERE / 'адрп_385E000.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'адрп_385E000.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved адрп_385E000.txt/.json')
