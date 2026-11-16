"""F2: поиск записей в job+0x144 (X-H2 5.33 b1).

Кандидаты: `str/strh/strb wN,[xM,#0x144]`. Для каждого сайта:
  * адрес функции (func_start), входит ли она в «job API» (диапазон 0x3089xxx–0x308bxxx,
    менеджер 0x30172xx) или ссылается на страницу 0x4daa000;
  * контекст 6 инструкций.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

b = load('X-H2', 'new', 1)
JOBBASE = (0x3089000, 0x308c000)
MGR = (0x3017000, 0x3018000)

# быстрый признак: есть ли в функции adrp 0x4daa000
mgr_pages = {va for va, r in adrp_sites(b, 0x4daa000)}

rows = []
for va, w in iter_words(b):
    if (w & 0xffc00000) not in (0xb9000000, 0xb8000000, 0xb9000000, 0x39000000, 0x79000000):
        pass
    ins = insns(b, va, 1)
    if not ins:
        continue
    x = ins[0]
    if not x.mnemonic.startswith('st'):
        continue
    m = re.fullmatch(r'\w+, \[x\d+, #0x144\]', x.op_str)
    if not m:
        continue
    fs, fe = func_range(b, va, 0x8000)
    injob = JOBBASE[0] <= va < JOBBASE[1]
    inmgr = MGR[0] <= va < MGR[1]
    hasmgr = any(fs <= p < fe for p in mgr_pages)
    rows.append((va, fs, x.mnemonic + ' ' + x.op_str, injob, inmgr, hasmgr))

print(f'всего записей [#0x144]: {len(rows)}')
print(f'{"сайт":>10} {"функция":>10}  job? mgr? refMgr?  инструкция')
for va, fs, ins, injob, inmgr, hasmgr in rows:
    print(f'{va:#10x} {fs:#10x}  {"J" if injob else "."}   {"M" if inmgr else "."}   '
          f'{"R" if hasmgr else "."}       {ins}')
