"""F: в большом логгере бэкапа (b0, вокруг 0x126765c) найти строку
eDotlcdPowoffDrivemode и смещение поля, которое рядом логируется.

Логгер печатает "\t$BACKUP[%d]<имя> %s(%d)->%s(%d)\r\n", где имя — отдельная
format-строка (или её часть). Собираем все adrp+add на C-строки в функции и
печатаем по порядку адресов вместе с контекстом (какое поле читается).
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

b = load('X-H2', 'new', 0)
fs = func_start(b, 0x126765c, limit=0x20000)
print('func_start:', hex(fs))
# найдём конец: следующий пролог после 0x126765c
end = 0x126765c
for va in range(0x126765c, 0x126765c + 0x8000, 4):
    w = b.u32(va)
    if (w & 0xffc07fff) == 0xa9807bfd and va > 0x126765c:
        end = va
        break
print('примерный конец:', hex(end))

rows = []
for x in insns(b, fs, (end - fs) // 4):
    if x.mnemonic == 'adrp':
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in insns(b, x.address + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str)
            if y.mnemonic == 'add' and m and m.group(2) == reg:
                a = page + int(m.group(3), 0)
                s = b.cstr(a)
                if s:
                    rows.append((x.address, a, s))
                break
seen = set()
for site, a, s in rows:
    if a in seen:
        continue
    seen.add(a)
    print(f'{site:#x} -> {a:#x}  {s[:90]}')
