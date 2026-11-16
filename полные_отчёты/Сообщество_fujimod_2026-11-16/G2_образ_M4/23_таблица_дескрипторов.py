"""23: разбор таблицы описаний в блоке 0 вокруг записи с 0x1C0274 (дескриптор компонента M4).

Пробуем шаг 0x28 и 0x24 байта: печатаем соседние записи, чтобы понять структуру
{смещение в flash, размер, ...}. Только чтение.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

b = m4lib.load_block('X-H2', 'new', 0)
va = 0x199D23C
o = b.off(va)
print(f'hex вокруг VA {va:#x}:')
for i in range(0, 0x180, 16):
    ch = b.data[o - 0x60 + i:o - 0x60 + i + 16]
    print(f'  {va - 0x60 + i:09x}  {ch.hex(" "):<47}  ' +
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))

for stride in (0x24, 0x28, 0x2C, 0x30):
    print(f'\n== шаг {stride:#x}: ищем выравнивание, где 0x1C0274 стоит на одном месте записи')
    for field in range(0, 10):
        for start in range(o - 0x200, o + 4, 4):
            vals = [struct.unpack_from('<I', b.data, start + k * stride + field * 4)[0] for k in range(6)]
            if 0x1C0274 in vals:
                idx = vals.index(0x1C0274)
                rec = [hex(struct.unpack_from('<I', b.data, start + idx * stride + f * 4)[0]) for f in range(10)]
                print(f'  field={field} stride={stride:#x} first@{start:#x} idx={idx}: {" ".join(rec)}')
                break
        else:
            continue
        break
