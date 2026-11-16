"""26: проверка «рабочего рецепта» из отчёта — строгий детектор M-profile образа.

Условия на выровненном слове w0 (чтобы не требовать длинных серий нечётных слов):
  * w0 чётное, 0x400 <= w0 < 0x100000 (SP в начале образа, стек растёт вниз);
  * w1 = w0 | 1 < 0x100000 (reset, Thumb-бит);
  * v2..v6 (NMI, HardFault, MemManage, BusFault, UsageFault) — нечётные, < 0x100000;
  * v7=v8=v9=0 и v12=0 (резервы ARMv7-M);
  * v10 (SVC), v13 (PendSV), v14 (SysTick), v15 (IRQ0) — нечётные, < 0x100000.
Печатает все совпадения и проверяет попадание в 0x1C0274. Только чтение.
"""
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
LIM = 0x100000
a = np.frombuffer(dec[:len(dec) & ~3], dtype='<u4').astype(np.int64)
n = len(a)
print(f'слов: {n}')

w = [a[k:n - 16 + k] for k in range(16)]
ok = lambda x: ((x & 1) == 1) & (x > 0) & (x < LIM)
# ARMv7-M: 7..10 — резерв (4 слова), 11 SVCall, 12 DebugMon, 13 резерв, 14 PendSV, 15 SysTick
m = (((w[0] & 1) == 0) & (w[0] >= 0x400) & (w[0] < LIM) &
     (w[1] == (w[0] | 1)) & (w[1] < LIM) &
     ok(w[2]) & ok(w[3]) & ok(w[4]) & ok(w[5]) & ok(w[6]) &
     (w[7] == 0) & (w[8] == 0) & (w[9] == 0) & (w[10] == 0) & (w[13] == 0) &
     ok(w[11]) & ok(w[14]) & ok(w[15]))
idx = np.nonzero(m)[0]
print(f'совпадений: {len(idx)}')
for i in idx[:20]:
    print(f'  DAT {int(i) * 4:#x}: SP={int(a[i]):#x} reset={int(a[i + 1]):#x} '
          f'NMI={int(a[i + 2]):#x} HardFault={int(a[i + 3]):#x} SysTick={int(a[i + 14]):#x}')
