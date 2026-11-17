# -*- coding: utf-8 -*-
"""Gate для cron-watch 4-го круга: печатает сообщение только когда готовы 10_1-1000 и 11_1-4000."""
import os
import sys

BASE = r'<корень проекта>\Анализ_прошивки\Камера_2026-11-17\K1_камера\снимки_серия'
p10 = os.path.join(BASE, '10_1-1000', 'backup.bin')
p11 = os.path.join(BASE, '11_1-4000', 'backup.bin')
have10 = os.path.isfile(p10)
have11 = os.path.isfile(p11)
if have10 and have11:
    print('READY: 10_1-1000 and 11_1-4000 backup.bin present — finalize Q3 round-4 comparison')
# иначе ничего не печатаем (exit 0) -> fire пропускается
sys.exit(0)
