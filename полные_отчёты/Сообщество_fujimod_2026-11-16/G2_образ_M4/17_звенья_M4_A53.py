"""17: звенья M4 ↔ A53: MOVDC-алиас, RTOS-ядро, строки, константы запуска на стороне A53.

(а) есть ли в образе M4 слова 0x5F97xxxx (алиас MOVDC) и вообще таблица периферийных алиасов
    0x5F9xxxxx — с гистограммой по блокам адресов;
(б) известные A53-адреса (0x4xxxxxx DRAM, флаг, задание) в образе M4;
(в) строки ThreadX/syslog в образе и рядом;
(г) дизасм обработчиков SVC/PendSV/SysTick/DebugMon — опознание RTOS;
(д) константы запуска на стороне A53: 0x1C0274, 0x31A80, 0xFA200000, 0xFF90C928 (и алиас).

Только чтение.
"""
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}

print('== (а) алиасы 0x5F9xxxxx в образе M4: гистограмма по страницам 0x1000')
words = struct.unpack_from(f'<{len(img) // 4}I', img, 0)
pages = Counter()
for v in words:
    if 0x5F900000 <= v < 0x5FA00000:
        pages[v & 0xFFFFF000] += 1
for page, c in sorted(pages.items()):
    note = {0x5F90E000: 'mailbox (A53: 0xFF90E000)', 0x5F90C000: 'clock-gates (0xFF90C000)',
            0x5F930000: 'DMA (0xFF930000)', 0x5F939000: 'flash-DMA (0xFF939000)',
            0x5F97_0000: 'MOVDC (0xFF970000)', 0x5F907000: 'gpio (0xFF907000)'}.get(page, '')
    print(f'  {page:#010x}  x{c:<3} {note}')
out['alias_pages'] = {hex(p): c for p, c in pages.items()}
print(f'  MOVDC-алиас 0x5F970000..0x5F973FFF: '
      f'{sum(c for p, c in pages.items() if 0x5F970000 <= p < 0x5F974000)} слов')

print('\n== (б) адреса A53 в образе M4 (литералы/слова)')
CHECKS = {'флаг A53 0x4c2ff14': 0x4C2FF14, 'задание 0x4daa6e8': 0x4DAA6E8,
          '0x4c2f000 (страница флага)': 0x4C2F000, '0x4daa000': 0x4DAA000,
          'SRAM 0xFA200000': 0xFA200000, 'SRAM 0xFA210000': 0xFA210000,
          'SRAM 0xFA300000': 0xFA300000, 'movdc 0xFF970000': 0xFF970000,
          'movdc 0x5F970000': 0x5F970000, '0x10030001': 0x10030001}
for name, v in CHECKS.items():
    n4 = words.count(v)
    n4u = img.count(struct.pack('<I', v))
    n8 = img.count(struct.pack('<Q', v))
    print(f'  {name:26s}: выровненных u32={n4}, любых u32={n4u}, u64={n8}')
    out[f'check_{name}'] = {'u32_aligned': n4, 'u32_any': n4u, 'u64': n8}

print('\n== (в) строки ThreadX/syslog')
for pat in (b'System Timer', b'ThreadX', b'syslog', b'Ver ', b'Copyright', b'Express Logic',
            b'FreeRTOS', b'task', b'Thread'):
    hits = [m.start() for m in re.finditer(re.escape(pat), img)]
    print(f'  {pat!r}: {len(hits)} {[hex(h) for h in hits[:6]]}')
    if not hits:
        # рядом с образом (до/после)
        around = dec[IMG_OFF - 0x4000:IMG_OFF + IMG_LEN + 0x4000]
        hits2 = [m.start() + IMG_OFF - 0x4000 for m in re.finditer(re.escape(pat), around)]
        if hits2:
            print(f'     рядом с образом: {[hex(h) for h in hits2[:6]]}')
out['threadx_strings'] = {p.decode(): [hex(m.start()) for m in re.finditer(re.escape(p), img)]
                          for p in (b'System Timer', b'ThreadX', b'syslog')}

print('\n== (г) обработчики исключений: опознание RTOS')
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
vecs = list(struct.unpack_from('<16I', img, 0))
names = ['SP', 'reset', 'NMI', 'HardFault', 'MemManage', 'BusFault', 'UsageFault', '-', '-', '-',
         'SVC', 'DebugMon', '-', 'PendSV', 'SysTick']
for k, nm in enumerate(names):
    if k >= len(vecs):
        break
    v = vecs[k]
    if not v or nm in ('SP', '-'):
        continue
    print(f'--- {nm}: вектор {v:#x}')
    for x in cs.disasm(img[v & ~1:v & ~1 | 0x0][:64] if False else img[(v & ~1):(v & ~1) + 64], v & ~1):
        print(f'  {x.address:06x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')

print('\n== (д) константы запуска на стороне A53 (поиск в блоках 0-3 и префиксе)')
SRC = {'0x1C0274 (смещение образа)': 0x1C0274, '0x1C0000 (flash)': 0x1C0000,
       '0x31A80 (длина X-H2)': 0x31A80, '0x22900 (длина X-H2S)': 0x22900,
       '0x32470 (длина X-T5)': 0x32470, '0xFF90C928 (старт)': 0xFF90C928,
       '0x5F90C928 (алиас)': 0x5F90C928, '0xFF90C000': 0xFF90C000,
       '0xFA200000': 0xFA200000, '0x200000 (бит21)': 0x200000}
report = {}
for bname, data, base in [('prefix', dec[:0x300274], 0)] + \
                          [(f'block{i}', blocks[i].data, blocks[i].base) for i in range(4)]:
    for name, v in SRC.items():
        hits32 = [i for i in range(0, len(data) - 3, 4)
                  if struct.unpack_from('<I', data, i)[0] == v]
        if hits32:
            report.setdefault(name, {})[bname] = [hex(base + h) for h in hits32[:8]]
            print(f'  {name:24s} {bname:7s}: {len(hits32)} шт. {[hex(base + h) for h in hits32[:5]]}')
out['launch_consts'] = report

(HERE / 'звенья_M4_A53.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved звенья_M4_A53.json')
