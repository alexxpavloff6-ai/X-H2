"""14: проверка и первичный разбор образа Cortex-M4 в DAT X-H2 5.33.

По данным координатора образ лежит в DAT по смещению 0x1C0274, длина 0x31A80,
слинкован от 0 (SRAM 0xFA200000 = образ+0). Скрипт:
  * проверяет векторную таблицу (SP, reset, NMI/HardFault...), считает span;
  * дизассемблирует reset и несколько векторов (Thumb, capstone);
  * считает Thumb-метрики по образу и по его части;
  * собирает строки ASCII;
  * собирает 4-байтные литералы-пулы и ищет в них MOVDC/mailbox/SRAM/0x10030001.

Даёт `проверка_образа.json` + `дизасм_reset.txt`. Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF = 0x1C0274
IMG_LEN = 0x31A80

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
print(f'образ: DAT[{IMG_OFF:#x}:{IMG_OFF + IMG_LEN:#x}] = {len(img):#x} байт, '
      f'sha256={__import__("hashlib").sha256(img).hexdigest()[:16]}')

vecs = list(struct.unpack_from(f'<{min(64, len(img) // 4)}I', img, 0))
print('первые 32 слова (векторная таблица / начало кода):')
for i in range(0, 32, 4):
    print('  ' + ' '.join(f'{vecs[i + k]:#010x}' for k in range(4)))
sp, reset = vecs[0], vecs[1]
print(f'SP={sp:#x}  reset={reset:#x}')

from collections import Counter
rest = [v for v in vecs[2:40] if v]
print('следующие непустые слова:', [hex(v) for v in rest[:16]])
print('всего ненулевых в первых 64:', sum(1 for v in vecs if v))

out = {'image': {'dat_off': hex(IMG_OFF), 'len': hex(IMG_LEN), 'sp': hex(sp), 'reset': hex(reset),
                 'first_words': [hex(v) for v in vecs[:40]]}}

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)


def disasm(off, count=24, tag=''):
    lines = []
    for ins in cs.disasm(img[off:off + count * 4], off):
        lines.append(f'{IMG_OFF + ins.address:08x} ({ins.address:06x})  '
                     f'{ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}')
        if len(lines) >= count:
            break
    hdr = f'--- {tag} (смещение в образе {off:#x}, адрес DAT {IMG_OFF + off:#x})'
    print(hdr)
    print('\n'.join('  ' + x for x in lines))
    return [hdr] + lines


lines = []
lines += disasm(reset & ~1, 32, 'reset-вектор')
for k in (2, 3, 4, 5):
    v = vecs[k]
    if v:
        lines += disasm(v & ~1, 8, f'вектор {k}')
# сам векторный пролог (первые 0x40 байт) как код — если таблица короткая
lines += disasm(0x00, 16, 'начало образа (как код)')
(HERE / 'дизасм_reset.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')

m = m4lib.thumb_metrics_np(img, 0, len(img))
print(f"\nThumb-метрики образа: полуслов={m['halfwords']} push_lr={m['push_lr']} ({m['push_lr_pct']}%) "
      f"bl={m['bl']} ({m['bl_pct']}%) bx_lr={m['bx_lr']} ({m['bx_lr_pct']}%) ldr_pc={m['ldr_pc_pct']}%")
out['metrics'] = m

# строки
import re
strings = []
for mm in re.finditer(rb'[\x20-\x7e]{6,}', img):
    strings.append((mm.start(), mm.group().decode('latin1')))
print(f'\nстрок ASCII >=6: {len(strings)} (первые 40)')
for off, s in strings[:40]:
    print(f'  +{off:06x}  {s}')
out['strings'] = [{'off': hex(o), 's': s} for o, s in strings]
out['strings_count'] = len(strings)

# литералы-пулы: все 4-байтные слова, разбитые по областям значений
words = list(struct.unpack_from(f'<{len(img) // 4}I', img, 0))
LITS = {
    'MOVDC_0xFF97xxxx': (lambda v: 0xFF970000 <= v < 0xFF974000),
    'MOVDC_регистр0xD8_0x10030001': (lambda v: v == 0x10030001),
    'SRAM_0xFA200000_1M': (lambda v: 0xFA200000 <= v < 0xFA300000),
    'mailbox_0xFF90E100': (lambda v: 0xFF90E000 <= v < 0xFF90F000),
    'mailbox_0x5F90E100': (lambda v: 0x5F90E000 <= v < 0x5F90F000),
    'flag_0x4c2ff14': (lambda v: 0x4C2FF14 == v or (0x4C2F000 <= v < 0x4C30000)),
    'job_0x4daa6e8': (lambda v: 0x4DAA000 <= v < 0x4DAB000),
    'flash_0xF00xxxxx': (lambda v: 0xF0000000 <= v < 0xF8000000),
    'periph_0xFF9xxxxx': (lambda v: 0xFF900000 <= v < 0xFFA00000),
    'clock_0xFF90Cxxx': (lambda v: 0xFF90C000 <= v < 0xFF90D000),
}
print('\nлитералы (4-байтные слова) по категориям:')
lits = {}
for name, pred in LITS.items():
    hits = [i * 4 for i, v in enumerate(words) if pred(v)]
    lits[name] = [{'off': hex(h), 'va': hex(h)} for h in hits[:40]]
    print(f'  {name}: {len(hits)} {[hex(h) for h in hits[:8]]}')
out['literals'] = lits
out['words_total'] = len(words)

(HERE / 'проверка_образа.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved проверка_образа.json, дизасм_reset.txt')
